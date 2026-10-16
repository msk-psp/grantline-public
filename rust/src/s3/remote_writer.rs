//! One explicit JSON endpoint, strong If-Match and an independently reviewed inverse.
use crate::{Result, config};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
    time::{Duration, Instant},
};
use url::Url;

const LIMIT: u64 = 4 * 1024 * 1024;
struct Http {
    url: Url,
    bearer: Option<String>,
    started: Instant,
    timeout: Duration,
}
impl Http {
    fn agent(&self) -> Result<ureq::Agent> {
        let left = self
            .timeout
            .checked_sub(self.started.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or("Remote IAM deadline exceeded")?;
        Ok(ureq::Agent::config_builder()
            .timeout_global(Some(left))
            .timeout_connect(Some(left.min(Duration::from_secs(5))))
            .max_redirects(0)
            .proxy(None)
            .http_status_as_error(false)
            .build()
            .into())
    }
    fn get(&self) -> Result<(Vec<u8>, String)> {
        let mut r = self
            .agent()?
            .get(self.url.as_str())
            .header("Accept", "application/json");
        if let Some(b) = &self.bearer {
            r = r.header("Authorization", &format!("Bearer {b}"));
        }
        let mut r = r
            .call()
            .map_err(|_| "Remote IAM read failed; response withheld")?;
        if r.status().as_u16() != 200 {
            return Err("Remote IAM read refused; response withheld".into());
        }
        let etag = r
            .headers()
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .filter(|v| {
                v.starts_with('"')
                    && v.ends_with('"')
                    && v.len() > 2
                    && !v[1..v.len() - 1].contains(['"', '\r', '\n'])
            })
            .ok_or("Remote writer requires a strong quoted ETag")?
            .to_owned();
        let mut bytes = vec![];
        r.body_mut()
            .as_reader()
            .take(LIMIT + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "Remote IAM body failed")?;
        if bytes.len() as u64 > LIMIT {
            return Err("Remote IAM body exceeds limit".into());
        }
        Ok((bytes, etag))
    }
    fn put(&self, etag: &str, bytes: &[u8]) -> Result<()> {
        let mut r = self
            .agent()?
            .put(self.url.as_str())
            .header("If-Match", etag)
            .header("Content-Type", "application/json");
        if let Some(b) = &self.bearer {
            r = r.header("Authorization", &format!("Bearer {b}"));
        }
        let r = r.send(bytes).map_err(
            |_| "Remote IAM outcome unknown after dispatch; inspect before retry or inverse",
        )?;
        match r.status().as_u16() {
            200..=204 => Ok(()),
            412 => Err("Remote IAM revision conflict; conditional write refused".into()),
            _ => Err("Remote IAM outcome unknown after dispatch; no automatic rollback".into()),
        }
    }
}
#[derive(Serialize)]
pub struct Receipt {
    pub system: String,
    pub plan_id: String,
    pub changed: bool,
    pub applied: bool,
    pub conditional_write: bool,
    pub service_reload_verified: bool,
    pub effective_access_verified: bool,
    pub previews: Vec<super::Preview>,
    pub restored: bool,
    pub backup: Option<std::path::PathBuf>,
}
fn apply_inner(
    path: &Path,
    system: &str,
    write: bool,
    expected: Option<&str>,
    restore: Option<&Path>,
) -> Result<Receipt> {
    if write && expected.is_none() && restore.is_none() {
        return Err("Remote IAM --write requires --expect PLAN_ID".into());
    }
    let (loaded, cfg, intent) = config::load_writer(path)?;
    let a = loaded
        .config
        .adapters
        .get(system)
        .filter(|a| a.typ(system) == "s3")
        .ok_or("S3 adapter required")?;
    let p = a.planes.get(&a.enforced).ok_or("Enforced plane missing")?;
    if !p.conditional_write
        || p.iam_url_env.is_some()
        || p.filer_url_env.is_some()
        || p.file.is_some()
        || p.dir.is_some()
        || p.ca_bundle_env.is_some()
    {
        return Err("Remote JSON writes require explicit conditional_write, no mixed/tree/IAM sources or custom CA".into());
    }
    let raw = std::env::var(
        p.admin_url_env
            .as_deref()
            .ok_or("Remote IAM admin_url_env required")?,
    )
    .map_err(|_| "Remote IAM admin endpoint unavailable")?;
    let url = Url::parse(&raw).map_err(|_| "Invalid remote IAM endpoint")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "Remote IAM requires an exact HTTP(S) URL without userinfo/query/fragment".into(),
        );
    }
    let bearer = p
        .admin_auth_env
        .as_deref()
        .map(|key| std::env::var(key).map_err(|_| "Remote IAM admin credential unavailable"))
        .transpose()?;
    if bearer
        .as_ref()
        .is_some_and(|b| b.is_empty() || b.chars().any(char::is_control))
        || !(1..=120).contains(&a.read_timeout_seconds)
    {
        return Err("Invalid remote IAM credential or timeout".into());
    }
    let http = Http {
        url,
        bearer,
        started: Instant::now(),
        timeout: Duration::from_secs(a.read_timeout_seconds),
    };
    let (before, revision) = http.get()?;
    let (after, previews) = if let Some(path) = restore {
        let (bytes, m) = super::writer::read(path, 32 * 1024 * 1024)?;
        if m.permissions().mode() & 0o077 != 0 {
            return Err("Remote IAM backup requires mode 0600".into());
        }
        let b: Backup = serde_json::from_slice(&bytes).map_err(|_| "Invalid remote backup")?;
        if b.version != 1
            || b.system != system
            || b.endpoint != http.url.as_str()
            || b.after_sha256 != digest(&before)
            || b.before_sha256 != digest(b.before.as_bytes())
        {
            return Err("Remote IAM backup identity/state mismatch".into());
        }
        let raw = super::writer::parse(b.before.as_bytes())?;
        super::writer::supported(&raw)?;
        (b.before.into_bytes(), vec![])
    } else {
        super::writer::candidate(&loaded, system, &before)?
    };
    let credential_binding = digest(http.bearer.as_deref().unwrap_or("").as_bytes());
    let binding = serde_json::to_vec(&(
        "remote-iam-v1",
        std::path::absolute(path).map_err(|_| "Config path unavailable")?,
        system,
        http.url.as_str(),
        credential_binding,
        &revision,
        &before,
        &after,
    ))
    .map_err(|_| "Cannot bind remote plan")?;
    let mut hash = Sha256::new();
    for b in [&cfg, &intent, &binding] {
        hash.update((b.len() as u64).to_be_bytes());
        hash.update(b);
    }
    let plan_id = format!("{:x}", hash.finalize());
    if write && restore.is_none() && expected != Some(&plan_id) {
        return Err("Remote IAM reviewed plan is stale; preview again".into());
    }
    let changed = before != after;
    let mut backup = None;
    if write && changed {
        let ip = config::relative(&loaded.base, &loaded.config.intent)?;
        if config::writer_file(path)? != cfg
            || config::writer_file(&ip)? != intent
            || http.get()? != (before.clone(), revision.clone())
        {
            return Err("Remote IAM source/revision changed before dispatch".into());
        }
        let mut f = tempfile::Builder::new()
            .prefix(".grantline-remote-")
            .suffix(".backup.json")
            .tempfile_in(&loaded.base)
            .map_err(|_| "Cannot create private remote backup")?;
        serde_json::to_writer(
            &mut f,
            &Backup {
                version: 1,
                system: system.into(),
                endpoint: http.url.to_string(),
                before_sha256: digest(&before),
                after_sha256: digest(&after),
                before: String::from_utf8(before.clone()).map_err(|_| "IAM JSON is not UTF-8")?,
            },
        )
        .map_err(|_| "Cannot encode remote backup")?;
        f.flush().map_err(|_| "Cannot flush remote backup")?;
        f.as_file()
            .sync_all()
            .map_err(|_| "Cannot sync remote backup")?;
        backup = Some(f.keep().map_err(|_| "Cannot retain remote backup")?.1);
        std::fs::File::open(&loaded.base)
            .and_then(|f| f.sync_all())
            .map_err(|_| "Cannot sync remote backup directory; no request sent")?;
        http.put(&revision, &after)?;
        let (got, _) = http
            .get()
            .map_err(|_| "Remote IAM outcome unknown: post-read failed")?;
        if got != after {
            return Err("Remote IAM outcome unknown: exact post-state mismatch".into());
        }
    }
    Ok(Receipt {
        system: system.into(),
        plan_id,
        changed,
        applied: write && changed,
        conditional_write: true,
        service_reload_verified: false,
        effective_access_verified: false,
        previews,
        restored: write && changed && restore.is_some(),
        backup,
    })
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
#[derive(Serialize, Deserialize)]
struct Backup {
    version: u8,
    system: String,
    endpoint: String,
    before_sha256: String,
    after_sha256: String,
    before: String,
}
pub fn apply(path: &Path, system: &str, write: bool, expected: Option<&str>) -> Result<Receipt> {
    apply_inner(path, system, write, expected, None)
}
pub fn restore(path: &Path, system: &str, backup: &Path, write: bool) -> Result<Receipt> {
    apply_inner(path, system, write, None, Some(backup))
}
