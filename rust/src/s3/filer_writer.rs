//! One owning identity file, never a flattened IAM tree. Non-atomic Filer writes are explicit.
use super::*;
use crate::config;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::{
    io::{Read, Write},
    time::Duration,
};
use url::Url;

fn endpoint(key: Option<&str>) -> Result<Url> {
    let raw = crate::integrations::env(key.ok_or("Filer endpoint is not configured")?)?;
    let u = Url::parse(&raw).map_err(|_| "Invalid Filer endpoint")?;
    if !matches!(u.scheme(), "http" | "https")
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err("Filer requires an exact HTTP(S) base URL without credentials or query".into());
    }
    Ok(u)
}
fn url(base: &Url, subject: &str) -> Result<Url> {
    if subject.is_empty()
        || !subject
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_+=,.@-".contains(&b))
        || matches!(subject, "." | "..")
    {
        return Err("Invalid Filer identity name".into());
    }
    let mut u = base.clone();
    u.set_path(&format!(
        "{}/etc/iam/identities/{subject}.json",
        base.path().trim_end_matches('/')
    ));
    Ok(u)
}
fn bearer(key: Option<&str>) -> Result<Option<String>> {
    key.map(crate::integrations::env).transpose()
}
fn agent(plane: &Plane, seconds: u64) -> Result<ureq::Agent> {
    if !(1..=120).contains(&seconds) {
        return Err("Invalid Filer timeout".into());
    }
    Ok(ureq::Agent::config_builder()
        .tls_config(crate::tls::http(plane.ca_bundle_env.as_deref())?)
        .timeout_global(Some(Duration::from_secs(seconds)))
        .max_redirects(0)
        .proxy(None)
        .http_status_as_error(false)
        .build()
        .into())
}
fn get(http: &ureq::Agent, url: &Url, token: Option<&str>) -> Result<(Vec<u8>, Option<String>)> {
    let mut request = http.get(url.as_str());
    if let Some(t) = token {
        request = request.header("Authorization", &format!("Bearer {t}"));
    }
    let mut r = request
        .call()
        .map_err(|_| "Filer read failed; response withheld")?;
    if r.status().as_u16() != 200 {
        return Err("Filer identity must already exist and be readable".into());
    }
    let etag = r
        .headers()
        .get("etag")
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned);
    let mut bytes = Vec::new();
    r.body_mut()
        .as_reader()
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Incomplete Filer identity")?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("Filer identity exceeds limit".into());
    }
    Ok((bytes, etag))
}
fn jwt(key: &str) -> Result<String> {
    let key = crate::integrations::env(key)?;
    let body = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(format!(
            "{{\"exp\":{}}}",
            chrono::Utc::now().timestamp() + 10
        ))
    );
    let mut h =
        Hmac::<Sha256>::new_from_slice(key.as_bytes()).map_err(|_| "Invalid Filer signing key")?;
    h.update(body.as_bytes());
    Ok(format!(
        "{body}.{}",
        URL_SAFE_NO_PAD.encode(h.finalize().into_bytes())
    ))
}
#[derive(Serialize)]
pub struct Receipt {
    pub system: String,
    pub subject: String,
    pub plan_id: String,
    pub applied: bool,
    pub changed: bool,
    pub conditional_write: bool,
    pub concurrent_admin_guarantee: bool,
    pub effective_access_verified: bool,
    pub backup: Option<std::path::PathBuf>,
    pub previews: Vec<Preview>,
}
pub fn apply(
    path: &Path,
    system: &str,
    subject: Option<&str>,
    write: bool,
    expected: Option<&str>,
) -> Result<Receipt> {
    if write && expected.is_none() {
        return Err("Filer --write requires --expect PLAN_ID".into());
    }
    let (loaded, cfg, intent) = config::load_writer(path)?;
    let a = loaded
        .config
        .adapters
        .get(system)
        .filter(|a| a.typ(system) == "s3")
        .ok_or("S3 adapter required")?;
    let p = a.planes.get(&a.enforced).ok_or("Missing enforced plane")?;
    if p.file.is_some() || p.dir.is_some() || p.url_env.is_some() || p.iam_url_env.is_some() {
        return Err("Filer writer requires an unmixed Filer plane".into());
    }
    let observation = super::observe_with_live(a, &loaded.base, system, true);
    let plan = crate::planner::build(
        &loaded.intent,
        &observation.grants,
        &observation.unknown,
        &loaded.kinds,
        vec![],
    );
    let subjects: BTreeSet<_> = plan
        .changes
        .iter()
        .filter(|c| c.grant.system == system)
        .map(|c| c.grant.subject.as_str())
        .collect();
    let declared: BTreeSet<_> = loaded
        .intent
        .grants
        .iter()
        .filter(|g| g.system == system)
        .map(|g| g.subject.as_str())
        .collect();
    let subject = subject
        .or_else(|| (subjects.len() == 1).then(|| *subjects.first().unwrap()))
        .or_else(|| {
            (subjects.is_empty() && declared.len() == 1).then(|| *declared.first().unwrap())
        })
        .ok_or("Select --subject for a single Filer identity plan")?;
    let unread = |o: &super::Observed| {
        o.unknown
            .iter()
            .any(|u| u.subjects.is_empty() || u.subjects.contains(subject))
    };
    if unread(&observation) {
        return Err(
            "Filer observation is incomplete for the selected identity; no writes allowed".into(),
        );
    }
    let read_url = url(&endpoint(p.filer_url_env.as_deref())?, subject)?;
    let write_url = url(&endpoint(p.admin_filer_url_env.as_deref())?, subject)?;
    let read_token = bearer(p.filer_auth_env.as_deref())?;
    let signing_key = p.admin_filer_jwt_env.as_deref();
    let write_token = bearer(p.admin_filer_auth_env.as_deref())?;
    let http = agent(p, a.read_timeout_seconds)?;
    let (before, revision) = get(&http, &read_url, read_token.as_deref())?;
    let original = super::writer::parse(&before)?;
    if original["name"] != subject {
        return Err("Filer identity name mismatch".into());
    }
    if observation.identities.get(subject).is_some_and(has_policy)
        && original
            .get("policy")
            .is_none_or(|v| v.as_object().is_none_or(|o| o.is_empty()))
    {
        return Err("Inherited policy owns this access; edit that policy instead of materializing per-user grants".into());
    }
    let raw = json!({"identities":[original.clone()]});
    let d = document(raw.clone(), system)?;
    let identity = d.identities.get(subject).ok_or("Missing Filer identity")?;
    let (held, _, unknown, _) = evaluate(identity, system)?;
    if !unknown.is_empty() {
        return Err("Owning identity policy is not fully evaluable".into());
    }
    let mut wanted = held;
    for c in plan
        .changes
        .iter()
        .filter(|c| c.grant.system == system && c.grant.subject == subject)
    {
        if c.action == "grant" {
            wanted.insert(c.grant.clone());
        } else if !wanted.remove(&c.grant) {
            return Err("Cannot revoke inherited access through this identity file".into());
        }
    }
    let mut scoped = loaded.clone();
    scoped.intent.grants = wanted;
    scoped.intent.managed = [subject.to_owned()].into_iter().collect();
    scoped.intent.managed_systems = [system.to_owned()].into_iter().collect();
    let (candidate, previews) = super::writer::candidate(
        &scoped,
        system,
        &serde_json::to_vec(&raw).map_err(|_| "Cannot encode identity")?,
    )?;
    let candidate: Value =
        serde_json::from_slice(&candidate).map_err(|_| "Invalid identity candidate")?;
    let after = serde_json::to_vec_pretty(&candidate["identities"][0])
        .map_err(|_| "Cannot encode Filer identity")?;
    let changed = candidate["identities"][0] != original;
    let state = serde_json::to_vec(&(
        &observation.grants,
        &observation.routes,
        &observation.unknown,
    ))
    .map_err(|_| "Cannot bind Filer observation")?;
    let credential_hash = crate::integrations::sha(
        &serde_json::to_vec(&(
            write_token.as_deref().unwrap_or("").as_bytes(),
            signing_key
                .map(crate::integrations::env)
                .transpose()?
                .unwrap_or_default()
                .as_bytes(),
        ))
        .map_err(|_| "Cannot bind Filer credentials")?,
    );
    let binding = serde_json::to_vec(&(
        system,
        subject,
        write_url.as_str(),
        &revision,
        &before,
        &after,
        &state,
        credential_hash,
    ))
    .map_err(|_| "Cannot bind Filer plan")?;
    let plan_id = crate::integrations::sha(
        &serde_json::to_vec(&(&cfg, &intent, &binding)).map_err(|_| "Cannot bind Filer inputs")?,
    );
    if write && expected != Some(plan_id.as_str()) {
        return Err("Filer reviewed plan is stale; preview again".into());
    }
    let mut backup = None;
    if write && changed {
        if config::writer_file(path)? != cfg
            || config::writer_file(&config::relative(&loaded.base, &loaded.config.intent)?)?
                != intent
            || get(&http, &read_url, read_token.as_deref())? != (before.clone(), revision.clone())
        {
            return Err("Filer source changed before dispatch".into());
        }
        let now = super::observe_with_live(a, &loaded.base, system, true);
        if unread(&now)
            || serde_json::to_vec(&(&now.grants, &now.routes, &now.unknown))
                .ok()
                .as_ref()
                != Some(&state)
        {
            return Err("Filer policy graph changed before dispatch".into());
        }
        let mut f = tempfile::Builder::new()
            .prefix(".grantline-filer-")
            .suffix(".backup.json")
            .tempfile_in(&loaded.base)
            .map_err(|_| "Cannot create private Filer backup")?;
        serde_json::to_writer(&mut f,&json!({"version":1,"system":system,"subject":subject,"endpoint":write_url,"before":original,"after_sha256":crate::integrations::sha(&after)})).map_err(|_|"Cannot encode Filer backup")?;
        f.flush().map_err(|_| "Cannot flush backup")?;
        f.as_file().sync_all().map_err(|_| "Cannot sync backup")?;
        backup = Some(f.keep().map_err(|_| "Cannot retain backup")?.1);
        std::fs::File::open(&loaded.base)
            .and_then(|f| f.sync_all())
            .map_err(|_| "Cannot sync backup directory")?;
        let token = signing_key.map(jwt).transpose()?.or(write_token);
        let mut request = http
            .put(write_url.as_str())
            .header("Content-Type", "application/json");
        if let Some(token) = token {
            request = request.header("Authorization", &format!("Bearer {token}"));
        }
        if p.conditional_write {
            let etag = revision
                .as_deref()
                .filter(|e| e.starts_with('"') && e.ends_with('"'))
                .ok_or("Conditional Filer write requires a strong ETag")?;
            request = request.header("If-Match", etag);
        }
        let r = request
            .send(&after)
            .map_err(|_| "Filer write outcome unknown; inspect the identity before retry")?;
        if r.status().as_u16() == 412 {
            return Err(
                "Filer revision conflict; identity was not overwritten; preview again".into(),
            );
        }
        if !(200..=204).contains(&r.status().as_u16()) {
            return Err("Filer write refused or outcome unknown; inspect before retry".into());
        }
        let (got, _) = get(&http, &read_url, read_token.as_deref())
            .map_err(|_| "Filer post-read failed; outcome unknown")?;
        if super::writer::parse(&got)? != candidate["identities"][0] {
            return Err("Filer post-state mismatch; outcome unknown".into());
        }
    }
    Ok(Receipt {
        system: system.into(),
        subject: subject.into(),
        plan_id,
        applied: write && changed,
        changed,
        conditional_write: p.conditional_write,
        concurrent_admin_guarantee: false,
        effective_access_verified: false,
        backup,
        previews,
    })
}
