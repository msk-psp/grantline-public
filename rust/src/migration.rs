//! Offline, copy-only state upgrade. Legacy bearer approvals never become authority.
use crate::{
    Result,
    integrations::sha,
    workflow::{Record, atomic_json, private_dir, private_json},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Deserialize)]
struct Legacy {
    id: String,
    ts: String,
    requester: String,
    action: String,
    system: String,
    subject: String,
    resource: String,
    #[serde(rename = "priv")]
    privilege: String,
    #[serde(default)]
    required: BTreeMap<String, Value>,
    #[serde(default)]
    approved: BTreeMap<String, Value>,
    status: String,
}
#[derive(Serialize, Deserialize)]
pub struct Archive {
    pub version: u8,
    pub id: String,
    pub created_at: i64,
    pub requester: String,
    pub action: String,
    pub grant: crate::model::Grant,
    pub required: Vec<String>,
    pub approved: Vec<String>,
    pub prior_status: String,
}
impl Archive {
    pub fn view(&self) -> Value {
        json!({"id":format!("legacy-{}",self.id),"created_at":self.created_at,"requester":self.requester,"action":self.action,"grant":self.grant,"required":self.required,"approved":self.approved,"status":"legacy","prior_status":self.prior_status,"readonly":true,"applied":false})
    }
    pub fn visible(&self, actor: &str, approval_identity: &str) -> bool {
        self.requester == actor
            || self.requester == approval_identity
            || self.required.iter().any(|p| p == approval_identity)
    }
}
fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}
fn directory(path: &Path) -> Result<()> {
    for p in path.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        let m = fs::symlink_metadata(p).map_err(|_| "Migration directories must already exist")?;
        use std::os::unix::fs::PermissionsExt;
        let mode = m.permissions().mode();
        if !m.is_dir() || m.is_symlink() || (mode & 0o022 != 0 && mode & 0o1000 == 0) {
            return Err("Migration path has an untrusted directory".into());
        }
        if p == path && mode & 0o077 != 0 {
            return Err("Migration directory must have mode 0700".into());
        }
    }
    Ok(())
}
fn input(source: &Path) -> Result<BTreeMap<String, Value>> {
    let meta = fs::symlink_metadata(source).map_err(|_| "Cannot inspect migration source")?;
    if !meta.is_dir() || meta.is_symlink() {
        return Err("Migration source must be a regular directory".into());
    }
    let mut rows = BTreeMap::new();
    for e in fs::read_dir(source).map_err(|_| "Cannot list migration source")? {
        let e = e.map_err(|_| "Cannot read migration entry")?;
        let name = e.file_name().to_string_lossy().into_owned();
        if name == "archive" {
            directory(&e.path())?;
            for archive in fs::read_dir(e.path()).map_err(|_| "Cannot list migration archives")? {
                let archive = archive.map_err(|_| "Cannot read migration archive")?;
                let file = archive.file_name().to_string_lossy().into_owned();
                if !file.strip_suffix(".json").is_some_and(valid_id) || rows.len() >= 1000 {
                    return Err("Invalid migration archive entry or size".into());
                }
                rows.insert(format!("archive/{file}"), private_json(&archive.path())?);
            }
            continue;
        }
        if name == "migration-manifest.json" {
            let manifest: Value = private_json(&e.path())?;
            if manifest["version"] != 1 {
                return Err("Unsupported migration manifest version".into());
            }
            rows.insert(name, manifest);
            continue;
        }
        if name.ends_with(".json") {
            if !name.strip_suffix(".json").is_some_and(valid_id) {
                return Err("Unexpected JSON file in migration source".into());
            }
            if rows.len() >= 1000 {
                return Err("Migration source exceeds 1000 records".into());
            }
            rows.insert(name, private_json(&e.path())?);
        }
    }
    Ok(rows)
}
pub fn migrate(source: &Path, destination: &Path, write: bool, offline: bool) -> Result<Value> {
    if write && !offline {
        return Err("Stop all source writers and pass --offline with --write".into());
    }
    if destination
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("Destination cannot traverse parents".into());
    }
    if destination.symlink_metadata().is_ok() {
        return Err("Migration destination must not exist".into());
    }
    directory(source)?;
    let source = source
        .canonicalize()
        .map_err(|_| "Cannot resolve migration source")?;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or("Destination needs an existing private parent")?;
    directory(parent)?;
    let parent = parent
        .canonicalize()
        .map_err(|_| "Destination parent must exist")?;
    if parent.starts_with(&source) {
        return Err("Migration destination must be outside its source".into());
    }
    let original = input(&source)?;
    let mut native = BTreeMap::new();
    let mut archives = BTreeMap::new();
    let mut hashes = BTreeMap::new();
    for (name, v) in &original {
        hashes.insert(
            name.clone(),
            sha(&serde_json::to_vec(v).map_err(|_| "Cannot hash source")?),
        );
        if name == "migration-manifest.json" {
            continue;
        }
        if let Some(name) = name.strip_prefix("archive/") {
            let a: Archive =
                serde_json::from_value(v.clone()).map_err(|_| "Invalid archive schema")?;
            if a.version != 1 || name != format!("{}.json", a.id) {
                return Err("Unsupported archive version or identity".into());
            }
            archives.insert(name.to_owned(), a);
        } else if v.get("version").is_some() {
            let mut r: Record =
                serde_json::from_value(v.clone()).map_err(|_| "Invalid native approval schema")?;
            if r.version != 1 || !valid_id(&r.id) || name != &format!("{}.json", r.id) {
                return Err("Unsupported native approval version or identity".into());
            }
            // Existing approval authority is not portable across auth or storage policies.
            if matches!(r.status.as_str(), "pending" | "approved") {
                r.status = "migration_review".into();
                r.approved.clear();
            }
            if r.status == "publishing" {
                r.status = "publish_unknown".into();
            }
            if r.notifications == "sending" {
                r.notifications = "unknown".into();
            }
            native.insert(name.clone(), r);
        } else {
            let r: Legacy =
                serde_json::from_value(v.clone()).map_err(|_| "Invalid legacy approval schema")?;
            if !valid_id(&r.id)
                || name != &format!("{}.json", r.id)
                || !["grant", "revoke"].contains(&r.action.as_str())
            {
                return Err("Invalid legacy approval identity or action".into());
            }
            let ts = chrono::DateTime::parse_from_rfc3339(&r.ts)
                .map_err(|_| "Invalid legacy approval time")?
                .timestamp();
            let a = Archive {
                version: 1,
                id: r.id,
                created_at: ts,
                requester: r.requester,
                action: r.action,
                grant: crate::model::Grant::new(&r.system, &r.subject, &r.resource, &r.privilege),
                required: r.required.into_keys().collect(),
                approved: r.approved.into_keys().collect(),
                prior_status: r.status,
            };
            archives.insert(name.clone(), a);
        }
    }
    let manifest = json!({"version":1,"native_records":native.len(),"legacy_archives":archives.len(),"source_semantic_sha256":hashes,"approval_authority_imported":false,"original_untouched":true});
    if !write {
        return Ok(json!({"written":false,"manifest":manifest}));
    }
    private_dir(&parent)?;
    let stage = tempfile::Builder::new()
        .prefix(".grantline-migrate-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(&parent)
        .map_err(|_| "Cannot stage migration")?;
    for (name, r) in &native {
        atomic_json(&stage.path().join(name), r)?;
    }
    if !archives.is_empty() {
        let dir = stage.path().join("archive");
        private_dir(&dir)?;
        for (name, r) in &archives {
            atomic_json(&dir.join(name), r)?;
        }
    }
    atomic_json(&stage.path().join("migration-manifest.json"), &manifest)?;
    if input(&source)? != original {
        return Err("Migration source changed; stop writers and retry".into());
    }
    if destination.symlink_metadata().is_ok() {
        return Err("Migration destination appeared during copy".into());
    }
    fs::rename(stage.path(), destination).map_err(|_| "Cannot publish migration directory")?;
    fs::File::open(&parent)
        .and_then(|f| f.sync_all())
        .map_err(|_| "Cannot sync migration parent")?;
    Ok(json!({"written":true,"manifest":manifest}))
}
