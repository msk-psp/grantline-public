//! Local, single-file IAM writes. No remote reader, service reload or shell command.
use super::{Observed, Preview, document, evaluate};
use crate::{Result, config, planner};
use serde::{Deserialize, Serialize, de};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, Metadata, OpenOptions, Permissions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const LIMIT: u64 = 4 * 1024 * 1024;
fn digest(bytes: &[u8]) -> String {
    crate::hex(&Sha256::digest(bytes))
}
fn hash_parts(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for part in parts {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    crate::hex(&h.finalize())
}

// Reject duplicate keys rather than silently deleting credentials or policy fields.
struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Strict;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("unambiguous JSON without floating point numbers")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut out = Vec::new();
                while let Some(Strict(v)) = seq.next_element()? {
                    out.push(v);
                }
                Ok(Strict(Value::Array(out)))
            }
            fn visit_map<A: de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut out = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    let Strict(value) = map.next_value()?;
                    if out.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate JSON field"));
                    }
                }
                Ok(Strict(Value::Object(out)))
            }
        }
        d.deserialize_any(Visitor)
    }
}
pub(super) fn parse(bytes: &[u8]) -> Result<Value> {
    serde_json::from_slice::<Strict>(bytes)
        .map(|v| v.0)
        .map_err(|_| "Invalid, duplicate-key, too deep or non-integral IAM/backup JSON".into())
}
pub(super) fn read(path: &Path, limit: u64) -> Result<(Vec<u8>, Metadata)> {
    // Check before opening: a FIFO must not make a supposedly bounded read hang.
    let before = fs::symlink_metadata(path).map_err(|_| "Cannot inspect local IAM file")?;
    if !before.is_file() || before.nlink() != 1 || before.len() > limit {
        return Err("Requires a bounded regular file with one link".into());
    }
    let file = File::open(path).map_err(|_| "Cannot read local IAM file")?;
    let meta = file
        .metadata()
        .map_err(|_| "Cannot inspect open IAM file")?;
    if stamp(&before) != stamp(&meta) {
        return Err("IAM file changed while opening".into());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read complete local IAM file")?;
    if bytes.len() as u64 > limit || bytes.len() as u64 != meta.len() {
        return Err("IAM file exceeded size limit or changed during read".into());
    }
    Ok((bytes, meta))
}
fn stamp(m: &Metadata) -> (u64, u64, u32, u32, u32, u64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.mode(),
        m.uid(),
        m.gid(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
    )
}
fn plain_path(path: &Path) -> Result<PathBuf> {
    for parent in path.ancestors() {
        let meta = fs::symlink_metadata(parent).map_err(|_| "Cannot inspect IAM path")?;
        if meta.is_symlink() {
            return Err("Symlinks in the IAM path are unsupported".into());
        }
        if meta.is_dir() && meta.mode() & 0o022 != 0 && meta.mode() & 0o1000 == 0 {
            return Err("IAM path has an untrusted group/world-writable ancestor".into());
        }
    }
    let parent = path.parent().ok_or("IAM path has no parent")?;
    if fs::metadata(parent)
        .map_err(|_| "Cannot inspect IAM parent")?
        .mode()
        & 0o022
        != 0
    {
        return Err("IAM files/backups require a parent without group/world write access".into());
    }
    fs::canonicalize(path).map_err(|_| "Cannot resolve local IAM path".into())
}
fn source(loaded: &config::Loaded, system: &str) -> Result<PathBuf> {
    let adapter = loaded
        .config
        .adapters
        .get(system)
        .ok_or("Unknown selected system")?;
    if adapter.typ(system) != "s3" {
        return Err("This writer only supports local S3 IAM files".into());
    }
    let plane = adapter
        .planes
        .get(&adapter.enforced)
        .ok_or("Missing enforced plane")?;
    if plane.remote() || plane.dir.is_some() {
        return Err("Remote IAM and shared directory trees are read-only in this writer".into());
    }
    let path = plane
        .file
        .as_deref()
        .filter(|p| !p.is_empty())
        .ok_or("No local IAM file")?;
    let base = fs::canonicalize(&loaded.base).map_err(|_| "Cannot resolve config directory")?;
    plain_path(&config::relative(&base, path)?)
}
pub(super) fn supported(raw: &Value) -> Result<()> {
    let object = raw.as_object().ok_or("IAM source must be an object")?;
    if object
        .keys()
        .any(|k| !["identities", "accounts"].contains(&k.as_str()))
    {
        return Err("Unsupported top-level IAM bindings/fields; source left unchanged".into());
    }
    for row in raw
        .get("identities")
        .and_then(Value::as_array)
        .ok_or("Missing identities")?
    {
        if row.as_object().is_none_or(|o| {
            o.keys().any(|k| {
                ![
                    "name",
                    "actions",
                    "policy",
                    "credentials",
                    "account",
                    "disabled",
                    "status",
                ]
                .contains(&k.as_str())
            })
        }) {
            return Err(
                "Unsupported identity fields or policy bindings; source left unchanged".into(),
            );
        }
    }
    Ok(())
}
#[derive(Serialize)]
pub struct Receipt {
    pub system: String,
    pub path: PathBuf,
    pub plan_id: String,
    pub changed: bool,
    pub applied: bool,
    pub restored: bool,
    pub service_reload_verified: bool,
    pub backup: Option<PathBuf>,
    pub previews: Vec<Preview>,
}
struct Prepared {
    receipt: Receipt,
    before: Vec<u8>,
    after: Vec<u8>,
    meta: Metadata,
    inputs: BTreeMap<PathBuf, Vec<u8>>,
}
fn load_inputs(path: &Path) -> Result<(config::Loaded, BTreeMap<PathBuf, Vec<u8>>)> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|_| "Cannot resolve config path")?
            .join(path)
    };
    let config_bytes = read(&path, LIMIT)?.0;
    let header: config::Config =
        toml::from_str(std::str::from_utf8(&config_bytes).map_err(|_| "Config is not UTF-8")?)
            .map_err(|_| "Invalid config TOML/schema")?;
    let intent_path =
        config::relative(path.parent().ok_or("Config has no parent")?, &header.intent)?;
    let intent_bytes = read(&intent_path, LIMIT)?.0;
    let inputs = BTreeMap::from([(path.clone(), config_bytes), (intent_path, intent_bytes)]);
    let loaded = config::load(&path)?;
    for (path, before) in &inputs {
        if read(path, LIMIT)?.0 != *before {
            return Err("Config/intent changed while loading".into());
        }
    }
    Ok((loaded, inputs))
}
pub(super) fn candidate(
    loaded: &config::Loaded,
    system: &str,
    before: &[u8],
) -> Result<(Vec<u8>, Vec<Preview>)> {
    let raw = parse(before)?;
    supported(&raw)?;
    let doc = document(raw.clone(), system)?;
    let mut obs = Observed {
        enforced: loaded.config.adapters[system].enforced.clone(),
        identities: doc.identities,
        ready: true,
        ..Default::default()
    };
    for ident in obs.identities.values() {
        let (grants, findings, unknown, _) = evaluate(ident, system)?;
        obs.grants.extend(grants);
        obs.findings.extend(findings);
        obs.unknown.extend(unknown);
    }
    if !obs.unknown.is_empty() {
        return Err("IAM source has unknown permissions; cannot safely rewrite it".into());
    }
    let mut report = planner::build(&loaded.intent, &obs.grants, &[], &loaded.kinds, vec![]);
    report.changes.retain(|c| c.grant.system == system);
    if report.changes.iter().any(|c| {
        c.grant
            .resource
            .strip_prefix("bucket:")
            .is_some_and(|scope| {
                scope
                    .split('/')
                    .any(|s| s.is_empty() || matches!(s, "." | ".."))
            })
    }) {
        return Err(
            "S3 writer cannot represent empty or traversal resource segments safely".into(),
        );
    }
    if report.changes.len() > 1000 {
        return Err("Local IAM writer change limit exceeded".into());
    }
    let previews = obs.previews(system, &mut report.changes);
    if previews.iter().any(|p| p.blocked.is_some()) {
        return Err("IAM plan is not exactly representable; inspect the read-only plan".into());
    }
    let mut changed = raw;
    let rows = changed["identities"]
        .as_array_mut()
        .ok_or("Missing identities")?;
    for preview in &previews {
        let index = if let Some(i) = rows
            .iter()
            .position(|r| r["name"].as_str() == Some(&preview.subject))
        {
            i
        } else {
            rows.push(json!({"name": preview.subject, "actions": []}));
            rows.len() - 1
        };
        rows[index][&preview.kind] = preview.after.clone().ok_or("Missing grouped document")?;
    }
    // Candidate correctness is insufficient if removing a covering grant loses intended access.
    let final_doc = document(changed.clone(), system)?;
    let mut final_grants = std::collections::BTreeSet::new();
    for ident in final_doc.identities.values() {
        let (grants, _, unknown, _) = evaluate(ident, system)?;
        if !unknown.is_empty() {
            return Err("Final IAM document has unknown permissions".into());
        }
        final_grants.extend(grants);
    }
    let followup = planner::build(&loaded.intent, &final_grants, &[], &loaded.kinds, vec![]);
    if followup.changes.iter().any(|c| c.grant.system == system)
        || followup.unverified.iter().any(|g| g.system == system)
    {
        return Err(
            "Single-file plan would not converge to the selected intent; source left unchanged"
                .into(),
        );
    }
    let after = if previews.is_empty() {
        before.to_vec()
    } else {
        let mut bytes =
            serde_json::to_vec_pretty(&changed).map_err(|_| "Cannot encode IAM file")?;
        bytes.push(b'\n');
        bytes
    };
    if after.len() as u64 > LIMIT {
        return Err("Resulting IAM file exceeds the writer limit".into());
    }
    Ok((after, previews))
}
fn prepare(config_path: &Path, system: &str) -> Result<Prepared> {
    let (loaded, inputs) = load_inputs(config_path)?;
    let path = source(&loaded, system)?;
    let (before, meta) = read(&path, LIMIT)?;
    let (after, previews) = candidate(&loaded, system, &before)?;
    if inputs
        .keys()
        .any(|p| fs::canonicalize(p).ok().as_ref() == Some(&path))
    {
        return Err("IAM source must not alias config or intent".into());
    }
    let binding = serde_json::to_vec(&(system, &path, stamp(&meta), &inputs, &previews))
        .map_err(|_| "Cannot bind IAM plan")?;
    let plan_id = hash_parts(&[&binding, &before, &after]);
    Ok(Prepared {
        receipt: Receipt {
            system: system.into(),
            path,
            plan_id,
            changed: !previews.is_empty(),
            applied: false,
            restored: false,
            service_reload_verified: false,
            backup: None,
            previews,
        },
        before,
        after,
        meta,
        inputs,
    })
}
fn writable(path: &Path, meta: &Metadata) -> Result<File> {
    if meta.mode() & 0o7022 != 0 || meta.mode() & 0o200 == 0 {
        return Err("IAM source requires owner-write and no special/group/world-write bits".into());
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| "Filesystem does not authorize IAM writes".into())
}
fn lock(path: &Path, owner: &Metadata) -> Result<File> {
    let name = path
        .file_name()
        .ok_or("IAM file has no name")?
        .to_string_lossy();
    let path = path.with_file_name(format!(".{name}.grantline.lock"));
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let (_, meta) = read(&path, 0)?;
            if meta.mode() & 0o777 != 0o600 || meta.uid() != owner.uid() {
                return Err("Unsafe IAM writer lock file".into());
            }
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .map_err(|_| "Cannot open IAM writer lock")?
        }
        Err(_) => return Err("Cannot create IAM writer lock".into()),
    };
    file.try_lock()
        .map_err(|_| "Another IAM writer holds the lock or locking is unsupported")?;
    let current = fs::symlink_metadata(&path).map_err(|_| "Cannot inspect writer lock")?;
    if !current.is_file()
        || current.nlink() != 1
        || current.mode() & 0o777 != 0o600
        || current.uid() != owner.uid()
        || stamp(&current) != stamp(&file.metadata().map_err(|_| "Cannot inspect open lock")?)
    {
        return Err("IAM lock path changed".into());
    }
    Ok(file)
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Backup {
    version: u8,
    system: String,
    path: PathBuf,
    before_sha256: String,
    after_sha256: String,
    mode: u32,
    uid: u32,
    gid: u32,
    before: String,
}
fn check_current(prepared: &Prepared) -> Result<()> {
    let (bytes, meta) = read(&plain_path(&prepared.receipt.path)?, LIMIT)?;
    if bytes != prepared.before || stamp(&meta) != stamp(&prepared.meta) {
        return Err("Stale IAM source; no replacement performed".into());
    }
    for (path, before) in &prepared.inputs {
        if read(path, LIMIT)?.0 != *before {
            return Err("Stale config or intent; no replacement performed".into());
        }
    }
    Ok(())
}
fn replace(prepared: &Prepared) -> Result<PathBuf> {
    // shortcut: POSIX mode/owner only; support ACLs/xattrs before using ACL-managed targets.
    let path = &prepared.receipt.path;
    let parent = path.parent().ok_or("IAM path has no parent")?;
    let mut staged =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "Cannot stage IAM replacement")?;
    let stage_meta = staged
        .as_file()
        .metadata()
        .map_err(|_| "Cannot inspect staged file")?;
    if stage_meta.uid() != prepared.meta.uid() || stage_meta.gid() != prepared.meta.gid() {
        return Err("Atomic replacement would change IAM owner/group".into());
    }
    staged
        .write_all(&prepared.after)
        .map_err(|_| "Cannot stage IAM bytes")?;
    staged
        .as_file()
        .sync_all()
        .map_err(|_| "Cannot sync IAM staging file")?;
    let backup = Backup {
        version: 1,
        system: prepared.receipt.system.clone(),
        path: path.clone(),
        before_sha256: digest(&prepared.before),
        after_sha256: digest(&prepared.after),
        mode: prepared.meta.mode() & 0o777,
        uid: prepared.meta.uid(),
        gid: prepared.meta.gid(),
        before: String::from_utf8(prepared.before.clone()).map_err(|_| "IAM file is not UTF-8")?,
    };
    let mut saved =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "Cannot create private IAM backup")?;
    saved
        .as_file()
        .set_permissions(Permissions::from_mode(0o600))
        .map_err(|_| "Cannot secure original IAM backup")?;
    serde_json::to_writer(saved.as_file_mut(), &backup)
        .map_err(|_| "Cannot save original IAM backup")?;
    saved
        .as_file()
        .sync_all()
        .map_err(|_| "Cannot sync original IAM backup")?;
    let backup_path = path.with_file_name(format!(
        ".{}.grantline-backup-{}",
        path.file_name()
            .ok_or("Missing IAM filename")?
            .to_string_lossy(),
        uuid::Uuid::new_v4()
    ));
    check_current(prepared)?;
    saved
        .persist_noclobber(&backup_path)
        .map_err(|_| "Cannot preserve original IAM backup")?;
    File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(|_| "Backup durability uncertain; original IAM not replaced")?;
    check_current(prepared)?;
    staged
        .as_file()
        .set_permissions(Permissions::from_mode(backup.mode))
        .map_err(|_| "Cannot preserve IAM mode")?;
    staged
        .as_file()
        .sync_all()
        .map_err(|_| "Cannot sync IAM permissions")?;
    check_current(prepared)?;
    staged
        .persist(path)
        .map_err(|_| "Cannot atomically replace IAM file; private backup retained")?;
    File::open(parent).and_then(|f| f.sync_all()).map_err(
        |_| "IAM replaced but directory sync failed; inspect private backup before retry",
    )?;
    if read(path, LIMIT)?.0 != prepared.after {
        return Err(
            "IAM replaced but verification failed; inspect private backup before retry".into(),
        );
    }
    Ok(backup_path)
}
pub fn apply(
    config_path: &Path,
    system: &str,
    write: bool,
    expected: Option<&str>,
) -> Result<Receipt> {
    if write && expected.is_none() {
        return Err("Writes require --expect from a reviewed apply dry-run".into());
    }
    let mut prepared = prepare(config_path, system)?;
    if !write {
        return Ok(prepared.receipt);
    }
    if expected != Some(prepared.receipt.plan_id.as_str()) {
        return Err("Stale or mismatched plan identifier; run apply dry-run again".into());
    }
    let _access = writable(&prepared.receipt.path, &prepared.meta)?;
    let _lock = lock(&prepared.receipt.path, &prepared.meta)?;
    check_current(&prepared)?;
    if prepared.receipt.changed {
        prepared.receipt.backup = Some(replace(&prepared)?);
        prepared.receipt.applied = true;
    }
    Ok(prepared.receipt)
}
pub fn restore(
    config_path: &Path,
    system: &str,
    backup_path: &Path,
    write: bool,
) -> Result<Receipt> {
    let (loaded, inputs) = load_inputs(config_path)?;
    let path = source(&loaded, system)?;
    let (before, meta) = read(&path, LIMIT)?;
    let (bytes, backup_meta) = read(&plain_path(backup_path)?, LIMIT * 8)?;
    if backup_meta.mode() & 0o777 != 0o600 || backup_meta.uid() != meta.uid() {
        return Err("Backup requires mode 0600 and the IAM file owner".into());
    }
    let backup: Backup =
        serde_json::from_value(parse(&bytes)?).map_err(|_| "Invalid IAM backup envelope")?;
    if backup.version != 1
        || backup.system != system
        || backup.path != path
        || backup.before.len() as u64 > LIMIT
        || digest(backup.before.as_bytes()) != backup.before_sha256
        || digest(&before) != backup.after_sha256
        || meta.mode() & 0o777 != backup.mode
        || meta.uid() != backup.uid
        || meta.gid() != backup.gid
    {
        return Err("Backup does not match this target or IAM changed since application".into());
    }
    let raw = parse(backup.before.as_bytes())?;
    supported(&raw)?;
    let _ = document(raw, system)?;
    let mut prepared = Prepared {
        receipt: Receipt {
            system: system.into(),
            path,
            plan_id: backup.before_sha256,
            changed: before != backup.before.as_bytes(),
            applied: false,
            restored: false,
            service_reload_verified: false,
            backup: None,
            previews: vec![],
        },
        before,
        after: backup.before.into_bytes(),
        meta,
        inputs,
    };
    if write {
        let _access = writable(&prepared.receipt.path, &prepared.meta)?;
        let _lock = lock(&prepared.receipt.path, &prepared.meta)?;
        check_current(&prepared)?;
        if prepared.receipt.changed {
            prepared.receipt.backup = Some(replace(&prepared)?);
            prepared.receipt.restored = true;
        }
    }
    Ok(prepared.receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        fs::write(root.join("config.toml"), "intent='intent.toml'\n[adapters.s3]\ntype='s3'\n[adapters.s3.planes.static]\nfile='iam.json'\n").unwrap();
        fs::write(root.join("intent.toml"), "managed_subjects=['demo']\n[[grants]]\nsystem='s3'\nsubject='demo'\nresource='bucket:demo/team'\nprivs=['Read']\n").unwrap();
        fs::write(
            root.join("iam.json"),
            b"{\"identities\":[{\"name\":\"demo\",\"actions\":[]}]}",
        )
        .unwrap();
        (dir, root)
    }
    #[test]
    fn mutation_after_prepare_does_not_replace_source_or_leave_temporary_files() {
        for filename in ["iam.json", "intent.toml", "config.toml"] {
            let (_dir, root) = fixture();
            let prepared = prepare(&root.join("config.toml"), "s3").unwrap();
            let mut bytes = fs::read(root.join(filename)).unwrap();
            bytes.push(b'\n');
            fs::write(root.join(filename), bytes).unwrap();
            let before = fs::read(root.join("iam.json")).unwrap();
            assert!(replace(&prepared).is_err());
            assert_eq!(fs::read(root.join("iam.json")).unwrap(), before);
            assert_eq!(fs::read_dir(&root).unwrap().count(), 3);
        }
    }
    #[test]
    fn concurrent_readers_only_see_complete_before_or_after_documents() {
        use std::sync::{
            Arc, Barrier,
            atomic::{AtomicBool, Ordering},
        };
        let (_dir, root) = fixture();
        let config = root.join("config.toml");
        let prepared = prepare(&config, "s3").unwrap();
        let before = prepared.before;
        let after = prepared.after;
        let source = root.join("iam.json");
        let running = Arc::new(AtomicBool::new(true));
        let signal = running.clone();
        let barrier = Arc::new(Barrier::new(2));
        let ready = barrier.clone();
        let reader = std::thread::spawn(move || {
            let mut n = 0;
            ready.wait();
            while signal.load(Ordering::Relaxed) {
                let bytes = fs::read(&source).unwrap();
                assert!(
                    bytes == before || bytes == after,
                    "reader saw a partial document"
                );
                n += 1;
            }
            n
        });
        barrier.wait();
        for _ in 0..10 {
            let p = apply(&config, "s3", false, None).unwrap();
            let written = apply(&config, "s3", true, Some(&p.plan_id)).unwrap();
            restore(&config, "s3", written.backup.as_deref().unwrap(), true).unwrap();
        }
        running.store(false, Ordering::Relaxed);
        assert!(reader.join().unwrap() > 0);
    }
}
