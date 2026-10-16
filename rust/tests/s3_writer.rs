#![cfg(unix)]
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions, Permissions},
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::Command,
};

const SECRET: &str = "NEVER-OUTPUT-CREDENTIAL";
fn setup() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    fs::write(root.join("config.toml"), "intent='intent.toml'\n[adapters.store]\ntype='s3'\nenforced='static'\n[adapters.store.planes.static]\nfile='iam.json'\n[adapters.store.planes.dynamic]\nurl_env='DO_NOT_RESOLVE_REMOTE_READER'\n[adapters.unrelated]\ntype='clickhouse'\nurl_env='DO_NOT_RESOLVE_OTHER_READER'\n").unwrap();
    fs::write(root.join("intent.toml"), "managed_subjects=['demo']\n[[grants]]\nsystem='store'\nsubject='demo'\nresource='bucket:demo/team'\nprivs=['Read']\n").unwrap();
    fs::write(root.join("iam.json"), serde_json::to_vec_pretty(&json!({
        "accounts":[{"id":"fixture","displayName":"Fixture","emailAddress":"demo@example.com"}],
        "identities":[
            {"name":"demo","actions":["Read:demo/old/*"],"credentials":[{"accessKey":"GLDEMO","secretKey":SECRET}],"account":{"id":"fixture"}},
            {"name":"unmanaged","actions":["Admin"],"credentials":[{"secretKey":SECRET}]}
        ]})).unwrap()).unwrap();
    fs::set_permissions(root.join("iam.json"), Permissions::from_mode(0o640)).unwrap();
    (dir, root)
}
fn run(root: &Path, args: &[&str], ok: bool) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_grantline-rs"))
        .arg("-c")
        .arg(root.join("config.toml"))
        .args(args)
        .current_dir("/")
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("AWS_ACCESS_KEY_ID", SECRET)
        .env("AWS_SECRET_ACCESS_KEY", SECRET)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!text.contains(SECRET), "secret escaped output");
    assert_eq!(output.status.success(), ok, "{text}");
    if ok {
        serde_json::from_slice(&output.stdout).unwrap()
    } else {
        Value::Null
    }
}
fn preview(root: &Path) -> Value {
    run(root, &["apply", "--system", "store", "--json"], true)
}
fn apply(root: &Path, id: &str, ok: bool) -> Value {
    run(
        root,
        &[
            "apply", "--system", "store", "--write", "--expect", id, "--json",
        ],
        ok,
    )
}
fn restore(root: &Path, backup: &str, write: bool, ok: bool) -> Value {
    let mut args = vec!["restore", "--system", "store", "--backup", backup, "--json"];
    if write {
        args.push("--write");
    }
    run(root, &args, ok)
}
fn entries(root: &Path) -> Vec<String> {
    let mut out = fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    out.sort();
    out
}
#[test]
fn dry_run_grouped_write_and_exact_conditional_restore_preserve_credentials() {
    let (_dir, root) = setup();
    let path = root.join("iam.json");
    let before = fs::read(&path).unwrap();
    let original: Value = serde_json::from_slice(&before).unwrap();
    let meta = fs::metadata(&path).unwrap();
    let names = entries(&root);
    let p = preview(&root);
    assert_eq!(entries(&root), names, "dry-run created files");
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(p["previews"][0]["changes"].as_array().unwrap().len(), 2);
    assert_eq!(p["previews"][0]["after"], json!(["Read:demo/team/*"]));
    run(
        &root,
        &["apply", "--system", "store", "--write", "--json"],
        false,
    );
    let result = apply(&root, p["plan_id"].as_str().unwrap(), true);
    assert_eq!(result["applied"], true);
    let after = fs::read(&path).unwrap();
    let changed: Value = serde_json::from_slice(&after).unwrap();
    assert_eq!(changed["accounts"], original["accounts"]);
    assert_eq!(
        changed["identities"][0]["credentials"],
        original["identities"][0]["credentials"]
    );
    assert_eq!(
        changed["identities"][0]["account"],
        original["identities"][0]["account"]
    );
    assert_eq!(changed["identities"][1], original["identities"][1]);
    let written = fs::metadata(&path).unwrap();
    assert_ne!(
        meta.ino(),
        written.ino(),
        "writer truncated the original inode"
    );
    assert_eq!(
        (written.mode(), written.uid(), written.gid()),
        (meta.mode(), meta.uid(), meta.gid())
    );
    let backup = result["backup"].as_str().unwrap();
    assert_eq!(fs::metadata(backup).unwrap().mode() & 0o777, 0o600);
    let saved: Value = serde_json::from_slice(&fs::read(backup).unwrap()).unwrap();
    assert_eq!(saved["before"].as_str().unwrap().as_bytes(), before);
    let converged = preview(&root);
    assert_eq!(converged["changed"], false);
    let count = entries(&root);
    let noop = apply(&root, converged["plan_id"].as_str().unwrap(), true);
    assert_eq!(noop["backup"], Value::Null);
    assert_eq!(entries(&root), count);
    assert_eq!(restore(&root, backup, false, true)["restored"], false);
    assert_eq!(fs::read(&path).unwrap(), after);
    let reverted = restore(&root, backup, true, true);
    assert_eq!(reverted["restored"], true);
    assert_eq!(fs::read(&path).unwrap(), before);
    // The restore itself has an original-byte backup, allowing a conditional redo.
    restore(&root, reverted["backup"].as_str().unwrap(), true, true);
    assert_eq!(fs::read(&path).unwrap(), after);
}
#[test]
fn policy_write_new_identity_and_unrelated_fields_follow_grouped_previews() {
    let (_dir, root) = setup();
    let path = root.join("iam.json");
    let mut raw: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    raw["identities"][0]["policy"] = json!({"Version":"2012-10-17","Statement":[{"Sid":"kept-id","Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::demo/old/*"]}]});
    fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();
    let p = preview(&root);
    assert_eq!(p["previews"][0]["kind"], "policy");
    apply(&root, p["plan_id"].as_str().unwrap(), true);
    let changed: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        changed["identities"][0]["actions"],
        raw["identities"][0]["actions"]
    );
    assert_eq!(
        changed["identities"][0]["policy"],
        p["previews"][0]["after"]
    );
    fs::write(root.join("intent.toml"),"managed_subjects=[]\n[[grants]]\nsystem='store'\nsubject='new-user'\nresource='bucket:demo/team'\nprivs=['Read']\n").unwrap();
    let p = preview(&root);
    assert_eq!(p["previews"][0]["creates_identity"], true);
    apply(&root, p["plan_id"].as_str().unwrap(), true);
    let raw: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let created = raw["identities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "new-user")
        .unwrap();
    assert_eq!(
        *created,
        json!({"name":"new-user","actions":["Read:demo/team/*"]})
    );
}
#[test]
fn stale_source_config_intent_metadata_and_foreign_plan_are_refused() {
    for changed in [
        "iam.json",
        "intent.toml",
        "config.toml",
        "mode",
        "other-file",
    ] {
        let (_dir, root) = setup();
        let p = preview(&root);
        match changed {
            "mode" => {
                fs::set_permissions(root.join("iam.json"), Permissions::from_mode(0o600)).unwrap()
            }
            "other-file" => {
                let old = fs::read(root.join("iam.json")).unwrap();
                fs::rename(root.join("iam.json"), root.join("original.json")).unwrap();
                fs::write(root.join("iam.json"), old).unwrap();
            }
            filename => {
                let mut bytes = fs::read(root.join(filename)).unwrap();
                bytes.push(b'\n');
                fs::write(root.join(filename), bytes).unwrap();
            }
        }
        let before = fs::read(root.join("iam.json")).unwrap();
        let names = entries(&root);
        apply(&root, p["plan_id"].as_str().unwrap(), false);
        assert_eq!(fs::read(root.join("iam.json")).unwrap(), before);
        assert_eq!(entries(&root), names);
    }
    let (_dir, root) = setup();
    let p = preview(&root);
    let (_other, other) = setup();
    apply(&other, p["plan_id"].as_str().unwrap(), false);
}
#[test]
fn malformed_unknown_and_duplicate_json_refuse_without_secret_output_or_mutation() {
    for raw in [
        format!("{{\"identities\":[],\"identities\":[],\"credentials\":\"{SECRET}\"}}"),
        format!("{{\"identities\":[{{\"name\":\"demo\",\"credentials\":[{{\"secretKey\":\"{SECRET}\",\"secretKey\":\"lost\"}}]}}]}}"),
        format!("{{\"identities\":[{{\"name\":\"demo\",\"credentials\":\"{SECRET}\",\"policy_names\":[\"shared\"]}}]}}"),
        "{\"identities\":[],\"groups\":[]}".into(),
        "{\"identities\":[{\"name\":\"demo\",\"actions\":[\"Read:demo\"],\"policy\":{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::demo/*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":true}}}]}}]}".into(),
        "{\"identities\":[{\"name\":\"demo\",\"account\":{\"number\":900719925474099312345}}]}".into(),
        "{\"identities\":[{\"name\":\"demo\",\"account\":{\"number\":1.5}}]}".into(),
        "{\"identities\":[{\"name\":\"demo\",\"actions\":[\"Read:demo\"]},{\"name\":\"demo\"}]}".into(),
    ] {
        let (_dir, root) = setup();
        fs::write(root.join("iam.json"), &raw).unwrap();
        run(&root,&["apply","--system","store","--json"],false);
        assert_eq!(fs::read_to_string(root.join("iam.json")).unwrap(),raw);
        assert_eq!(entries(&root).len(),3);
    }
}
#[test]
fn unsafe_files_lock_contention_and_unsupported_sources_never_write() {
    for kind in [
        "symlink",
        "parent-symlink",
        "hardlink",
        "readonly",
        "world-write",
        "unsafe-parent",
        "too-big",
        "lock",
        "lock-symlink",
        "remote",
        "tree",
        "type",
        "capability",
        "unsafe-scope",
    ] {
        let (_dir, root) = setup();
        let source = root.join("iam.json");
        match kind {
            "symlink" => { fs::rename(&source,root.join("real.json")).unwrap(); symlink("real.json",&source).unwrap(); }
            "parent-symlink" => {
                fs::create_dir(root.join("actual")).unwrap(); fs::rename(&source,root.join("actual/iam.json")).unwrap();
                symlink("actual",root.join("linked")).unwrap();
                let c=fs::read_to_string(root.join("config.toml")).unwrap().replace("file='iam.json'","file='linked/iam.json'"); fs::write(root.join("config.toml"),c).unwrap();
            }
            "hardlink" => fs::hard_link(&source,root.join("alias.json")).unwrap(),
            "readonly" => fs::set_permissions(&source,Permissions::from_mode(0o400)).unwrap(),
            "world-write" => fs::set_permissions(&source,Permissions::from_mode(0o666)).unwrap(),
            "unsafe-parent" => fs::set_permissions(&root,Permissions::from_mode(0o777)).unwrap(),
            "too-big" => OpenOptions::new().write(true).open(&source).unwrap().set_len(4*1024*1024+1).unwrap(),
            "lock-symlink" => symlink("intent.toml",root.join(".iam.json.grantline.lock")).unwrap(),
            "remote" | "tree" | "type" => {
                let text=fs::read_to_string(root.join("config.toml")).unwrap();
                let text=match kind { "remote"=>text.replace("file='iam.json'", "file='iam.json'\nurl_env='MISSING_READER'"), "tree"=>text.replace("file='iam.json'", "file='iam.json'\ndir='shared'"),_=>text.replace("type='s3'","type='postgres'") };
                fs::write(root.join("config.toml"),text).unwrap();
            }
            "capability" => fs::write(root.join("intent.toml"),"[[grants]]\nsystem='store'\nsubject='demo'\nresource='capability:s3/ListAllMyBuckets'\nprivs=['ListAllMyBuckets']\n").unwrap(),
            "unsafe-scope" => { let path=root.join("intent.toml"); let text=fs::read_to_string(&path).unwrap().replace("bucket:demo/team", "bucket:demo/team/../other"); fs::write(path,text).unwrap(); }
            _ => {}
        }
        let held = if kind == "lock" {
            let f = File::create(root.join(".iam.json.grantline.lock")).unwrap();
            f.set_permissions(Permissions::from_mode(0o600)).unwrap();
            f.try_lock().unwrap();
            Some(f)
        } else {
            None
        };
        let before = fs::read(&source).ok();
        if ["readonly", "world-write", "lock", "lock-symlink"].contains(&kind) {
            let p = preview(&root);
            apply(&root, p["plan_id"].as_str().unwrap(), false);
        } else {
            run(&root, &["apply", "--system", "store", "--json"], false);
        }
        assert_eq!(fs::read(&source).ok(), before, "{kind}");
        drop(held);
        if kind == "readonly" {
            fs::set_permissions(&source, Permissions::from_mode(0o600)).unwrap();
        }
    }
}
#[test]
fn restore_refuses_tampered_backup_or_any_subsequent_target_change() {
    for kind in ["target", "mode", "private", "tamper", "foreign"] {
        let (_dir, root) = setup();
        let p = preview(&root);
        let applied = apply(&root, p["plan_id"].as_str().unwrap(), true);
        let backup = PathBuf::from(applied["backup"].as_str().unwrap());
        match kind {
            "target" => {
                let mut b = fs::read(root.join("iam.json")).unwrap();
                b.push(b'\n');
                fs::write(root.join("iam.json"), b).unwrap();
            }
            "mode" => {
                fs::set_permissions(root.join("iam.json"), Permissions::from_mode(0o600)).unwrap()
            }
            "private" => fs::set_permissions(&backup, Permissions::from_mode(0o644)).unwrap(),
            "tamper" | "foreign" => {
                let mut v: Value = serde_json::from_slice(&fs::read(&backup).unwrap()).unwrap();
                if kind == "tamper" {
                    v["before"] = json!("{\"identities\":[]}");
                } else {
                    v["path"] = json!("/tmp/another-iam.json");
                }
                fs::write(&backup, serde_json::to_vec(&v).unwrap()).unwrap();
            }
            _ => unreachable!(),
        }
        let before = fs::read(root.join("iam.json")).unwrap();
        restore(&root, backup.to_str().unwrap(), true, false);
        assert_eq!(fs::read(root.join("iam.json")).unwrap(), before);
    }
}
#[test]
fn dropping_a_covering_grant_must_not_lose_the_intended_narrower_permission() {
    let (_dir, root) = setup();
    let path = root.join("iam.json");
    let mut raw: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    raw["identities"][0]["actions"] = json!(["Read:demo"]);
    let bytes = serde_json::to_vec(&raw).unwrap();
    fs::write(&path, &bytes).unwrap();
    run(&root, &["apply", "--system", "store", "--json"], false);
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(entries(&root).len(), 3);
}
