use grantline_rs::{config, engine, model::Grant, s3::policy_with};
use serde_json::{Value, json};
use std::{fs, path::Path, process::Command};

fn setup() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("config.toml"), "intent='intent.toml'\nenv_file='ignored.env'\n[adapters.object-store]\ntype='s3'\nenforced='dynamic'\n[adapters.object-store.planes.dynamic]\nfile='iam.json'\n").unwrap();
    fs::write(dir.path().join("intent.toml"), "managed_subjects=['demo']\n[[grants]]\nsystem='object-store'\nsubject='demo'\nresource='bucket:demo/team'\nprivs=['Read']\n").unwrap();
    dir
}
fn plan(root: &Path) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_grantline-rs"))
        .args([
            "-c",
            root.join("config.toml").to_str().unwrap(),
            "plan",
            "--json",
        ])
        .current_dir("/")
        .env(
            "IGNORED_ENDPOINT",
            "http://127.0.0.1:1/NEVER-OUTPUT-CREDENTIAL",
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("NEVER-OUTPUT-CREDENTIAL"));
    serde_json::from_slice(&output.stdout).unwrap()
}
fn put(root: &Path, doc: Value) {
    fs::write(root.join("iam.json"), serde_json::to_vec(&doc).unwrap()).unwrap();
}
fn stmt(action: &str, resource: &str) -> Value {
    json!({"Effect":"Allow","Action":action,"Resource":resource})
}
fn policy(ss: Vec<Value>) -> Value {
    json!({"identities":[{"name":"demo","actions":["Admin"],"credentials":[{"secretKey":"NEVER-OUTPUT-CREDENTIAL"}],"policy":{"Version":"2012-10-17","Statement":ss}}]})
}

#[test]
fn malformed_and_remote_sources_are_unknown_not_empty() {
    let dir = setup();
    let root = dir.path();
    for raw in [
        "{invalid NEVER-OUTPUT-CREDENTIAL",
        "{}",
        r#"{"identities":[{"name":"demo","actions":42}]}"#,
        r#"{"identities":[{"name":"demo"},{"name":"demo"}]}"#,
        r#"{"identities":[{"name":"demo","policy":{"Statement":{},"password":"NEVER-OUTPUT-CREDENTIAL"}}]}"#,
    ] {
        fs::write(root.join("iam.json"), raw).unwrap();
        let p = plan(root);
        assert!(!p["observation_complete"].as_bool().unwrap());
        assert_eq!(p["observed"], json!([]));
        assert_eq!(p["changes"], json!([]));
        assert_eq!(p["unverified"].as_array().unwrap().len(), 1);
    }
    put(root, json!({"identities":[]}));
    let path = root.join("config.toml");
    fs::write(
        &path,
        format!(
            "{}\niam_url_env='IGNORED_ENDPOINT'\n",
            fs::read_to_string(&path).unwrap()
        ),
    )
    .unwrap();
    let p = plan(root);
    assert_eq!(p["unverified"].as_array().unwrap().len(), 1);
    assert_eq!(
        fs::read_to_string(root.join("iam.json")).unwrap(),
        r#"{"identities":[]}"#
    );
}

#[test]
fn combined_preview_preserves_other_scopes_and_never_copies_credentials() {
    let dir = setup();
    let root = dir.path();
    put(
        root,
        policy(vec![
            json!({"Sid":"original","Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":["arn:aws:s3:::demo/old/*","arn:aws:s3:::demo/kept/*"]}),
        ]),
    );
    fs::write(root.join("intent.toml"),"managed_subjects=['demo']\n[[grants]]\nsystem='object-store'\nsubject='demo'\nresource='bucket:demo/team'\nprivs=['Read','Write']\n[[grants]]\nsystem='object-store'\nsubject='demo'\nresource='bucket:demo/kept'\nprivs=['Read','Write']\n").unwrap();
    let original = fs::read(root.join("iam.json")).unwrap();
    let p = plan(root);
    assert_eq!(p["s3_previews"].as_array().unwrap().len(), 1);
    let preview = &p["s3_previews"][0];
    assert!(preview["blocked"].is_null());
    assert_eq!(preview["changes"].as_array().unwrap().len(), 4);
    let after = preview["after"].to_string();
    assert!(!after.contains("demo/old"));
    assert!(after.contains("demo/kept"));
    assert!(after.contains("s3:DeleteObject"));
    assert_eq!(original, fs::read(root.join("iam.json")).unwrap());
    // Native canonicalization must revoke an original /* spelling, not leave it behind.
    put(
        root,
        json!({"identities":[{"name":"demo","actions":["Read:demo/old/*"]}]}),
    );
    let p = plan(root);
    let actions = p["s3_previews"][0]["after"].as_array().unwrap();
    assert!(!actions.iter().any(|a| a.as_str().unwrap().contains("old")));
}

#[test]
fn unrepresentable_revoke_and_capabilities_are_blocked() {
    let dir = setup();
    let root = dir.path();
    fs::write(
        root.join("intent.toml"),
        "managed_subjects=['demo']\nmanaged_systems=['object-store']\n",
    )
    .unwrap();
    for action in [
        "s3:CreateMultipartUpload",
        "s3:GetBucketLocation",
        "s3:ListAllMyBuckets",
    ] {
        put(
            root,
            policy(vec![stmt(
                action,
                if action == "s3:ListAllMyBuckets" {
                    "arn:aws:s3:::*"
                } else {
                    "arn:aws:s3:::demo"
                },
            )]),
        );
        let p = plan(root);
        assert!(!p["commands_complete"].as_bool().unwrap());
        assert!(p["s3_previews"][0]["blocked"].is_string());
        assert!(p["s3_previews"][0]["after"].is_null());
    }
    let g = Grant::new("s3", "demo", "bucket:demo/team", "List");
    assert!(policy_with(&json!({"Statement":[]}), &g, true).is_err());
    let g = Grant::new(
        "s3",
        "demo",
        "capability:s3/ListAllMyBuckets",
        "ListAllMyBuckets",
    );
    assert!(policy_with(&json!({"Statement":[]}), &g, false).is_err());
    fs::write(root.join("intent.toml"),"managed_subjects=['demo']\n[[grants]]\nsystem='object-store'\nsubject='demo'\nresource='capability:s3/ListAllMyBuckets'\nprivs=['ListAllMyBuckets']\n").unwrap();
    put(
        root,
        policy(vec![
            stmt("s3:ListAllMyBuckets", "arn:aws:s3:::*"),
            json!({"Effect":"Allow","NotAction":"s3:DeleteObject","Resource":"arn:aws:s3:::demo/*"}),
        ]),
    );
    let p = plan(root);
    assert_eq!(p["changes"], json!([]));
    assert_eq!(p["unverified"].as_array().unwrap().len(), 1);
}

#[test]
fn missing_shared_policies_and_empty_attached_policies_shadow_actions() {
    let dir = setup();
    let root = dir.path();
    let tree = root.join("tree");
    for d in ["identities", "groups", "policies"] {
        fs::create_dir_all(tree.join(d)).unwrap();
    }
    fs::write(
        tree.join("identities/demo.json"),
        r#"{"name":"demo","actions":["Admin"]}"#,
    )
    .unwrap();
    fs::write(
        tree.join("identities/loner.json"),
        r#"{"name":"loner","actions":["Read:temp"]}"#,
    )
    .unwrap();
    fs::write(
        tree.join("groups/research.json"),
        r#"{"name":"research","members":["demo"],"policy_names":["shared"]}"#,
    )
    .unwrap();
    let cfg = root.join("config.toml");
    fs::write(
        &cfg,
        fs::read_to_string(&cfg)
            .unwrap()
            .replace("file='iam.json'", "dir='tree'"),
    )
    .unwrap();
    let p = plan(root);
    assert_eq!(p["observed"].as_array().unwrap().len(), 1);
    assert_eq!(p["unverified"].as_array().unwrap().len(), 1);
    fs::write(tree.join("policies/shared.json"), r#"{"Statement":[]}"#).unwrap();
    let p = plan(root);
    assert_eq!(p["observed"].as_array().unwrap().len(), 1);
    assert_eq!(p["unverified"], json!([]));
    assert!(
        p["s3_previews"][0]["blocked"]
            .as_str()
            .unwrap()
            .contains("read-only")
    );
    fs::write(
        tree.join("policies/shared.json"),
        serde_json::to_vec(&json!({"Statement":[stmt("s3:GetObject","arn:aws:s3:::demo/team/*")]}))
            .unwrap(),
    )
    .unwrap();
    fs::write(tree.join("policies.json"),r#"{"inlinePolicies":{"demo":{"personal":{"Statement":[{"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::demo/team/*"}]}}}}"#).unwrap();
    let loaded = config::load(&cfg).unwrap();
    let obs = engine::observe(&loaded, None).unwrap();
    assert!(
        !obs.routes.iter().any(|r| r[1] == "demo"),
        "a cancelled allow must not remain a highlighted policy route"
    );
    assert!(!obs.snapshot.grants.iter().any(|g| g.subject == "demo"));
    // Malformed group or conflicting identity-specific policy name cannot appear healthy.
    fs::write(
        tree.join("groups/research.json"),
        "bad NEVER-OUTPUT-CREDENTIAL",
    )
    .unwrap();
    assert!(!plan(root)["observation_complete"].as_bool().unwrap());
    fs::write(
        tree.join("groups/research.json"),
        r#"{"name":"research","members":["demo"],"policy_names":["shared"]}"#,
    )
    .unwrap();
    fs::write(
        tree.join("policies.json"),
        r#"{"inlinePolicies":{"demo":{"shared":{"Statement":[]}}}}"#,
    )
    .unwrap();
    assert!(
        !plan(root)["observation_complete"].as_bool().unwrap(),
        "different inline and group documents must not share one graph node"
    );
}

#[test]
fn cross_plane_drift_is_one_way_and_imports_do_not_generate_policy_documents() {
    let dir = setup();
    let root = dir.path();
    put(
        root,
        json!({"identities":[{"name":"healthy","actions":["Read:demo"]}]}),
    );
    fs::write(
        root.join("static.json"),
        r#"{"identities":[{"name":"orphan"}]}"#,
    )
    .unwrap();
    let cfg = root.join("config.toml");
    fs::write(
        &cfg,
        format!(
            "{}\n[adapters.object-store.planes.static]\nfile='static.json'\n",
            fs::read_to_string(&cfg).unwrap()
        ),
    )
    .unwrap();
    let p = plan(root);
    let f = p["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["title"] == "identity missing from the enforced plane")
        .unwrap();
    assert_eq!(f["entities"], json!(["static", "dynamic", "orphan"]));
    let loaded = config::load(&cfg).unwrap();
    let obs = engine::observe(&loaded, None).unwrap();
    let saved = obs.snapshot.write(&root.join("snapshots")).unwrap();
    let imported = engine::observe(&loaded, Some(&saved)).unwrap();
    let report = engine::plan(&loaded, &imported);
    assert!(report.s3_previews.is_empty());
    assert!(!report.commands_complete);
}
