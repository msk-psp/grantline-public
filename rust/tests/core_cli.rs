use grantline_rs::{
    commands,
    graph::{Bridge, Graph, GraphConfig},
    model::{Grant, Kinds, Unobserved},
    snapshot::{self, Snapshot},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    process::Command,
};

fn native(args: &[&str], cwd: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_grantline-rs"))
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap()
}
#[test]
fn cli_resolves_config_paths_from_any_directory_and_never_writes_on_plan() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("config.toml"),"intent = 'intent.toml'\nsnapshots = 'history'\nenv_file = 'absent-secrets.env'\n[adapters.pg-test]\ntype = 'fixture'\nkind = 'postgres'\nfixture = 'fixture.json'\n[adapters.s3]\ntype = 's3'\n").unwrap();
    fs::write(dir.path().join("intent.toml"),"managed_subjects = ['demo']\n[[grants]]\nsystem = 'pg-test'\nsubject = 'demo'\nresource = 'db:analytics'\nprivs = ['CONNECT']\n[[grants]]\nsystem = 's3'\nsubject = 'demo'\nresource = 'bucket:demo/team/*'\nprivs = ['Read']\n").unwrap();
    fs::write(dir.path().join("fixture.json"), r#"{"grants":[]}"#).unwrap();
    let config = dir.path().join("config.toml");
    let before = fs::read(&config).unwrap();
    let out = native(
        &["-c", config.to_str().unwrap(), "plan", "--json"],
        Path::new("/"),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["observation_complete"], false);
    assert_eq!(value["changes"].as_array().unwrap().len(), 1);
    assert_eq!(
        value["changes"][0]["cmd"],
        "GRANT CONNECT ON DATABASE \"analytics\" TO \"demo\";"
    );
    assert_eq!(value["unverified"][0]["resource"], "bucket:demo/team");
    assert_eq!(fs::read(&config).unwrap(), before);
    assert!(!dir.path().join("history").exists());
    #[cfg(unix)]
    {
        let alias = dir.path().join("alias");
        fs::create_dir(&alias).unwrap();
        std::os::unix::fs::symlink(&config, alias.join("config.toml")).unwrap();
        fs::write(alias.join("intent.toml"), "").unwrap();
        fs::write(alias.join("fixture.json"), r#"{"grants":[]}"#).unwrap();
        let out = native(
            &[
                "-c",
                alias.join("config.toml").to_str().unwrap(),
                "plan",
                "--json",
            ],
            Path::new("/"),
        );
        let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(value["changes"].as_array().unwrap().is_empty());
    }
    fs::write(
        dir.path().join("fixture.json"),
        "invalid fixture with confidential text",
    )
    .unwrap();
    let out = native(
        &["-c", config.to_str().unwrap(), "plan", "--json"],
        Path::new("/"),
    );
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(value["changes"].as_array().unwrap().is_empty());
    assert_eq!(value["unverified"].as_array().unwrap().len(), 2);
    assert!(!String::from_utf8_lossy(&out.stdout).contains("confidential"));
    assert!(
        !native(
            &["-c", config.to_str().unwrap(), "apply", "--write"],
            dir.path()
        )
        .status
        .success()
    );
    fs::write(&config, "intent = 'do-not-echo-this-secret'\nbad = [").unwrap();
    let invalid = native(&["-c", config.to_str().unwrap(), "plan"], dir.path());
    assert!(!invalid.status.success());
    assert!(!String::from_utf8_lossy(&invalid.stderr).contains("do-not-echo-this-secret"));
}
#[test]
fn previews_quote_identifiers_and_reject_privilege_injection() {
    let mut g = Grant::new(
        "postgres",
        "demo\"; DROP ROLE x; --",
        "table:db.public.events",
        "SELECT",
    );
    assert_eq!(
        commands::preview(&g, "grant", "postgres").unwrap(),
        "GRANT SELECT ON TABLE \"public\".\"events\" TO \"demo\"\"; DROP ROLE x; --\";  -- in database db"
    );
    g.privilege = "SELECT; DROP TABLE x".into();
    assert!(commands::preview(&g, "grant", "postgres").is_err());
    g.privilege = "SELECT".into();
    g.subject = "demo\n--".into();
    assert!(commands::preview(&g, "grant", "clickhouse").is_err());
    assert!(commands::preview(&g, "grant", "s3").is_err());
}
#[test]
fn snapshots_are_private_non_overwriting_and_preserve_unknowns() {
    let dir = tempfile::tempdir().unwrap();
    let mut prev = Snapshot::new(BTreeSet::from(["postgres".into(), "s3".into()]));
    prev.grants
        .insert(Grant::new("s3", "demo", "bucket:demo/team", "Read"));
    for i in 0..40 {
        let mut g = Grant::new(
            "postgres",
            &format!("demo-{i}"),
            &format!("table:hr.public.t{i}"),
            "SELECT",
        );
        g.grantor = Some("demo-owner".into());
        prev.grants.insert(g);
    }
    let path = prev.write(dir.path()).unwrap();
    let original = fs::read(&path).unwrap();
    let second = prev.write(dir.path()).unwrap();
    assert_ne!(path, second);
    assert_eq!(fs::read(&path).unwrap(), original);
    let loaded = Snapshot::load(&path, &Kinds::new()).unwrap();
    assert_eq!(loaded.grants.len(), 41);
    assert_eq!(
        loaded
            .grants
            .iter()
            .find(|g| g.system == "postgres")
            .unwrap()
            .grantor
            .as_deref(),
        Some("demo-owner")
    );
    let mut cur = Snapshot::new(BTreeSet::from(["postgres".into()]));
    cur.unobserved.push(Unobserved {
        system: "postgres".into(),
        prefixes: vec!["table:hr.".into()],
        subjects: Default::default(),
        note: "postgres://demo:fixture-password@localhost unavailable".into(),
    });
    let cmp = snapshot::compare(&prev, &cur);
    assert_eq!(cmp.obscured.len(), 41);
    assert!(cmp.removed.is_empty());
    let saved = cur.write(dir.path()).unwrap();
    assert!(
        !fs::read_to_string(&saved)
            .unwrap()
            .contains("fixture-password")
    );
    let reveal = snapshot::compare(&cur, &prev);
    assert_eq!(reveal.revealed.len(), 41);
    assert!(reveal.added.is_empty());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(saved).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    fs::write(&second,"{\"grant\":{\"system\":\"s3\",\"subject\":\"demo\",\"resource\":\"bucket:demo\",\"priv\":\"Read\"}}\n").unwrap();
    assert!(Snapshot::load(&second, &Kinds::new()).is_err());
    fs::write(&second, String::from_utf8(original).unwrap().repeat(2)).unwrap();
    assert!(Snapshot::load(&second, &Kinds::new()).is_err());
    assert!(snapshot::since("999999999999999999999w", cur.ts).is_err());
    assert_eq!(
        (cur.ts - snapshot::since("2w", cur.ts).unwrap()).num_days(),
        14
    );
}
#[test]
fn graph_keeps_policy_routes_bridges_all_paths_and_cycle_limits() {
    let grants = BTreeSet::from([
        Grant::new("s3", "demo", "bucket:demo", "Read"),
        Grant::new("postgres", "demo", "role:reader", "MEMBER"),
        Grant::new("postgres", "reader", "table:demo.public.t", "SELECT"),
    ]);
    let routes = vec![
        [
            "s3".into(),
            "demo".into(),
            "group:demo".into(),
            "member".into(),
        ],
        [
            "s3".into(),
            "group:demo".into(),
            "bucket:demo".into(),
            "allows".into(),
        ],
    ];
    let config: GraphConfig =
        toml::from_str("services=['svc*']\n[environments]\n'운영'=['s3']\n").unwrap();
    let graph = Graph::build(
        &grants,
        &[Bridge {
            from: "reader".into(),
            to: "svc-reader".into(),
            system: "s3".into(),
            note: "server-held key".into(),
        }],
        &BTreeMap::from([
            ("demo".into(), "account".into()),
            ("group:demo".into(), "group".into()),
        ]),
        &routes,
        &config,
    )
    .unwrap();
    assert!(
        graph
            .edges
            .iter()
            .any(|e| e.src == "demo" && e.dst == "bucket:demo" && e.kind == "flat")
    );
    assert_eq!(graph.kind_of("group:demo"), "group");
    assert_eq!(graph.env_of("s3"), vec!["운영"]);
    assert!(graph.paths("demo", false, 100).paths.contains(&vec![
        "demo".into(),
        "group:demo".into(),
        "bucket:demo".into()
    ]));
    assert!(graph.paths("svc-reader", true, 100).paths.contains(&vec![
        "demo".into(),
        "reader".into(),
        "svc-reader".into()
    ]));
    let mut many = BTreeSet::new();
    for i in 0..205 {
        many.insert(Grant::new(
            "postgres",
            "demo",
            &format!("table:demo.public.t{i}"),
            "SELECT",
        ));
    }
    let graph = Graph::build(&many, &[], &BTreeMap::new(), &[], &GraphConfig::default()).unwrap();
    assert_eq!(graph.paths("demo", false, 1000).paths.len(), 205);
    assert!(graph.paths("demo", false, 200).truncated);
    let cycle = BTreeSet::from([
        Grant::new("postgres", "a", "role:b", "MEMBER"),
        Grant::new("postgres", "b", "role:a", "MEMBER"),
    ]);
    let graph = Graph::build(&cycle, &[], &BTreeMap::new(), &[], &GraphConfig::default()).unwrap();
    assert!(graph.paths("a", false, 100).paths.is_empty());
    assert_eq!(graph.depth("a").unwrap(), 2);
}
