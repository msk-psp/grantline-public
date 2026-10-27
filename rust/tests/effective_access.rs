//! Fictional, process-isolated credentials; no ambient profiles or live endpoints.
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderMap, Method, Uri},
    response::Response,
    routing::any,
};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};

const SECRET: &str = "synthetic-subject-secret-never-display";
const CONTENT: &str = "PRIVATE-OBJECT-CONTENTS";
#[derive(Default)]
struct Mock {
    mode: &'static str,
    calls: Vec<String>,
}
type Shared = Arc<Mutex<Mock>>;
async fn object_store(
    State(state): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let (mode, path) = {
        let mut state = state.lock().unwrap();
        state.calls.push(format!("{method} {uri}"));
        (state.mode, uri.path().to_owned())
    };
    assert!(matches!(method, Method::GET | Method::HEAD));
    let authorization = headers["authorization"].to_str().unwrap();
    assert!(authorization.contains("Credential=GLSUBJECT/"));
    assert!(!uri.to_string().contains(SECRET));
    let catalog = path.starts_with("/v1/");
    if mode == "slow" {
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    assert!(authorization.contains(if catalog {
        "/s3tables/aws4_request"
    } else {
        "/s3/aws4_request"
    }));
    let mut response = Response::builder().status(200);
    let body = if mode == "redirect" {
        response = response
            .status(302)
            .header("location", "http://127.0.0.1:1/never-follow");
        String::new()
    } else if mode == "deny"
        || mode == "bad-key"
        || (mode == "head-only"
            && method == Method::GET
            && !uri.query().is_some_and(|q| q.contains("list-type")))
    {
        response = response.status(403).header(
            "x-amz-error-code",
            if mode == "bad-key" {
                "SignatureDoesNotMatch"
            } else {
                "AccessDenied"
            },
        );
        format!(
            "<Error><Code>{}</Code><Message>{SECRET}</Message></Error>",
            if mode == "bad-key" {
                "SignatureDoesNotMatch"
            } else {
                "AccessDenied"
            }
        )
    } else if catalog && mode == "catalog-deny" {
        response = response.status(403);
        json!({"error":{"code":403,"type":"ForbiddenException","message":SECRET}}).to_string()
    } else if catalog {
        assert_eq!(path, "/v1/demo/namespaces/demo.events/tables/sample");
        let location = if mode == "escape" {
            "http://127.0.0.1:1/private"
        } else if mode == "other-bucket" {
            "s3://other/team/metadata/v1.json"
        } else {
            "s3://demo/team/metadata/v1.json"
        };
        json!({"metadata-location":location,"config":{"s3.secret-access-key":SECRET}}).to_string()
    } else if let Some(query) = uri.query().filter(|q| q.contains("list-type")) {
        let args: std::collections::BTreeMap<_, _> = url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        assert_eq!(args["max-keys"], "1");
        let prefix = &args["prefix"];
        let count = if mode == "empty" { 0 } else { 1 };
        let entry = if count == 0 {
            String::new()
        } else {
            format!(
                "<Contents><Key>{}</Key></Contents>",
                percent_encoding::utf8_percent_encode(
                    &format!("{prefix}sample.txt"),
                    percent_encoding::NON_ALPHANUMERIC
                )
            )
        };
        format!(
            "<ListBucketResult><Name>demo</Name><Prefix>{}</Prefix><MaxKeys>1</MaxKeys><EncodingType>url</EncodingType><KeyCount>{count}</KeyCount><IsTruncated>false</IsTruncated>{entry}</ListBucketResult>",
            percent_encoding::utf8_percent_encode(prefix, percent_encoding::NON_ALPHANUMERIC)
        )
    } else if mode == "missing" {
        response = response.status(404);
        "<Error><Code>NoSuchKey</Code></Error>".into()
    } else if method == Method::HEAD {
        response = response.header("etag", "\"fixture\"").header(
            "content-length",
            if mode == "empty-object" {
                0
            } else {
                CONTENT.len()
            },
        );
        String::new()
    } else {
        assert_eq!(headers["range"], "bytes=0-0");
        assert!(authorization.contains("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date"));
        if mode == "ignore-range" {
            CONTENT.into()
        } else if mode == "empty-object" {
            response = response.header("etag", "\"empty\"");
            String::new()
        } else {
            response = response.status(206).header(
                "content-range",
                format!(
                    "bytes {}/{}",
                    if mode == "wrong-range" { "1-1" } else { "0-0" },
                    CONTENT.len()
                ),
            );
            "P".into()
        }
    };
    response.body(Body::from(body)).unwrap()
}

struct Console {
    child: Child,
    base: String,
    agent: ureq::Agent,
    _dir: tempfile::TempDir,
}
impl Drop for Console {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Console {
    fn start(endpoint: &str, enabled: bool, live: bool) -> Self {
        Self::start_pg(endpoint, enabled, live, None)
    }
    fn start_pg(endpoint: &str, enabled: bool, live: bool, pg_dsn: Option<&str>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            dir.path().join("intent.toml"),
            "managed_subjects=[]\nmanaged_systems=[]\n",
        )
        .unwrap();
        std::fs::write(
            &path,
            format!(
                r#"intent="intent.toml"
[web]
probe_operators={}
[web.auth]
mode="proxy"
allowed_subjects=["operator","viewer"]
[adapters.objects-staging]
type="s3"
endpoint_env="FIXTURE_ENDPOINT"
probe_catalog_endpoint_env="FIXTURE_ENDPOINT"
read_timeout_seconds=2
[adapters.objects-staging.probe_credentials.alice]
key_env="FIXTURE_KEY"
secret_env="FIXTURE_SECRET"
[adapters.objects-staging.probe_credentials.bob]
key_env="MISSING_FIXTURE_KEY"
secret_env="MISSING_FIXTURE_SECRET"
[adapters.pg-staging]
type="postgres"
dsn_env="OBSERVER_MUST_NOT_BE_USED"
probe_dsn_envs={{alice="FIXTURE_PG_DSN",wrong="FIXTURE_PG_DSN"}}
"#,
                if enabled { r#"["operator"]"# } else { "[]" }
            ),
        )
        .unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_grantline-rs"));
        command
            .env_clear()
            .env("FIXTURE_ENDPOINT", endpoint)
            .env("FIXTURE_KEY", "GLSUBJECT")
            .env("FIXTURE_SECRET", SECRET)
            .env("AWS_ACCESS_KEY_ID", "DO_NOT_USE_OBSERVER")
            .env("AWS_SECRET_ACCESS_KEY", SECRET)
            .arg("-c")
            .arg(path)
            .args(["serve", "--port", "0"]);
        if live {
            command.arg("--live");
        }
        if let Some(dsn) = pg_dsn {
            command.env("FIXTURE_PG_DSN", dsn);
        }
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let base = line
            .trim()
            .strip_prefix("Grantline native console: ")
            .expect("console startup")
            .trim_end_matches('/')
            .to_owned();
        Self {
            child,
            base,
            agent: ureq::Agent::config_builder()
                .max_redirects(0)
                .proxy(None)
                .http_status_as_error(false)
                .timeout_global(Some(Duration::from_secs(5)))
                .build()
                .into(),
            _dir: dir,
        }
    }
    fn login(&self, actor: &str) -> (String, String) {
        let response = self
            .agent
            .get(&format!("{}/auth/login", self.base))
            .header("X-Forwarded-Email", actor)
            .call()
            .unwrap();
        assert_eq!(response.status(), 303);
        let cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let mut response = self
            .agent
            .get(&format!("{}/api/session", self.base))
            .header("X-Forwarded-Email", actor)
            .header("cookie", &cookie)
            .call()
            .unwrap();
        let value: Value =
            serde_json::from_str(&response.body_mut().read_to_string().unwrap()).unwrap();
        (cookie, value["csrf"].as_str().unwrap().to_owned())
    }
    fn check(&self, actor: &str, cookie: &str, csrf: &str, changes: Value) -> (u16, Value) {
        let mut input = json!({"csrf":csrf,"system":"objects-staging","subject":"alice","resource":"bucket:demo/team"});
        input
            .as_object_mut()
            .unwrap()
            .extend(changes.as_object().unwrap().clone());
        let mut response = self
            .agent
            .post(&format!("{}/api/probes", self.base))
            .header("origin", &self.base)
            .header("X-Forwarded-Email", actor)
            .header("cookie", cookie)
            .header("content-type", "application/json")
            .send(input.to_string().as_bytes())
            .unwrap();
        let status = response.status().as_u16();
        let body = response.body_mut().read_to_string().unwrap();
        assert!(
            !body.contains(SECRET)
                && !body.contains(CONTENT)
                && !body.contains("sample.txt")
                && !body.contains("metadata/v1.json")
        );
        (
            status,
            serde_json::from_str(&body).unwrap_or(Value::String(body)),
        )
    }
}
fn verdicts(report: &Value) -> Vec<&str> {
    report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["verdict"].as_str().unwrap())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requested_scopes_identity_and_read_stages_are_independent() {
    let state = Arc::new(Mutex::new(Mock::default()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let router = Router::new()
        .fallback(any(object_store))
        .with_state(state.clone());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let server = Console::start(&endpoint, true, true);
    let (cookie, csrf) = server.login("operator");
    let (status, report) = server.check("operator", &cookie, &csrf, json!({}));
    assert_eq!(status, 200);
    assert_eq!(verdicts(&report), vec!["allow", "allow", "allow"]);
    assert_eq!(report["applied"], false);
    assert_eq!(report["data_rows_verified"], false);
    assert!(report["checked_at"].is_string());
    let mut response = server
        .agent
        .get(&format!("{}/verify?lang=ko", server.base))
        .header("X-Forwarded-Email", "operator")
        .header("cookie", &cookie)
        .call()
        .unwrap();
    let html = response.body_mut().read_to_string().unwrap();
    assert!(
        html.contains("검증 실행")
            && html.contains("objects-staging")
            && html.contains("pg-staging")
            && html.contains("조회 권한")
            && html.contains("value=\"read\"")
            && html.contains("value=\"create\"")
    );
    assert!(!html.contains(SECRET));
    for (mode, expected) in [
        ("empty-object", vec!["allow", "allow", "allow"]),
        ("wrong-range", vec!["allow", "allow", "unknown"]),
        ("slow", vec!["unknown", "unknown", "unknown"]),
        ("empty", vec!["allow", "unknown", "unknown"]),
        ("head-only", vec!["allow", "allow", "deny"]),
        ("missing", vec!["allow", "unknown", "unknown"]),
        ("ignore-range", vec!["allow", "allow", "unknown"]),
        ("bad-key", vec!["unknown", "unknown", "unknown"]),
        ("redirect", vec!["unknown", "unknown", "unknown"]),
    ] {
        state.lock().unwrap().mode = mode;
        let (status, report) = server.check("operator", &cookie, &csrf, json!({}));
        assert_eq!(status, 200);
        assert_eq!(verdicts(&report), expected, "mode {mode}");
    }
    state.lock().unwrap().mode = "deny";
    let (status, report) = server.check(
        "operator",
        &cookie,
        &csrf,
        json!({"resource":"bucket:demo/outside","object":"outside/known.txt","expected":"deny"}),
    );
    assert_eq!(status, 200);
    assert_eq!(verdicts(&report), vec!["deny", "deny", "deny"]);
    state.lock().unwrap().mode = "";
    let (_, report) = server.check(
        "operator",
        &cookie,
        &csrf,
        json!({"table":"demo.events/sample"}),
    );
    assert_eq!(
        verdicts(&report),
        vec!["allow", "allow", "allow", "allow", "allow"]
    );
    for mode in ["escape", "other-bucket"] {
        state.lock().unwrap().mode = mode;
        let (_, report) = server.check(
            "operator",
            &cookie,
            &csrf,
            json!({"table":"demo.events/sample"}),
        );
        assert_eq!(
            verdicts(&report),
            vec!["allow", "allow", "allow", "unknown", "unknown"]
        );
    }
    state.lock().unwrap().mode = "catalog-deny";
    let (_, report) = server.check(
        "operator",
        &cookie,
        &csrf,
        json!({"table":"demo.events/sample"}),
    );
    assert_eq!(
        verdicts(&report),
        vec!["allow", "allow", "allow", "deny", "unknown"]
    );
    let count = state.lock().unwrap().calls.len();
    let (_, report) = server.check("operator", &cookie, &csrf, json!({"subject":"bob"}));
    assert_eq!(verdicts(&report), vec!["unknown", "unknown", "unknown"]);
    for changes in [
        json!({"object":"team-other/sample"}),
        json!({"resource":"bucket:demo/team/*"}),
        json!({"table":"../sample"}),
        json!({"subject":"administrator"}),
        json!({"postgres_operation":"unknown"}),
    ] {
        assert_eq!(server.check("operator", &cookie, &csrf, changes).0, 400);
    }
    assert_eq!(server.check("operator", &cookie, "bad", json!({})).0, 403);
    assert_eq!(
        server
            .check(
                "operator",
                &cookie,
                &csrf,
                json!({"endpoint":"http://127.0.0.1:1"})
            )
            .0,
        422
    );
    assert_eq!(server.check("viewer", &cookie, &csrf, json!({})).0, 401);
    let (viewer_cookie, viewer_csrf) = server.login("viewer");
    assert_eq!(
        server
            .check("viewer", &viewer_cookie, &viewer_csrf, json!({}))
            .0,
        403
    );
    assert_eq!(state.lock().unwrap().calls.len(), count);
    let (_, report) = server.check(
        "operator",
        &cookie,
        &csrf,
        json!({"system":"pg-staging","resource":"schema:example.registry"}),
    );
    assert_eq!(verdicts(&report), vec!["unknown"; 4]);
    assert!(
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["resource"] == "db:example" && r["priv"] == "CREATE")
    );
    for (enabled, live) in [(false, true), (true, false)] {
        let disabled = Console::start(&endpoint, enabled, live);
        let (c, t) = disabled.login("operator");
        assert_eq!(disabled.check("operator", &c, &t, json!({})).0, 403);
    }
    assert_eq!(state.lock().unwrap().calls.len(), count);
    task.abort();
}

#[test]
#[ignore = "requires Docker; creates only a disposable PostgreSQL fixture"]
fn postgres_creation_permissions_use_subject_login_without_ddl() {
    struct Postgres(String);
    impl Drop for Postgres {
        fn drop(&mut self) {
            let _ = Command::new("docker").args(["rm", "-f", &self.0]).output();
        }
    }
    impl Postgres {
        fn sql(&self, db: &str, sql: &str) -> String {
            use std::io::Write;
            let mut child = Command::new("docker")
                .args([
                    "exec",
                    "-i",
                    &self.0,
                    "psql",
                    "-XAt",
                    "-U",
                    "postgres",
                    "-d",
                    db,
                    "-v",
                    "ON_ERROR_STOP=1",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(sql.as_bytes())
                .unwrap();
            let result = child.wait_with_output().unwrap();
            assert!(result.status.success(), "fixture setup/query failed");
            String::from_utf8(result.stdout).unwrap()
        }
    }
    let postgres = Postgres(format!("gl-effective-{}", uuid::Uuid::new_v4()));
    let result = Command::new("docker")
        .env("POSTGRES_PASSWORD", SECRET)
        .args([
            "run",
            "--rm",
            "-d",
            "--name",
            &postgres.0,
            "-e",
            "POSTGRES_PASSWORD",
            "-p",
            "127.0.0.1::5432",
            "postgres@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "cannot start disposable PostgreSQL"
    );
    let mut ready = false;
    for _ in 0..100 {
        if Command::new("docker")
            .args([
                "exec",
                &postgres.0,
                "pg_isready",
                "-h",
                "127.0.0.1",
                "-U",
                "postgres",
            ])
            .output()
            .unwrap()
            .status
            .success()
        {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(ready, "fixture readiness timed out");
    let result = Command::new("docker")
        .args(["port", &postgres.0, "5432/tcp"])
        .output()
        .unwrap();
    let address = String::from_utf8(result.stdout).unwrap();
    let port = address.trim().rsplit(':').next().unwrap();
    postgres.sql("postgres",&format!("CREATE ROLE alice LOGIN PASSWORD '{SECRET}'; CREATE DATABASE example; CREATE DATABASE dev_example; GRANT CONNECT,CREATE ON DATABASE example TO alice; GRANT CONNECT ON DATABASE dev_example TO alice;"));
    for db in ["example", "dev_example"] {
        postgres.sql(db,"CREATE SCHEMA maintenance; CREATE SCHEMA registry; GRANT USAGE,CREATE ON SCHEMA maintenance TO alice; GRANT USAGE ON SCHEMA registry TO alice;");
    }
    let dsn = format!(
        "host=127.0.0.1 port={port} user=alice password={SECRET} dbname=example sslmode=disable"
    );
    let server = Console::start_pg("http://127.0.0.1:1", true, true, Some(&dsn));
    let (cookie, csrf) = server.login("operator");
    for db in ["example", "dev_example"] {
        let (_, report) = server.check(
            "operator",
            &cookie,
            &csrf,
            json!({"system":"pg-staging","resource":format!("schema:{db}.maintenance")}),
        );
        let rows = report["checks"].as_array().unwrap();
        let verdict = |resource: &str, privilege: &str| {
            rows.iter()
                .find(|r| r["resource"] == resource && r["priv"] == privilege)
                .unwrap()["verdict"]
                .as_str()
                .unwrap()
        };
        assert_eq!(verdict(&format!("db:{db}"), "CONNECT"), "allow");
        assert_eq!(
            verdict(&format!("db:{db}"), "CREATE"),
            if db == "example" { "allow" } else { "deny" }
        );
        assert_eq!(
            verdict(&format!("schema:{db}.maintenance"), "USAGE"),
            "allow"
        );
        assert_eq!(
            verdict(&format!("schema:{db}.maintenance"), "CREATE"),
            "allow"
        );
        assert!(
            rows.iter()
                .all(|r| r["how"].as_str().unwrap().starts_with("subject TCP login"))
        );
        let (_, report) = server.check(
            "operator",
            &cookie,
            &csrf,
            json!({"system":"pg-staging","resource":format!("schema:{db}.registry")}),
        );
        assert!(
            report["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["resource"] == format!("schema:{db}.registry")
                    && r["priv"] == "CREATE"
                    && r["verdict"] == "deny")
        );
        assert_eq!(postgres.sql(db,"SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('maintenance','registry');").trim(),"0");
        postgres.sql(
            db,
            "CREATE TABLE registry.events(id integer); GRANT SELECT ON registry.events TO alice;",
        );
        let (status, read) = server.check(
            "operator", &cookie, &csrf,
            json!({"system":"pg-staging","resource":format!("table:{db}.registry.events"),"postgres_operation":"read"}),
        );
        assert_eq!(status, 200);
        assert_eq!(verdicts(&read), vec!["allow", "allow", "allow"]);
        assert!(
            read["checks"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["priv"] != "CREATE")
        );
        assert_eq!(read["data_rows_verified"], false);
        assert_eq!(read["applied"], false);
        postgres.sql(db, "REVOKE SELECT ON registry.events FROM alice;");
        let (status, denied) = server.check(
            "operator", &cookie, &csrf,
            json!({"system":"pg-staging","resource":format!("table:{db}.registry.events"),"postgres_operation":"read"}),
        );
        assert_eq!(status, 200);
        assert_eq!(verdicts(&denied), vec!["allow", "allow", "deny"]);
    }
    let (_, report) = server.check(
        "operator",
        &cookie,
        &csrf,
        json!({"system":"pg-staging","subject":"wrong","resource":"db:example"}),
    );
    assert_eq!(verdicts(&report), vec!["unknown", "unknown"]);
}
