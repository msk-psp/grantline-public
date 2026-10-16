//! Native console transport. Production identity never comes from demo role switching.
use crate::{auth, config, engine};
use axum::{
    Form, Json, Router,
    extract::Request,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::Deserialize;
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Config {
    pub public_url: Option<String>,
    #[serde(default)]
    pub auth: auth::Config,
    pub assets: Option<String>,
}
pub struct App {
    pub auth: auth::Auth,
    pub path: PathBuf,
    pub live: bool,
    pub assets: PathBuf,
    #[cfg(unix)]
    pub workflow: Option<Arc<crate::workflow::Workflow>>,
}
pub type Shared = Arc<App>;
#[derive(Deserialize, Default)]
struct Destination {
    #[serde(default, alias = "next")]
    rd: String,
}
#[derive(Deserialize)]
struct Callback {
    state: String,
    code: String,
}
#[derive(Deserialize)]
struct Logout {
    csrf: String,
}
async fn login(
    State(s): State<Shared>,
    headers: HeaderMap,
    Query(q): Query<Destination>,
) -> Response {
    s.auth
        .login(&headers, if q.rd.is_empty() { "/" } else { &q.rd })
        .await
        .unwrap_or_else(IntoResponse::into_response)
}
async fn callback(
    State(s): State<Shared>,
    headers: HeaderMap,
    Query(q): Query<Callback>,
) -> Response {
    s.auth
        .callback(&headers, &q.state, &q.code)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}
async fn logout(State(s): State<Shared>, headers: HeaderMap, Form(f): Form<Logout>) -> Response {
    s.auth
        .logout(&headers, &f.csrf)
        .unwrap_or_else(IntoResponse::into_response)
}
async fn session(State(s): State<Shared>, headers: HeaderMap) -> Response {
    match s.auth.current(&headers) {
        Some(a) => Json(a).into_response(),
        None => (StatusCode::UNAUTHORIZED, "Sign in required").into_response(),
    }
}
pub async fn data(s: Shared) -> crate::Result<serde_json::Value> {
    tokio::task::spawn_blocking(move||{
        let l=config::load(&s.path)?;let o=engine::observe_with_live(&l,None,s.live)?;let p=engine::plan(&l,&o);let g=engine::graph(&l,&o)?;
        Ok(serde_json::json!({"plan":p,"graph":g,"snapshot":o.snapshot,"declared":l.intent.grants,"service_kinds":l.config.adapters.iter().map(|(s,a)|(s.clone(),a.kind(s).to_owned())).collect::<std::collections::BTreeMap<_,_>>(),"services":l.config.adapters.keys().collect::<Vec<_>>(),"environments":l.config.graph.environments,"live":s.live}))
    }).await.map_err(|_|"Observation worker failed".to_owned())?
}
async fn catalog(State(s): State<Shared>, headers: HeaderMap) -> Response {
    if s.auth.current(&headers).is_none() {
        return (StatusCode::UNAUTHORIZED, "Sign in required").into_response();
    }
    match data(s).await {
        Ok(v) => Json(v).into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Catalog unavailable; access is unknown",
        )
            .into_response(),
    }
}
fn preference(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|s| s.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.into())
}
fn language(headers: &HeaderMap, q: &std::collections::BTreeMap<String, String>) -> String {
    q.get("lang")
        .cloned()
        .or_else(|| preference(headers, "grantline_lang"))
        .filter(|s| grantline_ui::i18n::LANGUAGES.contains(&s.as_str()))
        .unwrap_or_else(|| "en".into())
}
fn html_document(
    lang: &str,
    theme: &str,
    body: &str,
    bootstrap: Option<&grantline_ui::Bootstrap>,
) -> String {
    let data = bootstrap
        .map(|b| {
            serde_json::to_string(b)
                .unwrap_or_default()
                .replace('<', "\\u003c")
                .replace('>', "\\u003e")
                .replace('&', "\\u0026")
        })
        .unwrap_or_default();
    let module = if bootstrap.is_some_and(|b| b.interactive) {
        "<script type=module src=/static/native-boot.js></script>"
    } else {
        ""
    };
    format!(
        "<!doctype html><html lang=\"{lang}\" data-theme=\"{theme}\"><head><meta charset=utf-8><meta name=viewport content=\"width=device-width, initial-scale=1\"><title>Grantline</title><link rel=icon href=/static/grantline-icon.svg><link rel=stylesheet href=/static/grantline.css></head><body><div id=grantline-app>{body}</div><script id=grantline-data type=application/json>{data}</script>{module}</body></html>"
    )
}
async fn home(
    State(s): State<Shared>,
    headers: HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> Response {
    use grantline_ui::Root;
    use leptos::prelude::*;
    let Some(actor) = s.auth.current(&headers) else {
        return Redirect::to(&format!(
            "/login?next={}",
            percent_encoding::utf8_percent_encode(
                &uri.to_string(),
                percent_encoding::NON_ALPHANUMERIC
            )
        ))
        .into_response();
    };
    let q: std::collections::BTreeMap<_, _> =
        url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes())
            .into_owned()
            .collect();
    let lang = language(&headers, &q);
    let theme = preference(&headers, "grantline_theme")
        .filter(|s| matches!(s.as_str(), "dark" | "light"))
        .unwrap_or("auto".into());
    let path = uri.path().trim_start_matches('/');
    let page = path.split('/').next().unwrap_or("").to_owned();
    let needs_data = !matches!(page.as_str(), "approvals" | "act" | "history");
    let loading = s.live && needs_data;
    let (data, mut error) = if loading || !needs_data {
        (grantline_ui::Data::default(), None)
    } else {
        match data(s.clone())
            .await
            .and_then(|v| serde_json::from_value(v).map_err(|_| "Invalid console data".into()))
        {
            Ok(d) => (d, None),
            Err(e) => (grantline_ui::Data::default(), Some(e)),
        }
    };
    let mut actor_value = grantline_ui::Actor {
        subject: actor.subject.clone(),
        display: actor.display.clone(),
        authenticated: actor.authenticated,
        csrf: actor.csrf.clone(),
        approval_identity: actor.subject.clone(),
    };
    let mut requests = vec![];
    let mut workflow = false;
    #[cfg(unix)]
    if let Some(w) = &s.workflow {
        workflow = w.config.code_writer.is_some();
        actor_value.approval_identity = w
            .config
            .identities
            .get(&actor.subject)
            .cloned()
            .unwrap_or(actor.subject.clone());
        if actor.authenticated {
            match w.list(&actor.subject) {
                Ok(rows) => requests = rows,
                Err(e) => error = Some(e),
            };
            if path.starts_with("approvals/") {
                let id = path.trim_start_matches("approvals/");
                match w.get(id, &actor.subject) {
                    Ok(row) => requests = vec![row],
                    Err(e) => {
                        error = Some(e);
                        requests.clear();
                    }
                }
            }
        }
    }
    let history = if page == "history" {
        match history_data(&s.path) {
            Ok(rows) => rows,
            Err(e) => {
                error = Some(e);
                vec![]
            }
        }
    } else {
        vec![]
    };
    let mut data = data;
    if data.services.is_empty()
        && let Ok(l) = config::load(&s.path)
    {
        data.services = l.config.adapters.keys().cloned().collect();
        data.service_kinds = l
            .config
            .adapters
            .iter()
            .map(|(s, a)| (s.clone(), a.kind(s).to_owned()))
            .collect();
        data.environments = l.config.graph.environments.into_iter().collect();
    }
    let bootstrap = grantline_ui::Bootstrap {
        data,
        actor: Some(actor_value),
        page,
        lang: lang.clone(),
        query: q.get("q").cloned().unwrap_or_default(),
        service: q.get("system").cloned().unwrap_or_default(),
        environment: q.get("environment").cloned().unwrap_or_default(),
        requests,
        history,
        workflow,
        interactive: s.assets.join("grantline_ui.js").is_file()
            && s.assets.join("grantline_ui_bg.wasm").is_file(),
        error,
        loading,
    };
    let render = bootstrap.clone();
    let html = Owner::new().with(move || view! {<Root bootstrap=render/>}.to_html());
    let mut response = Html(html_document(&lang, &theme, &html, Some(&bootstrap))).into_response();
    if q.contains_key("lang")
        && let Ok(v) =
            format!("grantline_lang={lang}; Path=/; SameSite=Lax; Max-Age=31536000").parse()
    {
        response.headers_mut().append(header::SET_COOKIE, v);
    }
    response
}
async fn sign_in(
    State(s): State<Shared>,
    headers: HeaderMap,
    Query(q): Query<Destination>,
) -> Html<String> {
    use grantline_ui::i18n::tr;
    use leptos::prelude::*;
    let lang = language(&headers, &Default::default());
    let theme = preference(&headers, "grantline_theme")
        .filter(|s| matches!(s.as_str(), "light" | "dark"))
        .unwrap_or("auto".into());
    let text = tr(
        &lang,
        if s.auth.config.mode == "local" {
            "Explore the console"
        } else {
            "Sign in"
        },
    );
    let phrase = tr(&lang, "Untangle access. Follow the grants.");
    let href = format!(
        "/auth/login?rd={}",
        percent_encoding::utf8_percent_encode(
            &auth::local_path(if q.rd.is_empty() { "/" } else { &q.rd }),
            percent_encoding::NON_ALPHANUMERIC
        )
    );
    let body=Owner::new().with(move||view!{<main class="login card"><img width="48" height="48" src="/static/grantline-icon.svg" alt=""/><h1>"Grantline"</h1><p>{phrase}</p><a class="button" href=href>{text}</a></main>}.to_html());
    Html(html_document(&lang, &theme, &body, None))
}
fn history_data(path: &std::path::Path) -> crate::Result<Vec<serde_json::Value>> {
    let l = config::load(path)?;
    let directory = config::relative(&l.base, &l.config.snapshots)?;
    let paths = crate::snapshot::list(&directory)?;
    if paths.len() > 1000 {
        return Err("Snapshot history limit exceeded".into());
    }
    let mut previous = None;
    let mut result = vec![];
    for path in paths
        .into_iter()
        .rev()
        .take(100)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        if std::fs::metadata(&path)
            .map_err(|_| "Cannot inspect snapshot")?
            .len()
            > 32 * 1024 * 1024
        {
            return Err("Snapshot exceeds console limit".into());
        }
        let current = crate::snapshot::Snapshot::load(&path, &l.kinds)?;
        let compared = previous
            .as_ref()
            .map(|p| crate::snapshot::compare(p, &current));
        result.push(serde_json::json!({"ts":current.ts,"grants":current.grants.len(),"unknown":current.unobserved.len(),"added":compared.as_ref().map(|c|c.added.len()),"removed":compared.as_ref().map(|c|c.removed.len()),"visibility":compared.as_ref().map(|c|c.revealed.len()+c.obscured.len())}));
        previous = Some(current);
    }
    result.reverse();
    Ok(result)
}
async fn assets(
    State(_s): State<Shared>,
    axum::extract::Path(name): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    let (bytes, mime): (Vec<u8>, &str) = match name.as_str() {
        "grantline.css" => (
            include_bytes!("../ui/style.css").to_vec(),
            "text/css; charset=utf-8",
        ),
        "native-boot.js" => (
            include_bytes!("../ui/boot.js").to_vec(),
            "text/javascript; charset=utf-8",
        ),
        "grantline-icon.svg" => (
            include_bytes!("../../grantline/static/grantline-icon.svg").to_vec(),
            "image/svg+xml",
        ),
        "postgresql.png" => (
            include_bytes!("../../grantline/static/postgresql.png").to_vec(),
            "image/png",
        ),
        "seaweedfs.png" => (
            include_bytes!("../../grantline/static/seaweedfs.png").to_vec(),
            "image/png",
        ),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    asset_response(bytes, mime, &headers)
}
fn asset_response(bytes: Vec<u8>, mime: &str, headers: &HeaderMap) -> Response {
    let etag = format!("\"{}\"", crate::integrations::sha(&bytes));
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|h| h.to_str().ok())
        == Some(&etag)
    {
        return StatusCode::NOT_MODIFIED.into_response();
    }
    (
        [(header::CONTENT_TYPE, mime), (header::ETAG, etag.as_str())],
        bytes,
    )
        .into_response()
}
async fn wasm_assets(
    State(s): State<Shared>,
    axum::extract::Path(name): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    let mime = match name.as_str() {
        "grantline_ui.js" => "text/javascript; charset=utf-8",
        "grantline_ui_bg.wasm" => "application/wasm",
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let path = s.assets.join(&name);
    let Ok(m) = std::fs::symlink_metadata(&path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !m.is_file() || m.len() > 32 * 1024 * 1024 {
        return StatusCode::NOT_FOUND.into_response();
    }
    match std::fs::read(path) {
        Ok(b) => asset_response(b, mime, &headers),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}
async fn security(request: Request, next: Next) -> Response {
    let static_asset = request.uri().path().starts_with("/static/");
    let mut r = next.run(request).await;
    let h = r.headers_mut();
    h.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static(if static_asset {
            "public, max-age=0, must-revalidate"
        } else {
            "no-store"
        }),
    );
    h.insert(
        "X-Content-Type-Options",
        header::HeaderValue::from_static("nosniff"),
    );
    h.insert(
        "Referrer-Policy",
        header::HeaderValue::from_static("no-referrer"),
    );
    h.insert("Content-Security-Policy",header::HeaderValue::from_static("default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"));
    r
}
pub fn app(s: Shared) -> Router {
    let mut router = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/", get(home))
        .route("/login", get(sign_in))
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/auth/logout", post(logout))
        .route("/api/session", get(session))
        .route("/api/catalog", get(catalog))
        .route("/static/{name}", get(assets))
        .route("/static/pkg/{name}", get(wasm_assets))
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn(security));
    for path in [
        "/accounts",
        "/account",
        "/resources",
        "/resource",
        "/services",
        "/matrix",
        "/changes",
        "/history",
        "/approvals",
        "/approvals/{id}",
        "/act",
    ] {
        router = router.route(path, get(home));
    }
    #[cfg(unix)]
    let router = router.merge(workflow_routes());
    router.layer(middleware::from_fn(security)).with_state(s)
}
pub async fn serve(path: PathBuf, host: IpAddr, port: u16, live: bool) -> crate::Result<()> {
    let config = config::load(&path)?;
    let listener = tokio::net::TcpListener::bind(SocketAddr::new(host, port))
        .await
        .map_err(|_| "Cannot bind native console")?;
    let actual = listener
        .local_addr()
        .map_err(|_| "Cannot inspect listener")?;
    let origin = config
        .config
        .web
        .public_url
        .clone()
        .unwrap_or_else(|| format!("http://{actual}/"));
    let auth = auth::Auth::new(config.config.web.auth.clone(), &origin, host.is_loopback())?;
    #[cfg(unix)]
    let workflow = config
        .config
        .approvals
        .clone()
        .filter(|_| config.config.web.auth.mode != "local")
        .map(|cfg| {
            crate::workflow::Workflow::open(
                cfg,
                &config.base,
                &origin,
                &serde_json::to_string(&config.config.web.auth)
                    .map_err(|_| "Cannot bind auth policy")?,
            )
            .map(Arc::new)
        })
        .transpose()?;
    let assets = config
        .config
        .web
        .assets
        .as_ref()
        .map(|p| config::relative(&config.base, p))
        .transpose()?
        .unwrap_or_else(|| {
            std::env::var_os("GRANTLINE_UI_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/pkg")))
        });
    println!("Grantline native console: {origin}");
    axum::serve(
        listener,
        app(Arc::new(App {
            auth,
            path,
            live,
            #[cfg(unix)]
            workflow,
            assets,
        })),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
    .map_err(|_| "Native console stopped with an error".into())
}

#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestInput {
    csrf: String,
    system: String,
    subject: String,
    resource: String,
    privilege: String,
    action: String,
}
#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionInput {
    csrf: String,
    plan_hash: String,
    decision: String,
}
#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishInput {
    csrf: String,
}
#[cfg(unix)]
fn workflow_routes() -> Router<Shared> {
    use axum::extract::Path;
    Router::new()
    .route("/api/requests/{id}",get(|State(s):State<Shared>,headers:HeaderMap,Path(id):Path<String>|async move {
        let Some(actor)=s.auth.current(&headers).filter(|a|a.authenticated)else{return(StatusCode::UNAUTHORIZED,"Authentication required").into_response()};
        match s.workflow.as_ref().ok_or_else(||"Approvals not configured".to_owned()).and_then(|w|w.get(&id,&actor.subject)){Ok(v)=>Json(v).into_response(),Err(_)=>(StatusCode::NOT_FOUND,"Request unavailable").into_response()}
    }))
    .route("/api/snapshots",post(|State(s):State<Shared>,headers:HeaderMap,Json(f):Json<PublishInput>|async move {
        if let Err(e)=s.auth.write_actor(&headers,&f.csrf){return e.into_response()}
        let result=tokio::task::spawn_blocking(move||{
            let l=config::load(&s.path)?;let o=engine::observe_with_live(&l,None,s.live)?;let dir=config::relative(&l.base,&l.config.snapshots)?;crate::workflow::private_dir(&dir)?;o.snapshot.write(&dir)?;
            Ok(serde_json::json!({"recorded":true,"applied":false}))
        }).await;workflow_result(result)
    }))
    .route("/api/requests",get(|State(s):State<Shared>,headers:HeaderMap|async move{
        let Some(actor)=s.auth.current(&headers).filter(|a|a.authenticated)else{return(StatusCode::UNAUTHORIZED,"Authentication required").into_response()};
        let Some(store)=&s.workflow else{return Json(serde_json::json!([])).into_response()};
        match store.list(&actor.subject){Ok(v)=>Json(v).into_response(),Err(_)=>(StatusCode::SERVICE_UNAVAILABLE,"Approval store unavailable").into_response()}
    }).post(|State(s):State<Shared>,headers:HeaderMap,Json(f):Json<RequestInput>|async move{
        let actor=match s.auth.write_actor(&headers,&f.csrf){Ok(a)=>a,Err(e)=>return e.into_response()};
        let result=tokio::task::spawn_blocking(move||{
            let loaded=config::load(&s.path)?;let adapter=loaded.config.adapters.get(&f.system).ok_or("Unknown request system")?;
            if [&f.system,&f.subject,&f.resource,&f.privilege].iter().any(|s|s.is_empty()||s.len()>1024||s.chars().any(char::is_control)){return Err("Invalid request fields".into())}
            let grant=crate::model::Grant::new(&f.system,&f.subject,&f.resource,&f.privilege).normalized(&loaded.kinds);
            if adapter.kind(&f.system)=="s3"{if !grant.resource.starts_with("bucket:")||!matches!(grant.privilege.as_str(),"Read"|"Write"|"List"){return Err("Unsupported S3 request".into())}}else{crate::commands::preview(&grant,&f.action,adapter.kind(&f.system))?;}
            s.workflow.as_ref().ok_or("Approval code writer is not configured")?.create(&actor,grant,f.action)
        }).await;
        workflow_result(result)
    })).route("/api/requests/{id}/decide",post(|State(s):State<Shared>,headers:HeaderMap,Path(id):Path<String>,Json(f):Json<DecisionInput>|async move{
        let actor=match s.auth.write_actor(&headers,&f.csrf){Ok(a)=>a,Err(e)=>return e.into_response()};
        if !matches!(f.decision.as_str(),"approve"|"deny"){return(StatusCode::BAD_REQUEST,"Invalid decision").into_response()}
        let result=tokio::task::spawn_blocking(move||s.workflow.as_ref().ok_or("Approvals not configured")?.decide_actor(&id,&actor,&f.plan_hash,f.decision=="approve")).await;workflow_result(result)
    })).route("/api/requests/{id}/publish",post(|State(s):State<Shared>,headers:HeaderMap,Path(id):Path<String>,Json(f):Json<PublishInput>|async move{
        let actor=match s.auth.write_actor(&headers,&f.csrf){Ok(a)=>a,Err(e)=>return e.into_response()};
        let result=tokio::task::spawn_blocking(move||s.workflow.as_ref().ok_or("Approvals not configured")?.publish(&id,&actor)).await;workflow_result(result)
    })).route("/api/slack/actions",post(|State(s):State<Shared>,headers:HeaderMap,body:axum::body::Bytes|async move{
        let result=tokio::task::spawn_blocking(move||s.workflow.as_ref().ok_or("Slack approvals not configured")?.slack(&headers,&body)).await;workflow_result(result)
    })).layer(axum::extract::DefaultBodyLimit::max(65536)).layer(middleware::from_fn(security))
}
#[cfg(unix)]
fn workflow_result(
    result: Result<crate::Result<serde_json::Value>, tokio::task::JoinError>,
) -> Response {
    match result {
        Ok(Ok(v)) => Json(v).into_response(),
        Ok(Err(e)) => (StatusCode::CONFLICT, e).into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Approval operation unavailable",
        )
            .into_response(),
    }
}
