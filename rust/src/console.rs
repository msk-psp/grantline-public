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
}
pub struct App {
    pub auth: auth::Auth,
    pub path: PathBuf,
    pub live: bool,
}
pub type Shared = Arc<App>;
#[derive(Deserialize, Default)]
struct Destination {
    #[serde(default)]
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
        Ok(serde_json::json!({"plan":p,"graph":g,"snapshot":o.snapshot,"services":l.config.adapters.keys().collect::<Vec<_>>(),"environments":l.config.graph.environments,"live":s.live}))
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
async fn home(State(s): State<Shared>, headers: HeaderMap) -> Response {
    if s.auth.current(&headers).is_none() {
        return Redirect::to("/login").into_response();
    }
    Html("<!doctype html><html lang=en><meta charset=utf-8><title>Grantline native console</title><h1>Grantline</h1><p>Native console transport is ready.</p><a href=/api/catalog>View native permission catalog</a></html>").into_response()
}
async fn sign_in() -> Html<&'static str> {
    Html(
        "<!doctype html><html lang=en><meta charset=utf-8><title>Sign in · Grantline</title><h1>Grantline</h1><a href=/auth/login>Sign in / explore console</a></html>",
    )
}
async fn security(request: Request, next: Next) -> Response {
    let mut r = next.run(request).await;
    let h = r.headers_mut();
    h.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
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
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/", get(home))
        .route("/login", get(sign_in))
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/auth/logout", post(logout))
        .route("/api/session", get(session))
        .route("/api/catalog", get(catalog))
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn(security))
        .with_state(s)
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
    println!("Grantline native console: {origin}");
    axum::serve(listener, app(Arc::new(App { auth, path, live })))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|_| "Native console stopped with an error".into())
}
