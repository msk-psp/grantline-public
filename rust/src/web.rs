//! SSR-only Leptos UI. Demo roles are intentionally fictional, never production auth.
use crate::{
    approval::{Request, Status},
    model::Grant,
};
use axum::{
    Form, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use leptos::prelude::*;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
struct AppState {
    requests: Arc<Mutex<BTreeMap<String, Request>>>,
    port: u16,
}
type WebResult = Result<Response, (StatusCode, &'static str)>;
const COOKIE: &str = "grantline_rust_demo";
const REQUESTER: &str = "demo-requester";
const REVIEWER: &str = "demo-reviewer";

pub fn app(port: u16) -> Router {
    let state = AppState {
        requests: Default::default(),
        port,
    };
    Router::new()
        .route("/", get(|| async { Redirect::to("/demo") }))
        .route("/demo", get(home))
        .route("/demo/login", post(login))
        .route("/demo/logout", post(logout))
        .route("/request", post(create))
        .route("/approve/{id}", get(review).post(decide))
        .route("/demo/pr/{id}", get(pull_request))
        .route(
            "/static/rust.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../style.css"),
                )
            }),
        )
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), boundary))
        .with_state(state)
}

async fn boundary(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let expected = format!("127.0.0.1:{}", state.port);
    let local = format!("localhost:{}", state.port);
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok());
    if !matches!(host, Some(h) if h == expected || h == local) {
        return (
            StatusCode::FORBIDDEN,
            "Only the local playground host is allowed.",
        )
            .into_response();
    }
    if request.method() == axum::http::Method::POST {
        let origin = request
            .headers()
            .get(header::ORIGIN)
            .and_then(|h| h.to_str().ok());
        let allowed = format!("http://{}", host.unwrap_or_default());
        if origin != Some(allowed.as_str()) {
            return (
                StatusCode::FORBIDDEN,
                "A same-origin browser form is required.",
            )
                .into_response();
        }
    }
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert(header::REFERRER_POLICY, "strict-origin".parse().unwrap());
    response
        .headers_mut()
        .insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    response.headers_mut().insert(header::CONTENT_SECURITY_POLICY, "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'".parse().unwrap());
    response
}
fn role(headers: &HeaderMap) -> Option<&'static str> {
    let values: Vec<_> = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .flat_map(|h| h.split(';'))
        .filter_map(|c| c.trim().split_once('='))
        .filter(|(name, _)| *name == COOKIE)
        .map(|(_, value)| value)
        .collect();
    match values.as_slice() {
        ["requester"] => Some(REQUESTER),
        ["reviewer"] => Some(REVIEWER),
        _ => None,
    }
}
fn page(title: &str, content: impl IntoView + 'static) -> Response {
    let title = title.to_owned();
    let html = Owner::new().with(|| view! {
        <!DOCTYPE html>
        <html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
            <title>{format!("{title} · Grantline Rust")}</title><link rel="stylesheet" href="/static/rust.css"/>
        </head><body><header><a class="brand" href="/demo">"Grantline"<span>"RUST + LEPTOS"</span></a>
            <span class="badge">"Experimental · stage R1"</span></header>
        <main><aside class="notice"><strong>"Local playground"</strong>" — fictional identities, simulated Slack and PRs. No live permissions change. State resets on restart."</aside>
        {content}</main><footer>"Native Rust backend · Leptos server rendering · No Python runtime"</footer></body></html>
    }.to_html());
    Html(html).into_response()
}
fn error(code: StatusCode, message: &'static str) -> Response {
    let mut response = page(
        "Cannot complete action",
        view! { <section><h1>"Cannot complete action"</h1><p>{message}</p><a href="/demo">"Back to playground"</a></section> },
    );
    *response.status_mut() = code;
    response
}
async fn home(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let actor = role(&headers);
    let requests: Vec<_> = match state.requests.lock() {
        Ok(store) => store.values().cloned().collect(),
        Err(_) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Playground state unavailable.",
            );
        }
    };
    let cards = requests.into_iter().map(move |r| {
        let status = format!("{:?}", r.status);
        let review_link = if actor == Some(REVIEWER) && r.status == Status::Pending {
            r.token_for(REVIEWER).map(|t| format!("/approve/{}?t={t}", r.id))
        } else { None };
        let pr_link = (r.status == Status::Proposed).then(|| format!("/demo/pr/{}", r.id));
        view! { <article><div class="row"><strong>{r.grant.subject}</strong><span class="badge">{status}</span></div>
            <p><code>{r.grant.resource}</code>" · "<span class="chip">{r.grant.privilege}</span></p>
            <p class="muted">{r.created_at}</p><p>{r.note}</p>
            {review_link.map(|url| view! { <a class="button" href=url>"Review request"</a> })}
            {pr_link.map(|url| view! { <a class="button" href=url>"View simulated PR"</a> })}
        </article> }
    }).collect_view();
    page(
        "Approval playground",
        view! {
            <h1>"A native path from request to review"</h1><p class="lead">"Try the approval workflow without credentials or external accounts."</p>
            <div class="grid"><section><h2>"1. Choose a demo role"</h2><p>"Current identity: "<strong>{actor.unwrap_or("not selected")}</strong></p>
                <form method="post" action="/demo/login"><button name="role" value="requester">"Use requester"</button><button class="secondary" name="role" value="reviewer">"Use reviewer"</button></form>
                <form method="post" action="/demo/logout"><button class="link" type="submit">"Sign out"</button></form>
            </section><section><h2>"2. Request sample access"</h2><p>"Account "<code>"demo-user"</code>" → "<code>"bucket:demo/team"</code></p><p>"Read access only. Nothing is applied to a real service."</p>
                <form method="post" action="/request"><label for="note">"Reason (optional)"</label><input id="note" name="note" maxlength="500" placeholder="Try a review workflow"/>
                    <button disabled=move || actor != Some(REQUESTER)>"Create request"</button></form>
            </section></div>
            <section><h2>{if actor == Some(REVIEWER) { "3. Simulated Slack inbox" } else { "3. Requests" }}</h2>
                <p class="muted">"Switch to reviewer to open an approval link. Approval creates a local simulated PR, and never applies IAM."</p>
                {if cards.is_empty() { view! { <p>"No requests yet. Choose requester and create one above."</p> }.into_any() } else { cards.into_any() }}
            </section>
        },
    )
}
#[derive(Deserialize)]
struct Login {
    role: String,
}
async fn login(Form(form): Form<Login>) -> Response {
    if !matches!(form.role.as_str(), "requester" | "reviewer") {
        return error(StatusCode::BAD_REQUEST, "Unknown demo role.");
    }
    cookie_redirect(&format!(
        "{COOKIE}={}; Path=/; HttpOnly; SameSite=Strict",
        form.role
    ))
}
async fn logout() -> Response {
    cookie_redirect(&format!(
        "{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
    ))
}
fn cookie_redirect(value: &str) -> Response {
    let mut response = Redirect::to("/demo").into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        value.parse().expect("fixed cookie values"),
    );
    response
}
#[derive(Default, Deserialize)]
struct Create {
    #[serde(default)]
    note: String,
}
async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<Create>,
) -> Response {
    if role(&headers) != Some(REQUESTER) {
        return error(StatusCode::FORBIDDEN, "Choose the requester role first.");
    }
    if form.note.chars().count() > 500 {
        return error(
            StatusCode::BAD_REQUEST,
            "Reason must be 500 characters or fewer.",
        );
    }
    let r = match Request::create(
        REQUESTER,
        &[REVIEWER],
        Grant::new("s3", "demo-user", "bucket:demo/team", "Read"),
        form.note,
    ) {
        Ok(r) => r,
        Err(message) => return error(StatusCode::BAD_REQUEST, message),
    };
    match state.requests.lock() {
        Ok(mut store) => {
            // shortcut: bounded disposable memory; durable retention belongs to R4.
            if store.len() >= 100 {
                return error(
                    StatusCode::CONFLICT,
                    "Playground is full (100 requests). Restart to reset.",
                );
            }
            store.insert(r.id.clone(), r);
            Redirect::to("/demo").into_response()
        }
        Err(_) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Playground state unavailable.",
        ),
    }
}
#[derive(Deserialize)]
struct Token {
    t: String,
}
async fn review(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<Token>,
) -> Response {
    let store = match state.requests.lock() {
        Ok(store) => store,
        Err(_) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Playground state unavailable.",
            );
        }
    };
    let Some(r) = store.get(&id) else {
        return error(StatusCode::NOT_FOUND, "Request not found.");
    };
    if let Err(message) = r.authorize(role(&headers).unwrap_or_default(), &query.t) {
        return error(StatusCode::FORBIDDEN, message);
    }
    if r.status != Status::Pending {
        return error(StatusCode::CONFLICT, "This request is already final.");
    }
    page(
        "Review request",
        view! { <section><h1>"Review access request"</h1><p>"Requester: "<code>{r.requester.clone()}</code></p>
        <p>{r.note.clone()}</p><p>"Preview hash: "<code>{r.plan_hash.clone()}</code></p><pre>{r.plan.clone()}</pre>
        <p class="notice">"Approving creates a simulated PR. Live IAM is never changed."</p>
        <form method="post" action=format!("/approve/{id}")><input type="hidden" name="t" value=query.t/>
            <button name="decision" value="approve">"Approve and simulate PR"</button><button class="danger" name="decision" value="deny">"Deny request"</button></form></section> },
    )
}
#[derive(Deserialize)]
struct Decision {
    t: String,
    decision: String,
}
async fn decide(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<Decision>,
) -> Response {
    let approve = match form.decision.as_str() {
        "approve" => true,
        "deny" => false,
        _ => return error(StatusCode::BAD_REQUEST, "Unknown decision."),
    };
    let mut store = match state.requests.lock() {
        Ok(store) => store,
        Err(_) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Playground state unavailable.",
            );
        }
    };
    let Some(r) = store.get_mut(&id) else {
        return error(StatusCode::NOT_FOUND, "Request not found.");
    };
    if let Err(message) = r.authorize(role(&headers).unwrap_or_default(), &form.t) {
        return error(StatusCode::FORBIDDEN, message);
    }
    if let Err(message) = r.decide(role(&headers).unwrap_or_default(), &form.t, approve) {
        return error(StatusCode::CONFLICT, message);
    }
    if approve {
        if let Err(message) = r.propose(&r.plan.clone()) {
            return error(StatusCode::CONFLICT, message);
        }
        Redirect::to(&format!("/demo/pr/{id}")).into_response()
    } else {
        Redirect::to("/demo").into_response()
    }
}
async fn pull_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> WebResult {
    if role(&headers).is_none() {
        return Ok(error(StatusCode::FORBIDDEN, "Choose a demo role first."));
    }
    let store = state.requests.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Playground state unavailable.",
        )
    })?;
    let r = store
        .get(&id)
        .ok_or((StatusCode::NOT_FOUND, "Request not found."))?;
    if r.status != Status::Proposed {
        return Ok(error(
            StatusCode::CONFLICT,
            "This request has no simulated PR.",
        ));
    }
    Ok(page(
        "Simulated pull request",
        view! { <section><span class="badge">"SIMULATED PR · NOT ON GITHUB"</span><h1>"Grant Read to demo-user"</h1>
        <p>"Approved by "<code>{r.approved.iter().cloned().collect::<Vec<_>>().join(", ")}</code></p>
        <p>"Preview hash: "<code>{r.plan_hash.clone()}</code></p><pre>{format!("+ {}", r.plan.replace('\n', "\n+ "))}</pre>
        <p class="notice">"Approval complete. PR simulated. Effective access remains unchanged."</p><a class="button" href="/demo">"Back to playground"</a></section> },
    ))
}
