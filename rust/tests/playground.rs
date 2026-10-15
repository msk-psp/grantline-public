use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use tower::ServiceExt;

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    actor: &str,
    body: &str,
) -> (StatusCode, String, String) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "127.0.0.1:8423")
        .header("origin", "http://127.0.0.1:8423")
        .header("content-type", "application/x-www-form-urlencoded");
    if !actor.is_empty() {
        request = request.header("cookie", format!("grantline_rust_demo={actor}"));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .map(|s| s.to_str().unwrap().to_owned())
        .unwrap_or_default();
    let html = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    (status, location, html)
}
fn review_link(html: &str) -> String {
    let start = html
        .find("href=\"/approve/")
        .expect("reviewer approval link")
        + 6;
    html[start..].split('"').next().unwrap().to_owned()
}
#[tokio::test]
async fn request_review_proposal_and_replay() {
    let app = grantline_rs::web::app(8423);
    assert_eq!(
        call(&app, "POST", "/request", "reviewer", "").await.0,
        StatusCode::FORBIDDEN
    );
    let created = call(
        &app,
        "POST",
        "/request",
        "requester",
        "note=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
    )
    .await;
    assert_eq!(created.0, StatusCode::SEE_OTHER);
    let requester = call(&app, "GET", "/demo", "requester", "").await.2;
    assert!(!requester.contains("?t="));
    assert!(!requester.contains("<script>"));
    assert!(requester.contains("&lt;script&gt;"));
    let inbox = call(&app, "GET", "/demo", "reviewer", "").await.2;
    let link = review_link(&inbox);
    assert_eq!(
        call(&app, "GET", &link, "requester", "").await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&app, "GET", &link, "reviewer", "").await.0,
        StatusCode::OK
    );
    let (path, query) = link.split_once('?').unwrap();
    assert_eq!(
        call(&app, "POST", path, "reviewer", "t=bad&decision=approve")
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let approved = call(
        &app,
        "POST",
        path,
        "reviewer",
        &format!("{query}&decision=approve"),
    )
    .await;
    assert_eq!(approved.0, StatusCode::SEE_OTHER);
    let proposed = call(&app, "GET", &approved.1, "reviewer", "").await;
    assert_eq!(proposed.0, StatusCode::OK);
    assert!(proposed.2.contains("NOT ON GITHUB"));
    assert!(proposed.2.contains("Effective access remains unchanged"));
    assert_eq!(
        call(
            &app,
            "POST",
            path,
            "reviewer",
            &format!("{query}&decision=approve")
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(&app, "GET", &approved.1, "", "").await.0,
        StatusCode::FORBIDDEN
    );
}
#[tokio::test]
async fn denial_produces_no_pr() {
    let app = grantline_rs::web::app(8423);
    call(&app, "POST", "/request", "requester", "").await;
    let inbox = call(&app, "GET", "/demo", "reviewer", "").await.2;
    let link = review_link(&inbox);
    let (path, query) = link.split_once('?').unwrap();
    assert_eq!(
        call(
            &app,
            "POST",
            path,
            "reviewer",
            &format!("{query}&decision=deny")
        )
        .await
        .0,
        StatusCode::SEE_OTHER
    );
    let pr = path.replace("/approve/", "/demo/pr/");
    assert_eq!(
        call(&app, "GET", &pr, "reviewer", "").await.0,
        StatusCode::CONFLICT
    );
    assert!(
        call(&app, "GET", "/demo", "requester", "")
            .await
            .2
            .contains("Denied")
    );
}
#[tokio::test]
async fn host_origin_and_body_boundaries() {
    let app = grantline_rs::web::app(8423);
    for (host, origin) in [
        ("attacker.example", "http://attacker.example"),
        ("127.0.0.1:8423", "https://attacker.example"),
        ("127.0.0.1:8423", "null"),
        ("127.0.0.1:8423", ""),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("/demo/login")
            .header("host", host)
            .header("origin", origin)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("role=reviewer"))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
    let request = Request::builder()
        .method("POST")
        .uri("/request")
        .header("host", "127.0.0.1:8423")
        .header("origin", "http://127.0.0.1:8423")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("note=".to_owned() + &"a".repeat(20000)))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let request = Request::builder()
        .uri("/demo")
        .header("host", "localhost:8423")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(
        response.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("form-action 'self'")
    );
}
