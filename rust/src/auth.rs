//! Production identities are supplied by a trusted loopback proxy or verified OIDC.
use axum::{
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Mutex,
    time::Duration,
};
use subtle::ConstantTimeEq;
use url::Url;
use uuid::Uuid;

type Error = (StatusCode, &'static str);
fn denied() -> Error {
    (StatusCode::UNAUTHORIZED, "Sign in required")
}
fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
fn random() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}
fn hash(s: &str) -> String {
    crate::hex(&Sha256::digest(s.as_bytes()))
}
fn mode() -> String {
    "local".into()
}
fn identity_header() -> String {
    "X-Forwarded-Email".into()
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    #[serde(default = "mode")]
    pub mode: String,
    #[serde(default = "identity_header")]
    pub identity_header: String,
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    pub client_secret_env: Option<String>,
    #[serde(default)]
    pub allowed_subjects: BTreeSet<String>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            mode: mode(),
            identity_header: identity_header(),
            issuer: None,
            client_id: None,
            client_secret_env: None,
            allowed_subjects: BTreeSet::new(),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Actor {
    pub subject: String,
    pub display: String,
    pub authenticated: bool,
    pub csrf: String,
    pub expires: i64,
}
struct Pending {
    metadata: CoreProviderMetadata,
    nonce: String,
    verifier: String,
    browser: String,
    destination: String,
    expires: i64,
}
pub struct Auth {
    pub config: Config,
    pub origin: Url,
    sessions: Mutex<BTreeMap<String, Actor>>,
    pending: Mutex<BTreeMap<String, Pending>>,
    http: openidconnect::reqwest::Client,
}
pub fn local_path(s: &str) -> String {
    let mut decoded = s.to_owned();
    for _ in 0..5 {
        decoded = percent_encoding::percent_decode_str(&decoded)
            .decode_utf8_lossy()
            .into_owned();
    }
    if !decoded.starts_with('/')
        || decoded.starts_with("//")
        || decoded.contains('\\')
        || decoded.chars().any(char::is_control)
        || s.len() > 4096
    {
        "/".into()
    } else {
        s.into()
    }
}
fn cookie(headers: &HeaderMap, key: &str) -> Option<String> {
    let values: Vec<_> = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .flat_map(|h| h.split(';'))
        .filter_map(|p| p.trim().split_once('='))
        .filter(|(k, _)| *k == key)
        .map(|(_, v)| v.to_owned())
        .collect();
    if values.len() == 1 {
        Some(values[0].clone())
    } else {
        None
    }
}
fn proxy(headers: &HeaderMap, key: &str) -> Option<String> {
    let v: Vec<_> = headers.get_all(key).iter().collect();
    if v.len() != 1 {
        return None;
    }
    let s = v[0].to_str().ok()?.trim();
    if s.is_empty() || s.len() > 256 || s.chars().any(char::is_control) {
        None
    } else {
        Some(s.into())
    }
}
fn endpoint(s: &str) -> bool {
    Url::parse(s).is_ok_and(|u| {
        u.username().is_empty()
            && u.password().is_none()
            && (u.scheme() == "https"
                || (u.scheme() == "http"
                    && matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))))
    })
}
impl Auth {
    pub fn new(config: Config, origin: &str, loopback: bool) -> crate::Result<Self> {
        let origin = Url::parse(origin).map_err(|_| "Invalid public console URL")?;
        if !endpoint(origin.as_str())
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || !matches!(config.mode.as_str(), "local" | "proxy" | "oidc")
            || (!loopback && config.mode != "oidc")
            || (!loopback && origin.scheme() != "https")
        {
            return Err(
                "Console requires a secure origin; local/proxy modes bind to loopback only".into(),
            );
        }
        if config.mode == "proxy"
            && (!config.identity_header.starts_with("X-")
                || header::HeaderName::from_bytes(config.identity_header.as_bytes()).is_err())
        {
            return Err("Invalid trusted identity header".into());
        }
        if config.mode == "oidc"
            && (config.issuer.as_deref().is_none_or(|s| !endpoint(s))
                || config.client_id.as_ref().is_none_or(String::is_empty)
                || config.allowed_subjects.is_empty())
        {
            return Err("OIDC needs issuer, client ID and explicit allowed_subjects".into());
        }
        let http = openidconnect::reqwest::Client::builder()
            .redirect(openidconnect::reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| "Cannot configure identity transport")?;
        Ok(Self {
            config,
            origin,
            sessions: Mutex::new(BTreeMap::new()),
            pending: Mutex::new(BTreeMap::new()),
            http,
        })
    }
    pub fn current(&self, headers: &HeaderMap) -> Option<Actor> {
        if self.config.mode == "local" {
            return Some(Actor {
                subject: "local-observer".into(),
                display: "Local preview".into(),
                authenticated: false,
                csrf: String::new(),
                expires: now() + 3600,
            });
        }
        let key = hash(&cookie(headers, "grantline_session")?);
        let mut sessions = self.sessions.lock().ok()?;
        sessions.retain(|_, a| a.expires > now());
        let actor = sessions.get(&key)?.clone();
        if self.config.mode == "proxy"
            && proxy(headers, &self.config.identity_header).as_deref()
                != Some(actor.subject.as_str())
        {
            return None;
        }
        Some(actor)
    }
    pub fn write_actor(&self, headers: &HeaderMap, csrf: &str) -> Result<Actor, Error> {
        let actor = self
            .current(headers)
            .filter(|a| a.authenticated)
            .ok_or_else(denied)?;
        if headers.get(header::ORIGIN).and_then(|v| v.to_str().ok())
            != Some(self.origin.origin().ascii_serialization().as_str())
            || csrf.is_empty()
            || !bool::from(actor.csrf.as_bytes().ct_eq(csrf.as_bytes()))
        {
            return Err((StatusCode::FORBIDDEN, "Invalid origin or CSRF token"));
        }
        Ok(actor)
    }
    fn set_cookie(&self, response: &mut Response, key: &str, value: &str, age: u32) {
        let secure = if self.origin.scheme() == "https" {
            "; Secure"
        } else {
            ""
        };
        if let Ok(v) = HeaderValue::from_str(&format!(
            "{key}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={age}{secure}"
        )) {
            response.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    fn session(
        &self,
        subject: String,
        display: String,
        destination: &str,
    ) -> Result<Response, Error> {
        let token = random();
        let actor = Actor {
            subject,
            display,
            authenticated: true,
            csrf: random(),
            expires: now() + 3600,
        };
        let mut sessions = self.sessions.lock().map_err(|_| denied())?;
        sessions.retain(|_, a| a.expires > now());
        if sessions.len() >= 4096 {
            return Err((StatusCode::TOO_MANY_REQUESTS, "Session capacity reached"));
        }
        sessions.insert(hash(&token), actor);
        let mut response = Redirect::to(&local_path(destination)).into_response();
        self.set_cookie(&mut response, "grantline_session", &token, 3600);
        Ok(response)
    }
    pub async fn login(&self, headers: &HeaderMap, destination: &str) -> Result<Response, Error> {
        if self.config.mode == "local" {
            return Ok(Redirect::to(&local_path(destination)).into_response());
        }
        if self.config.mode == "proxy" {
            let subject = proxy(headers, &self.config.identity_header).ok_or_else(denied)?;
            return self.session(subject.clone(), subject, destination);
        }
        let issuer =
            IssuerUrl::new(self.config.issuer.clone().ok_or_else(denied)?).map_err(|_| denied())?;
        let metadata = CoreProviderMetadata::discover_async(issuer, &self.http)
            .await
            .map_err(|_| (StatusCode::BAD_GATEWAY, "Identity provider unavailable"))?;
        if !endpoint(metadata.authorization_endpoint().as_str())
            || metadata
                .token_endpoint()
                .is_none_or(|u| !endpoint(u.as_str()))
            || !endpoint(metadata.jwks_uri().as_str())
        {
            return Err((
                StatusCode::BAD_GATEWAY,
                "Invalid identity provider endpoints",
            ));
        }
        let client = CoreClient::from_provider_metadata(
            metadata.clone(),
            ClientId::new(self.config.client_id.clone().ok_or_else(denied)?),
            self.secret()?,
        )
        .set_redirect_uri(
            RedirectUrl::new(
                self.origin
                    .join("auth/callback")
                    .map_err(|_| denied())?
                    .to_string(),
            )
            .map_err(|_| denied())?,
        );
        let state = random();
        let browser = random();
        let nonce = random();
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let csrf_value = CsrfToken::new(state.clone());
        let nonce_value = Nonce::new(nonce.clone());
        let (url, _, _) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                move || csrf_value,
                move || nonce_value,
            )
            .add_scope(Scope::new("email".into()))
            .set_pkce_challenge(challenge)
            .url();
        let mut pending = self.pending.lock().map_err(|_| denied())?;
        pending.retain(|_, p| p.expires > now());
        if pending.len() >= 4096 {
            return Err((StatusCode::TOO_MANY_REQUESTS, "Login capacity reached"));
        }
        pending.insert(
            hash(&state),
            Pending {
                metadata,
                nonce,
                verifier: verifier.secret().clone(),
                browser: hash(&browser),
                destination: local_path(destination),
                expires: now() + 300,
            },
        );
        let mut r = Redirect::to(url.as_str()).into_response();
        self.set_cookie(&mut r, "grantline_login", &browser, 300);
        Ok(r)
    }
    fn secret(&self) -> Result<Option<ClientSecret>, Error> {
        self.config
            .client_secret_env
            .as_ref()
            .map(|key| {
                std::env::var(key).map(ClientSecret::new).map_err(|_| {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Identity credential unavailable",
                    )
                })
            })
            .transpose()
    }
    pub async fn callback(
        &self,
        headers: &HeaderMap,
        state: &str,
        code: &str,
    ) -> Result<Response, Error> {
        if self.config.mode != "oidc" || state.len() > 256 || code.len() > 4096 {
            return Err(denied());
        }
        let p = self
            .pending
            .lock()
            .map_err(|_| denied())?
            .remove(&hash(state))
            .ok_or_else(denied)?;
        if p.expires <= now()
            || cookie(headers, "grantline_login")
                .is_none_or(|v| !bool::from(hash(&v).as_bytes().ct_eq(p.browser.as_bytes())))
        {
            return Err(denied());
        }
        let client = CoreClient::from_provider_metadata(
            p.metadata,
            ClientId::new(self.config.client_id.clone().ok_or_else(denied)?),
            self.secret()?,
        )
        .set_redirect_uri(
            RedirectUrl::new(
                self.origin
                    .join("auth/callback")
                    .map_err(|_| denied())?
                    .to_string(),
            )
            .map_err(|_| denied())?,
        );
        let tokens = client
            .exchange_code(AuthorizationCode::new(code.into()))
            .map_err(|_| denied())?
            .set_pkce_verifier(PkceCodeVerifier::new(p.verifier))
            .request_async(&self.http)
            .await
            .map_err(|_| (StatusCode::BAD_GATEWAY, "Identity exchange failed"))?;
        let claims = tokens
            .id_token()
            .ok_or_else(denied)?
            .claims(&client.id_token_verifier(), &Nonce::new(p.nonce))
            .map_err(|_| denied())?;
        let subject = claims.subject().as_str().to_owned();
        if !self.config.allowed_subjects.contains(&subject) {
            return Err((StatusCode::FORBIDDEN, "This identity is not allowed"));
        }
        let mut response = self.session(subject.clone(), subject, &p.destination)?;
        self.set_cookie(&mut response, "grantline_login", "", 0);
        Ok(response)
    }
    pub fn logout(&self, headers: &HeaderMap, csrf: &str) -> Result<Response, Error> {
        self.write_actor(headers, csrf)?;
        if let Some(v) = cookie(headers, "grantline_session") {
            self.sessions
                .lock()
                .map_err(|_| denied())?
                .remove(&hash(&v));
        }
        let mut r = Redirect::to("/login").into_response();
        self.set_cookie(&mut r, "grantline_session", "", 0);
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn shared_oidc_requires_https_even_for_a_loopback_public_url() {
        let config = Config {
            mode: "oidc".into(),
            issuer: Some("https://identity.example.com/".into()),
            client_id: Some("fixture".into()),
            allowed_subjects: BTreeSet::from(["fixture-sub".into()]),
            ..Config::default()
        };
        assert!(Auth::new(config.clone(), "http://127.0.0.1:8424/", false).is_err());
        assert!(Auth::new(config.clone(), "https://access.example.com/", false).is_ok());
        assert!(Auth::new(config, "http://127.0.0.1:8424/", true).is_ok());
    }
    #[test]
    fn redirects_and_proxy_are_unambiguous() {
        for v in [
            "//evil.example",
            "/%2f/evil.example",
            "/%255cevil.example",
            "/\\evil.example",
            "/x%0a",
        ] {
            assert_eq!(local_path(v), "/");
        }
        assert_eq!(local_path("/matrix?q=demo"), "/matrix?q=demo");
        let mut h = HeaderMap::new();
        h.append("X-Forwarded-Email", HeaderValue::from_static("alice"));
        assert_eq!(proxy(&h, "X-Forwarded-Email"), Some("alice".into()));
        h.append("X-Forwarded-Email", HeaderValue::from_static("bob"));
        assert!(proxy(&h, "X-Forwarded-Email").is_none());
    }
    #[tokio::test]
    async fn sessions_bind_identity_origin_csrf_and_logout() {
        let a = Auth::new(
            Config {
                mode: "proxy".into(),
                ..Config::default()
            },
            "http://127.0.0.1:8424/",
            true,
        )
        .unwrap();
        let mut h = HeaderMap::new();
        h.insert("X-Forwarded-Email", HeaderValue::from_static("alice"));
        let r = a.login(&h, "/").await.unwrap();
        let c = r.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        h.insert(header::COOKIE, HeaderValue::from_str(c).unwrap());
        let actor = a.current(&h).unwrap();
        h.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://127.0.0.1:8424"),
        );
        assert!(a.write_actor(&h, &actor.csrf).is_ok());
        assert!(a.write_actor(&h, "wrong").is_err());
        h.insert("X-Forwarded-Email", HeaderValue::from_static("bob"));
        assert!(a.current(&h).is_none());
        h.insert("X-Forwarded-Email", HeaderValue::from_static("alice"));
        a.logout(&h, &actor.csrf).unwrap();
        assert!(a.current(&h).is_none());
        assert!(Auth::new(Config::default(), "http://127.0.0.1:8424/", false).is_err());
    }
}
