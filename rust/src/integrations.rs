//! Bounded explicit external APIs. No ambient credentials, redirects or retries.
use crate::{Result, model::Grant};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{io::Read, time::Duration};
use url::Url;

pub fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn env(key: &str) -> Result<String> {
    std::env::var(key)
        .ok()
        .filter(|s| !s.is_empty() && !s.chars().any(char::is_control))
        .ok_or("External credential unavailable".into())
}
pub struct Http {
    base: Url,
    token: String,
}
impl Http {
    pub fn new(base: &str, token_env: &str) -> Result<Self> {
        let base = Url::parse(base).map_err(|_| "Invalid integration URL")?;
        if !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || !base.path().ends_with('/')
            || !(base.scheme() == "https"
                || (base.scheme() == "http"
                    && matches!(base.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))))
        {
            return Err(
                "Integration requires HTTPS (or loopback tests), no URL credentials or redirects"
                    .into(),
            );
        }
        Ok(Self {
            base,
            token: env(token_env)?,
        })
    }
    pub fn request(&self, method: &str, path: &str, value: Option<Value>) -> Result<Value> {
        let url = self
            .base
            .join(path)
            .map_err(|_| "Invalid integration path")?;
        if url.origin() != self.base.origin() {
            return Err("Integration origin mismatch".into());
        }
        let body = value
            .map(|v| serde_json::to_vec(&v))
            .transpose()
            .map_err(|_| "Invalid integration payload")?
            .unwrap_or_default();
        let req = ureq::http::Request::builder()
            .method(method)
            .uri(url.as_str())
            .header("Authorization", format!("Bearer {}", self.token))
            .header("User-Agent", "Grantline-native")
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .body(body)
            .map_err(|_| "Cannot create integration request")?;
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(15)))
            .max_redirects(0)
            .proxy(None)
            .http_status_as_error(false)
            .build()
            .into();
        let mut response = agent
            .run(req)
            .map_err(|_| "External request failed; response withheld")?;
        if !(200..300).contains(&response.status().as_u16()) {
            return Err("External API refused; response withheld".into());
        }
        let mut bytes = vec![];
        response
            .body_mut()
            .as_reader()
            .take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "External response failed")?;
        if bytes.len() > 2 * 1024 * 1024 {
            return Err("External response limit exceeded".into());
        }
        serde_json::from_slice(&bytes).map_err(|_| "Invalid external response".into())
    }
}
fn github_api() -> String {
    "https://api.github.com/".into()
}
fn main_branch() -> String {
    "main".into()
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GitHub {
    pub repository: String,
    pub intent_path: String,
    pub token_env: String,
    pub expected_login: String,
    #[serde(default)]
    pub allow_public_repository: bool,
    #[serde(default = "main_branch")]
    pub base_branch: String,
    #[serde(default = "github_api")]
    pub api_url: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Patch {
    pub base_commit: String,
    pub base_tree: String,
    pub before_blob: String,
    pub before: String,
    pub after: String,
    pub sha256: String,
    pub repository: String,
    pub path: String,
    pub branch: String,
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() < 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_/.".contains(&b))
        && !s.split('/').any(|p| p.is_empty() || p == "." || p == "..")
}
fn hash_patch(p: &Patch) -> String {
    sha(serde_json::to_string(&(
        &p.repository,
        &p.branch,
        &p.path,
        &p.base_commit,
        &p.base_tree,
        &p.before_blob,
        &p.before,
        &p.after,
    ))
    .unwrap()
    .as_bytes())
}
fn id(v: &Value) -> Result<String> {
    v.as_str()
        .filter(|s| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_owned)
        .ok_or("Invalid Git object identity".into())
}
fn field(v: &Value, key: &str) -> Result<String> {
    v[key]
        .as_str()
        .map(str::to_owned)
        .ok_or("Missing integration field".into())
}
impl GitHub {
    fn client(&self) -> Result<Http> {
        if !identifier(&self.repository)
            || self.repository.split('/').count() != 2
            || !identifier(&self.intent_path)
            || !self.intent_path.ends_with(".toml")
            || self.intent_path.split('/').count() > 8
            || !identifier(&self.base_branch)
        {
            return Err("GitHub repository/path/base scope invalid".into());
        }
        let http = Http::new(&self.api_url, &self.token_env)?;
        if http.request("GET", "user", None)?["login"] != self.expected_login {
            return Err("GitHub writer account mismatch".into());
        }
        if http.request("GET", &format!("repos/{}", self.repository), None)?["private"] != true
            && !self.allow_public_repository
        {
            return Err(
                "IAM code publication requires a private repository or explicit public opt-in"
                    .into(),
            );
        }
        Ok(http)
    }
    pub fn preview(&self, g: &Grant, action: &str) -> Result<Patch> {
        let http = self.client()?;
        let root = format!("repos/{}/", self.repository);
        let base_commit = id(&http.request(
            "GET",
            &format!("{root}git/ref/heads/{}", self.base_branch),
            None,
        )?["object"]["sha"])?;
        let base_tree = id(&http.request(
            "GET",
            &format!("{root}git/commits/{base_commit}"),
            None,
        )?["tree"]["sha"])?;
        let mut tree = base_tree.clone();
        let mut before_blob = String::new();
        let parts: Vec<_> = self.intent_path.split('/').collect();
        for (i, part) in parts.iter().enumerate() {
            let t = http.request("GET", &format!("{root}git/trees/{tree}"), None)?;
            let row = t["tree"]
                .as_array()
                .and_then(|a| a.iter().find(|r| r["path"] == *part))
                .ok_or("Configured intent path missing")?;
            if i + 1 == parts.len() {
                if row["mode"] != "100644" || row["type"] != "blob" {
                    return Err("Intent must be a regular Git blob".into());
                }
                before_blob = id(&row["sha"])?;
            } else {
                if row["type"] != "tree" {
                    return Err("Intent path traverses a non-tree".into());
                }
                tree = id(&row["sha"])?;
            }
        }
        let blob = http.request("GET", &format!("{root}git/blobs/{before_blob}"), None)?;
        if blob["encoding"] != "base64" {
            return Err("Unsupported Git blob encoding".into());
        }
        let encoded = field(&blob, "content")?.replace(['\r', '\n'], "");
        let before = String::from_utf8(STANDARD.decode(encoded).map_err(|_| "Invalid Git blob")?)
            .map_err(|_| "Intent is not UTF-8")?;
        if before.len() > 1024 * 1024 {
            return Err("Intent blob exceeds limit".into());
        }
        let after = edit_intent(&before, g, action)?;
        let mut p = Patch {
            base_commit,
            base_tree,
            before_blob,
            before,
            after,
            sha256: String::new(),
            repository: self.repository.clone(),
            path: self.intent_path.clone(),
            branch: self.base_branch.clone(),
        };
        p.sha256 = hash_patch(&p);
        Ok(p)
    }
    pub fn publish(&self, p: &Patch, request: &str, g: &Grant, action: &str) -> Result<String> {
        if p.sha256 != hash_patch(p)
            || p.repository != self.repository
            || p.path != self.intent_path
            || p.branch != self.base_branch
            || !request.bytes().all(|b| b.is_ascii_hexdigit())
            || request.len() != 32
        {
            return Err("Approved code plan binding mismatch".into());
        }
        let fresh = self.preview(g, action)?;
        if fresh.sha256 != p.sha256 {
            return Err("Approved repository source changed; create a new request".into());
        }
        let http = self.client()?;
        let root = format!("repos/{}/", self.repository);
        let branch = format!("grantline/{request}");
        http.request(
            "POST",
            &format!("{root}git/refs"),
            Some(json!({"ref":format!("refs/heads/{branch}"),"sha":p.base_commit})),
        )?;
        let blob = id(&http.request(
            "POST",
            &format!("{root}git/blobs"),
            Some(json!({"content":STANDARD.encode(p.after.as_bytes()),"encoding":"base64"})),
        )?["sha"])?;
        let tree=id(&http.request("POST",&format!("{root}git/trees"),Some(json!({"base_tree":p.base_tree,"tree":[{"path":p.path,"mode":"100644","type":"blob","sha":blob}]})))?["sha"])?;
        let writer = http.request("GET", "user", None)?;
        let user_id = writer["id"]
            .as_u64()
            .filter(|id| *id > 0)
            .ok_or("GitHub writer user ID missing")?;
        let author = json!({"name":self.expected_login,"email":format!("{user_id}+{}@users.noreply.github.com",self.expected_login)});
        let commit=id(&http.request("POST",&format!("{root}git/commits"),Some(json!({"message":format!("feat: 승인된 권한 요청 {request} 반영"),"tree":tree,"parents":[p.base_commit],"author":author,"committer":author})))?["sha"])?;
        http.request(
            "PATCH",
            &format!("{root}git/refs/heads/{branch}"),
            Some(json!({"sha":commit,"force":false})),
        )?;
        let body = format!(
            "## 변경 요약\n\n승인된 {action} 요청: {} / {} / {} / {}.\n계획 SHA-256: {}\n\n## 테스트 결과\n\n모든 필수 승인과 원본 commit·파일·패치 일치를 확인했습니다. 저장소 CI와 운영 적용은 별도 확인이 필요합니다.\n\n## 미검증 사항\n\n이 PR은 선언만 변경하며 실제 IAM 권한을 적용하지 않습니다. 머지·배포·대상 계정의 실효 접근은 별도 검증 대상입니다.\n",
            g.system, g.subject, g.resource, g.privilege, p.sha256
        );
        let pr=http.request("POST",&format!("{root}pulls"),Some(json!({"title":format!("feat: 승인된 권한 {action} 요청 {request}"),"head":branch,"base":self.base_branch,"body":body})))?;
        let number = pr["number"]
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or("Invalid published PR number")?;
        let expected = format!("https://github.com/{}/pull/{number}", self.repository);
        if pr["html_url"] != expected || pr["head"]["sha"] != commit {
            return Err("Published PR identity mismatch; inspect repository".into());
        }
        Ok(expected)
    }
}
pub fn edit_intent(before: &str, g: &Grant, action: &str) -> Result<String> {
    if !matches!(action, "grant" | "revoke") {
        return Err("Unknown request action".into());
    }
    let mut doc: toml::Value = toml::from_str(before).map_err(|_| "Invalid repository intent")?;
    let table = doc.as_table_mut().ok_or("Intent table required")?;
    if table
        .keys()
        .any(|k| !["grants", "managed_subjects", "managed_systems", "naming"].contains(&k.as_str()))
    {
        return Err("Repository file is not a supported intent document".into());
    }
    let rows = table
        .entry("grants")
        .or_insert_with(|| toml::Value::Array(vec![]))
        .as_array_mut()
        .ok_or("Invalid intent grants")?;
    if rows.len() > 10000 {
        return Err("Repository intent exceeds limit".into());
    }
    for r in rows.iter() {
        let t = r.as_table().ok_or("Malformed intent grant row")?;
        if t.keys()
            .any(|k| !["system", "subject", "resource", "privs"].contains(&k.as_str()))
            || ["system", "subject", "resource"].iter().any(|k| {
                t.get(*k)
                    .and_then(toml::Value::as_str)
                    .is_none_or(str::is_empty)
            })
            || t.get("privs")
                .and_then(toml::Value::as_array)
                .is_none_or(|a| {
                    a.is_empty() || a.iter().any(|v| v.as_str().is_none_or(str::is_empty))
                })
        {
            return Err("Repository intent has invalid grant fields".into());
        }
    }
    let mut found = false;
    for row in rows.iter_mut().filter(|r| {
        r.get("system").and_then(toml::Value::as_str) == Some(&g.system)
            && r.get("subject").and_then(toml::Value::as_str) == Some(&g.subject)
            && r.get("resource").and_then(toml::Value::as_str) == Some(&g.resource)
    }) {
        let ps = row
            .get_mut("privs")
            .and_then(toml::Value::as_array_mut)
            .ok_or("Invalid intent privileges")?;
        if ps.iter().any(|p| p.as_str() == Some(&g.privilege)) {
            found = true;
            if action == "revoke" {
                ps.retain(|p| p.as_str() != Some(&g.privilege));
            }
        }
    }
    if (action == "grant" && found) || (action == "revoke" && !found) {
        return Err("Request would not change the declared intent".into());
    }
    rows.retain(|r| {
        r.get("privs")
            .and_then(toml::Value::as_array)
            .is_none_or(|a| !a.is_empty())
    });
    if action == "grant" {
        let row=toml::Value::try_from(json!({"system":g.system,"subject":g.subject,"resource":g.resource,"privs":[g.privilege]})).map_err(|_|"Cannot encode grant")?;
        rows.push(row);
    }
    toml::to_string_pretty(&doc).map_err(|_| "Cannot encode intent".into())
}
