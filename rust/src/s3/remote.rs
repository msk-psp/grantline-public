use super::*;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    time::{Duration, Instant},
};
use url::Url;

const MAX_BODY: u64 = 4 * 1024 * 1024;
const MAX_TOTAL: usize = 64 * 1024 * 1024;
const MAX_CALLS: usize = 512;
const MAX_ITEMS: usize = 10_000;
const CONTENT_TYPE: &str = "application/x-www-form-urlencoded";
fn env(key: Option<&str>) -> Result<String> {
    let name = key
        .filter(|s| !s.is_empty())
        .ok_or("S3 reader environment variable is not configured")?;
    std::env::var(name).map_err(|_| "S3 reader environment variable is unavailable".into())
}
struct Http {
    base: Url,
    bearer: Option<String>,
    started: Instant,
    timeout: Duration,
    calls: usize,
    bytes: usize,
}
impl Http {
    fn new(raw: &str, bearer: Option<String>, seconds: u64) -> Result<Self> {
        let base = Url::parse(raw).map_err(|_| "Invalid S3 reader URL")?;
        if !matches!(base.scheme(), "http" | "https")
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || bearer
                .as_ref()
                .is_some_and(|s| s.is_empty() || s.chars().any(char::is_control))
        {
            return Err("S3 reader URL requires HTTP(S), no userinfo/query/fragment, and a valid optional bearer".into());
        }
        if !(1..=120).contains(&seconds) {
            return Err("read_timeout_seconds must be between 1 and 120".into());
        }
        Ok(Self {
            base,
            bearer,
            started: Instant::now(),
            timeout: Duration::from_secs(seconds),
            calls: 0,
            bytes: 0,
        })
    }
    fn request(
        &mut self,
        url: &Url,
        body: Option<&str>,
        headers: &BTreeMap<String, String>,
        optional: bool,
    ) -> Result<Option<Vec<u8>>> {
        self.calls += 1;
        if self.calls > MAX_CALLS {
            return Err("S3 reader request limit exceeded".into());
        }
        let remaining = self
            .timeout
            .checked_sub(self.started.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or("S3 observation deadline exceeded")?;
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(remaining))
            .timeout_connect(Some(remaining.min(Duration::from_secs(5))))
            .max_redirects(0)
            .proxy(None)
            .http_status_as_error(false)
            .build()
            .into();
        // All raw HTTP errors/bodies can contain credentials and must stay out of diagnostics.
        let mut response = if let Some(body) = body {
            let mut req = agent.post(url.as_str());
            for (k, v) in headers {
                req = req.header(k, v);
            }
            req.send(body)
                .map_err(|_| "S3 IAM transport/TLS failure or timeout")?
        } else {
            let mut req = agent.get(url.as_str()).header("Accept", "application/json");
            if let Some(token) = &self.bearer {
                req = req.header("Authorization", &format!("Bearer {token}"));
            }
            req.call()
                .map_err(|_| "S3 reader transport/TLS failure or timeout")?
        };
        let status = response.status().as_u16();
        if optional && status == 404 {
            return Ok(None);
        }
        if status != 200 {
            return Err(format!("S3 reader HTTP {status}; response body withheld"));
        }
        let mut bytes = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(MAX_BODY + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "Incomplete S3 response or timeout")?;
        self.bytes += bytes.len();
        if bytes.len() as u64 > MAX_BODY || self.bytes > MAX_TOTAL {
            return Err("S3 reader byte limit exceeded".into());
        }
        if self.started.elapsed() >= self.timeout {
            return Err("S3 observation deadline exceeded".into());
        }
        Ok(Some(bytes))
    }
    fn json(&mut self, url: &Url, optional: bool) -> Result<Option<Value>> {
        self.request(url, None, &BTreeMap::new(), optional)?
            .map(|b| serde_json::from_slice(&b).map_err(|_| "Invalid S3 reader JSON".into()))
            .transpose()
    }
    fn path(&self, relative: &str) -> Url {
        let mut url = self.base.clone();
        url.set_path(&format!(
            "{}/{}",
            self.base.path().trim_end_matches('/'),
            relative
        ));
        url
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Listing {
    path: String,
    #[serde(deserialize_with = "entries")]
    entries: Option<Vec<Entry>>,
    last_file_name: String,
    should_display_load_more: bool,
}
fn entries<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Vec<Entry>>, D::Error> {
    Option::<Vec<Entry>>::deserialize(d)
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Entry {
    full_path: String,
    mode: u32,
}
fn file_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_+=,.@-".contains(&b))
    {
        return Err("Unsupported remote IAM filename/name".into());
    }
    Ok(())
}
fn filer_files(
    http: &mut Http,
    directory: &str,
    optional: bool,
) -> Result<BTreeMap<String, Value>> {
    let path = format!("etc/iam/{directory}/");
    let mut marker = String::new();
    let mut found = BTreeSet::new();
    loop {
        let mut url = http.path(&path);
        url.query_pairs_mut()
            .append_pair("limit", "1000")
            .append_pair("lastFileName", &marker);
        let Some(raw) = http.json(&url, optional && marker.is_empty())? else {
            return Ok(BTreeMap::new());
        };
        let page: Listing = serde_json::from_value(raw)
            .map_err(|_| "Invalid or incomplete Filer listing schema")?;
        // A proxy mount prefix need not be part of FullPath/Path returned by the filer.
        let expected = format!("/etc/iam/{directory}");
        if page.path.trim_end_matches('/') != expected {
            return Err("Filer listing returned a different directory".into());
        }
        let entries = page.entries.unwrap_or_default();
        if page.should_display_load_more && entries.is_empty() {
            return Err("Truncated Filer listing has no progress".into());
        }
        let mut last = marker.clone();
        for entry in entries {
            let name = entry
                .full_path
                .strip_prefix(&(expected.clone() + "/"))
                .ok_or("Filer entry escaped IAM directory")?;
            file_name(name)?;
            if name <= last.as_str()
                || entry.mode & 0o170000 == 0o040000
                || entry.mode & 0x80000000 != 0
            {
                return Err("Invalid, duplicate or unordered Filer entry".into());
            }
            last = name.into();
            if !name.ends_with(".json") {
                return Err("Unrecognized file in IAM directory".into());
            }
            if !found.insert(name.to_owned()) || found.len() > MAX_ITEMS {
                return Err("Filer collection exceeded limit or repeated entries".into());
            }
        }
        if !page.should_display_load_more {
            break;
        }
        if page.last_file_name != last || last == marker {
            return Err("Invalid Filer pagination marker".into());
        }
        marker = last;
    }
    let mut files = BTreeMap::new();
    for name in found {
        let value = http
            .json(&http.path(&format!("{path}{name}")), false)?
            .ok_or("Missing Filer document")?;
        if !value.is_object() {
            return Err("Invalid Filer IAM document".into());
        }
        let stem = name.strip_suffix(".json").ok_or("Invalid IAM filename")?;
        if directory == "identities" && value.get("name").and_then(Value::as_str) != Some(stem) {
            return Err("Filer identity name does not match its filename".into());
        }
        files.insert(stem.to_owned(), value);
    }
    Ok(files)
}
fn filer(http: &mut Http, system: &str) -> Result<Document> {
    let top = http
        .json(&http.path("etc/iam/policies.json"), true)?
        .unwrap_or_else(|| json!({}));
    let ids = filer_files(http, "identities", false)?;
    let groups = filer_files(http, "groups", true)?;
    let policies = filer_files(http, "policies", true)?;
    // A disabled status has no representation in the policy model; fail closed.
    if ids.values().chain(groups.values()).any(|v| {
        v.get("disabled").is_some() || v.get("status").is_some() || v.get("enabled").is_some()
    }) {
        return Err("Remote IAM identity/group status cannot be represented".into());
    }
    merge_tree(ids, groups, policies, top, system)
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}
fn signed(
    url: &Url,
    body: &str,
    key: &str,
    secret: &str,
    token: Option<&str>,
    timestamp: &str,
) -> BTreeMap<String, String> {
    let mut host = url
        .host_str()
        .unwrap_or("")
        .trim_matches(['[', ']'])
        .to_owned();
    if host.contains(':') {
        host = format!("[{host}]");
    }
    if let Some(port) = url.port() {
        host += &format!(":{port}");
    }
    let mut headers = BTreeMap::from([
        ("host".into(), host),
        ("content-type".into(), CONTENT_TYPE.into()),
        ("x-amz-content-sha256".into(), sha(body.as_bytes())),
        ("x-amz-date".into(), timestamp.into()),
    ]);
    if let Some(token) = token {
        headers.insert("x-amz-security-token".into(), token.into());
    }
    let names = headers.keys().cloned().collect::<Vec<_>>().join(";");
    let canonical_headers = headers
        .iter()
        .map(|(k, v)| format!("{k}:{}\n", v.trim()))
        .collect::<String>();
    let canonical = format!(
        "POST\n{}\n\n{canonical_headers}\n{names}\n{}",
        url.path(),
        sha(body.as_bytes())
    );
    let date = &timestamp[..8];
    let scope = format!("{date}/us-east-1/iam/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
        sha(canonical.as_bytes())
    );
    let mut signing = ("AWS4".to_owned() + secret).into_bytes();
    for part in [date, "us-east-1", "iam", "aws4_request"] {
        signing = hmac(&signing, part);
    }
    let signature = hmac(&signing, &to_sign)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    headers.insert("authorization".into(),format!("AWS4-HMAC-SHA256 Credential={key}/{scope}, SignedHeaders={names}, Signature={signature}"));
    headers.remove("host");
    headers
}
fn xml_value(node: roxmltree::Node<'_, '_>, depth: usize) -> Result<Value> {
    if depth > 32 {
        return Err("IAM XML nesting limit exceeded".into());
    }
    let children = node
        .children()
        .filter(|n| n.is_element())
        .collect::<Vec<_>>();
    if children.is_empty() {
        return Ok(Value::String(node.text().unwrap_or("").into()));
    }
    let mut map = serde_json::Map::new();
    for child in children {
        let key = child.tag_name().name();
        let value = xml_value(child, depth + 1)?;
        if key == "member" {
            map.entry(key)
                .or_insert_with(|| json!([]))
                .as_array_mut()
                .ok_or("Invalid XML members")?
                .push(value);
        } else if map.insert(key.into(), value).is_some() {
            return Err("Duplicate IAM XML field".into());
        }
    }
    Ok(Value::Object(map))
}
struct Iam {
    http: Http,
    key: String,
    secret: String,
    token: Option<String>,
    cache: BTreeMap<String, Value>,
}
impl Iam {
    fn call(&mut self, action: &str, params: &[(&str, &str)]) -> Result<Value> {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("Action", action)
            .append_pair("Version", "2010-05-08");
        form.extend_pairs(params.iter().copied());
        let body = form.finish();
        let headers = signed(
            &self.http.base,
            &body,
            &self.key,
            &self.secret,
            self.token.as_deref(),
            &chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string(),
        );
        let url = self.http.base.clone();
        let bytes = self
            .http
            .request(&url, Some(&body), &headers, false)
            .map_err(|e| format!("IAM {action}: {e}"))?
            .ok_or("Missing IAM response")?;
        let text = std::str::from_utf8(&bytes).map_err(|_| "IAM response is not UTF-8")?;
        let xml =
            roxmltree::Document::parse(text).map_err(|_| "Invalid IAM XML (DTD is unsupported)")?;
        let root = xml.root_element();
        if xml
            .descendants()
            .any(|n| n.is_element() && n.tag_name().name() == "Error")
            || root.tag_name().name() != format!("{action}Response")
        {
            return Err("Unexpected IAM response envelope".into());
        }
        let value = xml_value(root, 0)?;
        value
            .get(format!("{action}Result"))
            .cloned()
            .ok_or("Missing IAM result".into())
    }
    fn list(
        &mut self,
        action: &str,
        params: &[(&str, &str)],
        collection: &str,
    ) -> Result<Vec<Value>> {
        let mut output = Vec::new();
        let mut marker = String::new();
        let mut seen = BTreeSet::new();
        loop {
            let mut params = params.to_vec();
            params.push(("MaxItems", "1000"));
            if !marker.is_empty() {
                params.push(("Marker", &marker));
            }
            let result = self.call(action, &params)?;
            if action == "GetGroup"
                && result.get("Group").is_some_and(|g| {
                    ["Status", "Disabled", "Enabled"]
                        .iter()
                        .any(|k| g.get(k).is_some())
                })
            {
                return Err("IAM group status is not represented by the permission model".into());
            }
            let values = match result.get(collection) {
                Some(Value::String(s)) if s.is_empty() => vec![],
                Some(v) => v
                    .get("member")
                    .and_then(Value::as_array)
                    .ok_or("Missing IAM member array")?
                    .clone(),
                None => return Err("Incomplete IAM collection".into()),
            };
            if output.len() + values.len() > MAX_ITEMS {
                return Err("IAM collection limit exceeded".into());
            }
            output.extend(values);
            match result.get("IsTruncated").and_then(Value::as_str) {
                Some("false") => break,
                Some("true") => {
                    marker = text_field(&result, "Marker")?.into();
                    if marker.is_empty() || !seen.insert(marker.clone()) {
                        return Err("IAM pagination made no progress".into());
                    }
                }
                _ => return Err("Missing/invalid IAM truncation flag".into()),
            }
        }
        Ok(output)
    }
    fn policy(&mut self, arn: &str) -> Result<Value> {
        if let Some(policy) = self.cache.get(arn) {
            return Ok(policy.clone());
        }
        if !arn.starts_with("arn:aws:iam:") {
            return Err("Unsupported managed policy ARN".into());
        }
        let metadata = self.call("GetPolicy", &[("PolicyArn", arn)])?;
        let version = text_field(
            metadata
                .get("Policy")
                .ok_or("Missing managed policy metadata")?,
            "DefaultVersionId",
        )?;
        let response = self.call(
            "GetPolicyVersion",
            &[("PolicyArn", arn), ("VersionId", version)],
        )?;
        let policy = decode_policy(text_field(
            response
                .get("PolicyVersion")
                .ok_or("Missing policy version")?,
            "Document",
        )?)?;
        self.cache.insert(arn.into(), policy.clone());
        Ok(policy)
    }
    fn user_policies(&mut self, user: &str) -> Result<Vec<(String, Value)>> {
        let mut policies = Vec::new();
        for name in self.list("ListUserPolicies", &[("UserName", user)], "PolicyNames")? {
            let name = name.as_str().ok_or("Invalid inline policy name")?;
            file_name(name)?;
            let response =
                self.call("GetUserPolicy", &[("UserName", user), ("PolicyName", name)])?;
            policies.push((
                format!("user:{user}:inline:{name}"),
                decode_policy(text_field(&response, "PolicyDocument")?)?,
            ));
        }
        for attached in self.list(
            "ListAttachedUserPolicies",
            &[("UserName", user)],
            "AttachedPolicies",
        )? {
            let arn = text_field(&attached, "PolicyArn")?;
            policies.push((arn.into(), self.policy(arn)?));
        }
        Ok(policies)
    }
    fn read(&mut self, system: &str) -> Result<Document> {
        let users = self.list("ListUsers", &[], "Users")?;
        let mut policies: BTreeMap<String, Vec<(String, Value)>> = BTreeMap::new();
        let mut doc = Document::default();
        for user in users {
            let name = text_field(&user, "UserName")?;
            file_name(name)?;
            let metadata = self.call("GetUser", &[("UserName", name)])?;
            let current = metadata.get("User").ok_or("Missing IAM user metadata")?;
            if text_field(current, "UserName")? != name {
                return Err("IAM user identity changed during observation".into());
            }
            if ["PermissionsBoundary", "Status", "Disabled", "Enabled"]
                .iter()
                .any(|k| current.get(k).is_some())
            {
                doc.gap_subjects.insert(name.into());
            }
            let direct = match self.user_policies(name) {
                Ok(direct) => direct,
                Err(_) => {
                    doc.gap_subjects.insert(name.into());
                    vec![]
                }
            };
            for (pname, _) in &direct {
                doc.routes
                    .push([name.into(), format!("policy:{pname}"), "inline".into()]);
            }
            if policies.insert(name.into(), direct).is_some() {
                return Err("Duplicate IAM user".into());
            }
            doc.kinds.insert(name.into(), "account".into());
        }
        let mut groups = BTreeSet::new();
        for group in self.list("ListGroups", &[], "Groups")? {
            let name = text_field(&group, "GroupName")?;
            file_name(name)?;
            if !groups.insert(name.to_owned()) {
                return Err("Duplicate IAM group".into());
            }
            let members = self.list("GetGroup", &[("GroupName", name)], "Users")?;
            let mut attached = Vec::new();
            for pname in self.list("ListGroupPolicies", &[("GroupName", name)], "PolicyNames")? {
                let pname = pname.as_str().ok_or("Invalid group inline policy name")?;
                file_name(pname)?;
                let response = self.call(
                    "GetGroupPolicy",
                    &[("GroupName", name), ("PolicyName", pname)],
                )?;
                attached.push((
                    format!("group:{name}:inline:{pname}"),
                    decode_policy(text_field(&response, "PolicyDocument")?)?,
                ));
            }
            for p in self.list(
                "ListAttachedGroupPolicies",
                &[("GroupName", name)],
                "AttachedPolicies",
            )? {
                let arn = text_field(&p, "PolicyArn")?;
                attached.push((arn.into(), self.policy(arn)?));
            }
            doc.kinds.insert(format!("group:{name}"), "group".into());
            for (pname, p) in &attached {
                policy_routes(&mut doc, pname, p, system)?;
                doc.routes.push([
                    format!("group:{name}"),
                    format!("policy:{pname}"),
                    "attaches".into(),
                ]);
            }
            let mut seen = BTreeSet::new();
            for member in members {
                let member = text_field(&member, "UserName")?;
                if !seen.insert(member.to_owned()) {
                    return Err("Duplicate IAM group member".into());
                }
                policies
                    .get_mut(member)
                    .ok_or("Group references an unlisted IAM user")?
                    .extend(attached.clone());
                doc.routes
                    .push([member.into(), format!("group:{name}"), "member".into()]);
            }
        }
        for (name, policies) in policies {
            let mut ss = Vec::new();
            if policies.is_empty() {
                doc.gap_subjects.insert(name.clone());
            }
            for (pname, p) in policies {
                ss.extend(statements(&p)?.clone());
                policy_routes(&mut doc, &pname, &p, system)?;
            }
            doc.identities.insert(
                name.clone(),
                Identity {
                    name,
                    actions: vec![],
                    policy: Some(json!({"Version":"2012-10-17","Statement":ss})),
                },
            );
        }
        for name in &doc.gap_subjects {
            doc.gaps.push((name.clone(),"IAM visibility".into(),"IAM Query cannot establish complete user-policy visibility, native-action access or a permissions boundary; subject remains unread".into()));
        }
        Ok(doc)
    }
}
fn text_field<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && !s.chars().any(char::is_control))
        .ok_or("Missing/invalid IAM result field".into())
}
fn decode_policy(text: &str) -> Result<Value> {
    let decoded = if text.trim_start().starts_with('{') {
        text.to_owned()
    } else {
        percent_encoding::percent_decode_str(text)
            .decode_utf8()
            .map_err(|_| "Invalid IAM policy encoding")?
            .into_owned()
    };
    let value: Value = serde_json::from_str(&decoded).map_err(|_| "Invalid IAM policy JSON")?;
    statements(&value)?;
    Ok(value)
}
pub(super) fn read(p: &Plane, system: &str, seconds: u64) -> Result<Document> {
    if p.ca_bundle_env.is_some() {
        return Err("Custom CA bundles are unsupported in native S3 readers".into());
    }
    let count = [&p.iam_url_env, &p.filer_url_env, &p.url_env]
        .iter()
        .filter(|x| x.is_some())
        .count();
    if count != 1 {
        return Err("Configure exactly one remote S3 source per plane".into());
    }
    if let Some(key) = p.iam_url_env.as_deref() {
        let raw = env(Some(key))?;
        let mut http = Http::new(&raw, None, seconds)?;
        if !http
            .base
            .path()
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-_.~".contains(&b))
        {
            return Err("Unsupported IAM endpoint path encoding".into());
        }
        if !http.base.path().ends_with('/') {
            let path = http.base.path().to_owned() + "/";
            http.base.set_path(&path);
        }
        let key = env(p.iam_key_env.as_deref())?;
        let secret = env(p.iam_secret_env.as_deref())?;
        let token = p
            .iam_session_token_env
            .as_deref()
            .map(|s| env(Some(s)))
            .transpose()?;
        if [&key, &secret]
            .into_iter()
            .chain(token.iter())
            .any(|s| s.is_empty() || s.chars().any(char::is_control))
        {
            return Err("Invalid IAM reader credential".into());
        }
        return Iam {
            http,
            key,
            secret,
            token,
            cache: BTreeMap::new(),
        }
        .read(system);
    }
    let filer = p.filer_url_env.is_some();
    let raw = env(if filer {
        p.filer_url_env.as_deref()
    } else {
        p.url_env.as_deref()
    })?;
    let auth = if filer {
        p.filer_auth_env.as_deref()
    } else {
        p.auth_env.as_deref()
    }
    .map(|s| env(Some(s)))
    .transpose()?;
    let mut http = Http::new(&raw, auth, seconds)?;
    if filer {
        self::filer(&mut http, system)
    } else {
        let url = http.base.clone();
        let value = http.json(&url, false)?.ok_or("Missing remote IAM JSON")?;
        let identities = value
            .get("identities")
            .and_then(Value::as_array)
            .ok_or("Missing remote identities array")?;
        if identities.len() > MAX_ITEMS
            || identities.iter().any(|i| {
                [
                    "disabled",
                    "status",
                    "enabled",
                    "policy_names",
                    "policyNames",
                    "groups",
                ]
                .iter()
                .any(|k| i.get(k).is_some())
            })
        {
            return Err("Remote JSON identities exceed limit or need a complete IAM tree".into());
        }
        document(value, system)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn remote_boundary() {
        for url in [
            "file:///tmp/iam.json",
            "http://reader:secret@localhost/",
            "http://localhost/?secret=x",
            "http://localhost/#x",
        ] {
            assert!(Http::new(url, None, 30).is_err());
        }
        for name in ["../escape.json", "%2e%2e.json", "a/b.json", ".", ""] {
            assert!(file_name(name).is_err());
        }
        assert!(decode_policy("%7B%22Statement%22%3A%5B%5D%7D").is_ok());
        assert!(decode_policy("%7Bnot-json").is_err());
        assert!(
            roxmltree::Document::parse("<!DOCTYPE a [<!ENTITY x 'secret'>]><a>&x;</a>").is_err()
        );
    }
}
