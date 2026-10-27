//! Subject-signed samples; the console also supports bounded, discarded Range GETs.
use super::remote::{Signer, uri_encode};
use crate::{
    Result,
    config::Adapter,
    model::Grant,
    probe::{Probe, Verdict},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    time::{Duration, Instant},
};
use url::Url;

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Credential {
    pub key_env: Option<String>,
    pub secret_env: Option<String>,
    pub session_token_env: Option<String>,
}
fn env(name: Option<&str>) -> Result<String> {
    let name = name
        .filter(|s| !s.is_empty())
        .ok_or("S3 probe credential/endpoint variable is not configured")?;
    let value =
        std::env::var(name).map_err(|_| "S3 probe credential/endpoint variable is unavailable")?;
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err("Invalid or empty S3 probe configuration value".into());
    }
    Ok(value)
}
fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 1024
        && !key.chars().any(char::is_control)
        && !key.split('/').any(|s| matches!(s, "." | ".."))
}
fn target(g: &Grant) -> Result<(String, String)> {
    if !matches!(g.privilege.as_str(), "List" | "Read" | "Write") {
        return Err("Only List, Read and explicitly enabled Write probes are implemented".into());
    }
    let scope = g
        .resource
        .strip_prefix("bucket:")
        .ok_or("Unsupported S3 probe resource")?;
    let (bucket, prefix) = scope.split_once('/').unwrap_or((scope, ""));
    if !(3..=63).contains(&bucket.len())
        || !bucket
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
        || !bucket.as_bytes()[0].is_ascii_alphanumeric()
        || !bucket.as_bytes()[bucket.len() - 1].is_ascii_alphanumeric()
        || bucket.contains("..")
        || bucket.parse::<std::net::IpAddr>().is_ok()
    {
        return Err("Select a concrete DNS-style bucket for the S3 probe".into());
    }
    if !prefix.is_empty() && (!valid_key(prefix) || prefix.contains(['*', '?', '['])) {
        return Err("Invalid or wildcard S3 probe prefix".into());
    }
    Ok((
        bucket.into(),
        if prefix.is_empty() {
            String::new()
        } else {
            format!("{}/", prefix.trim_end_matches('/'))
        },
    ))
}
fn endpoint(raw: &str) -> Result<Url> {
    let url = Url::parse(raw).map_err(|_| "Invalid S3 data endpoint")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url
            .path()
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-_.~".contains(&b))
    {
        return Err(
            "S3 endpoint requires HTTP(S), no credentials/query/fragment and a plain mount path"
                .into(),
        );
    }
    Ok(url)
}
fn object_url(base: &Url, bucket: &str, key: Option<&str>) -> Result<Url> {
    let path = format!(
        "{}/{}{}",
        base.path().trim_end_matches('/'),
        bucket,
        key.map(|k| format!("/{}", uri_encode(k, true)))
            .unwrap_or_default()
    );
    let mut url = base.clone();
    url.set_path(&path);
    if url.path() != path {
        return Err("Object path was changed by URL normalization".into());
    }
    Ok(url)
}
fn xml(bytes: &[u8]) -> Result<roxmltree::Document<'_>> {
    let text = std::str::from_utf8(bytes).map_err(|_| "S3 response is not UTF-8 XML")?;
    let doc = roxmltree::Document::parse(text).map_err(|_| "Invalid S3 XML; DTD is unsupported")?;
    if doc.descendants().filter(|n| n.is_element()).any(|n| {
        n.ancestors().count() > 32
            || n.tag_name()
                .namespace()
                .is_some_and(|s| s != "http://s3.amazonaws.com/doc/2006-03-01/")
    }) {
        return Err("Invalid S3 XML namespace or nesting".into());
    }
    Ok(doc)
}
fn text<'a, 'input>(node: roxmltree::Node<'a, 'input>, name: &str) -> Result<&'a str> {
    let mut found = node
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == name);
    let field = found.next().ok_or("Missing S3 response field")?;
    if found.next().is_some() || field.children().any(|n| n.is_element()) {
        return Err("Duplicate or invalid S3 response field".into());
    }
    Ok(field.text().unwrap_or(""))
}
fn decode(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'%'
            && (i + 2 >= bytes.len()
                || !bytes[i + 1].is_ascii_hexdigit()
                || !bytes[i + 2].is_ascii_hexdigit())
        {
            return Err("Invalid URL-encoded S3 listing".into());
        }
    }
    // SeaweedFS uses QueryEscape: '+' is space, while literal '+' is '%2B'.
    let value = value.replace('+', " ");
    percent_encoding::percent_decode_str(&value)
        .decode_utf8()
        .map(|s| s.into_owned())
        .map_err(|_| "Invalid S3 listing UTF-8".into())
}
fn listing(bytes: &[u8], bucket: &str, prefix: &str) -> Result<Option<String>> {
    let doc = xml(bytes)?;
    let root = doc.root_element();
    if root.tag_name().name() != "ListBucketResult"
        || text(root, "Name")? != bucket
        || text(root, "EncodingType")? != "url"
        || decode(text(root, "Prefix")?)? != prefix
        || text(root, "MaxKeys")? != "1"
    {
        return Err("Unexpected S3 listing envelope or scope".into());
    }
    let truncated = match text(root, "IsTruncated")? {
        "true" => true,
        "false" => false,
        _ => return Err("Invalid S3 listing truncation flag".into()),
    };
    let count = text(root, "KeyCount")?
        .parse::<usize>()
        .map_err(|_| "Invalid S3 KeyCount")?;
    let entries = root
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == "Contents")
        .collect::<Vec<_>>();
    if count > 1
        || count != entries.len()
        || root
            .children()
            .any(|n| n.is_element() && matches!(n.tag_name().name(), "Error" | "CommonPrefixes"))
        || truncated && count == 0
    {
        return Err("Incomplete or over-limit S3 listing".into());
    }
    if let Some(entry) = entries.first() {
        let key = decode(text(*entry, "Key")?)?;
        if !valid_key(&key) || !key.starts_with(prefix) {
            return Err(
                "Listed key escaped the requested scope or cannot be represented safely".into(),
            );
        }
        Ok(Some(key))
    } else {
        Ok(None)
    }
}
struct Response {
    status: u16,
    code: Option<String>,
    body: Vec<u8>,
    metadata: bool,
    length: Option<u64>,
    content_range: Option<String>,
}
struct Budget {
    started: Instant,
    timeout: Duration,
    calls: usize,
    bytes: usize,
    tls: ureq::tls::TlsConfig,
}
impl Budget {
    fn request(&mut self, method: &str, url: &Url, signer: &Signer<'_>) -> Result<Response> {
        self.request_headers(method, url, signer, BTreeMap::new())
    }
    fn request_headers(
        &mut self,
        method: &str,
        url: &Url,
        signer: &Signer<'_>,
        mut extra: BTreeMap<String, String>,
    ) -> Result<Response> {
        self.calls += 1;
        if self.calls > 512 {
            return Err("S3 probe request budget exceeded".into());
        }
        let remaining = self
            .timeout
            .checked_sub(self.started.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or("S3 probe deadline exceeded")?;
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .tls_config(self.tls.clone())
            .timeout_global(Some(remaining))
            .timeout_connect(Some(remaining.min(Duration::from_secs(5))))
            .max_redirects(0)
            .proxy(None)
            .http_status_as_error(false)
            .build()
            .into();
        let body: &[u8] = if method == "PUT" {
            b"grantline probe\n"
        } else {
            b""
        };
        let range = extra.contains_key("range");
        if method == "PUT" {
            extra.insert("if-none-match".into(), "*".into());
        }
        let headers = signer.sign(
            method,
            url,
            body,
            &chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string(),
            extra,
        );
        // The only write body is fixed and the object key is generated locally, never from a response.
        let mut response = if method == "PUT" {
            let mut req = agent.put(url.as_str());
            for (k, v) in &headers {
                req = req.header(k, v);
            }
            req.send(body)
                .map_err(|_| "S3 probe transport/TLS failure or timeout")?
        } else if method == "DELETE" {
            let mut req = agent.delete(url.as_str());
            for (k, v) in &headers {
                req = req.header(k, v);
            }
            req.call()
                .map_err(|_| "S3 probe cleanup transport/TLS failure or timeout")?
        } else if method == "HEAD" {
            let mut req = agent.head(url.as_str());
            for (k, v) in &headers {
                req = req.header(k, v);
            }
            req.call()
                .map_err(|_| "S3 probe transport/TLS failure or timeout")?
        } else {
            let mut req = agent.get(url.as_str());
            for (k, v) in &headers {
                req = req.header(k, v);
            }
            req.call()
                .map_err(|_| "S3 probe transport/TLS failure or timeout")?
        };
        let status = response.status().as_u16();
        let length = response
            .headers()
            .get("content-length")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());
        let content_range = response
            .headers()
            .get("content-range")
            .and_then(|h| h.to_str().ok())
            .filter(|s| s.len() <= 128)
            .map(str::to_owned);
        let metadata = response
            .headers()
            .get("etag")
            .is_some_and(|v| !v.as_bytes().is_empty() && v.as_bytes().len() <= 512)
            && response
                .headers()
                .get("content-length")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .is_some();
        let code = response
            .headers()
            .get("x-amz-error-code")
            .and_then(|h| h.to_str().ok())
            .map(str::to_owned);
        let mut body = Vec::new();
        if method != "HEAD" {
            response
                .body_mut()
                .as_reader()
                .take(if range && (200..300).contains(&status) {
                    2
                } else {
                    1024 * 1024 + 1
                })
                .read_to_end(&mut body)
                .map_err(|_| "Incomplete S3 response or timeout")?;
            self.bytes += body.len();
            if body.len() > 1024 * 1024 || self.bytes > 16 * 1024 * 1024 {
                return Err("S3 probe response byte budget exceeded".into());
            }
        }
        Ok(Response {
            status,
            code,
            body,
            metadata,
            length,
            content_range,
        })
    }
    fn expired(&self) -> bool {
        self.started.elapsed() >= self.timeout || self.calls > 512 || self.bytes > 16 * 1024 * 1024
    }
}
fn verdict_error(response: &Response) -> Verdict {
    if response.status != 403 {
        return Verdict::Unknown;
    }
    let code = response.code.as_deref().map(str::to_owned).or_else(|| {
        let doc = xml(&response.body).ok()?;
        let root = doc.root_element();
        if root.tag_name().name() != "Error" {
            return None;
        }
        text(root, "Code").ok().map(str::to_owned)
    });
    if code.as_deref() == Some("AccessDenied") {
        Verdict::Deny
    } else {
        Verdict::Unknown
    }
}

#[derive(Debug, Serialize)]
pub struct Check {
    pub step: &'static str,
    pub verdict: Verdict,
    pub status: Option<u16>,
    pub elapsed_ms: u64,
    pub how: String,
}
impl Check {
    fn unknown(step: &'static str, why: &str) -> Self {
        Self {
            step,
            verdict: Verdict::Unknown,
            status: None,
            elapsed_ms: 0,
            how: why.into(),
        }
    }
}
fn measured(
    step: &'static str,
    result: Result<Response>,
    started: Instant,
    valid: impl FnOnce(&Response) -> bool,
) -> (Check, Option<Response>) {
    match result {
        Ok(response) => {
            let verdict = if valid(&response) {
                Verdict::Allow
            } else if step == "CATALOG"
                && response.status == 403
                && serde_json::from_slice::<serde_json::Value>(&response.body)
                    .ok()
                    .is_some_and(|v| {
                        v["error"]["code"] == 403
                            && matches!(
                                v["error"]["type"].as_str(),
                                Some("ForbiddenException" | "AccessDeniedException")
                            )
                    })
            {
                Verdict::Deny
            } else {
                verdict_error(&response)
            };
            let how = match verdict {
                Verdict::Allow => {
                    "Subject-signed sample succeeded; this does not prove access to every object or data row"
                }
                Verdict::Deny => "Explicit AccessDenied from the service",
                Verdict::Unknown => {
                    "Missing object, authentication, invalid response or service failure; access is unverified"
                }
            };
            (
                Check {
                    step,
                    verdict,
                    status: Some(response.status),
                    elapsed_ms: started.elapsed().as_millis() as u64,
                    how: how.into(),
                },
                Some(response),
            )
        }
        Err(_) => (
            Check {
                elapsed_ms: started.elapsed().as_millis() as u64,
                ..Check::unknown(
                    step,
                    "Transport, TLS, response limit or timeout; access is unverified",
                )
            },
            None,
        ),
    }
}
fn range_valid(response: &Response) -> bool {
    (response.status == 206
        && response.body.len() == 1
        && response.length == Some(1)
        && response
            .content_range
            .as_deref()
            .and_then(|r| r.strip_prefix("bytes 0-0/"))
            .and_then(|total| total.parse::<u64>().ok())
            .is_some_and(|total| total > 0))
        || (response.status == 200
            && response.metadata
            && response.length == Some(0)
            && response.body.is_empty())
}
fn range_read(
    budget: &mut Budget,
    base: &Url,
    bucket: &str,
    key: &str,
    signer: &Signer<'_>,
) -> Result<Response> {
    budget.request_headers(
        "GET",
        &object_url(base, bucket, Some(key))?,
        signer,
        BTreeMap::from([("range".into(), "bytes=0-0".into())]),
    )
}
fn metadata_key(location: &str, bucket: &str, prefix: &str) -> Option<String> {
    let rest = location.strip_prefix("s3://")?;
    let (actual_bucket, key) = rest.split_once('/')?;
    (actual_bucket == bucket && valid_key(key) && key.starts_with(prefix)).then(|| key.to_owned())
}

/// Exact requested scopes can be checked before a grant exists. Never consult IAM credentials.
pub fn check(
    adapter: &Adapter,
    subject: &str,
    resource: &str,
    sample: Option<&str>,
    table: Option<&str>,
) -> Result<Vec<Check>> {
    let (bucket, prefix) = target(&Grant::new("s3", subject, resource, "Read"))?;
    let sample = sample
        .filter(|s| !s.is_empty())
        .or_else(|| adapter.probe_objects.get(resource).map(String::as_str));
    if sample.is_some_and(|key| !valid_key(key) || !key.starts_with(&prefix)) {
        return Err("Sample object must be inside the exact requested prefix".into());
    }
    let table = table
        .filter(|s| !s.is_empty())
        .map(|s| {
            let (namespace, table) = s
                .split_once('/')
                .ok_or("Use namespace/table for an Iceberg table")?;
            if [namespace, table].iter().any(|s| {
                s.is_empty()
                    || s.len() > 255
                    || matches!(*s, "." | "..")
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            }) {
                return Err("Invalid Iceberg namespace/table".to_owned());
            }
            Ok((namespace, table))
        })
        .transpose()?;
    let mut checks: Vec<_> = ["LIST", "HEAD", "GET"]
        .into_iter()
        .chain(table.into_iter().flat_map(|_| ["CATALOG", "METADATA GET"]))
        .map(|step| {
            Check::unknown(
                step,
                "No configured subject credential or endpoint; no administrator fallback",
            )
        })
        .collect();
    let setup: Result<_> = (|| {
        if !(1..=120).contains(&adapter.read_timeout_seconds)
            || adapter.probe_region.is_empty()
            || adapter.probe_region.len() > 64
            || !adapter
                .probe_region
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("Invalid S3 probe budget or region".into());
        }
        let base = endpoint(&env(adapter.endpoint_env.as_deref())?)?;
        let credential = adapter
            .probe_credentials
            .get(subject)
            .ok_or("No subject probe credential")?;
        let key = env(credential.key_env.as_deref())?;
        if !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return Err("Invalid subject key".into());
        }
        let secret = env(credential.secret_env.as_deref())?;
        let token = credential
            .session_token_env
            .as_deref()
            .map(|n| env(Some(n)))
            .transpose()?;
        let tls = crate::tls::http(adapter.ca_bundle_env.as_deref())?;
        Ok((base, key, secret, token, tls))
    })();
    let Ok((base, key, secret, token, tls)) = setup else {
        return Ok(checks);
    };
    let signer = Signer {
        key: &key,
        secret: &secret,
        token: token.as_deref(),
        region: &adapter.probe_region,
        service: "s3",
    };
    let mut budget = Budget {
        tls,
        started: Instant::now(),
        timeout: Duration::from_secs(adapter.read_timeout_seconds),
        calls: 0,
        bytes: 0,
    };
    let mut url = object_url(&base, &bucket, None)?;
    url.query_pairs_mut().extend_pairs([
        ("list-type", "2"),
        ("max-keys", "1"),
        ("prefix", prefix.as_str()),
        ("encoding-type", "url"),
    ]);
    let started = Instant::now();
    let (listed, response) = measured("LIST", budget.request("GET", &url, &signer), started, |r| {
        r.status == 200 && listing(&r.body, &bucket, &prefix).is_ok()
    });
    let object = sample.map(str::to_owned).or_else(|| {
        response
            .as_ref()
            .filter(|r| r.status == 200)
            .and_then(|r| listing(&r.body, &bucket, &prefix).ok())
            .flatten()
    });
    checks[0] = listed;
    if let Some(object) = object {
        let started = Instant::now();
        checks[1] = measured(
            "HEAD",
            budget.request("HEAD", &object_url(&base, &bucket, Some(&object))?, &signer),
            started,
            |r| r.status == 200 && r.metadata,
        )
        .0;
        let started = Instant::now();
        checks[2] = measured(
            "GET",
            range_read(&mut budget, &base, &bucket, &object, &signer),
            started,
            range_valid,
        )
        .0;
    } else {
        checks[1] = Check::unknown(
            "HEAD",
            "No in-scope object selected; an empty or denied LIST does not verify reads",
        );
        checks[2] = Check::unknown(
            "GET",
            "No in-scope object selected; an empty or denied LIST does not verify reads",
        );
    }
    if let Some((namespace, table)) = table {
        checks[3] = Check::unknown(
            "CATALOG",
            "SeaweedFS Iceberg REST endpoint is not configured",
        );
        checks[4] = Check::unknown(
            "METADATA GET",
            "Catalog metadata location has not been verified inside the requested S3 scope",
        );
        if let Ok(mut catalog) =
            env(adapter.probe_catalog_endpoint_env.as_deref()).and_then(|s| endpoint(&s))
        {
            catalog
                .path_segments_mut()
                .map_err(|_| "Invalid catalog endpoint")?
                .pop_if_empty()
                .extend([
                    "v1",
                    bucket.as_str(),
                    "namespaces",
                    namespace,
                    "tables",
                    table,
                ]);
            let catalog_signer = Signer {
                service: "s3tables",
                ..signer
            };
            let started = Instant::now();
            let (result, response) = measured(
                "CATALOG",
                budget.request("GET", &catalog, &catalog_signer),
                started,
                |r| {
                    r.status == 200
                        && serde_json::from_slice::<serde_json::Value>(&r.body)
                            .ok()
                            .and_then(|v| {
                                v["metadata-location"]
                                    .as_str()
                                    .and_then(|s| metadata_key(s, &bucket, &prefix))
                            })
                            .is_some()
                },
            );
            let metadata = response
                .filter(|_| result.verdict == Verdict::Allow)
                .and_then(|r| serde_json::from_slice::<serde_json::Value>(&r.body).ok())
                .and_then(|v| {
                    v["metadata-location"]
                        .as_str()
                        .and_then(|s| metadata_key(s, &bucket, &prefix))
                });
            checks[3] = result;
            if let Some(metadata) = metadata {
                let started = Instant::now();
                checks[4] = measured(
                    "METADATA GET",
                    range_read(&mut budget, &base, &bucket, &metadata, &signer),
                    started,
                    range_valid,
                )
                .0;
            }
        }
    }
    Ok(checks)
}
fn list(
    budget: &mut Budget,
    base: &Url,
    bucket: &str,
    prefix: &str,
    signer: &Signer<'_>,
) -> Result<(Verdict, Option<String>)> {
    let mut url = object_url(base, bucket, None)?;
    url.query_pairs_mut().extend_pairs([
        ("list-type", "2"),
        ("max-keys", "1"),
        ("prefix", prefix),
        ("encoding-type", "url"),
    ]);
    let response = budget.request("GET", &url, signer)?;
    if response.status == 200 {
        Ok((Verdict::Allow, listing(&response.body, bucket, prefix)?))
    } else {
        Ok((verdict_error(&response), None))
    }
}
pub fn run(adapter: &Adapter, grants: &[Grant]) -> Vec<Probe> {
    run_with_write(adapter, grants, false)
}
pub fn run_with_write(adapter: &Adapter, grants: &[Grant], write: bool) -> Vec<Probe> {
    let all_unknown = |why: &str| {
        grants
            .iter()
            .map(|g| Probe::new(g, Verdict::Unknown, why))
            .collect::<Vec<_>>()
    };
    if grants.len() > 1000
        || grants
            .iter()
            .map(|g| &g.subject)
            .collect::<BTreeSet<_>>()
            .len()
            > 128
        || !(1..=120).contains(&adapter.read_timeout_seconds)
    {
        return all_unknown("Invalid S3 probe count, subject count or deadline");
    }
    let setup: Result<Url> = (|| {
        if adapter.probe_region.is_empty()
            || adapter.probe_region.len() > 64
            || !adapter
                .probe_region
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("Invalid S3 probe region".into());
        }
        endpoint(&env(adapter.endpoint_env.as_deref())?)
    })();
    let base = match setup {
        Ok(base) => base,
        Err(why) => return all_unknown(&why),
    };
    let tls = match crate::tls::http(adapter.ca_bundle_env.as_deref()) {
        Ok(tls) => tls,
        Err(_) => return all_unknown("S3 probe CA bundle unavailable or invalid"),
    };
    let mut budget = Budget {
        tls,
        started: Instant::now(),
        timeout: Duration::from_secs(adapter.read_timeout_seconds),
        calls: 0,
        bytes: 0,
    };
    let mut out = Vec::new();
    let mut cache: BTreeMap<(String, String), (Verdict, Option<String>)> = BTreeMap::new();
    for g in grants {
        let result: Result<Probe> = (|| {
            let (bucket, prefix) = target(g)?;
            if g.privilege == "Write" && !write {
                return Ok(Probe::new(
                    g,
                    Verdict::Unknown,
                    "S3 Write probe requires --live --write; no object created",
                ));
            }
            let named = adapter
                .probe_credentials
                .get(&g.subject)
                .ok_or("No explicitly configured probe key for this subject")?;
            let key = env(named.key_env.as_deref())?;
            let secret = env(named.secret_env.as_deref())?;
            if !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            {
                return Err("Invalid S3 probe access key characters".into());
            }
            let token = named
                .session_token_env
                .as_deref()
                .map(|name| env(Some(name)))
                .transpose()?;
            let signer = Signer {
                key: &key,
                secret: &secret,
                token: token.as_deref(),
                region: &adapter.probe_region,
                service: "s3",
            };
            if g.privilege == "Write" {
                let key = format!("{prefix}_grantline-probe/{}", uuid::Uuid::new_v4());
                let url = object_url(&base, &bucket, Some(&key))?;
                let put = budget.request("PUT", &url, &signer);
                match put {
                    Ok(r) if (200..=204).contains(&r.status) => {
                        // Cleanup gets a separate bounded deadline so a slow PUT cannot consume it.
                        let mut cleanup = Budget {
                            tls: budget.tls.clone(),
                            started: Instant::now(),
                            timeout: budget.timeout,
                            calls: 0,
                            bytes: 0,
                        };
                        let deleted = cleanup
                            .request("DELETE", &url, &signer)
                            .is_ok_and(|r| (200..=204).contains(&r.status));
                        return Ok(Probe::new(
                            g,
                            Verdict::Allow,
                            &format!(
                                "subject-signed PUT succeeded; {}: s3://{bucket}/{key}; upload permission does not imply delete permission",
                                if deleted {
                                    "probe object deleted"
                                } else {
                                    "cleanup failed; probe object LEFT BEHIND"
                                }
                            ),
                        ));
                    }
                    Ok(r) => {
                        return Ok(Probe::new(
                            g,
                            verdict_error(&r),
                            "conditional unique-object PUT failed; no cleanup attempted for a refused request",
                        ));
                    }
                    Err(_) => {
                        return Ok(Probe::new(
                            g,
                            Verdict::Unknown,
                            &format!(
                                "PUT outcome unknown; inspect possible probe object s3://{bucket}/{key} before cleanup"
                            ),
                        ));
                    }
                }
            }
            let sample = if g.privilege == "Read" {
                adapter.probe_objects.get(&g.resource)
            } else {
                None
            };
            if let Some(key) = sample
                && (!valid_key(key) || !key.starts_with(&prefix))
            {
                return Err(
                    "Configured sample object is outside the requested scope or unsafe".into(),
                );
            }
            let cache_key = (g.subject.clone(), g.resource.clone());
            if sample.is_none() && !cache.contains_key(&cache_key) {
                cache.insert(
                    cache_key.clone(),
                    list(&mut budget, &base, &bucket, &prefix, &signer)?,
                );
            }
            if g.privilege == "List" {
                return Ok(Probe::new(
                    g,
                    cache[&cache_key].0,
                    "subject-signed ListObjectsV2 (max-keys=1); no object contents read",
                ));
            }
            let object=sample.cloned().or_else(||cache.get(&cache_key).and_then(|(_,key)|key.clone())).ok_or("No in-scope object could be selected; absent objects or inability to list are unknown for Read")?;
            let response =
                budget.request("HEAD", &object_url(&base, &bucket, Some(&object))?, &signer)?;
            let verdict = if response.status == 200 && response.metadata {
                Verdict::Allow
            } else {
                verdict_error(&response)
            };
            Ok(Probe::new(
                g,
                verdict,
                if verdict == Verdict::Unknown {
                    "HEAD sample was inconclusive; generic 403/404, authentication or service failure is not an ACL denial"
                } else {
                    "subject-signed HEAD of one in-scope object (metadata only); not proof for every object in the prefix"
                },
            ))
        })();
        out.push(result.unwrap_or_else(|why| Probe::new(g, Verdict::Unknown, &why)));
        if budget.expired() {
            if write {
                out.extend(grants[out.len()..].iter().map(|g| {
                    Probe::new(
                        g,
                        Verdict::Unknown,
                        "S3 probe budget exhausted; no further requests attempted",
                    )
                }));
                return out;
            }
            return all_unknown(
                "S3 probe deadline/request/byte budget exceeded; partial results discarded",
            );
        }
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scope_and_path_keep_literal_encoding() {
        let g = Grant::new("s3", "alice", "bucket:demo/team", "Read");
        let (bucket, prefix) = target(&g).unwrap();
        assert_eq!(prefix, "team/");
        let url = object_url(
            &endpoint("http://localhost:8333/gateway/").unwrap(),
            &bucket,
            Some("team/space +%漢?.txt"),
        )
        .unwrap();
        assert_eq!(
            url.path(),
            "/gateway/demo/team/space%20%2B%25%E6%BC%A2%3F.txt"
        );
        for resource in [
            "bucket:*",
            "bucket:demo/team/*",
            "bucket:demo/a/../b",
            "bucket:../bad",
            "prefix-list:demo/team",
        ] {
            assert!(target(&Grant::new("s3", "a", resource, "Read")).is_err());
        }
        assert!(!valid_key("team/../escape"));
    }
    #[test]
    fn incomplete_or_escaped_listing_is_never_allowed() {
        let make = |key: &str| {
            format!(
                "<ListBucketResult><Name>demo</Name><Prefix>team%2F</Prefix><MaxKeys>1</MaxKeys><EncodingType>url</EncodingType><KeyCount>1</KeyCount><IsTruncated>false</IsTruncated><Contents><Key>{key}</Key></Contents></ListBucketResult>"
            )
        };
        assert_eq!(
            listing(make("team%2Fa%20b").as_bytes(), "demo", "team/").unwrap(),
            Some("team/a b".into())
        );
        assert_eq!(
            listing(make("team%2Fa+b%2Bc%25").as_bytes(), "demo", "team/").unwrap(),
            Some("team/a b+c%".into())
        );
        for key in ["outside/a", "team%2F..%2Fa", "team%ZZa"] {
            assert!(listing(make(key).as_bytes(), "demo", "team/").is_err());
        }
        assert!(listing(b"<ListBucketResult/>", "demo", "team/").is_err());
        let r = Response {
            length: None,
            content_range: None,
            metadata: false,
            status: 403,
            code: None,
            body: b"<Error><Code>SignatureDoesNotMatch</Code></Error>".to_vec(),
        };
        assert_eq!(verdict_error(&r), Verdict::Unknown);
        assert_eq!(
            verdict_error(&Response {
                length: None,
                content_range: None,
                metadata: false,
                status: 403,
                code: None,
                body: b"<Error><Code>AccessDenied</Code></Error>".to_vec()
            }),
            Verdict::Deny
        );
    }
}
