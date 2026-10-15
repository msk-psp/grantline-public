//! Explicit read-only catalog observation. No caller-supplied SQL or write credential.
use crate::{
    Result,
    config::Adapter,
    model::{Grant, Kinds, Unobserved},
    planner::Finding,
};
use serde::{Deserialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io::Read,
    time::{Duration, Instant},
};
use url::Url;

const MAX_ROWS: usize = 10_000;
const MAX_BYTES: u64 = 16 * 1024 * 1024;
const ROLE_SQL: &str = "SELECT user_name, role_name, granted_role_name, with_admin_option FROM system.role_grants LIMIT 10001";
const GRANT_SQL: &str = "SELECT user_name, role_name, access_type, access_object, database, table, column, is_partial_revoke, grant_option FROM system.grants LIMIT 10001";
const DATABASE_SQL: &str = "SELECT name FROM system.databases LIMIT 10001";
const VISIBILITY_SQL: &str = "CHECK GRANT SHOW ACCESS, SHOW DATABASES ON *.*";

struct Http {
    url: Url,
    user: String,
    key: String,
    started: Instant,
    timeout: Duration,
}
#[derive(Deserialize)]
struct Envelope<T> {
    data: Vec<T>,
    rows: usize,
    #[serde(default)]
    exception: Option<serde_json::Value>,
    #[serde(default)]
    rows_before_limit_at_least: Option<u64>,
}
impl Http {
    fn from_config(adapter: &Adapter) -> Result<Self> {
        let name = adapter
            .url_env
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or("ClickHouse url_env read credential is not configured")?;
        let raw = std::env::var(name).map_err(|_| "ClickHouse read credential is unavailable")?;
        let mut url = Url::parse(&raw).map_err(|_| "Invalid ClickHouse reader URL")?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("ClickHouse reader URL must use HTTP(S), with no query or fragment".into());
        }
        let decode = |s: &str| {
            percent_encoding::percent_decode_str(s)
                .decode_utf8()
                .map(|s| s.into_owned())
                .map_err(|_| "Invalid reader URL encoding".to_owned())
        };
        let user = decode(url.username())?;
        let key = decode(url.password().unwrap_or(""))?;
        if [&user, &key]
            .iter()
            .any(|s| s.chars().any(char::is_control))
        {
            return Err("Invalid reader credential characters".into());
        }
        url.set_username("").map_err(|_| "Invalid reader URL")?;
        url.set_password(None).map_err(|_| "Invalid reader URL")?;
        let timeout = adapter.read_timeout_seconds;
        if !(1..=120).contains(&timeout) {
            return Err("read_timeout_seconds must be between 1 and 120".into());
        }
        Ok(Self {
            url,
            user: if user.is_empty() {
                "default".into()
            } else {
                user
            },
            key,
            started: Instant::now(),
            timeout: Duration::from_secs(timeout),
        })
    }
    fn query<T: DeserializeOwned>(&self, sql: &str) -> Result<Vec<T>> {
        let remaining = self
            .timeout
            .checked_sub(self.started.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or("ClickHouse observation timed out")?;
        let mut url = self.url.clone();
        url.query_pairs_mut().extend_pairs([
            ("query", sql),
            ("default_format", "JSON"),
            // readonly=2 permits per-query limits but still forbids writes.
            ("readonly", "2"),
            ("max_execution_time", "30"),
            ("timeout_before_checking_execution_speed", "0"),
            ("max_rows_to_read", "100000"),
            ("max_bytes_to_read", "16777216"),
            ("read_overflow_mode", "throw"),
            ("max_result_rows", "10001"),
            ("max_result_bytes", "16777216"),
            ("result_overflow_mode", "throw"),
            ("wait_end_of_query", "1"),
        ]);
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(remaining))
            .timeout_connect(Some(remaining.min(Duration::from_secs(5))))
            .max_redirects(0)
            .proxy(None)
            .http_status_as_error(false)
            .build()
            .into();
        // Do not format transport errors, response bodies or URLs: any can echo secrets.
        let mut response = agent
            .get(url.as_str())
            .header("X-ClickHouse-User", &self.user)
            .header("X-ClickHouse-Key", &self.key)
            .header("Accept", "application/json")
            .call()
            .map_err(|_| "ClickHouse transport/TLS failure or timeout")?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(format!(
                "ClickHouse catalog HTTP {status}; response body withheld"
            ));
        }
        if response
            .headers()
            .get("X-ClickHouse-Exception-Code")
            .is_some_and(|c| c.as_bytes() != b"0")
        {
            return Err("ClickHouse reported a query exception; response body withheld".into());
        }
        let mut bytes = vec![];
        response
            .body_mut()
            .as_reader()
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "Incomplete ClickHouse response or timeout")?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err("ClickHouse response exceeded byte limit".into());
        }
        let result: Envelope<T> = serde_json::from_slice(&bytes)
            .map_err(|_| "Invalid or incomplete ClickHouse catalog JSON/schema")?;
        if result.exception.is_some()
            || result
                .rows_before_limit_at_least
                .is_some_and(|n| n > MAX_ROWS as u64)
            || result.rows != result.data.len()
            || result.data.len() > MAX_ROWS
        {
            return Err("ClickHouse catalog is incomplete or exceeded row limit".into());
        }
        Ok(result.data)
    }
}
#[derive(Deserialize)]
struct RoleRow {
    #[serde(deserialize_with = "nullable")]
    user_name: Option<String>,
    #[serde(deserialize_with = "nullable")]
    role_name: Option<String>,
    granted_role_name: String,
    with_admin_option: u8,
}
#[derive(Deserialize)]
struct GrantRow {
    #[serde(deserialize_with = "nullable")]
    user_name: Option<String>,
    #[serde(deserialize_with = "nullable")]
    role_name: Option<String>,
    access_type: String,
    access_object: String,
    #[serde(deserialize_with = "nullable")]
    database: Option<String>,
    #[serde(deserialize_with = "nullable")]
    table: Option<String>,
    #[serde(deserialize_with = "nullable")]
    column: Option<String>,
    is_partial_revoke: u8,
    grant_option: u8,
}
fn nullable<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}
#[derive(Deserialize)]
struct DatabaseRow {
    name: String,
}
#[derive(Deserialize)]
struct Visibility {
    result: u8,
}
#[derive(Default)]
pub struct Observation {
    pub grants: BTreeSet<Grant>,
    pub findings: Vec<Finding>,
    pub unknown: Vec<Unobserved>,
    pub kinds: BTreeMap<String, String>,
}
fn principal(
    user: Option<String>,
    role: Option<String>,
    kinds: &mut BTreeMap<String, String>,
) -> Result<String> {
    let (subject, kind) = match (user, role) {
        (Some(u), None) if !u.is_empty() => (u, "account"),
        (None, Some(r)) if !r.is_empty() => (r, "role"),
        _ => return Err("Invalid catalog principal".into()),
    };
    register(&subject, kind, kinds)?;
    Ok(subject)
}
fn register(name: &str, kind: &str, kinds: &mut BTreeMap<String, String>) -> Result<()> {
    if name.is_empty() || name.chars().any(char::is_control) {
        return Err("Invalid catalog name".into());
    }
    if kinds.get(name).is_some_and(|k| k != kind) {
        return Err("User and role names collide in the permission model".into());
    }
    kinds.insert(name.into(), kind.into());
    Ok(())
}
fn flag(v: u8) -> Result<bool> {
    match v {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err("Invalid catalog flag".into()),
    }
}
fn quoted(s: &str) -> String {
    format!("`{}`", s.replace('\\', "\\\\").replace('`', "\\`"))
}

// Older system.grants versions erase the prefix wildcard. SHOW GRANTS preserves it.
fn check_show_scope(line: &str) -> Result<()> {
    let mut masked = String::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if matches!(c, '`' | '\'' | '"') {
            masked.push_str(" identifier ");
            let mut ended = false;
            while let Some(d) = chars.next() {
                if d == '\\' {
                    chars.next().ok_or("Invalid SHOW GRANTS quoting")?;
                } else if d == c {
                    if chars.peek() == Some(&c) {
                        chars.next();
                        continue;
                    }
                    ended = true;
                    break;
                }
            }
            if !ended {
                return Err("Invalid SHOW GRANTS quoting".into());
            }
        } else if matches!(c, '.' | '*' | ',' | '(' | ')' | ';') {
            masked.push(' ');
            masked.push(c);
            masked.push(' ');
        } else {
            masked.push(c);
        }
    }
    let tokens: Vec<_> = masked.split_whitespace().collect();
    if !matches!(tokens.first(), Some(&"GRANT" | &"REVOKE")) {
        return Err("Unrecognized SHOW GRANTS result".into());
    }
    for on in tokens
        .iter()
        .enumerate()
        .filter_map(|(i, t)| (*t == "ON").then_some(i))
    {
        let end = tokens
            .iter()
            .enumerate()
            .skip(on + 1)
            .find(|(_, t)| matches!(**t, "," | "TO" | "FROM"))
            .map(|(i, _)| i)
            .ok_or("Invalid SHOW GRANTS scope")?;
        let scope = &tokens[on + 1..end];
        if scope.contains(&"*")
            && scope != ["*"]
            && !(scope.len() == 3 && scope[1] == "." && scope[2] == "*")
        {
            return Err("Wildcard-prefix grants cannot be represented; catalog is unknown".into());
        }
    }
    Ok(())
}
fn observe_inner(adapter: &Adapter, system: &str) -> Result<Observation> {
    let http = Http::from_config(adapter)?;
    if !matches!(
        http.query::<Visibility>(VISIBILITY_SQL)?.as_slice(),
        [Visibility { result: 1 }]
    ) {
        return Err("Observer requires global SHOW ACCESS and SHOW DATABASES to establish complete catalog visibility".into());
    }
    let roles = http.query::<RoleRow>(ROLE_SQL)?;
    let permissions = http.query::<GrantRow>(GRANT_SQL)?;
    let databases: Vec<String> = http
        .query::<DatabaseRow>(DATABASE_SQL)?
        .into_iter()
        .map(|r| r.name)
        .collect();
    let mut out = Observation::default();
    let mut blind = BTreeSet::new();
    let mut dependants: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for r in roles {
        let subject = principal(r.user_name, r.role_name, &mut out.kinds)?;
        register(&r.granted_role_name, "role", &mut out.kinds)?;
        if flag(r.with_admin_option)? {
            out.findings.push(Finding::new(system,"role admin option not modeled","Role membership has ADMIN OPTION; delegation is not represented by the permission atom.".into(),vec![subject.clone(),r.granted_role_name.clone()]));
        }
        dependants
            .entry(r.granted_role_name.clone())
            .or_default()
            .insert(subject.clone());
        out.grants.insert(Grant::new(
            system,
            &subject,
            &format!("role:{}", r.granted_role_name),
            "MEMBER",
        ));
    }
    let kinds = Kinds::from([(system.into(), "clickhouse".into())]);
    for r in permissions {
        let subject = principal(r.user_name, r.role_name, &mut out.kinds)?;
        let db = r.database.unwrap_or_default();
        let table = r.table.unwrap_or_default();
        let partial = flag(r.is_partial_revoke)?;
        let grant_option = flag(r.grant_option)?;
        if r.access_type.is_empty() {
            return Err("Invalid empty catalog privilege".into());
        }
        if partial
            || r.column.is_some_and(|s| !s.is_empty())
            || !r.access_object.is_empty()
            || db.contains(['.', '*', '?', '['])
            || table.contains(['*', '?', '['])
            || (db.is_empty() && !table.is_empty())
        {
            blind.insert(subject);
            continue;
        }
        if grant_option {
            out.findings.push(Finding::new(
                system,
                "grant option not modeled",
                "Privilege has GRANT OPTION; delegation is not represented by the permission atom."
                    .into(),
                vec![subject.clone()],
            ));
        }
        let resource = if db.is_empty() {
            "global:*".into()
        } else if table.is_empty() {
            format!("db:{db}")
        } else {
            format!("table:{db}.{table}")
        };
        out.grants
            .insert(Grant::new(system, &subject, &resource, &r.access_type).normalized(&kinds));
    }
    // Bounded batches avoid one network walk per permission and excessively long URLs.
    let names: Vec<_> = out.kinds.keys().cloned().collect();
    for names in names.chunks(32) {
        let sql = format!(
            "SHOW GRANTS FOR {}",
            names
                .iter()
                .map(|s| quoted(s))
                .collect::<Vec<_>>()
                .join(", ")
        );
        for row in http.query::<BTreeMap<String, String>>(&sql)? {
            if row.len() != 1 {
                return Err("Invalid SHOW GRANTS row".into());
            }
            check_show_scope(row.values().next().ok_or("Missing SHOW GRANTS row")?)?;
        }
    }
    let mut pending: VecDeque<_> = blind.iter().cloned().collect();
    while let Some(subject) = pending.pop_front() {
        for parent in dependants.get(&subject).into_iter().flatten() {
            if blind.insert(parent.clone()) {
                pending.push_back(parent.clone());
            }
        }
    }
    for subject in blind {
        out.unknown.push(Unobserved{system:system.into(),prefixes:vec![String::new()],subjects:BTreeSet::from([subject.clone()]),note:"Column grants, partial revokes, parameterized/ambiguous scopes or inherited unknown access cannot be represented".into()});
        out.grants.retain(|g| g.subject != subject);
    }
    out.findings
        .extend(stale_findings(system, &out.grants, &databases));
    Ok(out)
}
pub fn observe(adapter: &Adapter, system: &str) -> Observation {
    match observe_inner(adapter, system) {
        Ok(out) => out,
        Err(note) => Observation {
            findings: vec![Finding::new(
                system,
                "system could not be read",
                format!("{note}. Everything in this instance is unknown, not empty."),
                vec![system.into()],
            )],
            unknown: vec![Unobserved {
                system: system.into(),
                prefixes: vec![String::new()],
                subjects: BTreeSet::new(),
                note,
            }],
            ..Default::default()
        },
    }
}
pub fn stale_findings(
    system: &str,
    grants: &BTreeSet<Grant>,
    databases: &[String],
) -> Vec<Finding> {
    let mut stale: BTreeMap<(&str, &str), Vec<String>> = BTreeMap::new();
    for g in grants {
        if let Some(db) = g.resource.strip_prefix("db:")
            && !databases.iter().any(|d| d == db)
        {
            stale
                .entry((&g.subject, &g.resource))
                .or_default()
                .push(g.privilege.clone());
        }
    }
    let mut out = vec![];
    for ((subject, resource), mut privs) in stale {
        privs.sort();
        let shown: Vec<_> = privs.iter().take(6).cloned().collect();
        let more = if privs.len() > 6 {
            format!(" (+{} more)", privs.len() - 6)
        } else {
            String::new()
        };
        let mut entities = vec![subject.into(), resource.into()];
        entities.extend(shown.clone());
        out.push(Finding::new(system,"stale grants on dropped database",format!("{subject} still holds {} privilege(s) on {resource} but the database is gone: {}{more}. ClickHouse keeps them; they re-apply if the name returns. Revoke by name.",privs.len(),shown.join(", ")),entities));
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn show_scope_keeps_global_wildcards_but_rejects_prefixes_and_bad_quoting() {
        for s in [
            "GRANT SELECT ON *.* TO demo",
            "GRANT TABLE ENGINE ON * TO default WITH GRANT OPTION",
            "GRANT SELECT ON `a b`.* TO `a``b`",
            "GRANT SELECT ON `a``b`.* TO demo",
            "GRANT SELECT ON db.table TO demo",
            "GRANT SHOW DATABASES ON *.*, SELECT ON system.grants, SHOW ACCESS ON *.* TO observer",
            "GRANT `r ON x` TO demo",
            "REVOKE SELECT ON db.table FROM demo",
        ] {
            assert!(check_show_scope(s).is_ok(), "{s}");
        }
        for s in [
            "GRANT SELECT ON foo*.* TO demo",
            "GRANT SELECT ON db.foo* TO demo",
            "GRANT SELECT ON `foo`*.* TO demo",
            "GRANT SELECT ON db.*, INSERT ON prefix*.* TO demo",
            "GRANT SELECT ON `unfinished",
            "garbage",
        ] {
            assert!(check_show_scope(s).is_err(), "{s}");
        }
    }
}
