//! One exact direct ACL statement; dispatch failures are uncertain, never retried.
use super::*;
use crate::{config as input, planner};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;

const PRINCIPALS: &str = "SELECT name,toString(id) AS id,storage,'account' AS kind FROM system.users UNION ALL SELECT name,toString(id) AS id,storage,'role' AS kind FROM system.roles LIMIT 10001";
const SESSION: &str = "SELECT currentUser() AS login,toString(serverUUID()) AS server_uuid,version() AS version LIMIT 1";
const RAW_GRANTS: &str = "SELECT user_name,role_name,access_type,access_object,nullIf(database,'') AS database,nullIf(table,'') AS table,nullIf(column,'') AS column,is_partial_revoke,grant_option FROM system.grants LIMIT 10001";

#[derive(Serialize, PartialEq)]
struct State {
    session: Vec<Value>,
    principals: Vec<Value>,
    members: Vec<Value>,
    grants: Vec<Value>,
    tables: Vec<Value>,
    databases: Vec<Value>,
}
fn sorted(mut rows: Vec<Value>) -> Vec<Value> {
    rows.sort_by_cached_key(Value::to_string);
    rows
}
fn literal(s: &str) -> Result<()> {
    if s.is_empty()
        || s.len() > 1024
        || s.chars().any(char::is_control)
        || s.contains(['.', '*', '?', '[', ']', '@'])
    {
        return Err("ClickHouse writes require exact representable literal identifiers".into());
    }
    Ok(())
}
fn table(resource: &str) -> Result<(&str, &str)> {
    let (db, name) = resource
        .strip_prefix("table:")
        .and_then(|r| r.split_once('.'))
        .ok_or("ClickHouse writer requires table:database.table")?;
    literal(db)?;
    literal(name)?;
    if matches!(db, "system" | "information_schema" | "INFORMATION_SCHEMA") {
        return Err("System tables cannot be write targets".into());
    }
    Ok((db, name))
}
fn string(s: &str) -> String {
    format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
}
fn scope(resource: &str) -> Result<(&str, Option<&str>)> {
    if let Some(db) = resource.strip_prefix("db:") {
        literal(db)?;
        if matches!(db, "system" | "information_schema" | "INFORMATION_SCHEMA") {
            return Err("System databases cannot be write targets".into());
        }
        return Ok((db, None));
    }
    let (db, t) = table(resource)?;
    Ok((db, Some(t)))
}
fn allowed(adapter: &Adapter, resource: &str) -> bool {
    if resource.starts_with("db:") {
        adapter.clickhouse_write_databases.contains(resource)
    } else {
        adapter.clickhouse_write_tables.contains(resource)
    }
}
fn target_sql(g: &Grant) -> Result<String> {
    let (db, t) = scope(&g.resource)?;
    if !matches!(g.privilege.as_str(), "SELECT" | "INSERT") {
        return Err("ClickHouse writer supports exact SELECT or INSERT only".into());
    }
    Ok(format!(
        "{}.{}",
        quoted(db),
        t.map(quoted).unwrap_or_else(|| "*".into())
    ))
}
fn identity(s: &Value) -> bool {
    s.as_str()
        .is_some_and(|s| !s.is_empty() && s != "00000000-0000-0000-0000-000000000000")
}
fn state(http: &Http, adapter: &Adapter) -> Result<State> {
    let tables = &adapter.clickhouse_write_tables;
    if !matches!(
        http.query::<Visibility>(VISIBILITY_SQL)?.as_slice(),
        [Visibility { result: 1 }]
    ) {
        return Err("Writer requires complete SHOW ACCESS and SHOW DATABASES visibility".into());
    }
    let session: Vec<Value> = http.query(SESSION)?;
    if session.len() != 1
        || session[0]["login"] != http.user
        || !identity(&session[0]["server_uuid"])
    {
        return Err("ClickHouse authenticated identity or server UUID does not match".into());
    }
    let principals: Vec<Value> = sorted(http.query(PRINCIPALS)?);
    let mut kinds = BTreeMap::new();
    for p in &principals {
        let name = p["name"].as_str().ok_or("Invalid principal catalog")?;
        let kind = p["kind"]
            .as_str()
            .filter(|s| matches!(*s, "role" | "account"))
            .ok_or("Invalid principal kind")?;
        if !identity(&p["id"]) || kinds.contains_key(name) {
            return Err("Ambiguous principal name or UUID".into());
        }
        register(name, kind, &mut kinds)?;
    }
    let mut filters = tables
        .iter()
        .map(|r| {
            let (db, t) = table(r)?;
            Ok(format!("(database={} AND name={})", string(db), string(t)))
        })
        .collect::<Result<Vec<_>>>()?;
    for resource in &adapter.clickhouse_write_databases {
        let (db, t) = scope(resource)?;
        if t.is_some() {
            return Err("clickhouse_write_databases requires exact db:name entries".into());
        }
        filters.push(format!("database={}", string(db)));
    }
    let selected = sorted(http.query::<Value>(&format!("SELECT database,name,toString(uuid) AS id,engine,create_table_query FROM system.tables WHERE {} LIMIT 10001", if filters.is_empty() { "0".into() } else { filters.join(" OR ") }))?);
    if selected.iter().any(|t| !identity(&t["id"])) {
        return Err("Selected ClickHouse objects require nonzero UUIDs".into());
    }
    for resource in tables {
        let (db, name) = table(resource)?;
        if !selected.iter().any(|t| {
            t["database"] == db
                && t["name"] == name
                && matches!(t["engine"].as_str(), Some("Memory" | "MergeTree"))
        }) {
            return Err(
                "Every allowed table must exist with a UUID and Memory/MergeTree engine".into(),
            );
        }
    }
    let databases = sorted(http.query::<Value>(
        "SELECT name,toString(uuid) AS id,engine FROM system.databases LIMIT 10001",
    )?);
    for r in tables.iter().chain(&adapter.clickhouse_write_databases) {
        let (db, _) = scope(r)?;
        if !databases
            .iter()
            .any(|d| d["name"] == db && d["engine"] == "Atomic" && identity(&d["id"]))
        {
            return Err("ClickHouse writer requires existing UUID-backed Atomic databases".into());
        }
    }
    Ok(State {
        session,
        principals,
        members: sorted(http.query(ROLE_SQL)?),
        grants: sorted(http.query(RAW_GRANTS)?),
        tables: selected,
        databases,
    })
}
fn ancestors(s: &State, user: &str) -> BTreeSet<String> {
    let mut parents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for m in &s.members {
        if let (Some(subject), Some(role)) = (
            m["user_name"].as_str().or(m["role_name"].as_str()),
            m["granted_role_name"].as_str(),
        ) {
            parents.entry(subject).or_default().push(role);
        }
    }
    let mut seen = BTreeSet::new();
    let mut todo = vec![user.to_owned()];
    while let Some(name) = todo.pop() {
        if seen.insert(name.clone()) {
            todo.extend(
                parents
                    .get(name.as_str())
                    .into_iter()
                    .flatten()
                    .map(|r| (*r).to_owned()),
            );
        }
    }
    seen
}
fn recipient<'a>(
    s: &'a State,
    subject: &str,
    protected: &BTreeSet<String>,
    adapter: &Adapter,
) -> Result<&'a Value> {
    let p = s
        .principals
        .iter()
        .find(|p| p["name"] == subject)
        .ok_or("Recipient must already exist")?;
    if p["storage"] != "local_directory" || protected.contains(subject) {
        return Err(
            "Recipient must be in local_directory and cannot be the writer or its role ancestors"
                .into(),
        );
    }
    for r in s
        .grants
        .iter()
        .filter(|r| r["user_name"] == subject || r["role_name"] == subject)
    {
        if r["is_partial_revoke"] != 0
            || r["grant_option"] != 0
            || !r["column"].is_null()
            || r["access_object"] != ""
            || !matches!(r["access_type"].as_str(), Some("SELECT" | "INSERT"))
            || r["database"].as_str().is_none_or(|s| literal(s).is_err())
            || match r["table"].as_str() {
                Some(t) => literal(t).is_err(),
                None => {
                    !r["table"].is_null()
                        || !r["database"].as_str().is_some_and(|db| {
                            adapter
                                .clickhouse_write_databases
                                .contains(&format!("db:{db}"))
                        })
                }
            }
        {
            return Err(
                "Recipient has broad, delegated, column, partial or unsupported direct ACLs".into(),
            );
        }
    }
    Ok(p)
}
fn atom(g: &Grant, p: &Value, grant_option: u8) -> Result<Value> {
    let (db, t) = scope(&g.resource)?;
    Ok(
        json!({"user_name": if p["kind"] == "account" { json!(g.subject) } else { Value::Null }, "role_name": if p["kind"] == "role" { json!(g.subject) } else { Value::Null }, "access_type":g.privilege,"access_object":"","database":db,"table":t,"column":Value::Null,"is_partial_revoke":0,"grant_option":grant_option}),
    )
}
fn report(
    loaded: &input::Loaded,
    system: &str,
    s: &State,
    observed: &Observation,
    issuer: &str,
) -> Result<planner::Report> {
    let adapter = &loaded.config.adapters[system];
    let intent = input::Intent {
        grants: loaded
            .intent
            .grants
            .iter()
            .filter(|g| g.system == system)
            .cloned()
            .collect(),
        managed: loaded.intent.managed.clone(),
        managed_systems: loaded
            .intent
            .managed_systems
            .iter()
            .filter(|s| *s == system)
            .cloned()
            .collect(),
        naming_synonyms: vec![],
    };
    if intent.grants.len() > 1000 {
        return Err("ClickHouse writer intent exceeds 1000 grants".into());
    }
    let protected = ancestors(s, issuer);
    // Changing between DB and table grants can silently coalesce/erase explicit ACLs.
    let mut levels: BTreeMap<(&str, &str, &str), BTreeSet<bool>> = BTreeMap::new();
    for g in intent.grants.iter().chain(&observed.grants).filter(|g| {
        intent.managed.contains(&g.subject) || intent.grants.iter().any(|i| i.subject == g.subject)
    }) {
        if let Ok((db, t)) = scope(&g.resource) {
            levels
                .entry((&g.subject, &g.privilege, db))
                .or_default()
                .insert(t.is_none());
        }
    }
    if levels.values().any(|v| v.len() > 1) {
        return Err("Overlapping held/declared DB and table privileges require separate manual reconciliation".into());
    }
    for g in &intent.grants {
        // Retain declared memberships read-only; any planned membership change is refused below.
        if g.resource.starts_with("role:") && g.privilege == "MEMBER" {
            continue;
        }
        target_sql(g)?;
        if !allowed(adapter, &g.resource) {
            return Err("ClickHouse writes require a literal table or database allowlist for the exact scope".into());
        }
        recipient(s, &g.subject, &protected, adapter)?;
    }
    if observed.unknown.iter().any(|u| {
        u.subjects.is_empty()
            || u.subjects.iter().any(|s| {
                intent.managed.contains(s) || intent.grants.iter().any(|g| &g.subject == s)
            })
    }) {
        return Err("Incomplete ClickHouse recipient catalog; unknown is not empty".into());
    }
    let mut plan = planner::build(
        &intent,
        &observed.grants,
        &observed.unknown,
        &loaded.kinds,
        vec![],
    );
    if !plan.commands_complete || plan.changes.len() > 1 {
        return Err(
            "ClickHouse writer requires at most one change; no multi-statement rollback exists"
                .into(),
        );
    }
    for c in &mut plan.changes {
        let target = target_sql(&c.grant)?;
        if !allowed(adapter, &c.grant.resource) {
            return Err("ClickHouse writes require a literal table or database allowlist for the exact scope".into());
        }
        recipient(s, &c.grant.subject, &protected, adapter)?;
        let actor = s
            .principals
            .iter()
            .find(|p| p["name"] == issuer && p["kind"] == "account")
            .ok_or("Writer principal disappeared")?;
        let mut authority = c.grant.clone();
        authority.subject = issuer.into();
        if !s.grants.contains(&atom(&authority, actor, 1)?) {
            return Err(
                "Writer must directly hold exact-scope GRANT OPTION for the changed privilege"
                    .into(),
            );
        }
        let (verb, to) = match c.action.as_str() {
            "grant" => ("GRANT", "TO"),
            "revoke" => ("REVOKE", "FROM"),
            _ => return Err("Unsupported ACL action".into()),
        };
        c.cmd = Some(format!(
            "{verb} {} ON {target} {to} {};",
            c.grant.privilege,
            quoted(&c.grant.subject)
        ));
    }
    Ok(plan)
}
fn checked(http: &Http, loaded: &input::Loaded, system: &str) -> Result<(State, planner::Report)> {
    let adapter = &loaded.config.adapters[system];
    if adapter.clickhouse_write_tables.len() + adapter.clickhouse_write_databases.len() > 128 {
        return Err("ClickHouse write allowlists exceed 128 entries".into());
    }
    let before = state(http, adapter)?;
    let observed = observe_http(http, system)?;
    let after = state(http, adapter)?;
    if before != after {
        return Err("ClickHouse catalog changed during observation; preview again".into());
    }
    let plan = report(loaded, system, &after, &observed, &http.user)?;
    Ok((after, plan))
}
fn execute(http: &Http, sql: &str) -> Result<()> {
    let remaining = http
        .timeout
        .checked_sub(http.started.elapsed())
        .filter(|d| !d.is_zero())
        .ok_or("ClickHouse write deadline exceeded before dispatch; no statement sent")?;
    let mut url = http.url.clone();
    url.query_pairs_mut().extend_pairs([
        ("readonly", "0"),
        ("wait_end_of_query", "1"),
        ("max_execution_time", "30"),
        ("timeout_before_checking_execution_speed", "0"),
    ]);
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(remaining))
        .timeout_connect(Some(remaining.min(Duration::from_secs(5))))
        .max_redirects(0)
        .proxy(None)
        .http_status_as_error(false)
        .build()
        .into();
    let unknown = "ClickHouse write outcome unknown after dispatch; inspect direct ACLs before any retry or inverse; no automatic rollback";
    let mut response = agent
        .post(url.as_str())
        .header("X-ClickHouse-User", &http.user)
        .header("X-ClickHouse-Key", &http.key)
        .send(sql.as_bytes())
        .map_err(|_| unknown)?;
    if response.status().as_u16() != 200
        || response
            .headers()
            .get("X-ClickHouse-Exception-Code")
            .is_some_and(|c| c.as_bytes() != b"0")
    {
        return Err(unknown.into());
    }
    let mut body = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(MAX_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|_| unknown)?;
    if body.len() as u64 > MAX_BYTES || !body.iter().all(u8::is_ascii_whitespace) {
        return Err(unknown.into());
    }
    Ok(())
}
#[derive(Serialize)]
pub struct Receipt {
    pub system: String,
    pub plan_id: String,
    pub applied: bool,
    pub changed: bool,
    pub effective_access_verified: bool,
    pub single_statement_only: bool,
    pub database_changes_include_future_tables: bool,
    pub changes: Vec<planner::Change>,
}
pub fn apply(path: &Path, system: &str, write: bool, expected: Option<&str>) -> Result<Receipt> {
    if write && expected.is_none() {
        return Err("ClickHouse --write requires a reviewed --expect PLAN_ID".into());
    }
    let path = std::path::absolute(path).map_err(|_| "Cannot resolve config path")?;
    let (loaded, config_bytes, intent_bytes) = input::load_writer(&path)?;
    let adapter = loaded
        .config
        .adapters
        .get(system)
        .filter(|a| a.typ(system) == "clickhouse" && a.kind(system) == "clickhouse")
        .ok_or("Native ClickHouse adapter required")?;
    let key = adapter
        .admin_url_env
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or("ClickHouse admin_url_env write credential is not configured")?;
    let raw = std::env::var(key).map_err(|_| "ClickHouse admin credential is unavailable")?;
    let url = Url::parse(&raw).map_err(|_| "Invalid ClickHouse admin URL")?;
    if url.username().is_empty() {
        return Err("ClickHouse admin URL requires an explicit authenticated user".into());
    }
    let http = Http::from_env(key, adapter.read_timeout_seconds, Instant::now())?;
    let (state, plan) = checked(&http, &loaded, system)?;
    let value = serde_json::to_vec(&json!({"format":"clickhouse-single-acl-v2","path":path,"system":system,"endpoint":http.url.as_str(),"state":state,"changes":plan.changes})).map_err(|_| "Cannot bind ClickHouse plan")?;
    let mut hash = Sha256::new();
    for part in [&config_bytes, &intent_bytes, &value] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    let plan_id = format!("{:x}", hash.finalize());
    if write && expected != Some(plan_id.as_str()) {
        return Err(
            "Reviewed ClickHouse plan is stale or belongs to another source/session; preview again"
                .into(),
        );
    }
    if write && !plan.changes.is_empty() {
        let now = self::state(&http, adapter)?;
        let intent_path = input::relative(&loaded.base, &loaded.config.intent)?;
        if state != now
            || input::writer_file(&path).ok().as_deref() != Some(&config_bytes)
            || input::writer_file(&intent_path).ok().as_deref() != Some(&intent_bytes)
        {
            return Err(
                "ClickHouse source/catalog changed before dispatch; no statement sent".into(),
            );
        }
        let c = &plan.changes[0];
        let p = recipient(
            &state,
            &c.grant.subject,
            &ancestors(&state, &http.user),
            adapter,
        )?;
        let row = atom(&c.grant, p, 0)?;
        let mut wanted = state;
        if c.action == "grant" {
            wanted.grants.push(row);
        } else {
            wanted.grants.retain(|r| r != &row);
        }
        wanted.grants = sorted(wanted.grants);
        execute(&http, c.cmd.as_deref().ok_or("Missing fixed SQL")?)?;
        let unknown = "ClickHouse write outcome unknown: post-check failed; inspect ACLs before retry or inverse; no automatic rollback";
        let (after, remaining) = checked(&http, &loaded, system).map_err(|_| unknown)?;
        if wanted != after || !remaining.changes.is_empty() {
            return Err(unknown.into());
        }
    }
    Ok(Receipt {
        system: system.into(),
        plan_id,
        applied: write && !plan.changes.is_empty(),
        changed: !plan.changes.is_empty(),
        effective_access_verified: false,
        single_statement_only: true,
        database_changes_include_future_tables: plan
            .changes
            .iter()
            .any(|c| c.grant.resource.starts_with("db:")),
        changes: plan.changes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_exact_table_leaf_rights_and_quoted_identifiers() {
        let g = Grant::new("ch", "user", "table:odd`db.odd\\table", "SELECT");
        assert_eq!(target_sql(&g).unwrap(), "`odd\\`db`.`odd\\\\table`");
        assert_eq!(string("a'\\b"), "'a\\'\\\\b'");
        for r in [
            "db:demo",
            "table:demo.*",
            "table:demo.t?",
            "table:system.users",
            "role:group",
            "table:demo.a.b",
        ] {
            assert!(table(r).is_err(), "{r}");
        }
        assert!(target_sql(&Grant::new("ch", "user", "table:demo.t", "ALL")).is_err());
        assert_eq!(
            target_sql(&Grant::new("ch", "user", "db:odd`db", "SELECT")).unwrap(),
            "`odd\\`db`.*"
        );
        for r in ["db:system", "db:*", "db:demo.*", "global:*", "db:demo?"] {
            assert!(scope(r).is_err(), "{r}");
        }
    }
}
