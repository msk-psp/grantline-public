//! One exact direct ACL statement; dispatch failures are uncertain, never retried.
mod privileges;
use super::*;
use crate::{config as input, planner};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;

const PRINCIPALS: &str = "SELECT name,toString(id) AS id,storage,'account' AS kind FROM system.users UNION ALL SELECT name,toString(id) AS id,storage,'role' AS kind FROM system.roles LIMIT 10001";
const SESSION: &str = "SELECT currentUser() AS login,toString(serverUUID()) AS server_uuid,version() AS version LIMIT 1";
const RAW_GRANTS: &str = "SELECT user_name,role_name,access_type,access_object,nullIf(database,'') AS database,nullIf(table,'') AS table,nullIf(column,'') AS column,is_partial_revoke,grant_option FROM system.grants LIMIT 10001";
const MEMBER_ROLES: &str = "SELECT user_name,role_name,granted_role_name,toString(granted_role_id) AS granted_role_id,granted_role_is_default,with_admin_option FROM system.role_grants LIMIT 10001";
const USER_POLICIES: &str = "SELECT name,default_roles_all,default_roles_list,default_roles_except,grantees_any,grantees_list,grantees_except FROM system.users LIMIT 10001";

#[derive(Serialize, PartialEq)]
struct State {
    session: Vec<Value>,
    principals: Vec<Value>,
    members: Vec<Value>,
    grants: Vec<Value>,
    tables: Vec<Value>,
    databases: Vec<Value>,
    user_policies: Vec<Value>,
    privilege_tree: Vec<Value>,
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
    let p = g.privilege.as_str();
    // report() separately requires server-defined leaf privileges and explicit authorization.
    if p.is_empty()
        || p.len() > 128
        || p == "ALL"
        || !p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b' ')
    {
        return Err("ClickHouse writer requires an exact server-defined leaf privilege".into());
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
                && (!adapter.clickhouse_write_privileges.is_empty()
                    || matches!(t["engine"].as_str(), Some("Memory" | "MergeTree")))
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
    let members: Vec<Value> = sorted(http.query(if adapter.membership_write_roles.is_empty() {
        ROLE_SQL
    } else {
        MEMBER_ROLES
    })?);
    let user_policies: Vec<Value> = if adapter.membership_write_roles.is_empty() {
        vec![]
    } else {
        sorted(http.query(USER_POLICIES)?)
    };
    if !adapter.membership_write_roles.is_empty() {
        let mut edges = BTreeSet::new();
        for m in &members {
            let subject = match (m["user_name"].as_str(), m["role_name"].as_str()) {
                (Some(u), None)
                    if m["role_name"].is_null() && kinds.get(u).is_some_and(|k| k == "account") =>
                {
                    u
                }
                (None, Some(r))
                    if m["user_name"].is_null() && kinds.get(r).is_some_and(|k| k == "role") =>
                {
                    r
                }
                _ => return Err("Invalid membership recipient catalog".into()),
            };
            let role = m["granted_role_name"].as_str().ok_or("Invalid role name")?;
            if !principals.iter().any(|p| {
                p["name"] == role && p["kind"] == "role" && p["id"] == m["granted_role_id"]
            }) || !matches!(m["with_admin_option"].as_u64(), Some(0 | 1))
                || !matches!(m["granted_role_is_default"].as_u64(), Some(0 | 1))
                || !edges.insert((subject, role))
            {
                return Err("Ambiguous role UUID or membership options".into());
            }
        }
        let mut users = BTreeSet::new();
        for p in &user_policies {
            let name = p["name"].as_str().ok_or("Invalid user policy catalog")?;
            if kinds.get(name).is_none_or(|k| k != "account")
                || !users.insert(name)
                || !matches!(p["default_roles_all"].as_u64(), Some(0 | 1))
                || !matches!(p["grantees_any"].as_u64(), Some(0 | 1))
                || [
                    "default_roles_list",
                    "default_roles_except",
                    "grantees_list",
                    "grantees_except",
                ]
                .iter()
                .any(|k| {
                    p[k].as_array()
                        .is_none_or(|a| a.iter().any(|v| !v.is_string()))
                })
            {
                return Err("Invalid or duplicate default-role/grantee policy".into());
            }
        }
        if users.len() != principals.iter().filter(|p| p["kind"] == "account").count() {
            return Err("Incomplete user policy catalog".into());
        }
    }
    let privilege_tree = if adapter.clickhouse_write_privileges.is_empty() {
        vec![]
    } else {
        sorted(http.query::<Value>("SELECT toString(privilege) AS privilege,aliases,toString(level) AS level,toString(parent_group) AS parent_group FROM system.privileges LIMIT 10001")?)
    };
    let raw_grants = sorted(http.query(RAW_GRANTS)?);
    let grants = if privilege_tree.is_empty() {
        raw_grants
    } else {
        privileges::rows(&privilege_tree, raw_grants)?
    };
    Ok(State {
        privilege_tree,
        session,
        principals,
        members,
        grants,
        tables: selected,
        databases,
        user_policies,
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
            || (adapter.clickhouse_write_privileges.is_empty()
                && !matches!(r["access_type"].as_str(), Some("SELECT" | "INSERT")))
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
fn local_principal<'a>(s: &'a State, name: &str) -> Result<&'a Value> {
    literal(name)?;
    s.principals
        .iter()
        .find(|p| p["name"] == name && p["storage"] == "local_directory")
        .ok_or_else(|| "Membership endpoints must already exist in local_directory".into())
}
fn member_atom(g: &Grant, p: &Value, role: &Value) -> Value {
    json!({"user_name": if p["kind"] == "account" { json!(g.subject) } else { Value::Null },
        "role_name": if p["kind"] == "role" { json!(g.subject) } else { Value::Null },
        "granted_role_name":role["name"],"granted_role_id":role["id"],
        "granted_role_is_default":1,"with_admin_option":0})
}
fn membership(s: &State, g: &Grant, adapter: &Adapter, issuer: &str) -> Result<Value> {
    let role = g
        .resource
        .strip_prefix("role:")
        .ok_or("Exact role:name required")?;
    if g.privilege != "MEMBER" || !adapter.membership_write_roles.contains(role) {
        return Err(
            "ClickHouse MEMBER writes require an exact membership_write_roles entry".into(),
        );
    }
    let p = local_principal(s, &g.subject)?;
    let r = local_principal(s, role)?;
    if r["kind"] != "role" || ancestors(s, issuer).contains(&g.subject) {
        return Err(
            "Membership cannot target an account as role, the writer or its ancestors".into(),
        );
    }
    let chain = ancestors(s, role);
    if chain.contains(&g.subject) {
        return Err("Self or cyclic role membership is refused".into());
    }
    for name in &chain {
        if local_principal(s, name)?["kind"] != "role" {
            return Err("Role chain contains a non-role principal".into());
        }
    }
    for m in &s.members {
        let subject = m["user_name"].as_str().or(m["role_name"].as_str());
        if subject.is_some_and(|n| chain.contains(n)) && m["with_admin_option"] != 0 {
            return Err("Target role chain carries unmodelled ADMIN delegation".into());
        }
    }
    for acl in &s.grants {
        if acl["role_name"].as_str().is_some_and(|n| chain.contains(n)) {
            let db = acl["database"]
                .as_str()
                .ok_or("Role chain has a global privilege")?;
            let resource = match acl["table"].as_str() {
                Some(t) => format!("table:{db}.{t}"),
                None if acl["table"].is_null() => format!("db:{db}"),
                _ => return Err("Invalid role ACL scope".into()),
            };
            scope(&resource)?;
            if acl["grant_option"] != 0
                || acl["is_partial_revoke"] != 0
                || !acl["column"].is_null()
                || acl["access_object"] != ""
                || !matches!(acl["access_type"].as_str(), Some("SELECT" | "INSERT"))
            {
                return Err("Role chain has delegated, partial, column or unsupported ACLs".into());
            }
        }
    }
    if p["kind"] == "account" {
        let policy = s
            .user_policies
            .iter()
            .find(|u| u["name"] == g.subject)
            .ok_or("Missing recipient default-role policy")?;
        if policy["default_roles_all"] != 1
            || policy["default_roles_list"] != json!([])
            || policy["default_roles_except"] != json!([])
        {
            return Err(
                "Membership recipient requires canonical DEFAULT ROLE ALL without exceptions"
                    .into(),
            );
        }
    }
    let row = member_atom(g, p, r);
    for held in s.members.iter().filter(|m| {
        (m["user_name"] == g.subject || m["role_name"] == g.subject)
            && m["granted_role_name"] == role
    }) {
        if *held != row {
            return Err(
                "Existing membership options are not canonical; manual reconciliation required"
                    .into(),
            );
        }
    }
    let mut authority = row.clone();
    authority["user_name"] = json!(issuer);
    authority["role_name"] = Value::Null;
    authority["with_admin_option"] = json!(1);
    // Default status of the writer's held role does not change its direct ADMIN authority.
    if !s.members.iter().any(|m| {
        let mut a = authority.clone();
        a["granted_role_is_default"] = m["granted_role_is_default"].clone();
        *m == a
    }) {
        return Err("Writer must directly hold ADMIN OPTION on the exact changed role".into());
    }
    Ok(row)
}
fn report(
    loaded: &input::Loaded,
    system: &str,
    s: &State,
    observed: &Observation,
    issuer: &str,
) -> Result<planner::Report> {
    let adapter = &loaded.config.adapters[system];
    let mut intent = input::Intent {
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
    let permitted = |g: &Grant| -> Result<()> {
        if g.privilege == "MEMBER" {
            return Ok(());
        }
        if s.privilege_tree.is_empty() {
            return if matches!(g.privilege.as_str(), "SELECT" | "INSERT") {
                Ok(())
            } else {
                Err("Additional ClickHouse privileges require clickhouse_write_privileges authorization".into())
            };
        }
        let wanted = privileges::expand(&s.privilege_tree, &g.privilege, &g.resource)?;
        let mut allowed = BTreeSet::from(["SELECT".to_owned(), "INSERT".to_owned()]);
        for p in &adapter.clickhouse_write_privileges {
            if let Ok(ps) = privileges::expand(&s.privilege_tree, p, &g.resource) {
                allowed.extend(ps)
            }
        }
        if wanted.iter().any(|p| !allowed.contains(p)) {
            return Err("Additional ClickHouse privileges require clickhouse_write_privileges authorization".into());
        }
        Ok(())
    };
    for g in &intent.grants {
        permitted(g)?;
    }
    if !s.privilege_tree.is_empty() {
        intent.grants = privileges::grants(&s.privilege_tree, &intent.grants)?;
    }
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
        // Undeclared write authorization still permits retaining unchanged membership rows.
        if g.resource.starts_with("role:") && g.privilege == "MEMBER" {
            if g.resource
                .strip_prefix("role:")
                .is_some_and(|r| adapter.membership_write_roles.contains(r))
            {
                membership(s, g, adapter, issuer)?;
            }
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
    let one_scope = plan.changes.first().is_none_or(|first| {
        plan.changes.iter().all(|c| {
            c.action == first.action
                && c.grant.subject == first.grant.subject
                && c.grant.resource == first.grant.resource
                && !c.grant.resource.starts_with("role:")
        })
    });
    if (s.privilege_tree.is_empty() && (!plan.commands_complete || plan.changes.len() > 1))
        || (!s.privilege_tree.is_empty() && (!one_scope || plan.changes.len() > 1000))
    {
        return Err(
            "ClickHouse writer requires at most one change; no multi-statement rollback exists"
                .into(),
        );
    }
    for c in &mut plan.changes {
        permitted(&c.grant)?;
        let (verb, to) = match c.action.as_str() {
            "grant" => ("GRANT", "TO"),
            "revoke" => ("REVOKE", "FROM"),
            _ => return Err("Unsupported ACL action".into()),
        };
        if let Some(role) = c.grant.resource.strip_prefix("role:") {
            membership(s, &c.grant, adapter, issuer)?;
            c.cmd = Some(format!(
                "{verb} {} {to} {};",
                quoted(role),
                quoted(&c.grant.subject)
            ));
            continue;
        }
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
        let exact = s.grants.contains(&atom(&authority, actor, 1)?);
        let broad = !s.privilege_tree.is_empty()
            && s.grants.iter().any(|r| {
                r["user_name"] == issuer
                    && r["grant_option"] == 1
                    && r["is_partial_revoke"] == 0
                    && r["column"].is_null()
                    && r["access_object"] == ""
                    && r["access_type"] == c.grant.privilege
                    && (r["database"].is_null()
                        || (r["database"] == scope(&c.grant.resource).unwrap().0
                            && r["table"].is_null()))
            });
        if !exact && !broad {
            return Err(
                "Writer must directly hold exact-scope GRANT OPTION for the changed privilege"
                    .into(),
            );
        }
        c.command_error = None;
        c.cmd = Some(format!(
            "{verb} {} ON {target} {to} {};",
            c.grant.privilege,
            quoted(&c.grant.subject)
        ));
    }
    plan.commands_complete = true;
    Ok(plan)
}
fn checked(http: &Http, loaded: &input::Loaded, system: &str) -> Result<(State, planner::Report)> {
    let adapter = &loaded.config.adapters[system];
    if adapter.clickhouse_write_tables.len()
        + adapter.clickhouse_write_databases.len()
        + adapter.membership_write_roles.len()
        > 128
    {
        return Err("ClickHouse write allowlists exceed 128 entries".into());
    }
    for role in &adapter.membership_write_roles {
        literal(role)?;
    }
    let before = state(http, adapter)?;
    let mut observed = observe_http(http, system)?;
    if !before.privilege_tree.is_empty() {
        observed.grants = privileges::grants(&before.privilege_tree, &observed.grants)?;
    }
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
    pub membership_changes_affect_dependants: bool,
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
    let http = Http::from_env(
        key,
        adapter.read_timeout_seconds,
        Instant::now(),
        adapter.ca_bundle_env.as_deref(),
    )?;
    let (state, plan) = checked(&http, &loaded, system)?;
    let value = serde_json::to_vec(&json!({"format":"clickhouse-single-acl-v3","path":path,"system":system,"endpoint":http.url.as_str(),"state":state,"changes":plan.changes})).map_err(|_| "Cannot bind ClickHouse plan")?;
    let mut hash = Sha256::new();
    for part in [&config_bytes, &intent_bytes, &value] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    let plan_id = crate::hex(&hash.finalize());
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
        let first = &plan.changes[0];
        let statement = if plan.changes.len() == 1 {
            first.cmd.clone().ok_or("Missing fixed SQL")?
        } else {
            let privileges = plan
                .changes
                .iter()
                .map(|c| c.grant.privilege.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let (verb, to) = if first.action == "grant" {
                ("GRANT", "TO")
            } else {
                ("REVOKE", "FROM")
            };
            format!(
                "{verb} {privileges} ON {} {to} {};",
                target_sql(&first.grant)?,
                quoted(&first.grant.subject)
            )
        };
        let mut expected_rows = Vec::new();
        for c in &plan.changes {
            let row = if c.grant.resource.starts_with("role:") {
                membership(&state, &c.grant, adapter, &http.user)?
            } else {
                let p = recipient(
                    &state,
                    &c.grant.subject,
                    &ancestors(&state, &http.user),
                    adapter,
                )?;
                atom(&c.grant, p, 0)?
            };
            expected_rows.push((c.action.clone(), c.grant.resource.starts_with("role:"), row));
        }
        let mut wanted = state;
        for (action, is_member, row) in expected_rows {
            let rows = if is_member {
                &mut wanted.members
            } else {
                &mut wanted.grants
            };
            if action == "grant" {
                rows.push(row)
            } else {
                rows.retain(|r| r != &row)
            }
            rows.sort_by_cached_key(Value::to_string);
            rows.dedup();
        }
        execute(&http, &statement)?;
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
        membership_changes_affect_dependants: plan
            .changes
            .iter()
            .any(|c| c.grant.resource.starts_with("role:")),
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
