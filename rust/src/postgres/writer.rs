//! Explicit, single-database table/schema/database ACL writes. No data SQL or role switching.
use super::*;
use crate::{config as input, planner};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;

const TABLE_STATE: &str = "SELECT c.oid::bigint AS oid, n.oid::bigint AS namespace_oid, n.nspname AS schema, c.relname AS name, c.relowner::bigint AS owner_oid, r.rolname AS owner, c.relkind::text AS kind, c.relacl::text AS acl, EXISTS(SELECT 1 FROM pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid) OR c.relispartition AS inherited, EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND cardinality(a.attacl)>0) AS columns FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_roles r ON r.oid=c.relowner WHERE c.relkind IN ('r','p','v','m','f') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname !~ '^pg_'";
const DATABASE_STATE: &str = "SELECT d.oid::bigint AS oid, d.datname AS name, d.datdba::bigint AS owner_oid, r.rolname AS owner, d.datacl::text AS acl FROM pg_database d LEFT JOIN pg_roles r ON r.oid=d.datdba WHERE NOT d.datistemplate";
const SCHEMA_STATE: &str = "SELECT n.oid::bigint AS oid, n.nspname AS name, n.nspowner::bigint AS owner_oid, r.rolname AS owner, n.nspacl::text AS acl FROM pg_namespace n LEFT JOIN pg_roles r ON r.oid=n.nspowner WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname !~ '^pg_'";
// Advisory keys are database-local and coordinate this writer version only.
const WRITER_LOCK: &str = "SELECT pg_try_advisory_xact_lock(1196576334, 1) AS present";
const ROLES: &str = "SELECT oid::bigint AS oid, rolname AS name, rolcanlogin AS login, rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls AS privileged, rolinherit AS inherit FROM pg_roles";
const SESSION: &str = "SELECT current_database() AS database, (SELECT oid::bigint FROM pg_database WHERE datname=current_database()) AS database_oid, session_user::text AS login, current_user::text AS active, inet_server_addr()::text AS address, inet_server_port() AS port, pg_postmaster_start_time()::text AS started, current_setting('server_version_num')::int AS version, current_setting('transaction_read_only')::bool AS readonly";

#[derive(Deserialize, Serialize, PartialEq)]
struct Table {
    oid: i64,
    namespace_oid: i64,
    schema: String,
    name: String,
    owner_oid: i64,
    owner: String,
    kind: String,
    acl: Option<String>,
    inherited: bool,
    columns: bool,
}
#[derive(Deserialize, Serialize)]
struct Object {
    oid: i64,
    name: String,
    owner_oid: i64,
    owner: String,
    acl: Option<String>,
}
#[derive(Deserialize, Serialize)]
struct WriterRole {
    oid: i64,
    name: String,
    login: bool,
    privileged: bool,
    inherit: bool,
}
struct Catalog {
    observed: Observed,
    tables: Vec<Table>,
    roles: Vec<WriterRole>,
    schemas: Vec<Object>,
    databases: Vec<Object>,
    acls: BTreeSet<AclAtom>,
    other: Value,
}
async fn rows(client: &Client, sql: &str) -> Result<Vec<Value>> {
    let mut rows: Vec<Value> = query(client, sql).await?;
    rows.sort_by_cached_key(Value::to_string);
    Ok(rows)
}
async fn catalog(client: &Client, system: &str, db: &str) -> Result<Catalog> {
    let mut roles: Vec<WriterRole> = query(client, ROLES).await?;
    roles.sort_by(|a, b| a.name.cmp(&b.name));
    for role in &roles {
        name(&role.name)?;
        if role.name == "PUBLIC" {
            return Err("PostgreSQL role conflicts with PUBLIC subject".into());
        }
    }
    let mut kinds: Kinds = roles
        .iter()
        .map(|r| {
            (
                r.name.clone(),
                if r.login { "account" } else { "role" }.into(),
            )
        })
        .collect();
    kinds.insert("PUBLIC".into(), "role".into());
    let mut observed = database_catalog(client, system, db, &kinds).await?;
    let members = rows(client, MEMBER_SQL).await?;
    for m in &members {
        let m: Membership =
            serde_json::from_value(m.clone()).map_err(|_| "Invalid membership catalog")?;
        observed.grants.insert(Grant {
            grantor: Some(m.grantor),
            ..Grant::new(system, &m.member, &format!("role:{}", m.role), "MEMBER")
        });
    }
    let dbs = rows(client, DB_SQL).await?;
    for row in &dbs {
        let row: DbAcl =
            serde_json::from_value(row.clone()).map_err(|_| "Invalid database ACL catalog")?;
        observed.acl(system, format!("db:{}", row.resource), row.acl)?;
    }
    let mut tables: Vec<Table> = query(client, TABLE_STATE).await?;
    tables.sort_by_key(|t| t.oid);
    let schemas = rows(client, SCHEMA_SQL).await?;
    let table_acls = rows(client, TABLE_SQL).await?;
    let mut acls = BTreeSet::new();
    for (kind, data) in [("db", &dbs), ("schema", &schemas), ("table", &table_acls)] {
        for row in data {
            let resource = match kind {
                "db" => format!(
                    "db:{}",
                    row["resource"].as_str().ok_or("Invalid database ACL")?
                ),
                "schema" => format!(
                    "schema:{db}.{}",
                    row["schema"].as_str().ok_or("Invalid schema ACL")?
                ),
                _ => format!(
                    "table:{db}.{}.{}",
                    row["schema"].as_str().ok_or("Invalid table ACL")?,
                    row["name"].as_str().ok_or("Invalid table ACL")?
                ),
            };
            let acl: Acl = serde_json::from_value(row.clone()).map_err(|_| "Invalid object ACL")?;
            acls.insert((
                resource,
                acl.subject,
                acl.privilege,
                acl.grantor,
                acl.is_grantable,
            ));
        }
    }
    let mut schemas: Vec<Object> = query(client, SCHEMA_STATE).await?;
    let mut databases: Vec<Object> = query(client, DATABASE_STATE).await?;
    schemas.sort_by_key(|s| s.oid);
    databases.sort_by_key(|d| d.oid);
    let other = json!({"roles": roles, "members": members,
        "defaults": rows(client, DEFAULT_SQL).await?});
    Ok(Catalog {
        observed,
        tables,
        roles,
        acls,
        other,
        schemas,
        databases,
    })
}
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Target {
    Database(String),
    Schema(String),
    Table(String, String),
}
impl Target {
    fn sql(&self) -> String {
        match self {
            Self::Database(db) => format!("DATABASE {}", identifier(db)),
            Self::Schema(schema) => format!("SCHEMA {}", identifier(schema)),
            Self::Table(schema, table) => {
                format!("TABLE {}.{}", identifier(schema), identifier(table))
            }
        }
    }
    fn owner<'a>(&self, cat: &'a Catalog) -> Result<&'a str> {
        match self {
            Self::Database(db) => cat
                .databases
                .iter()
                .find(|d| &d.name == db)
                .map(|d| d.owner.as_str()),
            Self::Schema(schema) => cat
                .schemas
                .iter()
                .find(|s| &s.name == schema)
                .map(|s| s.owner.as_str()),
            Self::Table(schema, table) => cat
                .tables
                .iter()
                .find(|t| &t.schema == schema && &t.name == table)
                .map(|t| t.owner.as_str()),
        }
        .ok_or_else(|| "Target object must already exist".into())
    }
}
fn target(g: &Grant, db: &str) -> Result<Target> {
    let (scope, rest) = g
        .resource
        .split_once(':')
        .ok_or("Unsupported PostgreSQL writer resource")?;
    let parts: Vec<_> = rest.split('.').collect();
    if parts.first().copied() != Some(db) {
        return Err("Writer requires objects in the selected database only".into());
    }
    for part in &parts {
        component(part)?;
    }
    let allowed = match (scope, parts.as_slice()) {
        ("db", [_]) => matches!(g.privilege.as_str(), "CONNECT" | "CREATE" | "TEMPORARY"),
        ("schema", [_, _]) => matches!(g.privilege.as_str(), "USAGE" | "CREATE"),
        ("table", [_, _, _]) => matches!(
            g.privilege.as_str(),
            "SELECT"
                | "INSERT"
                | "UPDATE"
                | "DELETE"
                | "TRUNCATE"
                | "REFERENCES"
                | "TRIGGER"
                | "MAINTAIN"
        ),
        _ => false,
    };
    if !allowed {
        return Err("Writer requires exact supported table/schema/database privileges; use TEMPORARY, not TEMP; ALL is unsupported".into());
    }
    name(&g.subject)?;
    if g.subject == "PUBLIC" || g.subject.starts_with("pg_") {
        return Err("PUBLIC and predefined targets are unsupported by this writer".into());
    }
    Ok(match scope {
        "db" => Target::Database(db.into()),
        "schema" => Target::Schema(parts[1].into()),
        _ => Target::Table(parts[1].into(), parts[2].into()),
    })
}

fn identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
fn report(
    loaded: &input::Loaded,
    system: &str,
    db: &str,
    cat: &Catalog,
) -> Result<planner::Report> {
    if !cat.observed.unknown.is_empty() {
        return Err("Incomplete PostgreSQL catalog; writer refuses unknown scopes".into());
    }
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
    // An excluded database must never be mistaken for an empty one.
    for g in &intent.grants {
        if g.resource.starts_with("table:")
            || g.resource.starts_with("schema:")
            || g.resource.starts_with("default:")
        {
            let location = g.resource.split_once(':').unwrap().1;
            if location.split('.').next() != Some(db) {
                return Err("Intent spans databases; writer requires one database".into());
            }
        }
    }
    let mut plan = planner::build(&intent, &cat.observed.grants, &[], &loaded.kinds, vec![]);
    if !plan.commands_complete || plan.changes.len() > 1000 {
        return Err("Incomplete or oversized PostgreSQL write plan".into());
    }
    for change in &mut plan.changes {
        let g = &change.grant;
        let target = target(g, db)?;
        let owner = target.owner(cat)?;
        let role = cat
            .roles
            .iter()
            .find(|r| r.name == g.subject)
            .ok_or("Target role must already exist")?;
        let database_owner = cat
            .databases
            .iter()
            .find(|d| d.name == db)
            .ok_or("Selected database disappeared")?;
        if role.privileged
            || owner == g.subject
            || (owner == "pg_database_owner" && database_owner.owner == g.subject)
        {
            return Err("Privileged and owner targets are unsupported".into());
        }
        if let Target::Table(schema, table) = &target {
            let t = cat
                .tables
                .iter()
                .find(|t| &t.schema == schema && &t.name == table)
                .ok_or("Target table disappeared")?;
            if t.kind != "r" || t.inherited || t.columns {
                return Err(
                    "Column ACLs, views, partitions and inherited tables are unsupported".into(),
                );
            }
        }
        if cat.acls.iter().any(|(resource, _, _, grantor, grantable)| {
            resource == &g.resource && (grantor != owner || *grantable)
        }) {
            return Err("Delegated or non-owner-issued object ACLs are unsupported".into());
        }
        let (verb, to, tail) = if change.action == "grant" {
            ("GRANT", "TO", "")
        } else {
            ("REVOKE", "FROM", " RESTRICT")
        };
        change.cmd = Some(format!(
            "{verb} {} ON {} {to} {}{tail};",
            g.privilege,
            target.sql(),
            identifier(&g.subject)
        ));
    }
    Ok(plan)
}
#[derive(Serialize)]
pub struct Receipt {
    pub system: String,
    pub database: String,
    pub plan_id: String,
    pub applied: bool,
    pub changed: bool,
    pub effective_access_verified: bool,
    pub changes: Vec<planner::Change>,
}
struct Inputs<'a> {
    path: &'a Path,
    loaded: &'a input::Loaded,
    system: &'a str,
    db: &'a str,
    endpoint: &'a Value,
    config_bytes: &'a [u8],
    intent_bytes: &'a [u8],
}
fn binding(
    inputs: &Inputs<'_>,
    session: &Value,
    cat: &Catalog,
    plan: &planner::Report,
) -> Result<String> {
    let Inputs {
        path,
        system,
        endpoint,
        config_bytes,
        intent_bytes,
        ..
    } = inputs;
    let mut session = session.clone();
    session
        .as_object_mut()
        .ok_or("Invalid session binding")?
        .remove("readonly");
    let state = serde_json::to_vec(
        &json!({"format": "postgres-object-writer-v2", "path": path, "system": system,
        "endpoint": endpoint, "session": session, "tables": cat.tables, "schemas": cat.schemas, "databases": cat.databases, "catalog": cat.other, "changes": plan.changes}),
    )
    .map_err(|_| "Cannot bind PostgreSQL write plan")?;
    let mut hash = Sha256::new();
    for part in [*config_bytes, *intent_bytes, &state] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    Ok(format!("{:x}", hash.finalize()))
}
type AclAtom = (String, String, String, String, bool);
fn metadata(cat: &Catalog) -> Result<Value> {
    let mut value = serde_json::to_value((&cat.tables, &cat.schemas, &cat.databases))
        .map_err(|_| "Cannot verify object metadata")?;
    for group in value.as_array_mut().ok_or("Invalid object metadata")? {
        for object in group.as_array_mut().ok_or("Invalid object metadata")? {
            object
                .as_object_mut()
                .ok_or("Invalid object metadata")?
                .remove("acl");
        }
    }
    Ok(value)
}
async fn transaction(
    client: &Client,
    inputs: &Inputs<'_>,
    write: bool,
    expected: Option<&str>,
) -> Result<Receipt> {
    let path = inputs.path;
    let loaded = inputs.loaded;
    let system = inputs.system;
    let db = inputs.db;
    let config_bytes = inputs.config_bytes;
    let intent_bytes = inputs.intent_bytes;
    let sessions = rows(client, SESSION).await?;
    let session = sessions
        .first()
        .filter(|_| sessions.len() == 1)
        .ok_or("Invalid writer session")?;
    if session["database"].as_str() != Some(db)
        || session["login"] != session["active"]
        || session["version"].as_i64().unwrap_or(0) < 160000
        || session["readonly"] != !write
    {
        return Err(
            "Writer requires PostgreSQL 16+, exact database and unmodified authenticated role"
                .into(),
        );
    }
    if write {
        let lock: Vec<Present> = query(client, WRITER_LOCK).await?;
        if lock.len() != 1 || !lock[0].present {
            return Err(
                "Another PostgreSQL writer holds the database advisory lock; no changes committed"
                    .into(),
            );
        }
    }
    let mut cat = catalog(client, system, db).await?;
    let mut plan = report(loaded, system, db, &cat)?;
    if write {
        let targets: BTreeSet<_> = plan
            .changes
            .iter()
            .map(|c| target(&c.grant, db))
            .collect::<Result<_>>()?;
        for target in &targets {
            let Target::Table(schema, table) = target else {
                continue;
            };
            client
                .batch_execute(&format!(
                    "LOCK TABLE ONLY {}.{} IN ACCESS EXCLUSIVE MODE NOWAIT",
                    identifier(schema),
                    identifier(table)
                ))
                .await
                .map_err(|_| "Cannot lock affected table; no changes committed")?;
        }
        cat = catalog(client, system, db).await?;
        plan = report(loaded, system, db, &cat)?;
        let locked_plan: BTreeSet<_> = plan
            .changes
            .iter()
            .map(|c| target(&c.grant, db))
            .collect::<Result<_>>()?;
        if locked_plan != targets {
            return Err("Affected objects changed while acquiring locks; preview again".into());
        }
    }
    let plan_id = binding(inputs, session, &cat, &plan)?;
    if write && expected != Some(plan_id.as_str()) {
        return Err(
            "Reviewed PostgreSQL plan is stale or belongs to another source/session; preview again"
                .into(),
        );
    }
    if write && !plan.changes.is_empty() {
        let mut wanted = cat.acls.clone();
        for change in &plan.changes {
            let owner = target(&change.grant, db)?.owner(&cat)?;
            if change.action == "grant" {
                wanted.insert((
                    change.grant.resource.clone(),
                    change.grant.subject.clone(),
                    change.grant.privilege.clone(),
                    owner.into(),
                    false,
                ));
            } else {
                wanted.retain(|(resource, subject, privilege, _, _)| {
                    !(resource == &change.grant.resource
                        && subject == &change.grant.subject
                        && privilege == &change.grant.privilege)
                });
            }
            client
                .batch_execute(change.cmd.as_deref().ok_or("Missing fixed SQL")?)
                .await
                .map_err(|_| "PostgreSQL ACL statement failed; transaction will be rolled back")?;
        }
        let after = catalog(client, system, db).await?;
        if wanted != after.acls
            || cat.other != after.other
            || metadata(&cat)? != metadata(&after)?
            || !report(loaded, system, db, &after)?.changes.is_empty()
        {
            return Err(
                "PostgreSQL ACL postcondition failed; transaction will be rolled back".into(),
            );
        }
    }
    let intent_path = input::relative(&loaded.base, &loaded.config.intent)?;
    if input::writer_file(path).ok().as_deref() != Some(config_bytes)
        || input::writer_file(&intent_path).ok().as_deref() != Some(intent_bytes)
    {
        return Err(
            "Config or intent changed during application; transaction will be rolled back".into(),
        );
    }
    Ok(Receipt {
        system: system.into(),
        database: db.into(),
        plan_id,
        applied: false,
        changed: !plan.changes.is_empty(),
        effective_access_verified: false,
        changes: plan.changes,
    })
}
pub fn apply(path: &Path, system: &str, write: bool, expected: Option<&str>) -> Result<Receipt> {
    if write && expected.is_none() {
        return Err("PostgreSQL --write requires a reviewed --expect PLAN_ID".into());
    }
    let path = std::path::absolute(path).map_err(|_| "Cannot resolve config path")?;
    let (loaded, config_bytes, intent_bytes) = input::load_writer(&path)?;
    let adapter = loaded
        .config
        .adapters
        .get(system)
        .filter(|a| a.typ(system) == "postgres")
        .ok_or("Native PostgreSQL adapter required")?;
    let db = adapter
        .databases
        .first()
        .filter(|_| adapter.databases.len() == 1 && adapter.exclude_databases.is_empty())
        .ok_or("Writer requires one literal databases entry and no excludes")?;
    component(db)?;
    if db.contains(['?', '[', ']']) {
        return Err("Writer databases entry must be literal".into());
    }
    let key = adapter
        .admin_dsn_env
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or("PostgreSQL admin_dsn_env write credential is not configured")?;
    let raw = std::env::var(key).map_err(|_| "PostgreSQL admin credential is unavailable")?;
    let mut cfg = config(&raw, adapter.read_timeout_seconds)?;
    if cfg.get_dbname() != Some(db.as_str()) {
        return Err("Admin DSN database must equal the single configured database".into());
    }
    cfg.application_name("grantline-rs-writer");
    let endpoint = json!({"host": match &cfg.get_hosts()[0] { Host::Tcp(host) => host, _ => unreachable!() },
        "ports": cfg.get_ports(), "tls_required": cfg.get_ssl_mode() != SslMode::Disable});
    let inputs = Inputs {
        path: &path,
        loaded: &loaded,
        system,
        db,
        endpoint: &endpoint,
        config_bytes: &config_bytes,
        intent_bytes: &intent_bytes,
    };
    let seconds = adapter.read_timeout_seconds;
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_| "Cannot create PostgreSQL writer runtime")?;
            let result = runtime.block_on(async {
                let deadline = Duration::from_secs(seconds);
                let client = tokio::time::timeout(deadline, open(&cfg)).await.map_err(|_| "PostgreSQL writer connection deadline exceeded")??;
                tokio::time::timeout(deadline, client.batch_execute(if write { "BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE" } else { "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY" })).await.map_err(|_| "PostgreSQL transaction start deadline exceeded")?.map_err(|_| "Cannot start PostgreSQL writer transaction")?;
                let prepared = tokio::time::timeout(deadline, transaction(&client, &inputs, write, expected)).await;
                let mut receipt = match prepared {
                    Ok(Ok(receipt)) => receipt,
                    failure => {
                        let _ = tokio::time::timeout(deadline, client.batch_execute("ROLLBACK")).await;
                        return Err(match failure { Ok(Err(e)) => e, _ => "PostgreSQL writer deadline exceeded; connection closed to roll back".into() });
                    }
                };
                if write && receipt.changed {
                    tokio::time::timeout(deadline, client.batch_execute("COMMIT")).await.map_err(|_| "COMMIT outcome unknown after timeout; inspect catalog before retry")?.map_err(|_| "COMMIT outcome unknown after connection failure; inspect catalog before retry")?;
                    receipt.applied = true;
                } else { tokio::time::timeout(deadline, client.batch_execute("ROLLBACK")).await.map_err(|_| "Preview rollback deadline exceeded; connection closed")?.map_err(|_| "Cannot close preview transaction")?; }
                Ok(receipt)
            });
            runtime.shutdown_background();
            result
        }).join().map_err(|_| "PostgreSQL writer failed".to_owned())?
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn schema_database_scopes_use_exact_privileges_and_quoted_targets() {
        for (resource, privilege, sql) in [
            ("db:odd\";db", "CONNECT", "DATABASE \"odd\"\";db\""),
            ("db:demo", "CREATE", "DATABASE \"demo\""),
            ("db:demo", "TEMPORARY", "DATABASE \"demo\""),
            (
                "schema:demo.odd\";schema",
                "USAGE",
                "SCHEMA \"odd\"\";schema\"",
            ),
            ("schema:demo.app", "CREATE", "SCHEMA \"app\""),
        ] {
            let db = if resource.starts_with("db:odd") {
                "odd\";db"
            } else {
                "demo"
            };
            assert_eq!(
                target(&Grant::new("pg", "demo-user", resource, privilege), db)
                    .unwrap()
                    .sql(),
                sql
            );
        }
        for (resource, privilege) in [
            ("db:demo", "TEMP"),
            ("db:demo", "USAGE"),
            ("db:demo", "ALL"),
            ("db:other", "CREATE"),
            ("db:demo.extra", "CONNECT"),
            ("schema:demo.app", "CONNECT"),
            ("schema:demo.*", "USAGE"),
            ("schema:demo.app.extra", "USAGE"),
            ("default:demo.app@owner", "SELECT"),
        ] {
            assert!(target(&Grant::new("pg", "demo-user", resource, privilege), "demo").is_err());
        }
    }
    #[test]
    fn exact_table_scope_and_quoted_identifiers() {
        let g = Grant::new(
            "pg",
            "odd\";role",
            "table:demo.public.odd\";table",
            "SELECT",
        );
        assert_eq!(
            target(&g, "demo").unwrap(),
            Target::Table("public".into(), "odd\";table".into())
        );
        assert_eq!(identifier("odd\";name"), "\"odd\"\";name\"");
        for (resource, privilege, subject) in [
            ("role:demo", "MEMBER", "demo"),
            ("table:other.public.t", "SELECT", "demo"),
            ("table:demo.public.*", "SELECT", "demo"),
            ("table:demo.public.t", "ALL", "demo"),
            ("table:demo.public.t", "SELECT", "PUBLIC"),
        ] {
            assert!(target(&Grant::new("pg", subject, resource, privilege), "demo").is_err());
        }
    }
}
