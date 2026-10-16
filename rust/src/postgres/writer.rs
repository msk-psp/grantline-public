//! Explicit, single-database ordinary-table ACL writes. No data SQL or role switching.
use super::*;
use crate::{config as input, planner};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;

const TABLE_STATE: &str = "SELECT c.oid::bigint AS oid, n.oid::bigint AS namespace_oid, n.nspname AS schema, c.relname AS name, c.relowner::bigint AS owner_oid, r.rolname AS owner, c.relkind::text AS kind, c.relacl::text AS acl, EXISTS(SELECT 1 FROM pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid) OR c.relispartition AS inherited, EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND cardinality(a.attacl)>0) AS columns FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_roles r ON r.oid=c.relowner WHERE c.relkind IN ('r','p','v','m','f') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname !~ '^pg_'";
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
    table_acls: Vec<Value>,
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
    let other = json!({"roles": roles, "members": members, "databases": dbs,
        "schemas": rows(client, SCHEMA_SQL).await?, "defaults": rows(client, DEFAULT_SQL).await?});
    Ok(Catalog {
        observed,
        tables,
        roles,
        table_acls: rows(client, TABLE_SQL).await?,
        other,
    })
}
fn target(g: &Grant, db: &str) -> Result<(String, String)> {
    let parts: Vec<_> = g
        .resource
        .strip_prefix("table:")
        .ok_or("Writer supports ordinary table ACL changes only")?
        .split('.')
        .collect();
    if parts.len() != 3 || parts[0] != db {
        return Err("Writer requires exact database.schema.table in the selected database".into());
    }
    for p in &parts {
        component(p)?;
    }
    if !matches!(
        g.privilege.as_str(),
        "SELECT"
            | "INSERT"
            | "UPDATE"
            | "DELETE"
            | "TRUNCATE"
            | "REFERENCES"
            | "TRIGGER"
            | "MAINTAIN"
    ) {
        return Err("Writer requires exact supported table privileges; ALL is unsupported".into());
    }
    name(&g.subject)?;
    if g.subject == "PUBLIC" || g.subject.starts_with("pg_") {
        return Err("PUBLIC and predefined targets are unsupported by this writer".into());
    }
    Ok((parts[1].into(), parts[2].into()))
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
        let (schema, table) = target(g, db)?;
        let role = cat
            .roles
            .iter()
            .find(|r| r.name == g.subject)
            .ok_or("Target role must already exist")?;
        let t = cat
            .tables
            .iter()
            .find(|t| t.schema == schema && t.name == table)
            .ok_or("Target table must already exist")?;
        if role.privileged || t.owner == g.subject || t.kind != "r" || t.inherited || t.columns {
            return Err("Privileged/owner targets, column ACLs, views, partitions and inherited tables are unsupported".into());
        }
        // Every non-owner ACL on an affected table must be a simple owner-issued grant.
        if cat
            .observed
            .findings
            .iter()
            .any(|f| f.title == "grant option is not modelled" && f.entities.contains(&g.resource))
            || cat
                .observed
                .grants
                .iter()
                .any(|h| h.resource == g.resource && h.grantor.as_deref() != Some(&t.owner))
            || cat.table_acls.iter().any(|row| {
                row["schema"] == schema
                    && row["name"] == table
                    && (row["grantor"] != t.owner || row["is_grantable"] == true)
            })
        {
            return Err("Delegated or non-owner-issued table ACLs are unsupported".into());
        }
        let (verb, to, tail) = if change.action == "grant" {
            ("GRANT", "TO", "")
        } else {
            ("REVOKE", "FROM", " RESTRICT")
        };
        change.cmd = Some(format!(
            "{verb} {} ON TABLE {}.{} {to} {}{tail};",
            g.privilege,
            identifier(&schema),
            identifier(&table),
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
        &json!({"format": "postgres-table-writer-v1", "path": path, "system": system,
        "endpoint": endpoint, "session": session, "tables": cat.tables, "catalog": cat.other, "changes": plan.changes}),
    )
    .map_err(|_| "Cannot bind PostgreSQL write plan")?;
    let mut hash = Sha256::new();
    for part in [*config_bytes, *intent_bytes, &state] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    Ok(format!("{:x}", hash.finalize()))
}
type AclAtom = (String, String, String, String, String, bool);
fn table_atoms(cat: &Catalog) -> Result<BTreeSet<AclAtom>> {
    cat.table_acls
        .iter()
        .map(|raw| {
            let row: TableAcl =
                serde_json::from_value(raw.clone()).map_err(|_| "Invalid table ACL")?;
            Ok((
                row.schema,
                row.name,
                row.acl.subject,
                row.acl.privilege,
                row.acl.grantor,
                row.acl.is_grantable,
            ))
        })
        .collect()
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
    let mut cat = catalog(client, system, db).await?;
    let mut plan = report(loaded, system, db, &cat)?;
    if write {
        let tables: BTreeSet<_> = plan
            .changes
            .iter()
            .map(|c| target(&c.grant, db))
            .collect::<Result<_>>()?;
        for (schema, table) in &tables {
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
        if locked_plan != tables {
            return Err("Affected tables changed while acquiring locks; preview again".into());
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
        let mut wanted = table_atoms(&cat)?;
        for change in &plan.changes {
            let (schema, table) = target(&change.grant, db)?;
            let owner = &cat
                .tables
                .iter()
                .find(|t| t.schema == schema && t.name == table)
                .ok_or("Target disappeared")?
                .owner;
            if change.action == "grant" {
                wanted.insert((
                    schema,
                    table,
                    change.grant.subject.clone(),
                    change.grant.privilege.clone(),
                    owner.clone(),
                    false,
                ));
            } else {
                wanted.retain(|(s, t, subject, privilege, _, _)| {
                    !(s == &schema
                        && t == &table
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
        let mut before_meta =
            serde_json::to_value(&cat.tables).map_err(|_| "Cannot verify table state")?;
        let mut after_meta =
            serde_json::to_value(&after.tables).map_err(|_| "Cannot verify table state")?;
        for meta in [&mut before_meta, &mut after_meta] {
            for t in meta.as_array_mut().ok_or("Invalid table metadata")? {
                t.as_object_mut()
                    .ok_or("Invalid table metadata")?
                    .remove("acl");
            }
        }
        if wanted != table_atoms(&after)?
            || cat.other != after.other
            || before_meta != after_meta
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
    fn exact_table_scope_and_quoted_identifiers() {
        let g = Grant::new(
            "pg",
            "odd\";role",
            "table:demo.public.odd\";table",
            "SELECT",
        );
        assert_eq!(target(&g, "demo").unwrap().1, "odd\";table");
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
