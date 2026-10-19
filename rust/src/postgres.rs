//! PostgreSQL catalog reads, ACL probes and explicit transactional table ACL writes.
pub mod probe;
pub mod writer;
use crate::{
    Result,
    config::Adapter,
    model::{Grant, Kinds, Unobserved},
    planner::Finding,
};
use futures_util::TryStreamExt;
use serde::{Deserialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    time::Duration,
};
use tokio_postgres::{
    Client, Config,
    config::{Host, SslMode},
};

const MAX_ROWS: usize = 10_000;
const MAX_BYTES: usize = 16 * 1024 * 1024;
const ROLE_SQL: &str =
    "SELECT rolname AS name, rolcanlogin AS login, rolsuper AS superuser FROM pg_roles";
const MEMBER_SQL: &str = "SELECT m.rolname AS member, r.rolname AS role, g.rolname AS grantor, am.inherit_option, am.set_option, am.admin_option FROM pg_auth_members am LEFT JOIN pg_roles m ON m.oid=am.member LEFT JOIN pg_roles r ON r.oid=am.roleid LEFT JOIN pg_roles g ON g.oid=am.grantor";
const DATABASE_SQL: &str = "SELECT datname AS name FROM pg_database WHERE NOT datistemplate";
const DB_SQL: &str = "SELECT d.datname AS resource, CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE r.rolname END AS subject, a.privilege_type AS privilege, d.datacl IS NULL AS implicit, g.rolname AS grantor, a.is_grantable FROM pg_database d CROSS JOIN LATERAL aclexplode(coalesce(d.datacl, acldefault('d', d.datdba))) a LEFT JOIN pg_roles r ON r.oid=a.grantee LEFT JOIN pg_roles g ON g.oid=a.grantor WHERE NOT d.datistemplate";
const SCHEMA_SQL: &str = "SELECT n.nspname AS schema, CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE r.rolname END AS subject, a.privilege_type AS privilege, n.nspacl IS NULL AS implicit, g.rolname AS grantor, a.is_grantable FROM pg_namespace n CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) a LEFT JOIN pg_roles r ON r.oid=a.grantee LEFT JOIN pg_roles g ON g.oid=a.grantor WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname !~ '^pg_'";
const TABLE_SQL: &str = "SELECT n.nspname AS schema, c.relname AS name, CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE r.rolname END AS subject, a.privilege_type AS privilege, c.relacl IS NULL AS implicit, g.rolname AS grantor, a.is_grantable FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a LEFT JOIN pg_roles r ON r.oid=a.grantee LEFT JOIN pg_roles g ON g.oid=a.grantor WHERE c.relkind IN ('r','p','v','m','f') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname !~ '^pg_'";
const DEFAULT_SQL: &str = "SELECT c.rolname AS creator, n.nspname AS schema, CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE r.rolname END AS subject, a.privilege_type AS privilege, false AS implicit, g.rolname AS grantor, a.is_grantable FROM pg_default_acl d JOIN pg_namespace n ON n.oid=d.defaclnamespace LEFT JOIN pg_roles c ON c.oid=d.defaclrole CROSS JOIN LATERAL aclexplode(d.defaclacl) a LEFT JOIN pg_roles r ON r.oid=a.grantee LEFT JOIN pg_roles g ON g.oid=a.grantor WHERE d.defaclobjtype='r'";
const GLOBAL_DEFAULT_SQL: &str = "SELECT EXISTS(SELECT 1 FROM pg_default_acl WHERE defaclobjtype='r' AND defaclnamespace=0) AS present";
const COLUMN_SQL: &str = "SELECT DISTINCT n.nspname AS schema FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE a.attnum>0 AND NOT a.attisdropped AND a.attacl IS NOT NULL AND cardinality(a.attacl)>0 AND c.relkind IN ('r','p','v','m','f') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname !~ '^pg_'";
// ACL empty arrays can retain dimensions; equality to an empty literal misses them.
const FROZEN_SQL: &str = "SELECT n.nspname AS schema, c.relname AS name, r.rolname AS owner FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_roles r ON r.oid=c.relowner WHERE c.relkind IN ('r','p','v','m','f') AND cardinality(c.relacl)=0 AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname !~ '^pg_'";

#[derive(Default)]
pub struct Observed {
    pub grants: BTreeSet<Grant>,
    pub unknown: Vec<Unobserved>,
    pub findings: Vec<Finding>,
    pub kinds: Kinds,
}
fn unread(system: &str, prefixes: Vec<String>, note: &str) -> Unobserved {
    Unobserved {
        system: system.into(),
        prefixes,
        subjects: BTreeSet::new(),
        note: note.into(),
    }
}
fn db_prefixes(db: &str) -> Vec<String> {
    ["table", "schema", "default"]
        .map(|k| format!("{k}:{db}."))
        .to_vec()
}
fn name(value: &str) -> Result<()> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err("Invalid PostgreSQL catalog identifier".into());
    }
    Ok(())
}
fn component(value: &str) -> Result<()> {
    name(value)?;
    if value.contains(['.', '@', '*']) {
        return Err("PostgreSQL identifier cannot be represented by the resource model".into());
    }
    Ok(())
}
fn config(raw: &str, seconds: u64) -> Result<Config> {
    if !(1..=120).contains(&seconds) {
        return Err("read_timeout_seconds must be between 1 and 120".into());
    }
    let mut cfg: Config = raw.parse().map_err(|_| "Invalid PostgreSQL reader DSN")?;
    if cfg.get_hosts().len() != 1
        || !matches!(&cfg.get_hosts()[0], Host::Tcp(s) if !s.is_empty())
        || !cfg.get_hostaddrs().is_empty()
        || cfg.get_user().is_none_or(str::is_empty)
        || cfg.get_dbname().is_none_or(str::is_empty)
        || cfg.get_options().is_some()
    {
        return Err("Reader DSN requires one TCP host, user and maintenance dbname; hostaddr/options are unsupported".into());
    }
    // Prefer must not silently send the reader password over a plaintext fallback.
    if cfg.get_ssl_mode() != SslMode::Disable {
        cfg.ssl_mode(SslMode::Require);
    }
    cfg.connect_timeout(Duration::from_secs(seconds.min(5)))
        .application_name("grantline-rs-reader")
        .options(format!("-c default_transaction_read_only=on -c statement_timeout={} -c lock_timeout=1000 -c idle_in_transaction_session_timeout={} -c search_path=pg_catalog", seconds*1000,seconds*1000));
    Ok(cfg)
}
async fn open(cfg: &Config, ca: Option<&str>) -> Result<Client> {
    let tls = crate::tls::postgres(ca)?;
    let (client, connection) = cfg
        .connect(tls)
        .await
        .map_err(|_| "PostgreSQL connection/authentication/TLS failure")?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}
async fn connect(cfg: &Config, ca: Option<&str>) -> Result<Client> {
    let client = open(cfg, ca).await?;
    client
        .batch_execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .await
        .map_err(|_| "Cannot start PostgreSQL read-only catalog transaction")?;
    Ok(client)
}
async fn query<T: DeserializeOwned>(client: &Client, sql: &str) -> Result<Vec<T>> {
    // The only SQL argument values are module constants. The extra row detects truncation.
    let sql = format!("SELECT row_to_json(q)::text FROM ({sql} LIMIT 10001) q");
    let stream = client
        .query_raw(&sql, std::iter::empty::<&str>())
        .await
        .map_err(|_| "PostgreSQL catalog query failed; server details withheld")?;
    let mut stream = std::pin::pin!(stream);
    let mut result = Vec::new();
    let mut bytes = 0;
    while let Some(row) = stream
        .try_next()
        .await
        .map_err(|_| "Incomplete PostgreSQL catalog response")?
    {
        let raw: &str = row
            .try_get(0)
            .map_err(|_| "Invalid PostgreSQL catalog row type")?;
        bytes += raw.len();
        if bytes > MAX_BYTES || result.len() == MAX_ROWS {
            return Err("PostgreSQL catalog exceeded row/byte limit".into());
        }
        result
            .push(serde_json::from_str(raw).map_err(|_| "Invalid PostgreSQL catalog JSON/schema")?);
    }
    Ok(result)
}
#[derive(Deserialize)]
struct Role {
    name: String,
    login: bool,
    superuser: bool,
}
#[derive(Clone, Deserialize, serde::Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct Membership {
    member: String,
    role: String,
    grantor: String,
    inherit_option: bool,
    set_option: bool,
    admin_option: bool,
}
#[derive(Deserialize)]
struct Database {
    name: String,
}
#[derive(Deserialize)]
struct Acl {
    subject: String,
    privilege: String,
    implicit: bool,
    grantor: String,
    is_grantable: bool,
}
#[derive(Deserialize)]
struct DbAcl {
    resource: String,
    #[serde(flatten)]
    acl: Acl,
}
#[derive(Deserialize)]
struct SchemaAcl {
    schema: String,
    #[serde(flatten)]
    acl: Acl,
}
#[derive(Deserialize)]
struct TableAcl {
    schema: String,
    name: String,
    #[serde(flatten)]
    acl: Acl,
}
#[derive(Deserialize)]
struct DefaultAcl {
    creator: String,
    schema: String,
    #[serde(flatten)]
    acl: Acl,
}
#[derive(Deserialize)]
struct Frozen {
    schema: String,
    name: String,
    owner: String,
}
#[derive(Deserialize)]
struct Present {
    present: bool,
}
#[derive(Deserialize)]
struct Column {
    schema: String,
}

impl Observed {
    fn acl(&mut self, system: &str, resource: String, acl: Acl) -> Result<()> {
        name(&acl.subject)?;
        name(&acl.grantor)?;
        if acl.subject != "PUBLIC" && !self.kinds.contains_key(&acl.subject)
            || !self.kinds.contains_key(&acl.grantor)
        {
            return Err("PostgreSQL ACL references an unknown role".into());
        }
        let kind = resource.split(':').next().unwrap_or("");
        let supported = match kind {
            "db" => matches!(acl.privilege.as_str(), "CONNECT" | "CREATE" | "TEMPORARY"),
            "schema" => matches!(acl.privilege.as_str(), "USAGE" | "CREATE"),
            _ => matches!(
                acl.privilege.as_str(),
                "SELECT"
                    | "INSERT"
                    | "UPDATE"
                    | "DELETE"
                    | "TRUNCATE"
                    | "REFERENCES"
                    | "TRIGGER"
                    | "MAINTAIN"
            ),
        };
        if !supported {
            return Err("Unsupported PostgreSQL catalog privilege".into());
        }
        if acl.is_grantable {
            self.findings.push(Finding::new(system,"grant option is not modelled", "Delegation rights are present; the permission atom does not represent grant options".into(),vec![acl.subject.clone(),resource.clone()]));
        }
        self.grants.insert(Grant {
            system: system.into(),
            subject: acl.subject,
            resource,
            privilege: acl.privilege,
            source: if acl.implicit {
                "implicit".into()
            } else {
                "explicit".into()
            },
            grantor: Some(acl.grantor),
        });
        Ok(())
    }
}
pub fn frozen_finding(system: &str, table: &str, owner: &str) -> Finding {
    Finding::new(
        system,
        "frozen ACL (owner locked out)",
        format!(
            "{table} (owner {owner}): ACL is an empty array, so even the owner has no privileges. Recover with an explicit GRANT ALL ON {table} TO \"{owner}\";"
        ),
        vec![table.into(), owner.into()],
    )
}
async fn database(
    cfg: &Config,
    system: &str,
    db: &str,
    kinds: &Kinds,
    ca: Option<&str>,
) -> Result<Observed> {
    let mut cfg = cfg.clone();
    cfg.dbname(db);
    let client = connect(&cfg, ca).await?;
    database_catalog(&client, system, db, kinds).await
}
async fn database_catalog(
    client: &Client,
    system: &str,
    db: &str,
    kinds: &Kinds,
) -> Result<Observed> {
    let mut out = Observed {
        kinds: kinds.clone(),
        ..Default::default()
    };
    for row in query::<TableAcl>(client, TABLE_SQL).await? {
        component(&row.schema)?;
        component(&row.name)?;
        out.acl(
            system,
            format!("table:{db}.{}.{}", row.schema, row.name),
            row.acl,
        )?;
    }
    for row in query::<SchemaAcl>(client, SCHEMA_SQL).await? {
        component(&row.schema)?;
        out.acl(system, format!("schema:{db}.{}", row.schema), row.acl)?;
    }
    for row in query::<DefaultAcl>(client, DEFAULT_SQL).await? {
        component(&row.schema)?;
        component(&row.creator)?;
        if !kinds.contains_key(&row.creator) {
            return Err("Unknown default privilege creator".into());
        }
        out.acl(
            system,
            format!("default:{db}.{}@{}", row.schema, row.creator),
            row.acl,
        )?;
    }
    let global = query::<Present>(client, GLOBAL_DEFAULT_SQL).await?;
    if global.len() != 1 {
        return Err("Incomplete global default privilege visibility".into());
    }
    if global[0].present {
        out.unknown.push(unread(system,vec![format!("default:{db}.")],"Global default table privileges cannot be represented; all default scopes in this database are unread"));
    }
    for row in query::<Column>(client, COLUMN_SQL).await? {
        component(&row.schema)?;
        out.unknown.push(unread(
            system,
            vec![format!("table:{db}.{}.", row.schema)],
            "Column privileges cannot be represented; table scopes in this schema are unread",
        ));
    }
    for row in query::<Frozen>(client, FROZEN_SQL).await? {
        component(&row.schema)?;
        component(&row.name)?;
        name(&row.owner)?;
        out.findings.push(frozen_finding(
            system,
            &format!("{db}.{}.{}", row.schema, row.name),
            &row.owner,
        ));
    }
    // Dropping the client rolls the read-only transaction back; nothing is committed.
    Ok(out)
}
async fn observe_async(cfg: Config, adapter: &Adapter, system: &str) -> Result<Observed> {
    let client = connect(&cfg, adapter.ca_bundle_env.as_deref()).await?;
    #[derive(Deserialize)]
    struct Version {
        version: i32,
        readonly: bool,
    }
    let version=query::<Version>(&client,"SELECT current_setting('server_version_num')::int AS version, current_setting('transaction_read_only')::bool AS readonly").await?;
    if version.len() != 1 || version[0].version < 160000 || !version[0].readonly {
        return Err("PostgreSQL 16+ and a read-only catalog transaction are required".into());
    }
    let mut out = Observed::default();
    out.kinds.insert("PUBLIC".into(), "role".into());
    let mut unknown = BTreeSet::new();
    for role in query::<Role>(&client, ROLE_SQL).await? {
        name(&role.name)?;
        if role.name == "PUBLIC" {
            return Err("PostgreSQL role conflicts with PUBLIC subject".into());
        }
        if role.superuser || role.name.starts_with("pg_") {
            unknown.insert(role.name.clone());
        }
        out.kinds.insert(
            role.name,
            if role.login {
                "account".into()
            } else {
                "role".into()
            },
        );
    }
    let memberships = query::<Membership>(&client, MEMBER_SQL).await?;
    for m in &memberships {
        if [&m.member, &m.role, &m.grantor]
            .iter()
            .any(|r| !out.kinds.contains_key(*r))
        {
            return Err("PostgreSQL membership references an unknown role".into());
        }
        if !m.inherit_option || !m.set_option {
            unknown.insert(m.member.clone());
        }
        if m.admin_option {
            out.findings.push(Finding::new(
                system,
                "admin option is not modelled",
                "Role delegation is present; MEMBER does not represent admin options".into(),
                vec![m.member.clone(), m.role.clone()],
            ));
        }
        out.grants.insert(Grant {
            system: system.into(),
            subject: m.member.clone(),
            resource: format!("role:{}", m.role),
            privilege: "MEMBER".into(),
            source: "explicit".into(),
            grantor: Some(m.grantor.clone()),
        });
    }
    let mut dependants: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for m in &memberships {
        dependants.entry(&m.role).or_default().push(&m.member);
    }
    let mut pending: VecDeque<_> = unknown.iter().cloned().collect();
    while let Some(role) = pending.pop_front() {
        for member in dependants.get(role.as_str()).into_iter().flatten() {
            if unknown.insert((*member).to_owned()) {
                pending.push_back((*member).to_owned());
            }
        }
    }
    for row in query::<DbAcl>(&client, DB_SQL).await? {
        component(&row.resource)?;
        out.acl(system, format!("db:{}", row.resource), row.acl)?;
    }
    let databases = query::<Database>(&client, DATABASE_SQL).await?;
    drop(client);
    if databases.len() > 128 {
        return Err("PostgreSQL observation exceeds 128 databases".into());
    }
    let include = adapter
        .databases
        .iter()
        .map(|p| glob::Pattern::new(p).map_err(|_| "Invalid databases glob"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let exclude = adapter
        .exclude_databases
        .iter()
        .map(|p| glob::Pattern::new(p).map_err(|_| "Invalid exclude_databases glob"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for db in databases {
        component(&db.name)?;
        if !include.iter().any(|p| p.matches(&db.name))
            || exclude.iter().any(|p| p.matches(&db.name))
        {
            out.unknown.push(unread(
                system,
                db_prefixes(&db.name),
                "Database excluded from configured catalog observation",
            ));
            continue;
        }
        match database(
            &cfg,
            system,
            &db.name,
            &out.kinds,
            adapter.ca_bundle_env.as_deref(),
        )
        .await
        {
            Ok(mut part) => {
                out.grants.append(&mut part.grants);
                out.unknown.append(&mut part.unknown);
                out.findings.append(&mut part.findings);
                if out.grants.len() > 100_000 {
                    return Err("PostgreSQL observation exceeds aggregate grant limit".into());
                }
            }
            Err(reason) => out
                .unknown
                .push(unread(system, db_prefixes(&db.name), &reason)),
        }
    }
    if !unknown.is_empty() {
        out.unknown.push(Unobserved {system:system.into(),prefixes:vec![String::new()],subjects:unknown,note:"Superuser/predefined role privileges or membership INHERIT/SET options cannot be represented, including role dependants".into()});
    }
    out.grants
        .retain(|g| !out.unknown.iter().any(|u| u.covers(g)));
    Ok(out)
}
pub fn observe(adapter: &Adapter, system: &str) -> Observed {
    let result = (|| {
        let key = adapter
            .dsn_env
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or("PostgreSQL dsn_env read credential is not configured")?;
        let raw = std::env::var(key).map_err(|_| "PostgreSQL read credential is unavailable")?;
        let cfg = config(&raw, adapter.read_timeout_seconds)?;
        // The offline engine is synchronous and can also be called from an Axum runtime.
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| "Cannot create PostgreSQL reader runtime")?;
                    let result = runtime.block_on(async {
                        tokio::time::timeout(
                            Duration::from_secs(adapter.read_timeout_seconds),
                            observe_async(cfg, adapter, system),
                        )
                        .await
                        .map_err(|_| "PostgreSQL observation deadline exceeded".to_owned())?
                    });
                    runtime.shutdown_background();
                    result
                })
                .join()
                .map_err(|_| "PostgreSQL reader failed".to_owned())?
        })
    })();
    match result {
        Ok(out) => out,
        Err(note) => Observed {
            unknown: vec![unread(system, vec![String::new()], &note)],
            ..Default::default()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reader_boundary() {
        for dsn in [
            "user=reader dbname=demo",
            "host=/tmp user=reader dbname=demo",
            "host=a,b user=reader dbname=demo",
            "host=localhost dbname=demo",
            "host=localhost user=reader",
            "host=localhost user=reader dbname=demo options='-c role=admin'",
        ] {
            assert!(config(dsn, 30).is_err());
        }
        let cfg = config("postgresql://reader:synthetic@localhost/demo", 30).unwrap();
        assert_eq!(cfg.get_ssl_mode(), SslMode::Require);
        assert!(
            cfg.get_options()
                .unwrap()
                .contains("default_transaction_read_only=on")
        );
        assert!(config("host=localhost user=reader dbname=demo", 0).is_err());
        for value in ["", "a.b", "a@b", "*"] {
            assert!(component(value).is_err());
        }
        assert!(component("odd'\"name").is_ok());
    }
}
