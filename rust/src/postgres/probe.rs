//! Fixed privilege inquiry SELECTs; no table rows, SET ROLE or permission writes.
use super::{component, config, connect, name};
use crate::{
    Result,
    config::Adapter,
    model::Grant,
    probe::{Probe, Verdict},
};
use std::{collections::BTreeMap, time::Duration};

const HOW: &str = "server-evaluated (has_*_privilege), not a login";
const LOGIN_HOW: &str = "subject TCP login + server-evaluated ACL (no data read or write)";
struct Target {
    db: Option<String>,
    sql: &'static str,
    object: String,
    column: Option<String>,
}
fn target(g: &Grant) -> Result<Target> {
    name(&g.subject)?;
    if g.subject.len() > 63 {
        return Err("PostgreSQL subject exceeds identifier byte limit".into());
    }
    if g.subject == "PUBLIC" {
        return Err("PUBLIC pseudo-role probes are unsupported".into());
    }
    let (kind, rest) = g
        .resource
        .split_once(':')
        .ok_or("Invalid PostgreSQL resource")?;
    let (db, object, sql, allowed): (Option<String>, String, &str, &[&str]) = match kind {
        "role" => {
            name(rest)?;
            if rest.len() > 63 {
                return Err("PostgreSQL role exceeds identifier byte limit".into());
            }
            (
                None,
                rest.into(),
                "SELECT pg_catalog.pg_has_role($1::name, $2::name, 'MEMBER')",
                &["MEMBER"],
            )
        }
        "db" => {
            component(rest)?;
            (
                Some(rest.into()),
                rest.into(),
                "SELECT pg_catalog.has_database_privilege($1::name, $2::text, $3::text)",
                &["CONNECT", "CREATE", "TEMPORARY"],
            )
        }
        "schema" => {
            let (db, schema) = rest.split_once('.').ok_or("Invalid schema resource")?;
            component(db)?;
            component(schema)?;
            (
                Some(db.into()),
                schema.into(),
                "SELECT pg_catalog.has_schema_privilege($1::name, $2::text, $3::text)",
                &["USAGE", "CREATE"],
            )
        }
        "table" | "column" => {
            let parts: Vec<_> = rest.split('.').collect();
            if parts.len() != if kind == "column" { 4 } else { 3 } {
                return Err("Invalid table/column resource".into());
            }
            for part in &parts {
                component(part)?;
                if part.len() > 63 {
                    return Err("PostgreSQL table component exceeds identifier byte limit".into());
                }
            }
            (
                Some(parts[0].into()),
                format!(
                    "\"{}\".\"{}\"",
                    parts[1].replace('"', "\"\""),
                    parts[2].replace('"', "\"\"")
                ),
                if kind == "column" {
                    "SELECT pg_catalog.has_column_privilege($1::name, $2::text, $3::text, $4::text)"
                } else {
                    "SELECT pg_catalog.has_table_privilege($1::name, $2::text, $3::text)"
                },
                if kind == "column" {
                    &["SELECT", "INSERT", "UPDATE", "REFERENCES"]
                } else {
                    &[
                        "SELECT",
                        "INSERT",
                        "UPDATE",
                        "DELETE",
                        "TRUNCATE",
                        "REFERENCES",
                        "TRIGGER",
                        "MAINTAIN",
                    ]
                },
            )
        }
        _ => return Err("No native evaluator for this resource kind".into()),
    };
    if !allowed.contains(&g.privilege.as_str()) {
        return Err("Unsupported privilege for PostgreSQL resource kind".into());
    }
    let column = if kind == "column" {
        rest.rsplit_once('.').map(|(_, c)| c.to_owned())
    } else {
        None
    };
    Ok(Target {
        db,
        sql,
        object,
        column,
    })
}
fn included(adapter: &Adapter, db: &str) -> Result<bool> {
    let matches = |patterns: &[String]| -> Result<bool> {
        let patterns = patterns
            .iter()
            .map(|p| {
                glob::Pattern::new(p).map_err(|_| "Invalid database selection glob".to_owned())
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(patterns.iter().any(|p| p.matches(db)))
    };
    Ok(matches(&adapter.databases)? && !matches(&adapter.exclude_databases)?)
}
async fn evaluate(adapter: &Adapter, grants: &[Grant]) -> Result<Vec<Probe>> {
    let mut out = Vec::new();
    let mut groups = BTreeMap::new();
    for g in grants {
        let t = match target(g) {
            Ok(t) => t,
            Err(reason) => {
                out.push(Probe::new(g, Verdict::Unknown, &reason));
                continue;
            }
        };
        if let Some(db) = &t.db
            && !included(adapter, db)?
        {
            out.push(Probe::new(
                g,
                Verdict::Unknown,
                "Database excluded from configured probe scope",
            ));
            continue;
        }
        let login = adapter.probe_dsn_envs.contains_key(&g.subject);
        // Observer DB privilege checks use its maintenance DB; subject checks log into the target DB.
        let db = if g.resource.starts_with("db:") && !login {
            None
        } else {
            t.db.clone()
        };
        groups
            .entry((db, if login { Some(g.subject.clone()) } else { None }))
            .or_insert_with(Vec::new)
            .push((g, t));
    }
    if groups.len() > 128 {
        return Err("PostgreSQL probes exceed 128 connection groups".into());
    }
    for ((db, subject), targets) in groups {
        let connection: Result<tokio_postgres::Client> = async {
            let key = if let Some(subject) = &subject {
                adapter.probe_dsn_envs.get(subject)
            } else {
                adapter.dsn_env.as_ref()
            }
            .filter(|k| !k.is_empty())
            .ok_or("PostgreSQL probe credential is not configured")?;
            let raw =
                std::env::var(key).map_err(|_| "PostgreSQL probe credential is unavailable")?;
            let mut cfg = config(&raw, adapter.read_timeout_seconds)?;
            if let Some(db) = &db {
                cfg.dbname(db);
            }
            let client = connect(&cfg, adapter.ca_bundle_env.as_deref()).await?;
            if let Some(subject) = &subject {
                let row = client
                    .query_one("SELECT session_user::text, current_user::text", &[])
                    .await
                    .map_err(|_| "Subject login identity could not be verified")?;
                let session: &str = row
                    .try_get(0)
                    .map_err(|_| "Invalid login identity response")?;
                let current: &str = row
                    .try_get(1)
                    .map_err(|_| "Invalid login identity response")?;
                if session != subject || current != subject {
                    return Err("Credential does not log in as the requested subject".into());
                }
            }
            Ok(client)
        }
        .await;
        let client = match connection {
            Ok(client) => client,
            Err(reason) => {
                out.extend(
                    targets
                        .iter()
                        .map(|(g, _)| Probe::new(g, Verdict::Unknown, &reason)),
                );
                continue;
            }
        };
        let how = if subject.is_some() { LOGIN_HOW } else { HOW };
        for (g, t) in targets {
            // An invalid/missing role or object must not poison subsequent evaluations.
            client
                .batch_execute("SAVEPOINT grantline_probe")
                .await
                .map_err(|_| "Cannot isolate PostgreSQL evaluation")?;
            let params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
                if g.resource.starts_with("role:") {
                    vec![&g.subject, &t.object]
                } else if let Some(column) = &t.column {
                    vec![&g.subject, &t.object, column, &g.privilege]
                } else {
                    vec![&g.subject, &t.object, &g.privilege]
                };
            let value = client
                .query_one(t.sql, &params)
                .await
                .ok()
                .and_then(|row| row.try_get::<_, Option<bool>>(0).ok())
                .flatten();
            client
                .batch_execute(
                    "ROLLBACK TO SAVEPOINT grantline_probe; RELEASE SAVEPOINT grantline_probe",
                )
                .await
                .map_err(|_| "Cannot recover PostgreSQL evaluation transaction")?;
            out.push(match value {
                Some(true) => Probe::new(g, Verdict::Allow, how),
                Some(false) => Probe::new(g, Verdict::Deny, how),
                None => Probe::new(
                    g,
                    Verdict::Unknown,
                    "ACL evaluation failed or returned no verdict; server details withheld",
                ),
            });
        }
    }
    out.sort_by(|a, b| {
        (&a.system, &a.subject, &a.resource, &a.privilege).cmp(&(
            &b.system,
            &b.subject,
            &b.resource,
            &b.privilege,
        ))
    });
    Ok(out)
}
pub fn run(adapter: &Adapter, grants: &[Grant]) -> Vec<Probe> {
    if grants.len() > 1000 || !(1..=120).contains(&adapter.read_timeout_seconds) {
        return grants
            .iter()
            .map(|g| Probe::new(g, Verdict::Unknown, "Invalid probe count or deadline limit"))
            .collect();
    }
    let result = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| "Cannot create PostgreSQL probe runtime")?;
                let result = runtime.block_on(async {
                    tokio::time::timeout(
                        Duration::from_secs(adapter.read_timeout_seconds),
                        evaluate(adapter, grants),
                    )
                    .await
                    .map_err(|_| "PostgreSQL probe deadline exceeded".to_owned())?
                });
                runtime.shutdown_background();
                result
            })
            .join()
            .map_err(|_| "PostgreSQL probe failed".to_owned())?
    });
    match result {
        Ok(out) => out,
        Err(reason) => grants
            .iter()
            .map(|g| Probe::new(g, Verdict::Unknown, &reason))
            .collect(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn group_limit_precedes_any_credential_lookup() {
        let adapter: Adapter = toml::from_str("type='postgres'").unwrap();
        let grants: Vec<_> = (0..129)
            .map(|i| Grant::new("pg", "alice", &format!("schema:demo{i}.public"), "USAGE"))
            .collect();
        let result = run(&adapter, &grants);
        assert_eq!(result.len(), 129);
        assert!(
            result
                .iter()
                .all(|p| p.verdict == Verdict::Unknown && p.how.contains("128 connection groups"))
        );
    }
    #[test]
    fn fixed_evaluators_and_quoted_names() {
        let g = Grant::new("pg", "a'--", "table:demo.odd\"schema.t\"able", "SELECT");
        let t = target(&g).unwrap();
        assert_eq!(t.object, "\"odd\"\"schema\".\"t\"\"able\"");
        assert!(!t.sql.contains(&g.subject));
        let column = target(&Grant::new(
            "pg",
            "a'--",
            "column:demo.odd\"schema.t\"able.c'--",
            "SELECT",
        ))
        .unwrap();
        assert_eq!(column.object, t.object);
        assert_eq!(column.column.as_deref(), Some("c'--"));
        assert_eq!(
            column.sql,
            "SELECT pg_catalog.has_column_privilege($1::name, $2::text, $3::text, $4::text)"
        );
        assert!(target(&Grant::new("pg", &"a".repeat(64), "db:demo", "CONNECT")).is_err());
        assert!(
            target(&Grant::new(
                "pg",
                "alice",
                &format!("role:{}", "a".repeat(64)),
                "MEMBER"
            ))
            .is_err()
        );
        for (subject, resource, privilege) in [
            ("PUBLIC", "db:demo", "CONNECT"),
            ("alice", "table:demo.public.*", "SELECT"),
            ("alice", "schema:demo.public", "SELECT"),
            ("alice", "default:demo.public@owner", "SELECT"),
            ("alice", "table:demo.public.events", "ALL"),
            ("alice", "role:reader", "SELECT"),
            ("alice", "column:demo.public.events", "SELECT"),
            ("alice", "column:demo.public.events.a", "DELETE"),
        ] {
            assert!(target(&Grant::new("pg", subject, resource, privilege)).is_err());
        }
    }
}
