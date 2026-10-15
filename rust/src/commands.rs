//! SQL previews only: no connection or execution path is present in R2.
use crate::{Result, model::Grant};
fn ident(name: &str, dialect: &str, public: bool) -> Result<String> {
    if name.is_empty() || name.chars().any(|c| (c as u32) < 32) {
        return Err("Empty identifier or control character".into());
    }
    if dialect == "postgres" {
        Ok(if public && name == "PUBLIC" {
            name.into()
        } else {
            format!("\"{}\"", name.replace('"', "\"\""))
        })
    } else {
        Ok(format!(
            "`{}`",
            name.replace('\\', "\\\\").replace('`', "\\`")
        ))
    }
}
pub fn preview(g: &Grant, action: &str, dialect: &str) -> Result<String> {
    let (verb, to) = match action {
        "grant" => ("GRANT", "TO"),
        "revoke" => ("REVOKE", "FROM"),
        _ => return Err("Unknown change action".into()),
    };
    if !matches!(dialect, "postgres" | "clickhouse") {
        return Err("Native command generation requires the R3 adapter".into());
    }
    let (scope, rest) = g.resource.split_once(':').ok_or("Unsupported resource")?;
    let priv_ = g.privilege.to_uppercase();
    let allowed: &[&str] = match (dialect, scope) {
        (_, "role") => &["MEMBER"],
        ("postgres", "db") => &["CONNECT", "CREATE", "TEMP", "TEMPORARY", "ALL"],
        ("postgres", "schema") => &["USAGE", "CREATE", "ALL"],
        ("postgres", "table" | "default") => &[
            "SELECT",
            "INSERT",
            "UPDATE",
            "DELETE",
            "TRUNCATE",
            "REFERENCES",
            "TRIGGER",
            "MAINTAIN",
            "ALL",
        ],
        ("clickhouse", _) => &[
            "SELECT", "INSERT", "ALTER", "CREATE", "DROP", "SHOW", "OPTIMIZE", "DICTGET", "ALL",
        ],
        _ => &[],
    };
    if !allowed.contains(&priv_.as_str()) {
        return Err("Unsupported privilege for this resource".into());
    }
    let p = if priv_ == "DICTGET" && dialect == "clickhouse" {
        "dictGet"
    } else {
        &priv_
    };
    let id = |s: &str| ident(s, dialect, false);
    let subject = ident(&g.subject, dialect, true)?;
    if scope == "role" {
        return Ok(format!("{verb} {} {to} {subject};", id(rest)?));
    }
    if dialect == "clickhouse" {
        let on = match scope {
            "db" => format!("{}.*", id(rest)?),
            "table" => {
                let (db, table) = rest.split_once('.').ok_or("Expected database.table")?;
                format!("{}.{}", id(db)?, id(table)?)
            }
            _ => return Err("Unsupported ClickHouse resource".into()),
        };
        return Ok(format!("{verb} {p} ON {on} {to} {subject};"));
    }
    if scope == "default" {
        let (location, creator) = rest
            .rsplit_once('@')
            .ok_or("Expected default scope@creator")?;
        let (db, schema) = location.split_once('.').ok_or("Expected database.schema")?;
        id(db)?;
        return Ok(format!(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA {} {verb} {p} ON TABLES {to} {subject};  -- in database {db}",
            id(creator)?,
            id(schema)?
        ));
    }
    let (target, note) = match scope {
        "db" => (format!("DATABASE {}", id(rest)?), String::new()),
        "schema" => {
            let (db, schema) = rest.split_once('.').ok_or("Expected database.schema")?;
            id(db)?;
            (
                format!("SCHEMA {}", id(schema)?),
                format!("  -- in database {db}"),
            )
        }
        "table" => {
            let mut parts = rest.splitn(3, '.');
            let db = parts.next().unwrap_or_default();
            let schema = parts.next().ok_or("Expected database.schema.table")?;
            let table = parts.next().ok_or("Expected database.schema.table")?;
            id(db)?;
            (
                format!("TABLE {}.{}", id(schema)?, id(table)?),
                format!("  -- in database {db}"),
            )
        }
        _ => return Err("Unsupported PostgreSQL resource".into()),
    };
    Ok(format!("{verb} {p} ON {target} {to} {subject};{note}"))
}
