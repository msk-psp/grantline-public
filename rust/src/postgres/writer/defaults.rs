//! Per-schema table defaults for the authenticated creator, with no role switching.
use super::*;

pub(super) const STATE: &str = "SELECT d.oid::bigint AS oid, d.defaclrole::bigint AS creator_oid, d.defaclnamespace::bigint AS schema_oid, c.rolname AS creator, n.nspname AS schema, d.defaclobjtype::text AS kind, d.defaclacl::text AS acl FROM pg_default_acl d LEFT JOIN pg_roles c ON c.oid=d.defaclrole LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace";

pub(super) fn target(g: &Grant, db: &str) -> Result<Target> {
    let (location, creator) = g
        .resource
        .strip_prefix("default:")
        .and_then(|s| s.split_once('@'))
        .ok_or("Default scope requires database.schema@creator")?;
    let parts: Vec<_> = location.split('.').collect();
    if parts.len() != 2 || parts[0] != db || creator.contains('@') {
        return Err("Default scope requires an exact selected database, schema and creator".into());
    }
    for value in [parts[0], parts[1], creator] {
        component(value)?;
        if value.contains(['?', '[', ']']) {
            return Err("Default write scopes must be literal".into());
        }
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
        return Err(
            "Default writer requires exact supported table privileges; ALL is unsupported".into(),
        );
    }
    Ok(Target::Default(parts[1].into(), creator.into()))
}

pub(super) fn command(
    g: &Grant,
    db: &str,
    cat: &Catalog,
    allowlist: &BTreeSet<String>,
    issuer: &str,
    action: Option<&str>,
    allow_public: bool,
) -> Result<Option<String>> {
    let t = target(g, db)?;
    let Target::Default(schema, creator) = &t else {
        unreachable!()
    };
    if !allowlist.contains(&g.resource) || creator != issuer {
        return Err("Default writes require literal default_write_scopes and the authenticated creator; no role switching".into());
    }
    let actor = cat
        .roles
        .iter()
        .find(|r| r.name == *creator)
        .ok_or("Default creator must exist")?;
    let schema = cat
        .schemas
        .iter()
        .find(|s| s.name == *schema)
        .ok_or("Default schema must already exist")?;
    let database = cat
        .databases
        .iter()
        .find(|d| d.name == db)
        .ok_or("Default database disappeared")?;
    let recipient = cat.roles.iter().find(|r| r.name == g.subject);
    if g.subject != "PUBLIC" && recipient.is_none() {
        return Err("Default recipient must already exist".into());
    }
    name(&g.subject)?;
    if actor.privileged
        || creator.starts_with("pg_")
        || recipient.is_some_and(|r| r.privileged)
        || g.subject.starts_with("pg_")
        || (g.subject == "PUBLIC" && !allow_public)
        || g.subject == *creator
        || g.subject == schema.owner
        || g.subject == database.owner
    {
        return Err("Default creator must be ordinary; PUBLIC/predefined/privileged/creator/owner recipients are unsupported".into());
    }
    if cat
        .default_acls
        .iter()
        .any(|(resource, _, _, grantor, grantable)| {
            resource == &g.resource && (grantor != creator || *grantable)
        })
    {
        return Err("Delegated or non-creator-issued default privileges are unsupported".into());
    }
    let Some(action) = action else {
        return Ok(None);
    };
    let (verb, to, tail) = match action {
        "grant" => ("GRANT", "TO", ""),
        "revoke" => ("REVOKE", "FROM", " RESTRICT"),
        _ => return Err("Unsupported default privilege action".into()),
    };
    Ok(Some(format!(
        "ALTER DEFAULT PRIVILEGES {} {verb} {} ON TABLES {to} {}{tail};",
        t.sql(),
        g.privilege,
        recipient_identifier(&g.subject)
    )))
}

// Changed table-default rows can disappear/reappear; every other raw row must stay identical.
pub(super) fn untouched(cat: &Catalog, plan: &planner::Report, db: &str) -> Result<Vec<Value>> {
    let scopes: BTreeSet<_> = plan
        .changes
        .iter()
        .filter(|c| c.grant.resource.starts_with("default:"))
        .map(|c| target(&c.grant, db))
        .collect::<Result<_>>()?;
    Ok(cat
        .default_state
        .iter()
        .filter(|r| {
            !scopes.iter().any(|t| match t {
                Target::Default(schema, creator) => {
                    r["kind"] == "r" && r["schema"] == *schema && r["creator"] == *creator
                }
                _ => false,
            })
        })
        .cloned()
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scopes_are_exact_and_sql_quotes_every_identifier() {
        let g = Grant::new(
            "pg",
            "odd\";user",
            "default:demo.odd\";schema@odd\";creator",
            "SELECT",
        );
        let t = target(&g, "demo").unwrap();
        assert_eq!(
            t.sql(),
            "FOR ROLE \"odd\"\";creator\" IN SCHEMA \"odd\"\";schema\""
        );
        for resource in [
            "default:other.app@creator",
            "default:demo.app",
            "default:demo.app@creator@other",
            "default:demo.app.extra@creator",
            "default:demo.*@creator",
            "default:demo.app?@creator",
            "default:demo.app@creator[1]",
        ] {
            assert!(
                target(&Grant::new("pg", "user", resource, "SELECT"), "demo").is_err(),
                "{resource}"
            );
        }
        assert!(
            target(
                &Grant::new("pg", "user", "default:demo.app@creator", "ALL"),
                "demo"
            )
            .is_err()
        );
    }
}
