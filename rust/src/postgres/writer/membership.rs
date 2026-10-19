//! Canonical, allowlisted role membership SQL. Role privileges are cluster-wide.
use super::*;

fn ancestors(cat: &Catalog, root: &str) -> BTreeSet<String> {
    let mut parents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for m in &cat.members {
        if m.inherit_option || m.set_option {
            parents.entry(&m.member).or_default().push(&m.role);
        }
    }
    let mut seen = BTreeSet::new();
    let mut pending = vec![root.to_owned()];
    while let Some(role) = pending.pop() {
        if seen.insert(role.clone()) {
            pending.extend(
                parents
                    .get(role.as_str())
                    .into_iter()
                    .flatten()
                    .map(|r| (*r).to_owned()),
            );
        }
    }
    seen
}
fn safe_ancestry(cat: &Catalog, root: &str) -> Result<()> {
    let reachable = ancestors(cat, root);
    let mut found = 0;
    for role in cat.roles.iter().filter(|r| reachable.contains(&r.name)) {
        found += 1;
        if role.privileged
            || role.name == "PUBLIC"
            || role.name.starts_with("pg_")
            || cat.owner_role_oids.contains(&role.oid)
        {
            return Err("Membership endpoint/ancestor is privileged, predefined or owns objects in the cluster".into());
        }
    }
    if found != reachable.len() {
        return Err("Unknown membership role".into());
    }
    if cat.members.iter().any(|m| {
        reachable.contains(&m.member) && (m.admin_option || !m.inherit_option || !m.set_option)
    }) {
        return Err("Membership ancestry has unsupported options or delegation".into());
    }
    Ok(())
}
pub(super) fn command(
    g: &Grant,
    cat: &Catalog,
    allowlist: &BTreeSet<String>,
    issuer: &str,
    action: Option<&str>,
) -> Result<Option<String>> {
    let role = g
        .resource
        .strip_prefix("role:")
        .ok_or("Expected role membership")?;
    name(role)?;
    name(&g.subject)?;
    if g.privilege != "MEMBER" || !allowlist.contains(role) || role.contains('*') {
        return Err(
            "Membership writes require literal membership_write_roles and MEMBER privilege".into(),
        );
    }
    let group = cat
        .roles
        .iter()
        .find(|r| r.name == role)
        .ok_or("Membership group must already exist")?;
    if group.login
        || role == g.subject
        || role == issuer
        || g.subject == issuer
        || ancestors(cat, issuer).contains(&g.subject)
    {
        return Err(
            "Login groups, self/writer membership and changes to writer authority are unsupported"
                .into(),
        );
    }
    safe_ancestry(cat, role)?;
    safe_ancestry(cat, &g.subject)?;
    let held: Vec<_> = cat
        .members
        .iter()
        .filter(|m| m.member == g.subject && m.role == role)
        .collect();
    if held.len() > 1
        || held
            .iter()
            .any(|m| m.admin_option || !m.inherit_option || !m.set_option)
    {
        return Err(
            "Membership has ambiguous grantors or noncanonical options; not rewritten".into(),
        );
    }
    let Some(action) = action else {
        return Ok(None);
    };
    if !cat
        .members
        .iter()
        .any(|m| m.member == issuer && m.role == role && m.admin_option)
    {
        return Err("Membership writer must directly hold ADMIN OPTION on the group".into());
    }
    let subject = identifier(&g.subject);
    let group = identifier(role);
    let grantor = identifier(issuer);
    Ok(Some(match action {
        "grant" if held.is_empty() => format!("GRANT {group} TO {subject} WITH ADMIN FALSE, INHERIT TRUE, SET TRUE GRANTED BY {grantor};"),
        "revoke" if held.len() == 1 && held[0].grantor == issuer => format!("REVOKE {group} FROM {subject} GRANTED BY {grantor} RESTRICT;"),
        _ => return Err("Membership change requires an absent edge or a single edge granted by the authenticated writer".into()),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn catalog() -> Catalog {
        let role = |name: &str, oid, login| WriterRole {
            name: name.into(),
            oid,
            login,
            privileged: false,
            privilege_flags: [false; 5],
            inherit: true,
        };
        Catalog {
            table_privileges: vec![],
            observed: Observed::default(),
            default_acls: BTreeSet::new(),
            default_state: vec![],
            tables: vec![],
            schemas: vec![],
            databases: vec![],
            acls: BTreeSet::new(),
            other: Value::Null,
            roles: vec![
                role("writer", 1, true),
                role("user\";name", 2, true),
                role("group\";name", 3, false),
            ],
            members: BTreeSet::from([Membership {
                member: "writer".into(),
                role: "group\";name".into(),
                grantor: "bootstrap".into(),
                inherit_option: false,
                set_option: false,
                admin_option: true,
            }]),
            owner_role_oids: BTreeSet::new(),
        }
    }
    #[test]
    fn options_grantor_and_quoting_are_explicit() {
        let mut cat = catalog();
        let g = Grant::new("pg", "user\";name", "role:group\";name", "MEMBER");
        let roles = BTreeSet::from(["group\";name".into()]);
        assert_eq!(
            command(&g, &cat, &roles, "writer", Some("grant"))
                .unwrap()
                .unwrap(),
            "GRANT \"group\"\";name\" TO \"user\"\";name\" WITH ADMIN FALSE, INHERIT TRUE, SET TRUE GRANTED BY \"writer\";"
        );
        assert!(command(&g, &cat, &BTreeSet::new(), "writer", Some("grant")).is_err());
        let m = Membership {
            member: g.subject.clone(),
            role: "group\";name".into(),
            grantor: "writer".into(),
            inherit_option: true,
            set_option: true,
            admin_option: false,
        };
        cat.members.insert(m.clone());
        assert_eq!(
            command(&g, &cat, &roles, "writer", Some("revoke"))
                .unwrap()
                .unwrap(),
            "REVOKE \"group\"\";name\" FROM \"user\"\";name\" GRANTED BY \"writer\" RESTRICT;"
        );
        cat.members.insert(Membership {
            grantor: "another".into(),
            ..m
        });
        assert!(command(&g, &cat, &roles, "writer", None).is_err());
    }
    #[test]
    fn owner_and_indirect_privilege_paths_are_refused() {
        let mut cat = catalog();
        let g = Grant::new("pg", "user\";name", "role:group\";name", "MEMBER");
        let roles = BTreeSet::from(["group\";name".into()]);
        cat.owner_role_oids.insert(3);
        assert!(command(&g, &cat, &roles, "writer", Some("grant")).is_err());
        cat.owner_role_oids.clear();
        cat.roles.push(WriterRole {
            name: "privileged".into(),
            oid: 4,
            login: false,
            privileged: true,
            privilege_flags: [true, false, false, false, false],
            inherit: true,
        });
        cat.members.insert(Membership {
            member: "group\";name".into(),
            role: "privileged".into(),
            grantor: "bootstrap".into(),
            inherit_option: true,
            set_option: true,
            admin_option: false,
        });
        assert!(command(&g, &cat, &roles, "writer", Some("grant")).is_err());
    }
}
