//! Expand server-defined aliases/groups into exact ACL atoms at the requested scope.
use super::*;

pub(super) fn expand(tree: &[Value], privilege: &str, resource: &str) -> Result<Vec<String>> {
    let root = tree
        .iter()
        .find(|r| {
            r["privilege"]
                .as_str()
                .is_some_and(|p| p.eq_ignore_ascii_case(privilege))
                || r["aliases"].as_array().is_some_and(|a| {
                    a.iter().any(|p| {
                        p.as_str()
                            .is_some_and(|p| p.eq_ignore_ascii_case(privilege))
                    })
                })
        })
        .and_then(|r| r["privilege"].as_str())
        .ok_or("Privilege is absent from the server catalog")?;
    let mut todo = vec![root.to_owned()];
    let mut seen = BTreeSet::new();
    let mut result = BTreeSet::new();
    while let Some(p) = todo.pop() {
        if !seen.insert(p.clone()) {
            continue;
        }
        let row = tree
            .iter()
            .find(|r| r["privilege"] == p)
            .ok_or("Incomplete privilege tree")?;
        if let Some(level) = row["level"].as_str() {
            let fits = resource == "global:*"
                || match level {
                    "GLOBAL" => resource == "global:*",
                    "DATABASE" => resource == "global:*" || resource.starts_with("db:"),
                    "TABLE" | "COLUMN" | "VIEW" | "DICTIONARY" => true,
                    _ => false,
                };
            if fits {
                if !p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b' ') {
                    return Err("Invalid privilege catalog token".into());
                }
                result.insert(p);
            }
        } else {
            todo.extend(
                tree.iter()
                    .filter(|r| r["parent_group"] == p)
                    .filter_map(|r| r["privilege"].as_str().map(str::to_owned)),
            );
        }
        if seen.len() > 1000 {
            return Err("Privilege tree exceeds limit".into());
        }
    }
    if result.is_empty() {
        return Err("Privilege is not valid at the requested scope".into());
    }
    Ok(result.into_iter().collect())
}
pub(super) fn rows(tree: &[Value], original: Vec<Value>) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for r in original {
        let resource = match (r["database"].as_str(), r["table"].as_str()) {
            (None, _) => "global:*".into(),
            (Some(db), None) => format!("db:{db}"),
            (Some(db), Some(t)) => format!("table:{db}.{t}"),
        };
        for privilege in expand(
            tree,
            r["access_type"].as_str().ok_or("Invalid ACL privilege")?,
            &resource,
        )? {
            let mut row = r.clone();
            row["access_type"] = json!(privilege);
            out.push(row);
        }
        if out.len() > 100000 {
            return Err("Expanded ACL catalog exceeds limit".into());
        }
    }
    let mut out = sorted(out);
    out.dedup();
    Ok(out)
}
pub(super) fn grants(tree: &[Value], grants: &BTreeSet<Grant>) -> Result<BTreeSet<Grant>> {
    let mut out = BTreeSet::new();
    for g in grants {
        if g.privilege == "MEMBER" {
            out.insert(g.clone());
            continue;
        }
        for privilege in expand(tree, &g.privilege, &g.resource)? {
            out.insert(Grant {
                privilege,
                ..g.clone()
            });
        }
        if out.len() > 100000 {
            return Err("Expanded grant set exceeds limit".into());
        }
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aliases_expand_only_to_scope_appropriate_leaf_permissions() {
        let tree = vec![
            json!({"privilege":"ALL","level":null,"parent_group":null}),
            json!({"privilege":"ALTER","level":null,"parent_group":"ALL"}),
            json!({"privilege":"ALTER ADD COLUMN","level":"COLUMN","parent_group":"ALTER"}),
            json!({"privilege":"CREATE DATABASE","level":"DATABASE","parent_group":"ALL"}),
            json!({"privilege":"dictGet","aliases":["DICTGET"],"level":"DICTIONARY","parent_group":"ALL"}),
        ];
        assert_eq!(
            expand(&tree, "ALTER", "table:demo.t").unwrap(),
            vec!["ALTER ADD COLUMN"]
        );
        assert!(
            !expand(&tree, "ALL", "table:demo.t")
                .unwrap()
                .contains(&"CREATE DATABASE".into())
        );
        assert!(
            expand(&tree, "ALL", "db:demo")
                .unwrap()
                .contains(&"CREATE DATABASE".into())
        );
        assert_eq!(
            expand(&tree, "DICTGET", "table:demo.d").unwrap(),
            vec!["dictGet"]
        );
    }
}
