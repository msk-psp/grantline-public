use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    hash::{Hash, Hasher},
};

pub type Kinds = BTreeMap<String, String>;
pub type GrantKey = [String; 4];

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Grant {
    pub system: String,
    pub subject: String,
    pub resource: String,
    #[serde(rename = "priv")]
    pub privilege: String,
    #[serde(default = "explicit")]
    pub source: String,
    #[serde(default)]
    pub grantor: Option<String>,
}
fn explicit() -> String {
    "explicit".into()
}
impl Grant {
    pub fn new(system: &str, subject: &str, resource: &str, privilege: &str) -> Self {
        Self {
            system: system.into(),
            subject: subject.into(),
            resource: resource.into(),
            privilege: privilege.into(),
            source: explicit(),
            grantor: None,
        }
    }
    pub fn normalized(mut self, kinds: &Kinds) -> Self {
        if kind(&self.system, kinds) == "s3"
            && let Some(body) = self.resource.strip_prefix("bucket:")
        {
            let body = body.trim_end_matches('*').trim_end_matches('/');
            self.resource = format!("bucket:{}", if body.is_empty() { "*" } else { body });
        }
        self
    }
    pub fn key(&self) -> GrantKey {
        [
            self.system.clone(),
            self.subject.clone(),
            self.resource.clone(),
            self.privilege.clone(),
        ]
    }
    fn identity(&self) -> (&str, &str, &str, &str) {
        (&self.system, &self.subject, &self.resource, &self.privilege)
    }
}
impl PartialEq for Grant {
    fn eq(&self, rhs: &Self) -> bool {
        self.identity() == rhs.identity()
    }
}
impl Eq for Grant {}
impl Ord for Grant {
    fn cmp(&self, rhs: &Self) -> Ordering {
        self.identity().cmp(&rhs.identity())
    }
}
impl PartialOrd for Grant {
    fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> {
        Some(self.cmp(rhs))
    }
}
impl Hash for Grant {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.identity().hash(state);
    }
}
pub fn kind<'a>(system: &'a str, kinds: &'a Kinds) -> &'a str {
    kinds.get(system).map(String::as_str).unwrap_or(system)
}

pub fn covers(held: &Grant, wanted: &Grant, kinds: &Kinds) -> bool {
    if held.system != wanted.system || held.subject != wanted.subject {
        return false;
    }
    let dialect = kind(&held.system, kinds);
    let privilege = held.privilege == wanted.privilege
        || matches!(
            held.privilege.to_uppercase().as_str(),
            "ALL" | "ALL PRIVILEGES"
        )
        || (dialect == "s3" && matches!(held.privilege.as_str(), "Admin" | "ADMIN"));
    if !privilege {
        return false;
    }
    if held.resource == wanted.resource {
        return true;
    }
    match dialect {
        "postgres" => held
            .resource
            .strip_prefix("table:")
            .zip(wanted.resource.strip_prefix("column:"))
            .is_some_and(|(table, column)| {
                table.split('.').count() == 3
                    && column.rsplit_once('.').is_some_and(|(parent, name)| {
                        parent == table && !name.is_empty() && !name.contains(['*', '?', '['])
                    })
            }),
        "clickhouse" => {
            held.resource == "global:*"
                || held
                    .resource
                    .strip_prefix("db:")
                    .zip(wanted.resource.strip_prefix("table:"))
                    .is_some_and(|(db, table)| table.starts_with(&format!("{db}.")))
        }
        "s3" => held
            .resource
            .strip_prefix("bucket:")
            .zip(wanted.resource.strip_prefix("bucket:"))
            .is_some_and(|(h, w)| {
                let h = h.trim_end_matches('*').trim_end_matches('/');
                let w = w.trim_end_matches('*').trim_end_matches('/');
                h.is_empty() || h == "*" || h == w || w.starts_with(&format!("{h}/"))
            }),
        _ => false,
    }
}

pub fn level(privs: &BTreeSet<String>) -> &'static str {
    if privs.is_empty() {
        "none"
    } else if privs.iter().any(|p| {
        matches!(
            p.as_str(),
            "ALL" | "OWNER" | "ADMIN" | "Admin" | "GRANT" | "BypassGovernanceRetention"
        )
    }) {
        "admin"
    } else if privs.iter().any(|p| {
        matches!(
            p.as_str(),
            "INSERT"
                | "UPDATE"
                | "DELETE"
                | "TRUNCATE"
                | "CREATE"
                | "TEMPORARY"
                | "ALTER"
                | "DROP"
                | "Write"
                | "WRITE"
                | "DeleteObjectVersion"
        )
    }) {
        "write"
    } else if privs.iter().all(|p| {
        matches!(
            p.as_str(),
            "ListAllMyBuckets" | "ListBucket" | "ListBucketVersions" | "GetBucketLocation"
        )
    }) {
        "list"
    } else {
        "read"
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Unobserved {
    pub system: String,
    pub prefixes: Vec<String>,
    #[serde(default)]
    pub subjects: BTreeSet<String>,
    #[serde(default)]
    pub note: String,
}
impl Unobserved {
    pub fn covers(&self, grant: &Grant) -> bool {
        grant.system == self.system
            && (self.subjects.is_empty() || self.subjects.contains(&grant.subject))
            && self.prefixes.iter().any(|p| {
                if p.starts_with("bucket:") && p != "bucket:" {
                    grant.resource == *p || grant.resource.starts_with(&format!("{p}/"))
                } else {
                    grant.resource.starts_with(p)
                }
            })
    }
}

#[derive(Default, Debug, Deserialize)]
pub struct PlanInput {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub kinds: Kinds,
    #[serde(default)]
    pub intent: Vec<Grant>,
    #[serde(default)]
    pub observed: Vec<Grant>,
    #[serde(default)]
    pub managed: BTreeSet<String>,
    #[serde(default)]
    pub managed_systems: BTreeSet<String>,
    #[serde(default)]
    pub unobserved: Vec<Unobserved>,
    #[serde(default)]
    pub pairs: Vec<[Grant; 2]>,
}
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct Plan {
    pub name: String,
    pub canonical_observed: Vec<GrantKey>,
    pub covers: Vec<bool>,
    pub changes: Vec<(String, GrantKey)>,
    pub unverified: Vec<GrantKey>,
}

pub fn plan(input: PlanInput) -> Plan {
    let normalize = |gs: Vec<Grant>| -> BTreeSet<Grant> {
        gs.into_iter().map(|g| g.normalized(&input.kinds)).collect()
    };
    let observed = normalize(input.observed);
    let intent = normalize(input.intent);
    let blind = |g: &&Grant| input.unobserved.iter().any(|u| u.covers(g));
    let unverified: BTreeSet<_> = intent.iter().filter(blind).cloned().collect();
    let visible_intent: BTreeSet<_> = intent.difference(&unverified).cloned().collect();
    let visible_observed: BTreeSet<_> = observed.iter().filter(|g| !blind(g)).cloned().collect();
    let described: BTreeSet<_> = intent
        .iter()
        .map(|g| g.system.clone())
        .chain(input.managed_systems)
        .collect();
    let mut by_subject: BTreeMap<(&str, &str), Vec<&Grant>> = BTreeMap::new();
    for g in &visible_observed {
        by_subject
            .entry((&g.system, &g.subject))
            .or_default()
            .push(g);
    }
    let mut changes = Vec::new();
    for g in visible_intent.difference(&visible_observed) {
        let covered = by_subject
            .get(&(g.system.as_str(), g.subject.as_str()))
            .is_some_and(|held| held.iter().any(|h| covers(h, g, &input.kinds)));
        if !covered {
            changes.push(("grant".into(), g.key()));
        }
    }
    for g in visible_observed.difference(&visible_intent) {
        if input.managed.contains(&g.subject) && described.contains(&g.system) {
            changes.push(("revoke".into(), g.key()));
        }
    }
    changes.sort();
    Plan {
        name: input.name,
        canonical_observed: observed.iter().map(Grant::key).collect(),
        covers: input
            .pairs
            .iter()
            .map(|[h, w]| {
                covers(
                    &h.clone().normalized(&input.kinds),
                    &w.clone().normalized(&input.kinds),
                    &input.kinds,
                )
            })
            .collect(),
        changes,
        unverified: unverified.iter().map(Grant::key).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn column_privileges_are_narrower_than_the_exact_parent_table() {
        let table = Grant::new("postgres", "demo", "table:db.s.events", "SELECT");
        let column = Grant::new("postgres", "demo", "column:db.s.events.a", "SELECT");
        assert!(covers(&table, &column, &Kinds::new()));
        assert!(!covers(&column, &table, &Kinds::new()));
        for (resource, privilege) in [
            ("column:db.s.events.b", "UPDATE"),
            ("column:db.s.events_extra.a", "SELECT"),
            ("column:db.s.events.", "SELECT"),
        ] {
            assert!(!covers(
                &table,
                &Grant::new("postgres", "demo", resource, privilege),
                &Kinds::new()
            ));
        }
        assert!(crate::commands::preview(&column, "grant", "postgres").is_err());
        assert!(crate::commands::preview(&column, "revoke", "postgres").is_err());
    }
    #[test]
    fn metadata_is_not_permission_identity() {
        let a = Grant::new("s3", "demo", "bucket:demo/team", "Read");
        let mut b = a.clone();
        b.source = "policy".into();
        b.grantor = Some("someone".into());
        assert_eq!(a, b);
        assert_eq!(BTreeSet::from([a, b]).len(), 1);
    }
    #[test]
    fn instances_and_prefix_boundaries_are_isolated() {
        let h = Grant::new("s3", "demo", "bucket:demo/team", "Read");
        assert!(!covers(
            &h,
            &Grant::new("s3", "demo", "bucket:demo/teamwork", "Read"),
            &Kinds::new()
        ));
        assert!(!covers(
            &h,
            &Grant::new("s3-staging", "demo", "bucket:demo/team/file", "Read"),
            &Kinds::new()
        ));
        assert!(!covers(
            &Grant::new("s3", "demo", "bucket:demo/team", "Write"),
            &h,
            &Kinds::new()
        ));
    }
    #[test]
    fn unknown_scopes_never_plan_a_grant_or_revoke() {
        let g = Grant::new("s3", "demo", "bucket:demo/team", "Read");
        let output = plan(PlanInput {
            intent: vec![g.clone()],
            observed: vec![g],
            managed: BTreeSet::from(["demo".into()]),
            unobserved: vec![Unobserved {
                system: "s3".into(),
                prefixes: vec!["bucket:demo".into()],
                ..Default::default()
            }],
            ..Default::default()
        });
        assert!(output.changes.is_empty());
        assert_eq!(output.unverified.len(), 1);
    }
}
