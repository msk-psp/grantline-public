//! Read-only verification results. Unknown is neither agreement nor denial.
use crate::{model::Grant, planner::Finding};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Deny,
    Unknown,
}
#[derive(Debug, Serialize)]
pub struct Probe {
    pub system: String,
    pub subject: String,
    pub resource: String,
    #[serde(rename = "priv")]
    pub privilege: String,
    pub verdict: Verdict,
    pub how: String,
}
impl Probe {
    pub fn new(g: &Grant, verdict: Verdict, how: &str) -> Self {
        Self {
            system: g.system.clone(),
            subject: g.subject.clone(),
            resource: g.resource.clone(),
            privilege: g.privilege.clone(),
            verdict,
            how: how.into(),
        }
    }
}
pub fn summary(probes: &[Probe]) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::from([("allow", 0), ("deny", 0), ("unknown", 0)]);
    for p in probes {
        *counts
            .get_mut(match p.verdict {
                Verdict::Allow => "allow",
                Verdict::Deny => "deny",
                Verdict::Unknown => "unknown",
            })
            .unwrap() += 1;
    }
    counts
}
pub fn compare(probes: &[Probe], observed: &BTreeSet<Grant>) -> Vec<Finding> {
    probes
        .iter()
        .filter_map(|p| {
            let g = Grant::new(&p.system, &p.subject, &p.resource, &p.privilege);
            let title = match p.verdict {
                Verdict::Deny if observed.contains(&g) => "granted on paper, denied on the path",
                Verdict::Allow if !observed.contains(&g) => "reachable, but no grant explains it",
                _ => return None,
            };
            Some(Finding::new(
                &p.system,
                title,
                format!("{} {} on {}: {}", p.subject, p.privilege, p.resource, p.how),
                vec![p.subject.clone(), p.privilege.clone(), p.resource.clone()],
            ))
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_definite_verdicts_disagree() {
        let held = Grant::new("pg", "alice", "db:demo", "CONNECT");
        let absent = Grant::new("pg", "bob", "db:demo", "CONNECT");
        let probes = [
            Probe::new(&held, Verdict::Deny, "ACL"),
            Probe::new(&held, Verdict::Unknown, "unavailable"),
            Probe::new(&absent, Verdict::Allow, "ACL"),
        ];
        let findings = compare(&probes, &BTreeSet::from([held]));
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].title, "granted on paper, denied on the path");
        assert_eq!(findings[1].title, "reachable, but no grant explains it");
        assert!(findings.iter().all(|f| f.level == "error"));
        assert_eq!(
            summary(&probes),
            BTreeMap::from([("allow", 1), ("deny", 1), ("unknown", 1)])
        );
    }
}
