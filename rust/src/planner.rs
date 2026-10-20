use crate::{
    commands,
    config::Intent,
    model::{self, Grant, Kinds, ObservationGap, PlanInput, Unobserved},
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub system: String,
    pub title: String,
    pub detail: String,
    pub level: String,
    pub entities: Vec<String>,
}
impl Finding {
    pub fn new(system: &str, title: &str, detail: String, entities: Vec<String>) -> Self {
        let level = match title {
            "already covered by a broader grant"
            | "deny without a matching allow"
            | "excluded observation scope"
            | "unsupported observation scope" => "info",
            "unobserved scope"
            | "system could not be read"
            | "auth plane unreachable"
            | "policy document missing"
            | "policy evaluation incomplete"
            | "policy statement with an unknown effect"
            | "identity missing from the enforced plane"
            | "frozen ACL (owner locked out)"
            | "granted on paper, denied on the path"
            | "reachable, but no grant explains it" => "error",
            _ => "warning",
        };
        Self {
            system: system.into(),
            title: title.into(),
            detail,
            level: level.into(),
            entities,
        }
    }
}
#[derive(Debug, Serialize)]
pub struct Change {
    pub action: String,
    pub grant: Grant,
    pub cmd: Option<String>,
    pub command_error: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct Group {
    pub system: String,
    pub subject: String,
    pub grants: usize,
    pub revokes: usize,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub observation_complete: bool,
    pub commands_complete: bool,
    pub observed: BTreeSet<Grant>,
    pub changes: Vec<Change>,
    pub findings: Vec<Finding>,
    pub unverified: Vec<Grant>,
    pub groups: Vec<Group>,
    pub s3_previews: Vec<crate::s3::Preview>,
}
fn where_(gs: &[&Grant]) -> (String, Vec<String>) {
    let resources: BTreeSet<_> = gs.iter().map(|g| g.resource.clone()).collect();
    let shown: Vec<_> = resources.iter().take(3).cloned().collect();
    let mut label = shown.join(", ");
    if resources.len() > 3 {
        label += &format!(" (+{} more)", resources.len() - 3);
    }
    (label, shown)
}
pub fn build(
    intent: &Intent,
    observed: &BTreeSet<Grant>,
    unknown: &[Unobserved],
    kinds: &Kinds,
    mut findings: Vec<Finding>,
) -> Report {
    let raw = model::plan(PlanInput {
        kinds: kinds.clone(),
        intent: intent.grants.iter().cloned().collect(),
        observed: observed.iter().cloned().collect(),
        managed: intent.managed.clone(),
        managed_systems: intent.managed_systems.clone(),
        unobserved: unknown.into(),
        ..Default::default()
    });
    let declared: BTreeMap<_, _> = intent.grants.iter().map(|g| (g.key(), g)).collect();
    let held: BTreeMap<_, _> = observed.iter().map(|g| (g.key(), g)).collect();
    let unverified: Vec<_> = raw
        .unverified
        .iter()
        .map(|k| (*declared[k]).clone())
        .collect();
    let blind = |g: &Grant| unknown.iter().any(|u| u.blocks_change(g));
    for u in unknown {
        let n = unverified.iter().filter(|g| u.blocks_change(g)).count();
        let subjects = if u.subjects.is_empty() {
            String::new()
        } else {
            format!(
                "{}: ",
                u.subjects.iter().cloned().collect::<Vec<_>>().join(", ")
            )
        };
        let mut entities: Vec<_> = u.subjects.iter().cloned().collect();
        entities.extend(u.prefixes.iter().filter(|p| !p.is_empty()).cloned());
        entities.extend(u.privileges.iter().cloned());
        let title = match u.category {
            ObservationGap::Excluded if n == 0 => "excluded observation scope",
            ObservationGap::Unsupported if n == 0 => "unsupported observation scope",
            _ => "unobserved scope",
        };
        findings.push(Finding::new(&u.system,title,format!("{subjects}{}: {}. {n} intent grant(s) there are unverified — shown as '?', not planned. 'no access' and 'could not check' are different facts.",u.prefixes.join(", "),u.note),entities));
    }
    let mut visible: BTreeMap<(&str, &str), Vec<&Grant>> = BTreeMap::new();
    for g in observed.iter().filter(|g| !blind(g)) {
        visible.entry((&g.system, &g.subject)).or_default().push(g);
    }
    for g in intent.grants.difference(observed).filter(|g| !blind(g)) {
        if let Some(w) = visible
            .get(&(g.system.as_str(), g.subject.as_str()))
            .and_then(|held| held.iter().find(|h| model::covers(h, g, kinds)))
        {
            findings.push(Finding::new(&g.system,"already covered by a broader grant",format!("{}: {} on {} is declared, and {} on {} already covers it. No grant planned; the held privilege is wider than the declared one.",g.subject,g.privilege,g.resource,w.privilege,w.resource),vec![g.subject.clone(),g.privilege.clone(),g.resource.clone(),w.privilege.clone(),w.resource.clone()]));
        }
    }
    let described: BTreeSet<_> = intent
        .grants
        .iter()
        .map(|g| g.system.clone())
        .chain(intent.managed_systems.iter().cloned())
        .collect();
    let mut unmanaged: BTreeMap<(&str, &str), Vec<&Grant>> = BTreeMap::new();
    let mut undeclared = BTreeMap::new();
    for g in observed.difference(&intent.grants).filter(|g| !blind(g)) {
        if !intent.managed.contains(&g.subject) {
            unmanaged
                .entry((&g.system, &g.subject))
                .or_default()
                .push(g);
        } else if !described.contains(&g.system) {
            undeclared
                .entry((&g.system, &g.subject))
                .or_insert_with(Vec::new)
                .push(g);
        }
    }
    let group_roles: BTreeSet<_> = intent
        .grants
        .iter()
        .chain(observed)
        .filter(|g| g.privilege == "MEMBER")
        .filter_map(|g| g.resource.strip_prefix("role:"))
        .collect();
    for g in intent.grants.iter().filter(|g| {
        model::kind(&g.system, kinds) == "postgres" && g.resource.starts_with("default:")
    }) {
        if let Some((_, creator)) = g.resource.rsplit_once('@')
            && group_roles.contains(creator)
        {
            findings.push(Finding::new("postgres","default privileges on a group role",format!("{}: creator role '{creator}' has members, so its members' objects are NOT covered (owner is the member, not the group). Declare default privileges per creating role instead.",g.resource),vec![g.resource.clone(),creator.into()]));
        }
    }
    let mut roles: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for g in intent.grants.iter().chain(observed) {
        if let Some(role) = g.resource.strip_prefix("role:")
            && let Some((stem, suffix)) = role.rsplit_once('_')
        {
            roles.entry(stem.into()).or_default().insert(suffix.into());
        }
    }
    for (stem, suffixes) in roles {
        for group in &intent.naming_synonyms {
            let hit: Vec<_> = suffixes
                .iter()
                .filter(|s| group.contains(s))
                .cloned()
                .collect();
            if hit.len() > 1 {
                let list = hit
                    .iter()
                    .map(|s| format!("'{s}'"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let mut entities = vec![stem.clone()];
                entities.extend(hit);
                findings.push(Finding::new("*","naming drift",format!("role stem '{stem}' uses synonymous suffixes [{list}] — same concept, two names. Pick one and rename the other."),entities));
            }
        }
    }
    for ((system, subject), gs) in undeclared {
        let grade = model::level(&gs.iter().map(|g| g.privilege.clone()).collect());
        let (where_, shown) = where_(&gs);
        let mut entities = vec![subject.into(), system.into(), grade.into()];
        entities.extend(shown);
        findings.push(Finding::new(system,"undeclared system for a managed subject",format!("{subject} holds {} grant(s) up to {grade} on {where_} in '{system}', but the intent declares nothing for them there. Silence is not a mandate to revoke — declare it, or list '{system}' in managed_systems to say the system is fully described.",gs.len()),entities));
    }
    for ((system, subject), gs) in unmanaged {
        let grade = model::level(&gs.iter().map(|g| g.privilege.clone()).collect());
        let (where_, shown) = where_(&gs);
        let mut entities = vec![subject.into(), grade.into()];
        entities.extend(shown);
        findings.push(Finding::new(system,"unmanaged drift",format!("{subject} holds {} grant(s) up to {grade} on {where_}; the subject is not in managed_subjects so nothing is planned. Add it to manage it, or accept that this tool does not speak for it.",gs.len()),entities));
    }
    let mut groups: BTreeMap<(String, String), Group> = BTreeMap::new();
    let changes: Vec<_> = raw
        .changes
        .into_iter()
        .map(|(action, key)| {
            let grant = if action == "grant" {
                (*declared[&key]).clone()
            } else {
                (*held[&key]).clone()
            };
            let group = groups
                .entry((grant.system.clone(), grant.subject.clone()))
                .or_insert_with(|| Group {
                    system: grant.system.clone(),
                    subject: grant.subject.clone(),
                    grants: 0,
                    revokes: 0,
                });
            if action == "grant" {
                group.grants += 1;
            } else {
                group.revokes += 1;
            }
            let (cmd, command_error) =
                match commands::preview(&grant, &action, model::kind(&grant.system, kinds)) {
                    Ok(cmd) => (Some(cmd), None),
                    Err(e) => (None, Some(e)),
                };
            Change {
                action,
                grant,
                cmd,
                command_error,
            }
        })
        .collect();
    Report {
        observation_complete: unknown.is_empty(),
        commands_complete: changes.iter().all(|c| c.cmd.is_some()),
        observed: observed.clone(),
        changes,
        findings,
        unverified,
        groups: groups.into_values().collect(),
        s3_previews: Vec::new(),
    }
}

#[cfg(test)]
mod observation_tests {
    use super::*;
    #[test]
    fn expected_gaps_are_informational_until_declared_intent_is_unverified() {
        let gap = Unobserved {
            system: "postgres".into(),
            prefixes: vec!["table:scratch.".into()],
            category: ObservationGap::Excluded,
            note: "Configured exclusion".into(),
            ..Default::default()
        };
        let mut intent = Intent {
            grants: BTreeSet::new(),
            managed: BTreeSet::new(),
            managed_systems: BTreeSet::new(),
            naming_synonyms: vec![],
        };
        let report = build(
            &intent,
            &BTreeSet::new(),
            std::slice::from_ref(&gap),
            &Kinds::new(),
            vec![],
        );
        assert!(!report.observation_complete);
        assert_eq!(report.findings[0].level, "info");
        intent.grants.insert(Grant::new(
            "postgres",
            "alice",
            "table:scratch.public.events",
            "SELECT",
        ));
        let report = build(&intent, &BTreeSet::new(), &[gap], &Kinds::new(), vec![]);
        assert_eq!(report.unverified.len(), 1);
        assert!(report.changes.is_empty());
        assert_eq!(report.findings[0].level, "error");
    }
}
