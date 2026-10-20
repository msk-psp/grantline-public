use crate::{Result, model::Grant};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub type Route = [String; 4];
#[derive(Clone, Debug, Deserialize)]
pub struct Bridge {
    pub from: String,
    pub to: String,
    #[serde(default = "any_system")]
    pub system: String,
    #[serde(default)]
    pub note: String,
}
fn any_system() -> String {
    "*".into()
}
#[derive(Clone, Debug, Deserialize)]
pub struct GraphConfig {
    #[serde(default = "services")]
    pub services: Vec<String>,
    #[serde(default)]
    pub people: BTreeMap<String, String>,
    #[serde(default)]
    pub teams: BTreeMap<String, String>,
    #[serde(default)]
    pub environments: indexmap::IndexMap<String, Vec<String>>,
}
fn services() -> Vec<String> {
    vec!["svc-*".into()]
}
impl Default for GraphConfig {
    fn default() -> Self {
        Self {
            services: services(),
            people: Default::default(),
            teams: Default::default(),
            environments: Default::default(),
        }
    }
}
impl GraphConfig {
    pub fn validate(&self) -> Result<()> {
        for pattern in &self.services {
            glob::Pattern::new(pattern).map_err(|_| "Invalid graph service glob")?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Edge {
    pub src: String,
    pub dst: String,
    pub system: String,
    pub privs: BTreeSet<String>,
    pub kind: String,
    pub note: String,
}
impl Edge {
    pub fn label(&self) -> String {
        if self.kind == "bridge" {
            return if self.note.is_empty() {
                "bridge".into()
            } else {
                self.note.clone()
            };
        }
        let mut label = self
            .privs
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        if self.privs.len() > 3 {
            label += &format!(" +{}", self.privs.len() - 3);
        }
        label
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Graph {
    pub edges: Vec<Edge>,
    pub principals: BTreeSet<String>,
    pub hops: BTreeSet<String>,
    pub terminals: BTreeSet<String>,
    pub kind: BTreeMap<String, String>,
    pub names: BTreeMap<String, String>,
    pub envs: BTreeMap<String, Vec<String>>,
    pub teams: BTreeMap<String, String>,
    #[serde(default)]
    pub homes: BTreeMap<String, BTreeSet<String>>,
}
#[derive(Debug, Serialize)]
pub struct Paths {
    pub paths: Vec<Vec<String>>,
    pub truncated: bool,
}
impl Graph {
    pub fn build(
        grants: &BTreeSet<Grant>,
        bridges: &[Bridge],
        kinds: &BTreeMap<String, String>,
        routes: &[Route],
        cfg: &GraphConfig,
    ) -> Result<Self> {
        let patterns: Vec<_> = cfg
            .services
            .iter()
            .map(|p| glob::Pattern::new(p))
            .collect::<std::result::Result<_, _>>()
            .map_err(|_| "Invalid graph service glob")?;
        let mut subjects: BTreeSet<_> = grants
            .iter()
            .map(|g| g.subject.clone())
            .chain(bridges.iter().map(|b| b.from.clone()))
            .chain(kinds.keys().cloned())
            .collect();
        for [_, src, dst, _] in routes {
            subjects.insert(src.clone());
            if !dst.starts_with("bucket:") {
                subjects.insert(dst.clone());
            }
        }
        let routed: BTreeSet<_> = routes
            .iter()
            .map(|[s, src, _, _]| (s.as_str(), src.as_str()))
            .collect();
        let mut merged: BTreeMap<(String, String, String), Edge> = BTreeMap::new();
        for g in grants {
            let dst = g
                .resource
                .strip_prefix("role:")
                .filter(|r| subjects.contains(*r))
                .unwrap_or(&g.resource)
                .to_owned();
            let kind = if routed.contains(&(g.system.as_str(), g.subject.as_str()))
                && !dst.starts_with("role:")
            {
                "flat"
            } else {
                "grant"
            };
            merged
                .entry((g.subject.clone(), dst.clone(), g.system.clone()))
                .or_insert_with(|| Edge {
                    src: g.subject.clone(),
                    dst,
                    system: g.system.clone(),
                    privs: Default::default(),
                    kind: kind.into(),
                    note: String::new(),
                })
                .privs
                .insert(g.privilege.clone());
        }
        for [system, src, dst, note] in routes {
            merged
                .entry((src.clone(), dst.clone(), system.clone()))
                .or_insert_with(|| Edge {
                    src: src.clone(),
                    dst: dst.clone(),
                    system: system.clone(),
                    privs: Default::default(),
                    kind: "route".into(),
                    note: note.clone(),
                });
        }
        for b in bridges {
            merged.insert(
                (b.from.clone(), b.to.clone(), b.system.clone()),
                Edge {
                    src: b.from.clone(),
                    dst: b.to.clone(),
                    system: b.system.clone(),
                    privs: Default::default(),
                    kind: "bridge".into(),
                    note: b.note.clone(),
                },
            );
        }
        let edges: Vec<_> = merged.into_values().collect();
        // An observed identity exists even when its privileges are empty or unread.
        let srcs: BTreeSet<_> = edges
            .iter()
            .map(|e| e.src.clone())
            .chain(kinds.keys().cloned())
            .collect();
        let dsts: BTreeSet<_> = edges.iter().map(|e| e.dst.clone()).collect();
        let principals: BTreeSet<_> = srcs.difference(&dsts).cloned().collect();
        let hops = srcs.intersection(&dsts).cloned().collect();
        let terminals = dsts.difference(&srcs).cloned().collect();
        let mut kind = BTreeMap::new();
        for node in srcs.union(&dsts) {
            let svc = patterns.iter().any(|p| p.matches(node));
            let k = if node.starts_with("service:") {
                Some("service")
            } else {
                match kinds.get(node).map(String::as_str) {
                    Some("account") => Some(if svc { "svc-account" } else { "human" }),
                    None if principals.contains(node) => {
                        Some(if svc { "service" } else { "human" })
                    }
                    other => other,
                }
            };
            if let Some(k @ ("human" | "service" | "svc-account" | "role" | "group" | "policy")) = k
            {
                kind.insert(node.clone(), k.into());
            }
        }
        let mut envs: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (env, systems) in &cfg.environments {
            for s in systems {
                envs.entry(s.clone()).or_default().push(env.clone());
            }
        }
        let mut homes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for e in &edges {
            for node in [&e.src, &e.dst] {
                homes
                    .entry(node.clone())
                    .or_default()
                    .insert(e.system.clone());
            }
        }
        Ok(Self {
            edges,
            principals,
            hops,
            terminals,
            kind,
            names: cfg
                .people
                .iter()
                .filter(|(_, v)| !v.is_empty())
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            envs,
            teams: cfg.teams.clone(),
            homes,
        })
    }
    pub fn kind_of(&self, node: &str) -> &str {
        self.kind
            .get(node)
            .map(String::as_str)
            .unwrap_or(if self.hops.contains(node) {
                "role"
            } else {
                "human"
            })
    }
    pub fn env_of(&self, system: &str) -> Vec<String> {
        self.envs.get(system).cloned().unwrap_or_else(|| {
            vec![
                if system.contains("staging") {
                    "staging"
                } else {
                    "prod"
                }
                .into(),
            ]
        })
    }
    pub fn label(&self, node: &str) -> String {
        self.names
            .get(node)
            .map(|n| format!("{node} ({n})"))
            .unwrap_or_else(|| node.into())
    }
    pub fn paths(&self, node: &str, reverse: bool, limit: usize) -> Paths {
        let mut out = Vec::new();
        let mut work = vec![(node.to_owned(), Vec::<String>::new())];
        let mut steps = 0;
        while let Some((node, mut trail)) = work.pop() {
            if trail.contains(&node) {
                continue;
            }
            if out.len() >= limit || steps >= 100_000 {
                return Paths {
                    paths: out,
                    truncated: true,
                };
            }
            steps += 1;
            if reverse {
                trail.insert(0, node.clone());
            } else {
                trail.push(node.clone());
            }
            let children: Vec<_> = self
                .edges
                .iter()
                .filter_map(|e| {
                    if reverse && e.dst == node {
                        Some(e.src.clone())
                    } else if !reverse && e.src == node {
                        Some(e.dst.clone())
                    } else {
                        None
                    }
                })
                .collect();
            if children.is_empty() {
                if reverse || trail.len() > 1 {
                    out.push(trail);
                }
            } else {
                for child in children.into_iter().rev() {
                    work.push((child, trail.clone()));
                }
            }
        }
        Paths {
            paths: out,
            truncated: false,
        }
    }
    pub fn depth(&self, node: &str) -> Result<usize> {
        let mut work = vec![(node.to_owned(), BTreeSet::new(), 0)];
        let mut longest = 0;
        let mut steps = 0;
        while let Some((node, mut seen, depth)) = work.pop() {
            steps += 1;
            if steps > 100_000 {
                return Err("Graph depth traversal exceeded its work budget".into());
            }
            if !seen.insert(node.clone()) {
                longest = longest.max(depth);
                continue;
            }
            let parents: Vec<_> = self.edges.iter().filter(|e| e.dst == node).collect();
            if parents.is_empty() {
                longest = longest.max(depth);
            } else {
                for p in parents {
                    work.push((p.src.clone(), seen.clone(), depth + 1));
                }
            }
        }
        Ok(longest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_entities_need_no_grants_but_labels_alone_are_not_inventory() {
        let cfg = GraphConfig {
            people: BTreeMap::from([("not-observed".into(), "Name only".into())]),
            ..Default::default()
        };
        let kinds = [
            ("alice", "account"),
            ("svc-empty", "account"),
            ("group:empty", "group"),
            ("policy:empty", "policy"),
            ("reader", "role"),
        ]
        .into_iter()
        .map(|(a, b)| (a.into(), b.into()))
        .collect();
        let graph = Graph::build(&BTreeSet::new(), &[], &kinds, &[], &cfg).unwrap();
        assert_eq!(graph.principals.len(), 5);
        assert!(graph.edges.is_empty());
        assert!(!graph.principals.contains("not-observed"));
        assert_eq!(graph.kind_of("svc-empty"), "svc-account");
        assert_eq!(graph.kind_of("group:empty"), "group");
        assert_eq!(graph.kind_of("policy:empty"), "policy");
    }
}
