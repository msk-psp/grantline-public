//! Recorded grant changes select current routes; removed or invisible access is never drawn as live.
use crate::{
    Result, config,
    graph::Graph,
    model::Grant,
    snapshot::{self, Snapshot},
};
use chrono::{DateTime, FixedOffset};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

pub fn days(value: &str) -> Result<u16> {
    if value.is_empty()
        || value.len() > 4
        || value.starts_with('0')
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("Days must be a whole number between 1 and 3650".into());
    }
    value
        .parse::<u16>()
        .ok()
        .filter(|n| (1..=3650).contains(n))
        .ok_or_else(|| "Days must be a whole number between 1 and 3650".into())
}
pub fn apply(path: &Path, data: &mut Value, window: u16) -> Result<()> {
    let loaded = config::load(path)?;
    let dir = config::relative(&loaded.base, &loaded.config.snapshots)?;
    let files = snapshot::list(&dir)?;
    if files.len() > 1000 {
        return Err("Snapshot history limit exceeded".into());
    }
    let mut history = Vec::new();
    let mut bytes = 0;
    for file in files {
        let size = std::fs::metadata(&file)
            .map_err(|_| "Snapshot unavailable")?
            .len();
        bytes += size;
        if bytes > 128 * 1024 * 1024 {
            return Err("Recent history exceeds 128 MiB limit".into());
        }
        if size > 32 * 1024 * 1024 {
            return Err("Snapshot exceeds console limit".into());
        }
        history.push(Snapshot::load(&file, &loaded.kinds)?);
    }
    let mut graph: Graph =
        serde_json::from_value(data["graph"].clone()).map_err(|_| "Invalid observation graph")?;
    let current: Snapshot = serde_json::from_value(data["snapshot"].clone())
        .map_err(|_| "Invalid observation snapshot")?;
    let info = filter(&mut graph, &current, history, window)?;
    data["graph"] = serde_json::to_value(graph).map_err(|_| "Cannot encode recent graph")?;
    data["recent"] = info;
    Ok(())
}
fn filter(
    graph: &mut Graph,
    current: &Snapshot,
    mut history: Vec<Snapshot>,
    window: u16,
) -> Result<Value> {
    let now = current.ts;
    let cutoff = now - chrono::Duration::days(i64::from(window));
    history.retain(|s| s.ts <= now);
    history.sort_by_key(|s| s.ts);
    let baseline = history.iter().rposition(|s| s.ts <= cutoff);
    let start = baseline.unwrap_or(0);
    let mut observations: Vec<_> = history.iter().skip(start).collect();
    observations.push(current);
    let mut changed = BTreeSet::<Grant>::new();
    let mut removed = BTreeSet::new();
    for pair in observations.windows(2) {
        let delta = snapshot::compare(pair[0], pair[1]);
        changed.extend(delta.added);
        changed.extend(delta.removed.iter().cloned());
        removed.extend(delta.removed);
    }
    changed.retain(|g| current.grants.contains(g));
    let mut selected = BTreeSet::new();
    let mut forward_starts = BTreeSet::new();
    let mut reverse_starts = BTreeSet::new();
    for (seed, edge) in graph.edges.iter().enumerate() {
        let resource = if graph.hops.contains(&edge.dst) {
            format!("role:{}", edge.dst)
        } else {
            edge.dst.clone()
        };
        if !edge
            .privs
            .iter()
            .any(|p| changed.contains(&Grant::new(&edge.system, &edge.src, &resource, p)))
        {
            continue;
        }
        selected.insert(seed);
        reverse_starts.insert(&edge.src);
        forward_starts.insert(&edge.dst);
        if edge.kind == "flat" {
            forward_starts.insert(&edge.src);
        }
    }
    // Traverse the union once per direction, keeping sibling routes out of ordinary grants.
    for (starts, reverse) in [(reverse_starts, true), (forward_starts, false)] {
        let mut adjacency = BTreeMap::<&String, Vec<(usize, &String)>>::new();
        for (i, edge) in graph.edges.iter().enumerate() {
            let (a, b) = if reverse {
                (&edge.dst, &edge.src)
            } else {
                (&edge.src, &edge.dst)
            };
            adjacency.entry(a).or_default().push((i, b));
        }
        let mut pending: Vec<_> = starts.into_iter().collect();
        let mut seen = BTreeSet::new();
        while let Some(node) = pending.pop() {
            if !seen.insert(node) {
                continue;
            }
            for (i, next) in adjacency.get(node).into_iter().flatten() {
                selected.insert(*i);
                pending.push(*next);
            }
        }
    }
    let mut index = 0;
    graph.edges.retain(|_| {
        let keep = selected.contains(&index);
        index += 1;
        keep
    });
    let nodes: BTreeSet<_> = graph
        .edges
        .iter()
        .flat_map(|e| [e.src.clone(), e.dst.clone()])
        .collect();
    graph.principals.retain(|n| nodes.contains(n));
    graph.hops.retain(|n| nodes.contains(n));
    graph.terminals.retain(|n| nodes.contains(n));
    let first: Option<DateTime<FixedOffset>> = observations
        .first()
        .filter(|_| !history.is_empty())
        .map(|s| s.ts);
    Ok(
        json!({"days":window,"baseline":first,"observed_at":now,"complete":baseline.is_some(),"added":changed.len(),"removed":removed.len(),"observations":observations.len()}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    fn graph(snapshot: &Snapshot) -> Graph {
        Graph::build(
            &snapshot.grants,
            &[],
            &Default::default(),
            &[],
            &Default::default(),
        )
        .unwrap()
    }
    #[test]
    fn changes_keep_route_context_without_drawing_removed_or_unknown_access() {
        let member = Grant::new("pg", "alice", "role:reader", "MEMBER");
        let old = Grant::new("pg", "reader", "table:old", "SELECT");
        let new = Grant::new("pg", "reader", "table:new", "SELECT");
        let other = Grant::new("pg", "bob", "table:unrelated", "SELECT");
        let mut base = Snapshot::new(["pg".into()].into_iter().collect());
        base.ts = DateTime::parse_from_rfc3339("2026-10-01T00:00:00Z").unwrap();
        base.grants = [member, old, other].into_iter().collect();
        let mut current = base.clone();
        current.ts = base.ts + chrono::Duration::days(10);
        current.grants.insert(new);
        let mut g = graph(&current);
        let info = filter(&mut g, &current, vec![base.clone()], 7).unwrap();
        assert_eq!(g.edges.len(), 2);
        assert!(g.terminals.contains("table:new"));
        assert!(!g.principals.contains("bob"));
        assert_eq!(info["added"], 1);
        assert_eq!(info["complete"], true);
        let mut unread = current.clone();
        unread.grants.clear();
        unread.unobserved.push(crate::model::Unobserved {
            system: "pg".into(),
            prefixes: vec!["".into()],
            subjects: Default::default(),
            note: "offline".into(),
        });
        assert_eq!(
            filter(&mut graph(&unread), &unread, vec![base.clone()], 7).unwrap()["removed"],
            0
        );
        assert_eq!(
            filter(&mut graph(&current), &current, vec![], 7).unwrap()["added"],
            0
        );
        let recent = current.clone();
        let mut reverted = base.clone();
        reverted.ts = current.ts + chrono::Duration::days(1);
        let mut g = graph(&reverted);
        let info = filter(&mut g, &reverted, vec![base, recent], 7).unwrap();
        assert!(g.edges.is_empty());
        assert_eq!(info["removed"], 1);
        for invalid in ["", "0", "-1", "1.5", "0007", "3651"] {
            assert!(days(invalid).is_err());
        }
        assert_eq!(days("7").unwrap(), 7);
    }
}
