#[cfg(any(feature = "hydrate", test))]
use super::{Edge, Graph};
#[cfg(any(feature = "hydrate", test))]
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn bucket(resource: &str) -> Option<String> {
    let name = if let Some(scope) = resource.strip_prefix("bucket:") {
        scope.split('/').next()?
    } else if resource.starts_with("capability:s3/") {
        resource
            .split_whitespace()
            .find_map(|part| part.strip_prefix("bucket="))?
    } else {
        return None;
    };
    (!name.is_empty()).then(|| format!("bucket:{name}"))
}

/// Only the view is folded. The original graph remains the permission-path index.
#[cfg(any(feature = "hydrate", test))]
pub(super) fn fold(
    graph: &Graph,
    kinds: &BTreeMap<String, String>,
) -> (Graph, BTreeMap<String, BTreeSet<String>>) {
    let keep: BTreeSet<_> = graph.principals.iter().chain(&graph.hops).collect();
    let mut members: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut edges: BTreeMap<(String, String, String, String), Edge> = BTreeMap::new();
    for edge in &graph.edges {
        let mut item = edge.clone();
        if kinds.get(&edge.system).is_some_and(|k| k == "s3")
            && !keep.contains(&edge.dst)
            && let Some(id) = bucket(&edge.dst)
        {
            members
                .entry(id.clone())
                .or_default()
                .insert(edge.dst.clone());
            item.dst = id;
        }
        edges
            .entry((
                item.src.clone(),
                item.dst.clone(),
                item.system.clone(),
                item.kind.clone(),
            ))
            .and_modify(|old| {
                old.privs.extend(item.privs.clone());
                old.privs.sort();
                old.privs.dedup();
            })
            .or_insert(item);
    }
    let edges: Vec<_> = edges.into_values().collect();
    let terminals = edges
        .iter()
        .filter(|e| !keep.contains(&e.dst))
        .map(|e| e.dst.clone())
        .collect();
    let view = Graph {
        edges,
        terminals,
        principals: graph.principals.clone(),
        hops: graph.hops.clone(),
        names: graph.names.clone(),
        kind: graph.kind.clone(),
        envs: graph.envs.clone(),
        homes: graph.homes.clone(),
        teams: graph.teams.clone(),
    };
    (view, members)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_capabilities_join_their_bucket_but_global_capabilities_do_not() {
        assert_eq!(bucket("bucket:assets/team/*"), Some("bucket:assets".into()));
        assert_eq!(
            bucket("capability:s3/ListBucketVersions bucket=assets prefix='team/*'"),
            Some("bucket:assets".into())
        );
        assert_eq!(
            bucket("bucket:project-*/*"),
            Some("bucket:project-*".into())
        );
        assert_eq!(bucket("capability:s3/ListAllMyBuckets"), None);
        assert_eq!(bucket("bucket:"), None);
        assert_eq!(bucket("schema:public"), None);
    }

    #[test]
    fn folding_preserves_service_boundaries_global_actions_and_privileges() {
        let graph = Graph {
            edges: [
                ("s3", "bucket:assets/a", "Read"),
                ("s3", "bucket:assets/b", "Write"),
                (
                    "s3",
                    "capability:s3/ListBucketVersions bucket=assets prefix='a/*'",
                    "ListBucketVersions",
                ),
                ("s3", "capability:s3/ListAllMyBuckets", "ListAllMyBuckets"),
                ("postgres", "bucket:assets/untouched", "SELECT"),
            ]
            .into_iter()
            .map(|(system, dst, privilege)| Edge {
                src: "user".into(),
                dst: dst.into(),
                system: system.into(),
                privs: vec![privilege.into()],
                ..Default::default()
            })
            .collect(),
            ..Default::default()
        };
        let (view, members) = fold(
            &graph,
            &BTreeMap::from([
                ("s3".into(), "s3".into()),
                ("postgres".into(), "postgres".into()),
            ]),
        );
        assert_eq!(graph.edges.len(), 5);
        assert_eq!(view.edges.len(), 3);
        assert_eq!(members["bucket:assets"].len(), 3);
        assert!(
            view.terminals
                .contains(&"capability:s3/ListAllMyBuckets".into())
        );
        assert!(view.terminals.contains(&"bucket:assets/untouched".into()));
        assert_eq!(
            view.edges
                .iter()
                .find(|e| e.dst == "bucket:assets")
                .unwrap()
                .privs,
            ["ListBucketVersions", "Read", "Write"]
        );
    }
}
