use super::super::Graph;
use std::collections::{BTreeSet, HashMap};

#[derive(Clone, Copy)]
struct Link {
    node: usize,
    instance: Option<usize>,
}

struct Adjacency {
    offsets: Vec<usize>,
    links: Vec<Link>,
}

impl Adjacency {
    fn new(count: usize, edges: &[(usize, Link)]) -> Self {
        let mut offsets = vec![0; count + 1];
        for (src, _) in edges {
            offsets[src + 1] += 1;
        }
        for i in 1..offsets.len() {
            offsets[i] += offsets[i - 1];
        }
        let mut cursor = offsets.clone();
        let mut links = vec![
            Link {
                node: 0,
                instance: None
            };
            edges.len()
        ];
        for &(src, link) in edges {
            links[cursor[src]] = link;
            cursor[src] += 1;
        }
        Self { offsets, links }
    }

    fn neighbors(&self, node: usize) -> &[Link] {
        &self.links[self.offsets[node]..self.offsets[node + 1]]
    }
}

/// Stable integer IDs and two CSR indices. Hover never scans unrelated edges.
pub(super) struct Index {
    pub ids: HashMap<String, usize>,
    pub names: Vec<String>,
    outgoing: Adjacency,
    incoming: Adjacency,
}

impl Index {
    pub fn new(graph: &Graph, extra: impl IntoIterator<Item = String>) -> Self {
        let names: BTreeSet<_> = graph
            .edges
            .iter()
            .flat_map(|e| [e.src.clone(), e.dst.clone()])
            .chain(graph.principals.iter().cloned())
            .chain(graph.hops.iter().cloned())
            .chain(extra)
            .collect();
        Self::with_names(graph, names.into_iter().collect())
    }

    pub fn with_names(graph: &Graph, names: Vec<String>) -> Self {
        let ids: HashMap<_, _> = names
            .iter()
            .enumerate()
            .map(|(i, n)| (n.clone(), i))
            .collect();
        let keep: BTreeSet<_> = graph.principals.iter().chain(&graph.hops).collect();
        let mut forward = Vec::with_capacity(graph.edges.len());
        let mut reverse = Vec::with_capacity(graph.edges.len());
        for edge in &graph.edges {
            let (Some(&src), Some(&dst)) = (ids.get(&edge.src), ids.get(&edge.dst)) else {
                continue;
            };
            let instance = (!keep.contains(&edge.dst))
                .then(|| ids.get(&format!("@{}", edge.system)).copied())
                .flatten();
            forward.push((
                src,
                Link {
                    node: dst,
                    instance,
                },
            ));
            reverse.push((
                dst,
                Link {
                    node: src,
                    instance,
                },
            ));
        }
        Self {
            outgoing: Adjacency::new(names.len(), &forward),
            incoming: Adjacency::new(names.len(), &reverse),
            ids,
            names,
        }
    }

    pub fn reach(&self, start: usize, instances: bool) -> Vec<u8> {
        self.reach_many(&[start], instances)
    }

    #[cfg(any(feature = "hydrate", test))]
    pub fn descendants(&self, starts: &[usize]) -> Vec<u8> {
        let mut active = vec![0; self.names.len()];
        let mut stack = starts.to_vec();
        while let Some(node) = stack.pop() {
            if active[node] != 0 {
                continue;
            }
            active[node] = 1;
            stack.extend(self.outgoing.neighbors(node).iter().map(|link| link.node));
        }
        active
    }

    pub fn reach_many(&self, starts: &[usize], instances: bool) -> Vec<u8> {
        let mut active = vec![0; self.names.len()];
        let mut visited = vec![0_u8; self.names.len()];
        let mut stack = Vec::new();
        let mut touched = Vec::new();
        // Keep directions separate: an undirected walk would light sibling resources.
        for (direction, adjacency) in [(1, &self.outgoing), (2, &self.incoming)] {
            for &start in starts {
                visited[start] |= direction;
                stack.push(start);
            }
            while let Some(node) = stack.pop() {
                if active[node] == 0 {
                    active[node] = 1;
                    touched.push(node);
                }
                for link in adjacency.neighbors(node) {
                    if visited[link.node] & direction == 0 {
                        visited[link.node] |= direction;
                        stack.push(link.node);
                    }
                }
            }
        }
        if instances {
            // Include cross-links between the two direction sets, too. They may
            // belong to another service without being traversed in either walk.
            for node in touched {
                for link in self.incoming.neighbors(node) {
                    if active[link.node] != 0
                        && let Some(instance) = link.instance
                    {
                        active[instance] = 1;
                    }
                }
            }
        }
        active
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Edge;

    fn reference(graph: &Graph, start: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::from([start.to_owned()]);
        for reverse in [false, true] {
            let mut seen = BTreeSet::new();
            let mut stack = vec![start.to_owned()];
            while let Some(node) = stack.pop() {
                if !seen.insert(node.clone()) {
                    continue;
                }
                out.insert(node.clone());
                for edge in &graph.edges {
                    let (a, b) = if reverse {
                        (&edge.dst, &edge.src)
                    } else {
                        (&edge.src, &edge.dst)
                    };
                    if a == &node {
                        stack.push(b.clone());
                    }
                }
            }
        }
        out
    }

    #[test]
    fn indexed_paths_match_reference_for_cycles_diamonds_and_disconnected_nodes() {
        let mut seed = 137_u64;
        for _ in 0..40 {
            let mut graph = Graph {
                principals: (0..16).map(|n| n.to_string()).collect(),
                ..Default::default()
            };
            for _ in 0..60 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let src = seed as usize % 16;
                let dst = (seed >> 16) as usize % 16;
                graph.edges.push(Edge {
                    src: src.to_string(),
                    dst: dst.to_string(),
                    ..Default::default()
                });
            }
            let index = Index::new(&graph, []);
            for start in &graph.principals {
                let active = index.reach(index.ids[start], false);
                let actual = index
                    .names
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| active[*i] != 0)
                    .map(|(_, n)| n.clone())
                    .collect();
                assert_eq!(reference(&graph, start), actual);
            }
            let starts = [&graph.principals[0], &graph.principals[7]];
            let active = index.reach_many(&starts.map(|s| index.ids[s]), false);
            let actual: BTreeSet<_> = index
                .names
                .iter()
                .enumerate()
                .filter(|(i, _)| active[*i] != 0)
                .map(|(_, n)| n.clone())
                .collect();
            let expected: BTreeSet<_> = starts
                .into_iter()
                .flat_map(|s| reference(&graph, s))
                .collect();
            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn hundred_thousand_resources_keep_siblings_unlit() {
        let graph = Graph {
            principals: vec!["user".into()],
            hops: vec!["role".into()],
            edges: std::iter::once(Edge {
                src: "user".into(),
                dst: "role".into(),
                system: "s3".into(),
                ..Default::default()
            })
            .chain((0..100_000).map(|n| Edge {
                src: "role".into(),
                dst: format!("resource:{n}"),
                system: "s3".into(),
                ..Default::default()
            }))
            .collect(),
            ..Default::default()
        };
        let index = Index::new(&graph, ["@s3".into()]);
        let active = index.reach(index.ids["resource:99999"], true);
        assert_eq!(active.iter().filter(|&&x| x != 0).count(), 4);
        for name in ["user", "role", "resource:99999", "@s3"] {
            assert_eq!(active[index.ids[name]], 1);
        }
        assert_eq!(active[index.ids["resource:0"]], 0);
        assert!(index.reach(index.ids["role"], true).iter().all(|&x| x == 1));
    }

    #[test]
    fn aggregate_instances_include_cross_service_links_between_ancestors_and_descendants() {
        let graph = Graph {
            principals: vec!["user".into()],
            hops: vec!["role".into()],
            edges: [
                ("user", "role", "a"),
                ("role", "resource", "a"),
                ("user", "resource", "b"),
            ]
            .into_iter()
            .map(|(src, dst, system)| Edge {
                src: src.into(),
                dst: dst.into(),
                system: system.into(),
                ..Default::default()
            })
            .collect(),
            ..Default::default()
        };
        let index = Index::new(&graph, ["@a".into(), "@b".into()]);
        let active = index.reach(index.ids["role"], true);
        assert!(active.iter().all(|&x| x == 1));
    }
}
