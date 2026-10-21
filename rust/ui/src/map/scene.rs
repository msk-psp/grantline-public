#![cfg_attr(not(feature = "hydrate"), allow(dead_code))]
use super::{Graph, H, Layout, Node, W, index::Index, layout, tone, tr};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::ops::Range;
use std::rc::Rc;

pub(super) struct Model {
    pub graph: Graph,
    pub kinds: BTreeMap<String, String>,
    pub index: Index,
    folded: Index,
    buckets: BTreeMap<String, Vec<usize>>,
    people: Vec<usize>,
    policies: Vec<usize>,
    cache: VecDeque<(usize, Rc<Vec<u8>>)>,
}

impl Model {
    pub fn new(graph: Graph, kinds: BTreeMap<String, String>) -> Self {
        let (view, buckets) = super::buckets::fold(&graph, &kinds);
        let folded = layout(&view, &kinds, None, None);
        let index = Index::new(
            &graph,
            folded
                .nodes
                .iter()
                .map(|n| n.id.clone())
                .chain(buckets.keys().cloned()),
        );
        let people = view
            .principals
            .iter()
            .chain(&view.hops)
            .filter(|id| matches!(super::kind(&view, id), "human" | "svc-account" | "service"))
            .filter_map(|id| index.ids.get(id).copied())
            .collect();
        let policies = view
            .kind
            .iter()
            .filter(|(_, k)| k.as_str() == "policy")
            .filter_map(|(id, _)| index.ids.get(id).copied())
            .collect();
        let buckets = buckets
            .into_iter()
            .map(|(id, members)| (id, members.into_iter().map(|n| index.ids[&n]).collect()))
            .collect();
        let folded = Index::with_names(
            &Graph {
                edges: folded.edges,
                ..Default::default()
            },
            index.names.clone(),
        );
        Self {
            graph: view,
            kinds,
            index,
            folded,
            buckets,
            people,
            policies,
            cache: VecDeque::new(),
        }
    }

    pub fn active(&mut self, id: &str) -> Rc<Vec<u8>> {
        let start = self.index.ids[id];
        if let Some(pos) = self.cache.iter().position(|(i, _)| *i == start) {
            let item = self.cache.remove(pos).expect("position exists");
            let result = item.1.clone();
            self.cache.push_front(item);
            return result;
        }
        let mut active = if id.starts_with('@') {
            self.folded.reach(start, false)
        } else if let Some(members) = self.buckets.get(id) {
            self.index.reach_many(members, true)
        } else {
            self.index.reach(start, true)
        };
        self.project_buckets(&mut active);
        let result = Rc::new(active);
        if result.len() <= 8 * 1024 * 1024 {
            self.cache.push_front((start, result.clone()));
            let limit = (8 * 1024 * 1024 / self.index.names.len().max(1)).clamp(1, 32);
            self.cache.truncate(limit);
        }
        result
    }

    pub fn scene(&self, query: &str, expanded: Option<&str>, lang: &str) -> Scene {
        let visible = (!query.is_empty()).then(|| {
            let q = query.to_lowercase();
            let mut starts = BTreeSet::new();
            for (i, name) in self.index.names.iter().enumerate() {
                if name.to_lowercase().contains(&q)
                    || self
                        .graph
                        .names
                        .get(name)
                        .is_some_and(|label| label.to_lowercase().contains(&q))
                {
                    if let Some(members) = self.buckets.get(name) {
                        starts.extend(members.iter().copied());
                    } else {
                        starts.insert(i);
                    }
                }
            }
            let mut active = self
                .index
                .reach_many(&starts.into_iter().collect::<Vec<_>>(), false);
            self.project_buckets(&mut active);
            self.index
                .names
                .iter()
                .enumerate()
                .filter(|(i, _)| active[*i] != 0)
                .map(|(_, n)| n.clone())
                .collect()
        });
        let mut data = layout(&self.graph, &self.kinds, expanded, visible.as_ref());
        for node in &mut data.nodes {
            if node.kind == "resource"
                && let Some(members) = self.buckets.get(&node.id)
            {
                node.count = members.len();
            }
        }
        Scene::new(data, self, lang)
    }

    fn project_buckets(&self, active: &mut [u8]) {
        for (id, members) in &self.buckets {
            if members.iter().any(|&i| active[i] != 0) {
                active[self.index.ids[id]] = 1;
            }
        }
    }

    pub fn policy_priority(&self, active: &[u8]) -> Vec<u8> {
        let people: Vec<_> = self
            .people
            .iter()
            .copied()
            .filter(|&i| active[i] != 0)
            .collect();
        let mut priority = self.folded.descendants(&people);
        for &id in &self.policies {
            priority[id] |= active[id];
        }
        priority
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Camera {
    pub zoom: f64,
    pub x: f64,
    pub y: f64,
}
impl Default for Camera {
    fn default() -> Self {
        Self {
            zoom: 1.,
            x: 0.,
            y: 0.,
        }
    }
}
impl Camera {
    pub fn scale(&self, width: f64, scene: &Scene) -> f64 {
        width / scene.width as f64 * self.zoom
    }
    pub fn world(&self, x: f64, y: f64, width: f64, scene: &Scene) -> (f64, f64) {
        let scale = self.scale(width, scene);
        ((x - self.x) / scale, (y - self.y) / scale)
    }
    pub fn zoom_at(&mut self, factor: f64, x: f64, y: f64) {
        let next = (self.zoom * factor).clamp(0.35, 4.);
        self.x = x - (x - self.x) * next / self.zoom;
        self.y = y - (y - self.y) * next / self.zoom;
        self.zoom = next;
    }
    pub fn reveal(&mut self, node: &Node, width: f64, height: f64, scene: &Scene) {
        let scale = self.scale(width, scene);
        let (x, y) = (
            node.x as f64 * scale + self.x,
            node.y as f64 * scale + self.y,
        );
        if x < 12. {
            self.x += 12. - x;
        } else if x + W as f64 * scale > width - 12. {
            self.x += width - 12. - x - W as f64 * scale;
        }
        if y < 30. {
            self.y += 30. - y;
        } else if y + H as f64 * scale > height - 30. {
            self.y += height - 30. - y - H as f64 * scale;
        }
    }
}

pub(super) struct Label {
    pub text: String,
    pub tag: String,
    pub icons: Vec<String>,
}
pub(super) struct DrawEdge {
    pub src: usize,
    pub dst: usize,
    pub from: (usize, usize),
    pub to: (usize, usize),
    pub tone: usize,
    pub dash: f32,
}
pub(super) struct Scene {
    pub nodes: Vec<Node>,
    pub labels: Vec<Label>,
    pub edges: Vec<DrawEdge>,
    pub columns: Vec<(usize, String, usize)>,
    pub groups: Vec<(usize, usize, String)>,
    pub width: usize,
    pub height: usize,
    pub ids: Vec<usize>,
    pub lookup: HashMap<String, usize>,
    pub policy_range: Range<usize>,
    pub policy_edges: Vec<Range<usize>>,
    policy_base: Vec<usize>,
    policy_rows: Vec<usize>,
    columns_nodes: Vec<Range<usize>>,
    base_edges: usize,
    resource_edges: Vec<(usize, Range<usize>)>,
}
pub(super) struct Visible {
    pub nodes: Vec<Range<usize>>,
    pub edges: Vec<Range<usize>>,
}
impl Scene {
    fn new(layout: Layout, model: &Model, lang: &str) -> Self {
        let lookup: HashMap<_, _> = layout
            .nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (n.id.clone(), i))
            .collect();
        let ids: Vec<usize> = layout
            .nodes
            .iter()
            .map(|n| model.index.ids[&n.id])
            .collect();
        let mut edges = Vec::new();
        let mut resource_edges = Vec::new();
        for e in &layout.edges {
            let (Some(&src), Some(&dst)) = (lookup.get(&e.src), lookup.get(&e.dst)) else {
                continue;
            };
            let item = DrawEdge {
                src: model.index.ids[&e.src],
                dst: model.index.ids[&e.dst],
                from: (layout.nodes[src].x, layout.nodes[src].y),
                to: (layout.nodes[dst].x, layout.nodes[dst].y),
                tone: tone_index(tone(e)),
                dash: match e.kind.as_str() {
                    "route" => 1.,
                    "bridge" => 2.,
                    _ => 0.,
                },
            };
            if layout.nodes[dst].kind == "resource" {
                resource_edges.push(item);
            } else {
                edges.push(item);
            }
        }
        let base_edges = edges.len();
        resource_edges.sort_by_key(|e| e.to.1);
        let mut blocks: Vec<(usize, Range<usize>)> = Vec::new();
        for e in resource_edges {
            let i = edges.len();
            if let Some((y, range)) = blocks.last_mut()
                && *y == e.to.1
            {
                range.end = i + 1;
            } else {
                blocks.push((e.to.1, i..i + 1));
            }
            edges.push(e);
        }
        let mut columns_nodes: Vec<Range<usize>> = Vec::new();
        for (i, node) in layout.nodes.iter().enumerate() {
            if i == 0 || layout.nodes[i - 1].x != node.x {
                columns_nodes.push(i..i + 1);
            } else {
                columns_nodes.last_mut().expect("column exists").end = i + 1;
            }
        }
        let labels = layout
            .nodes
            .iter()
            .map(|n| {
                let icons: BTreeSet<_> = n
                    .homes
                    .iter()
                    .filter_map(|s| model.kinds.get(s).cloned())
                    .collect();
                let envs: BTreeSet<_> = n
                    .homes
                    .iter()
                    .flat_map(|s| model.graph.envs.get(s).into_iter().flatten().cloned())
                    .collect();
                let tag = if n.kind == "instance" {
                    format!("{} {} ›", n.count, tr(lang, "Resources"))
                } else if n.kind == "resource" && n.count > 0 {
                    format!("{} {}", n.count, tr(lang, "Resources"))
                } else if envs.len() > 1 {
                    envs.into_iter().collect::<Vec<_>>().join("·")
                } else {
                    envs.into_iter()
                        .next()
                        .filter(|s| s != "prod")
                        .unwrap_or_default()
                };
                let room =
                    (W - 12 - icons.len() * 19).saturating_sub(tag.chars().count() * 6 + 20) / 7;
                let text = if n.label.chars().count() > room {
                    n.label
                        .chars()
                        .take(room.saturating_sub(1))
                        .collect::<String>()
                        + "…"
                } else {
                    n.label.clone()
                };
                Label {
                    text,
                    tag,
                    icons: icons.into_iter().collect(),
                }
            })
            .collect();
        let policy_range = columns_nodes
            .iter()
            .find(|r| layout.nodes[r.start].kind == "policy")
            .cloned()
            .unwrap_or(0..0);
        let policy_base = ids[policy_range.clone()].to_vec();
        let policy_ids: BTreeSet<_> = policy_base.iter().copied().collect();
        let policy_rows = layout.nodes[policy_range.clone()]
            .iter()
            .map(|n| n.y)
            .collect();
        let mut policy_edges: Vec<Range<usize>> = Vec::new();
        for (i, edge) in edges.iter().enumerate() {
            if policy_ids.contains(&edge.src) || policy_ids.contains(&edge.dst) {
                if let Some(last) = policy_edges.last_mut()
                    && last.end == i
                {
                    last.end = i + 1;
                } else {
                    policy_edges.push(i..i + 1);
                }
            }
        }
        Self {
            nodes: layout.nodes,
            labels,
            edges,
            columns: layout.columns,
            groups: layout.groups,
            width: layout.width,
            height: layout.height,
            ids,
            lookup,
            policy_range,
            policy_edges,
            policy_base,
            policy_rows,
            columns_nodes,
            base_edges,
            resource_edges: blocks,
        }
    }

    /// Stable partition of the policy column only; preserve every other node position.
    pub fn prioritize_policies(&mut self, priority: Option<&[u8]>) -> bool {
        let hot = |id: &usize| priority.is_some_and(|p| p[*id] != 0);
        let order: Vec<_> = self
            .policy_base
            .iter()
            .filter(|id| hot(id))
            .chain(self.policy_base.iter().filter(|id| !hot(id)))
            .copied()
            .collect();
        if self.ids[self.policy_range.clone()] == order {
            return false;
        }
        let mut positions: HashMap<_, _> = self
            .policy_range
            .clone()
            .map(|i| (self.ids[i], i))
            .collect();
        for (row, id) in order.into_iter().enumerate() {
            let target = self.policy_range.start + row;
            let source = positions[&id];
            let displaced = self.ids[target];
            self.nodes.swap(source, target);
            self.labels.swap(source, target);
            self.ids.swap(source, target);
            positions.insert(id, target);
            positions.insert(displaced, source);
            *self
                .lookup
                .get_mut(&self.nodes[source].id)
                .expect("node exists") = source;
            *self
                .lookup
                .get_mut(&self.nodes[target].id)
                .expect("node exists") = target;
        }
        for (row, i) in self.policy_range.clone().enumerate() {
            self.nodes[i].y = self.policy_rows[row];
        }
        for range in &self.policy_edges {
            for edge in &mut self.edges[range.clone()] {
                if let Some(&i) = positions.get(&edge.src) {
                    edge.from.1 = self.nodes[i].y;
                }
                if let Some(&i) = positions.get(&edge.dst) {
                    edge.to.1 = self.nodes[i].y;
                }
            }
        }
        true
    }

    pub fn visible(&self, camera: Camera, width: f64, height: f64) -> Visible {
        let (left, top) = camera.world(0., 0., width, self);
        let (right, bottom) = camera.world(width, height, width, self);
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        if self.base_edges > 0 {
            edges.push(0..self.base_edges);
        }
        for column in &self.columns_nodes {
            let col = &self.nodes[column.clone()];
            let x = col[0].x as f64;
            if x > right + W as f64 || x + (W as f64) < left {
                continue;
            }
            let first = col.partition_point(|n| ((n.y + H + 2 * super::ROW) as f64) < top);
            let last = col.partition_point(|n| (n.y as f64) <= bottom + 2. * super::ROW as f64);
            if first < last {
                nodes.push(column.start + first..column.start + last);
            }
        }
        // Offscreen resource routes remain represented by the folded service edges.
        // Keep exact routes only for resource rows in the viewport (+overscan).
        let first = self
            .resource_edges
            .partition_point(|(y, _)| ((*y + H + 2 * super::ROW) as f64) < top);
        let last = self
            .resource_edges
            .partition_point(|(y, _)| (*y as f64) <= bottom + 2. * super::ROW as f64);
        if first < last {
            edges.push(self.resource_edges[first].1.start..self.resource_edges[last - 1].1.end);
        }
        Visible { nodes, edges }
    }

    pub fn hit(&self, camera: Camera, width: f64, x: f64, y: f64) -> Option<usize> {
        let (x, y) = camera.world(x, y, width, self);
        for column in &self.columns_nodes {
            let col = &self.nodes[column.clone()];
            let nx = col[0].x as f64;
            if x < nx || x > nx + W as f64 {
                continue;
            }
            let i = col.partition_point(|n| n.y as f64 <= y).checked_sub(1)?;
            if y <= (col[i].y + H) as f64 {
                return Some(column.start + i);
            }
        }
        None
    }

    pub fn navigate(&self, current: usize, key: &str) -> usize {
        if self.nodes.is_empty() {
            return 0;
        }
        let current = current.min(self.nodes.len() - 1);
        match key {
            "Home" => 0,
            "End" => self.nodes.len() - 1,
            "ArrowDown" => (current + 1).min(self.nodes.len() - 1),
            "ArrowUp" => current.saturating_sub(1),
            "ArrowLeft" | "ArrowRight" => {
                let col = self
                    .columns_nodes
                    .iter()
                    .position(|r| r.contains(&current))
                    .unwrap_or(0);
                let col = if key == "ArrowLeft" {
                    col.saturating_sub(1)
                } else {
                    (col + 1).min(self.columns_nodes.len() - 1)
                };
                let range = &self.columns_nodes[col];
                let rows = &self.nodes[range.clone()];
                let y = self.nodes[current].y;
                let i = rows.partition_point(|n| n.y < y).min(rows.len() - 1);
                let i = if i > 0 && rows[i - 1].y.abs_diff(y) < rows[i].y.abs_diff(y) {
                    i - 1
                } else {
                    i
                };
                range.start + i
            }
            _ => current,
        }
    }
}
pub(super) fn tone_index(tone: &str) -> usize {
    match tone {
        "read" => 0,
        "write" => 1,
        "admin" | "bridge" => 2,
        "member" => 3,
        "policy" | "route" => 4,
        _ => 5,
    }
}
pub(super) fn kind_index(kind: &str) -> usize {
    match kind {
        "human" => 0,
        "service" | "svc-account" => 1,
        "role" => 2,
        "group" | "policy" => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Edge;

    fn policies() -> Model {
        let mut graph = Graph {
            principals: vec!["alice".into(), "bob".into(), "carol".into()],
            hops: ["policy:a", "policy:b", "policy:z", "policy:z-secondary"]
                .map(str::to_owned)
                .to_vec(),
            ..Default::default()
        };
        for id in &graph.hops {
            graph.kind.insert(id.clone(), "policy".into());
        }
        for (src, dst) in [
            ("alice", "policy:z"),
            ("alice", "policy:z-secondary"),
            ("bob", "policy:a"),
            ("carol", "policy:b"),
            ("policy:z", "bucket:assets/private/*"),
            ("policy:a", "bucket:assets/public/*"),
            ("policy:z-secondary", "bucket:other/team/*"),
            ("policy:b", "bucket:isolated/*"),
        ] {
            graph.edges.push(Edge {
                src: src.into(),
                dst: dst.into(),
                system: "s3".into(),
                ..Default::default()
            });
        }
        Model::new(graph, BTreeMap::from([("s3".into(), "s3".into())]))
    }

    #[test]
    fn bucket_rows_union_prefix_routes_without_joining_sibling_people_or_other_buckets() {
        let mut model = policies();
        let scene = model.scene("", Some("s3"), "en");
        assert_eq!(
            scene.nodes.iter().filter(|n| n.kind == "resource").count(),
            3
        );
        assert_eq!(scene.nodes[scene.lookup["bucket:assets"]].count, 2);
        assert!(!scene.lookup.contains_key("bucket:assets/private/*"));
        let active = model.active("alice");
        assert_eq!(active[model.index.ids["bucket:assets"]], 1);
        assert_eq!(active[model.index.ids["bob"]], 0);
        assert_eq!(active[model.index.ids["policy:a"]], 0);
        let bucket = model.active("bucket:assets");
        for name in ["alice", "bob", "policy:a", "policy:z"] {
            assert_eq!(bucket[model.index.ids[name]], 1);
        }
        for name in ["carol", "policy:b", "policy:z-secondary", "bucket:other"] {
            assert_eq!(bucket[model.index.ids[name]], 0);
        }
    }

    #[test]
    fn prefix_search_stays_exact_while_rendering_and_prioritizing_bucket_rows() {
        let mut model = policies();
        let scene = model.scene("private", Some("s3"), "en");
        assert!(scene.lookup.contains_key("bucket:assets"));
        assert!(scene.lookup.contains_key("alice"));
        assert!(!scene.lookup.contains_key("bob"));
        assert!(!scene.lookup.contains_key("bucket:other"));
        let active = model.active("bucket:assets/private/*");
        let priority = model.policy_priority(&active);
        assert_eq!(priority[model.index.ids["policy:z-secondary"]], 1);
        assert_eq!(active[model.index.ids["policy:z-secondary"]], 0);
        assert_eq!(priority[model.index.ids["policy:a"]], 0);
    }

    #[test]
    fn policy_partition_preserves_positions_labels_routes_and_hit_testing_then_restores() {
        let mut model = policies();
        let mut scene = model.scene("", Some("s3"), "en");
        let base: Vec<_> = scene
            .nodes
            .iter()
            .map(|n| (n.id.clone(), n.x, n.y))
            .collect();
        let edges: Vec<_> = scene.edges.iter().map(|e| (e.from, e.to)).collect();
        let order = |s: &Scene| {
            s.nodes[s.policy_range.clone()]
                .iter()
                .map(|n| n.id.as_str().to_owned())
                .collect::<Vec<_>>()
        };
        let active = model.active("bucket:assets");
        let priority = model.policy_priority(&active);
        assert!(scene.prioritize_policies(Some(&priority)));
        assert_eq!(
            order(&scene),
            ["policy:a", "policy:z", "policy:z-secondary", "policy:b"]
        );
        assert!(!scene.prioritize_policies(Some(&priority)));
        for (id, x, y) in &base {
            let i = scene.lookup[id];
            if scene.nodes[i].kind != "policy" {
                assert_eq!((scene.nodes[i].x, scene.nodes[i].y), (*x, *y));
            }
        }
        for i in scene.policy_range.clone() {
            let n = &scene.nodes[i];
            assert_eq!(scene.ids[i], model.index.ids[&n.id]);
            assert_eq!(scene.labels[i].text, n.label);
            let scale = Camera::default().scale(1200., &scene);
            assert_eq!(
                scene.hit(
                    Camera::default(),
                    1200.,
                    (n.x + 8) as f64 * scale,
                    (n.y + 8) as f64 * scale
                ),
                Some(i)
            );
        }
        for edge in &scene.edges {
            if let Some(i) = scene
                .nodes
                .iter()
                .position(|n| model.index.ids[&n.id] == edge.src)
            {
                assert_eq!(edge.from, (scene.nodes[i].x, scene.nodes[i].y));
            }
            if let Some(i) = scene
                .nodes
                .iter()
                .position(|n| model.index.ids[&n.id] == edge.dst)
            {
                assert_eq!(edge.to, (scene.nodes[i].x, scene.nodes[i].y));
            }
        }
        assert!(scene.prioritize_policies(None));
        assert_eq!(
            scene
                .nodes
                .iter()
                .map(|n| (n.id.clone(), n.x, n.y))
                .collect::<Vec<_>>(),
            base
        );
        assert_eq!(
            scene
                .edges
                .iter()
                .map(|e| (e.from, e.to))
                .collect::<Vec<_>>(),
            edges
        );
    }

    #[test]
    fn hundred_thousand_prefixes_share_one_bucket_and_a_single_merged_route() {
        let graph = Graph {
            principals: vec!["user".into()],
            edges: (0..100_000)
                .map(|n| Edge {
                    src: "user".into(),
                    dst: format!("bucket:assets/item-{n:06}"),
                    system: "s3".into(),
                    privs: vec!["Read".into()],
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        let mut model = Model::new(graph, BTreeMap::from([("s3".into(), "s3".into())]));
        let scene = model.scene("", Some("s3"), "en");
        assert_eq!(scene.nodes.len(), 3);
        assert_eq!(scene.edges.len(), 2);
        assert_eq!(scene.nodes[scene.lookup["bucket:assets"]].count, 100_000);
        assert!(
            model
                .scene("item-099999", Some("s3"), "en")
                .lookup
                .contains_key("bucket:assets")
        );
        let active = model.active("bucket:assets");
        assert_eq!(active[model.index.ids["user"]], 1);
    }
    #[test]
    fn every_resource_remains_addressable_with_bounded_visible_geometry() {
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
                dst: format!("bucket:{n:06}"),
                system: "s3".into(),
                ..Default::default()
            }))
            .collect(),
            ..Default::default()
        };
        let model = Model::new(graph, BTreeMap::from([("s3".into(), "s3".into())]));
        let searched = model.scene("bucket:099999", Some("s3"), "en");
        assert!(searched.lookup.contains_key("bucket:099999"));
        assert!(!searched.lookup.contains_key("bucket:000000"));
        assert!(searched.lookup.contains_key("user"));
        let scene = model.scene("", Some("s3"), "en");
        assert_eq!(scene.nodes.len(), 100_003);
        let last = scene.lookup["bucket:099999"];
        let mut camera = Camera::default();
        let first = scene.visible(camera, 1200., 700.);
        assert!(first.nodes.iter().map(Range::len).sum::<usize>() < 100);
        assert!(first.edges.iter().map(Range::len).sum::<usize>() < 100);
        camera.reveal(&scene.nodes[last], 1200., 700., &scene);
        let end = scene.visible(camera, 1200., 700.);
        assert!(end.nodes.iter().any(|r| r.contains(&last)));
        assert!(end.nodes.iter().map(Range::len).sum::<usize>() < 100);
        let node = &scene.nodes[last];
        let scale = camera.scale(1200., &scene);
        assert_eq!(
            scene.hit(
                camera,
                1200.,
                (node.x + 10) as f64 * scale + camera.x,
                (node.y + 10) as f64 * scale + camera.y
            ),
            Some(last)
        );
        assert_eq!(scene.navigate(0, "End"), last);
    }
    #[test]
    fn cached_directions_keep_aggregate_instances_and_service_scope() {
        let mut model = Model::new(
            super::super::tests::fixture(),
            BTreeMap::from([("s3".into(), "s3".into())]),
        );
        let active = model.active("bucket:b");
        assert_eq!(active[model.index.ids["@s3"]], 1);
        assert_eq!(active[model.index.ids["alice"]], 0);
        assert!(Rc::ptr_eq(&active, &model.active("bucket:b")));
    }
}
