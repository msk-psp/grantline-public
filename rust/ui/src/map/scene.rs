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
    cache: VecDeque<(usize, Rc<Vec<u8>>)>,
}

impl Model {
    pub fn new(graph: Graph, kinds: BTreeMap<String, String>) -> Self {
        let folded = layout(&graph, &kinds, "", None);
        let index = Index::new(&graph, folded.nodes.iter().map(|n| n.id.clone()));
        let folded = Index::with_names(
            &Graph {
                edges: folded.edges,
                ..Default::default()
            },
            index.names.clone(),
        );
        Self {
            graph,
            kinds,
            index,
            folded,
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
        let result = Rc::new(if id.starts_with('@') {
            self.folded.reach(start, false)
        } else {
            self.index.reach(start, true)
        });
        if result.len() <= 8 * 1024 * 1024 {
            self.cache.push_front((start, result.clone()));
            let limit = (8 * 1024 * 1024 / self.index.names.len().max(1)).clamp(1, 32);
            self.cache.truncate(limit);
        }
        result
    }

    pub fn scene(&self, query: &str, expanded: Option<&str>, lang: &str) -> Scene {
        Scene::new(
            layout(&self.graph, &self.kinds, query, expanded),
            self,
            lang,
        )
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
        let ids = layout
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
            columns_nodes,
            base_edges,
            resource_edges: blocks,
        }
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
