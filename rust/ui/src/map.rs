#[cfg(any(feature = "hydrate", test))]
use super::Edge;
use super::{Graph, tr};
use leptos::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

#[cfg(any(feature = "hydrate", test))]
const COL: usize = 350;
#[cfg(any(feature = "hydrate", test))]
const ROW: usize = 48;
#[cfg(any(feature = "hydrate", test))]
const W: usize = 270;
#[cfg(any(feature = "hydrate", test))]
const H: usize = 32;
#[cfg(any(feature = "hydrate", test))]
const TOP: usize = 150;
#[cfg(any(feature = "hydrate", test))]
const KINDS: [&str; 6] = [
    "human",
    "svc-account",
    "role",
    "group",
    "policy",
    "instance",
];

#[cfg(feature = "hydrate")]
mod gpu;
mod index;
#[cfg(feature = "hydrate")]
mod runtime;
#[cfg(any(feature = "hydrate", test))]
mod scene;

pub fn highlighted(graph: &Graph, start: &str) -> BTreeSet<String> {
    let index = index::Index::new(graph, [start.to_owned()]);
    let active = index.reach(index.ids[start], false);
    index
        .names
        .iter()
        .enumerate()
        .filter(|(i, _)| active[*i] != 0)
        .map(|(_, name)| name.clone())
        .collect()
}

#[cfg(any(feature = "hydrate", test))]
#[derive(Clone)]
struct Node {
    id: String,
    kind: String,
    label: String,
    homes: BTreeSet<String>,
    count: usize,
    x: usize,
    y: usize,
}
#[cfg(any(feature = "hydrate", test))]
struct Layout {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    columns: Vec<(usize, String, usize)>,
    groups: Vec<(usize, usize, String)>,
    width: usize,
    height: usize,
}
#[cfg(any(feature = "hydrate", test))]
fn kind<'a>(graph: &'a Graph, id: &str) -> &'a str {
    graph.kind.get(id).map(String::as_str).unwrap_or_else(|| {
        if graph.hops.iter().any(|n| n == id) {
            "role"
        } else {
            "human"
        }
    })
}
#[cfg(any(feature = "hydrate", test))]
fn service_rank(name: &str) -> usize {
    match name {
        "postgres" => 0,
        "clickhouse" => 1,
        "s3" => 2,
        _ => 3,
    }
}
#[cfg(any(feature = "hydrate", test))]
fn layout(
    graph: &Graph,
    service_kinds: &BTreeMap<String, String>,
    query: &str,
    expanded: Option<&str>,
) -> Layout {
    let keep: BTreeSet<_> = graph
        .principals
        .iter()
        .chain(&graph.hops)
        .cloned()
        .collect();
    let connected: BTreeSet<_> = graph
        .edges
        .iter()
        .flat_map(|e| [e.src.clone(), e.dst.clone()])
        .chain(keep.iter().cloned())
        .collect();
    let mut visible = connected.clone();
    if !query.is_empty() {
        visible.clear();
        let q = query.to_lowercase();
        let index = index::Index::new(graph, []);
        let starts: Vec<_> = connected
            .iter()
            .filter(|n| {
                n.to_lowercase().contains(&q)
                    || graph
                        .names
                        .get(*n)
                        .is_some_and(|label| label.to_lowercase().contains(&q))
            })
            .map(|n| index.ids[n])
            .collect();
        let active = index.reach_many(&starts, false);
        visible.extend(
            index
                .names
                .iter()
                .enumerate()
                .filter(|(i, _)| active[*i] != 0)
                .map(|(_, n)| n.clone()),
        );
    }
    let mut homes = graph.homes.clone();
    let mut resources: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut fan: BTreeMap<(String, String), Edge> = BTreeMap::new();
    let mut edges = Vec::new();
    for e in &graph.edges {
        if !visible.contains(&e.src) || !visible.contains(&e.dst) {
            continue;
        }
        if e.system != "*" {
            for id in [&e.src, &e.dst] {
                homes
                    .entry(id.clone())
                    .or_default()
                    .insert(e.system.clone());
            }
        }
        if keep.contains(&e.dst) {
            if e.kind != "flat" {
                edges.push(e.clone());
            }
        } else {
            resources
                .entry(e.system.clone())
                .or_default()
                .insert(e.dst.clone());
            // Flattened effective grants are already represented by their role/policy path.
            if e.kind == "flat" {
                continue;
            }
            let entry = fan
                .entry((e.src.clone(), e.system.clone()))
                .or_insert_with(|| Edge {
                    dst: format!("@{}", e.system),
                    ..e.clone()
                });
            entry.privs.extend(e.privs.clone());
            entry.privs.sort();
            entry.privs.dedup();
        }
    }
    edges.extend(fan.into_values());
    let mut nodes: Vec<_> = keep
        .intersection(&visible)
        .map(|id| {
            let k = kind(graph, id);
            let label = if matches!(k, "group" | "policy" | "service") {
                id.split_once(':').map(|(_, s)| s).unwrap_or(id).to_owned()
            } else if let Some(name) = graph.names.get(id) {
                format!("{id} ({name})")
            } else {
                id.clone()
            };
            Node {
                id: id.clone(),
                kind: k.into(),
                label,
                homes: homes.get(id).cloned().unwrap_or_default(),
                count: 0,
                x: 0,
                y: 0,
            }
        })
        .collect();
    for (system, reached) in &resources {
        nodes.push(Node {
            id: format!("@{system}"),
            kind: "instance".into(),
            label: system.clone(),
            homes: BTreeSet::from([system.clone()]),
            count: reached.len(),
            x: 0,
            y: 0,
        });
    }
    let group = |n: &Node| {
        if n.kind == "human" {
            graph
                .teams
                .get(&n.id)
                .cloned()
                .unwrap_or_else(|| "Users".into())
        } else if n.kind == "service" {
            "Services".into()
        } else if n.kind == "instance" {
            String::new()
        } else {
            n.homes
                .iter()
                .filter_map(|s| service_kinds.get(s))
                .min_by_key(|k| service_rank(k))
                .cloned()
                .unwrap_or_default()
        }
    };
    nodes.sort_by_key(|n| {
        let g = group(n);
        (
            if n.kind == "service" { 1 } else { 0 },
            if n.kind == "human" {
                0
            } else {
                service_rank(&g)
            },
            g,
            n.id.clone(),
        )
    });
    let mut columns = Vec::new();
    let mut groups = Vec::new();
    let mut positioned = Vec::new();
    let mut rows_max = 5;
    for k in KINDS {
        let members: Vec<_> = nodes
            .iter()
            .filter(|n| n.kind == k || (k == "human" && n.kind == "service"))
            .collect();
        if members.is_empty() {
            continue;
        }
        let x = 60 + columns.len() * COL;
        let title = match k {
            "human" => "Principals",
            "svc-account" => "Service accounts",
            "role" => "Roles",
            "group" => "Groups",
            "policy" => "Policies",
            _ => "Resources in",
        };
        columns.push((x, title.into(), members.len()));
        let mut row = 0;
        let mut last = None;
        for n in members {
            let g = group(n);
            if !g.is_empty() && last.as_ref() != Some(&g) {
                groups.push((x, TOP + ROW * row, g.clone()));
                row += 1;
                last = Some(g);
            }
            let mut n = n.clone();
            n.x = x;
            n.y = TOP + ROW * row;
            positioned.push(n);
            row += 1;
        }
        rows_max = rows_max.max(row);
    }
    if let Some((system, reached)) = expanded.and_then(|s| resources.get_key_value(s)) {
        let x = 60 + columns.len() * COL;
        columns.push((x, "Resources".into(), reached.len()));
        for (row, id) in reached.iter().enumerate() {
            positioned.push(Node {
                id: id.clone(),
                kind: "resource".into(),
                label: id.clone(),
                homes: BTreeSet::from([system.clone()]),
                count: 0,
                x,
                y: TOP + ROW * row,
            });
        }
        // These lines reveal the exact grant behind each resource; the overview stays folded.
        edges.extend(
            graph
                .edges
                .iter()
                .filter(|e| e.system == *system && reached.contains(&e.dst) && e.kind != "flat")
                .cloned(),
        );
        rows_max = rows_max.max(reached.len());
    }
    Layout {
        width: (60 + COL * columns.len() + W).max(700),
        height: TOP + 20 + ROW * rows_max,
        nodes: positioned,
        edges,
        columns,
        groups,
    }
}
#[cfg(any(feature = "hydrate", test))]
fn tone(edge: &Edge) -> &'static str {
    if edge.kind == "bridge" {
        "bridge"
    } else if edge.dst.starts_with("policy:") {
        "policy"
    } else if edge.privs.iter().any(|p| p == "MEMBER") || edge.dst.starts_with("group:") {
        "member"
    } else if edge.kind == "route" && edge.privs.is_empty() {
        "route"
    } else if edge.privs.iter().any(|p| {
        matches!(
            p.as_str(),
            "ALL" | "OWNER" | "ADMIN" | "Admin" | "GRANT" | "BypassGovernanceRetention"
        )
    }) {
        "admin"
    } else if edge.privs.iter().any(|p| {
        matches!(
            p.as_str(),
            "Write"
                | "INSERT"
                | "UPDATE"
                | "DELETE"
                | "CREATE"
                | "DROP"
                | "ALTER"
                | "TRUNCATE"
                | "DeleteObjectVersion"
        )
    }) {
        "write"
    } else {
        "read"
    }
}
#[cfg(any(feature = "hydrate", test))]
fn route(x: usize, y: usize, dx: usize, dy: usize) -> String {
    let back = dx < x;
    let (x1, x2) = if back {
        (x, dx + W + 7)
    } else {
        (x + W, dx.saturating_sub(7))
    };
    let (y1, y2) = (y + H / 2, dy + H / 2);
    let mid = (x1 + x2) / 2;
    if dx == x + COL {
        format!("M{x1},{y1} C{mid},{y1} {mid},{y2} {x2},{y2}")
    } else {
        let r = if back { -40_isize } else { 40 };
        let (a, b) = (x1 as isize + r, x2 as isize - r);
        format!(
            "M{x1},{y1} C{a},{y1} {a},40 {},40 L{},40 C{b},40 {b},{y2} {x2},{y2}",
            a + r,
            b - r
        )
    }
}

#[derive(Clone, Default)]
struct FocusInfo {
    id: String,
    label: String,
    position: usize,
    total: usize,
}

fn command(_viewport: NodeRef<leptos::html::Div>, _action: &str) {
    #[cfg(feature = "hydrate")]
    if let Some(root) = _viewport.get() {
        let init = web_sys::CustomEventInit::new();
        init.set_detail(&wasm_bindgen::JsValue::from_str(_action));
        if let Ok(event) =
            web_sys::CustomEvent::new_with_event_init_dict("grantline-map-command", &init)
        {
            let _ = root.dispatch_event(&event);
        }
    }
}

#[component]
pub(super) fn PermissionMap(
    graph: Graph,
    service_kinds: BTreeMap<String, String>,
    service: String,
    environment: String,
    query: String,
    lang: String,
) -> impl IntoView {
    let graph = StoredValue::new(graph.scoped(&service, &environment));
    let selected = RwSignal::new(None::<String>);
    let focus = RwSignal::new(None::<FocusInfo>);
    let unavailable = RwSignal::new(false);
    let viewport = NodeRef::<leptos::html::Div>::new();
    #[cfg(feature = "hydrate")]
    {
        let kinds = StoredValue::new(service_kinds);
        let query = StoredValue::new(query);
        let locale = StoredValue::new(lang.clone());
        let runtime = StoredValue::new_local(None::<runtime::Runtime>);
        Effect::new(move |_| {
            if let Some(root) = viewport.get() {
                match runtime::Runtime::mount(
                    root.into(),
                    graph.get_value(),
                    kinds.get_value(),
                    query.get_value(),
                    locale.get_value(),
                    selected,
                    focus,
                ) {
                    Ok(driver) => runtime.set_value(Some(driver)),
                    Err(_) => unavailable.set(true),
                }
            }
        });
        on_cleanup(move || {
            runtime.try_update_value(|driver| *driver = None);
        });
    }
    #[cfg(not(feature = "hydrate"))]
    let _ = (service_kinds, query);
    let detail_lang = lang.clone();
    let detail_scope = format!(
        "&system={}&environment={}",
        super::encode(&service),
        super::encode(&environment)
    );
    view! {
        <section class="map-card">
        <div class="map-tools">
        <p class="muted">{tr(&lang,"Hover or focus a resource to follow its access routes.")}</p>
        <div class="map-view" role="group" aria-label=tr(&lang,"View")>
        <button class="quiet" aria-label=tr(&lang,"Zoom in") on:click=move |_|command(viewport,"zoom-in")>"+"</button>
        <button class="quiet" aria-label=tr(&lang,"Zoom out") on:click=move |_|command(viewport,"zoom-out")>"−"</button>
        <button class="quiet" on:click=move |_|command(viewport,"reset")>{tr(&lang,"Fit view")}</button>
        <button class="quiet" on:click=move |_|command(viewport,"clear")>{tr(&lang,"Clear selection")}</button>
        </div>
        {move||selected.get().map(|id|{
            let href=if let Some(system)=id.strip_prefix('@') {format!("/services?system={}",super::encode(system))} else {let resource=graph.with_value(|g|g.terminals.contains(&id) || g.edges.iter().any(|e|e.dst==id) && !g.principals.contains(&id) && !g.hops.contains(&id));format!("/{}?{}={}&lang={}",if resource{"resource"}else{"account"},if resource{"resource"}else{"subject"},super::encode(&id),super::encode(&detail_lang))+&detail_scope};
            view!{<a class="entity" href=href>{tr(&detail_lang,"View details")}" · "{id}</a>}
        })}</div>
        <div class="map-viewport" node_ref=viewport tabindex="0" role="listbox"
            aria-label=tr(&lang,"Map") aria-describedby="map-keys"
            aria-activedescendant=move||focus.with(|f|f.as_ref().map(|_|"map-active-node"))>
            <canvas class="map-gpu" aria-hidden="true"></canvas>
            <canvas class="map-labels" aria-hidden="true"></canvas>
            {move||focus.get().map(|item|view!{
                <span id="map-active-node" class="sr-only" role="option" data-node-id=item.id.clone()
                    aria-posinset=item.position aria-setsize=item.total
                    aria-selected=move||selected.with(|s|s.as_ref()==Some(&item.id))>{item.label}</span>
            })}
            <noscript><p class="notice">{tr(&lang,"Enable JavaScript to explore the map.")}</p></noscript>
            {let lang=lang.clone();move||unavailable.get().then(||view!{<p class="notice">{tr(&lang,"Map unavailable. Use Accounts or Resources.")}</p>})}
            <div class="map-hint">{tr(&lang,"Click to follow · scroll to zoom · Shift+scroll to pan · drag to pan · Esc to reset")}</div>
        </div>
        <p class="sr-only" id="map-keys">{tr(&lang,"Arrow keys: navigate nodes. Enter: select or expand. Home/End: first/last node. Page Up/Down: pan.")}</p>
        <div class="map-legend">
        {[("human","Users"),("service","Services"),("svc-account","Service accounts"),("role","Roles"),("group","Groups"),("policy","Policies"),("instance","Service instances")].into_iter().map(|(class,label)|view!{<span class=class><i></i>{tr(&lang,label)}</span>}).collect_view()}
        <span class="legend-read">"→ "{tr(&lang,"Read")}</span><span class="legend-write">"→ "{tr(&lang,"Write")}</span><span class="legend-admin">"→ "{tr(&lang,"Admin")}</span>
        </div></section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn isolated_inventory_stays_searchable_with_service_and_environment_filters() {
        let mut g = fixture();
        g.principals.push("loner".into());
        g.kind.insert("loner".into(), "human".into());
        g.names.insert("loner".into(), "New person".into());
        g.homes
            .insert("loner".into(), BTreeSet::from(["s3".into()]));
        g.envs.insert("s3".into(), vec!["prod".into()]);
        let kinds = BTreeMap::from([("s3".into(), "s3".into())]);
        let scoped = g.scoped("s3", "prod");
        let map = layout(&scoped, &kinds, "new person", None);
        assert_eq!(map.nodes.len(), 1);
        assert_eq!(map.nodes[0].id, "loner");
        assert!(map.edges.is_empty());
        assert!(
            !g.scoped("postgres", "")
                .principals
                .contains(&"loner".into())
        );
        assert!(!g.scoped("", "staging").principals.contains(&"loner".into()));
    }
    pub(super) fn fixture() -> Graph {
        let mut g = Graph {
            principals: vec!["alice".into(), "service:app".into()],
            hops: vec![
                "svc".into(),
                "reader".into(),
                "group:team".into(),
                "policy:read".into(),
            ],
            ..Default::default()
        };
        g.kind = [
            ("alice", "human"),
            ("service:app", "service"),
            ("svc", "svc-account"),
            ("reader", "role"),
            ("group:team", "group"),
            ("policy:read", "policy"),
        ]
        .into_iter()
        .map(|(a, b)| (a.into(), b.into()))
        .collect();
        for (src, dst) in [
            ("alice", "reader"),
            ("service:app", "svc"),
            ("svc", "group:team"),
            ("group:team", "policy:read"),
            ("reader", "bucket:a"),
            ("policy:read", "bucket:a"),
            ("policy:read", "bucket:b"),
        ] {
            g.edges.push(Edge {
                src: src.into(),
                dst: dst.into(),
                system: "s3".into(),
                privs: vec!["Read".into()],
                ..Default::default()
            });
        }
        g
    }
    #[test]
    fn original_columns_collapse_resources_and_keep_exact_routes_when_expanded() {
        let g = fixture();
        let kinds = BTreeMap::from([("s3".into(), "s3".into())]);
        let folded = layout(&g, &kinds, "", None);
        assert_eq!(folded.columns.len(), 6);
        assert!(folded.nodes.iter().any(|n| n.id == "@s3" && n.count == 2));
        assert!(!folded.nodes.iter().any(|n| n.id == "bucket:a"));
        let xs: Vec<_> = ["alice", "svc", "reader", "group:team", "policy:read", "@s3"]
            .iter()
            .map(|id| folded.nodes.iter().find(|n| &n.id == id).unwrap().x)
            .collect();
        assert!(xs.windows(2).all(|w| w[1] - w[0] == COL));
        let opened = layout(&g, &kinds, "", Some("s3"));
        assert_eq!(opened.columns.len(), 7);
        assert!(
            opened
                .edges
                .iter()
                .any(|e| e.src == "policy:read" && e.dst == "bucket:b")
        );
        let h = highlighted(&g, "bucket:b");
        assert!(h.contains("service:app"));
        assert!(!h.contains("alice"));
        assert_eq!(
            layout(&g, &kinds, "bucket:b", None)
                .nodes
                .iter()
                .filter(|n| n.kind == "instance")
                .count(),
            1
        );
    }
    #[test]
    fn long_edges_use_the_lane_above_nodes_and_privilege_colors_are_semantic() {
        assert!(route(60, TOP, 60 + 2 * COL, TOP + ROW).contains(",40"));
        assert!(!route(60, TOP, 60 + COL, TOP + ROW).contains(",40"));
        for (privilege, expected) in [
            ("Read", "read"),
            ("Write", "write"),
            ("ALL", "admin"),
            ("MEMBER", "member"),
            ("DeleteObjectVersion", "write"),
            ("BypassGovernanceRetention", "admin"),
            ("GetObjectVersion", "read"),
        ] {
            assert_eq!(
                tone(&Edge {
                    privs: vec![privilege.into()],
                    ..Default::default()
                }),
                expected
            );
        }
    }
}
