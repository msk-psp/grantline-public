use super::{Edge, Graph, tr};
use leptos::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

const COL: usize = 350;
const ROW: usize = 48;
const W: usize = 270;
const H: usize = 32;
const TOP: usize = 150;
const KINDS: [&str; 6] = [
    "human",
    "svc-account",
    "role",
    "group",
    "policy",
    "instance",
];

pub fn highlighted(graph: &Graph, start: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::from([start.to_owned()]);
    for reverse in [false, true] {
        let mut seen = BTreeSet::new();
        let mut stack = vec![start.to_owned()];
        while let Some(n) = stack.pop() {
            if seen.insert(n.clone()) {
                out.insert(n.clone());
                for e in &graph.edges {
                    let (a, b) = if reverse {
                        (&e.dst, &e.src)
                    } else {
                        (&e.src, &e.dst)
                    };
                    if *a == n {
                        stack.push(b.clone());
                    }
                }
            }
        }
    }
    out
}

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
struct Layout {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    columns: Vec<(usize, String, usize)>,
    groups: Vec<(usize, usize, String)>,
    width: usize,
    height: usize,
    limited: bool,
}
fn kind<'a>(graph: &'a Graph, id: &str) -> &'a str {
    graph.kind.get(id).map(String::as_str).unwrap_or_else(|| {
        if graph.hops.iter().any(|n| n == id) {
            "role"
        } else {
            "human"
        }
    })
}
fn service_rank(name: &str) -> usize {
    match name {
        "postgres" => 0,
        "clickhouse" => 1,
        "s3" => 2,
        _ => 3,
    }
}
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
        .collect();
    let mut visible = connected.clone();
    if !query.is_empty() {
        visible.clear();
        let q = query.to_lowercase();
        for n in connected.iter().filter(|n| {
            n.to_lowercase().contains(&q)
                || graph
                    .names
                    .get(*n)
                    .is_some_and(|label| label.to_lowercase().contains(&q))
        }) {
            visible.extend(highlighted(graph, n));
        }
    }
    let mut homes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
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
    let total = nodes.len();
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
            if positioned.len() >= 1000 {
                break;
            }
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
            if positioned.len() >= 1000 {
                break;
            }
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
        rows_max = rows_max.max(reached.len().min(1000));
    }
    let limited = total > positioned.iter().filter(|n| n.kind != "resource").count()
        || expanded
            .and_then(|s| resources.get(s))
            .is_some_and(|r| r.len() > positioned.iter().filter(|n| n.kind == "resource").count());
    Layout {
        width: (60 + COL * columns.len() + W).max(700),
        height: TOP + 20 + ROW * rows_max,
        nodes: positioned,
        edges,
        columns,
        groups,
        limited,
    }
}
fn tone(edge: &Edge) -> &'static str {
    if edge.kind == "bridge" {
        "bridge"
    } else if edge.dst.starts_with("policy:") {
        "policy"
    } else if edge.privs.iter().any(|p| p == "MEMBER") || edge.dst.starts_with("group:") {
        "member"
    } else if edge.kind == "route" && edge.privs.is_empty() {
        "route"
    } else if edge
        .privs
        .iter()
        .any(|p| matches!(p.as_str(), "ALL" | "OWNER" | "ADMIN" | "Admin" | "GRANT"))
    {
        "admin"
    } else if edge.privs.iter().any(|p| {
        matches!(
            p.as_str(),
            "Write" | "INSERT" | "UPDATE" | "DELETE" | "CREATE" | "DROP" | "ALTER" | "TRUNCATE"
        )
    }) {
        "write"
    } else {
        "read"
    }
}
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

#[component]
pub(super) fn PermissionMap(
    graph: Graph,
    service_kinds: BTreeMap<String, String>,
    service: String,
    environment: String,
    query: String,
    lang: String,
) -> impl IntoView {
    let mut graph = graph;
    graph.edges.retain(|e| {
        (service.is_empty() || e.system == service || e.system == "*")
            && (environment.is_empty()
                || e.system == "*"
                || graph
                    .envs
                    .get(&e.system)
                    .is_some_and(|env| env.contains(&environment)))
    });
    let graph = StoredValue::new(graph);
    let kinds = StoredValue::new(service_kinds);
    let hover = RwSignal::new(None::<String>);
    let selected = RwSignal::new(None::<String>);
    let expanded = RwSignal::new(None::<String>);
    let zoom = RwSignal::new(1_f64);
    let pan = RwSignal::new((0_f64, 0_f64));
    let drag = RwSignal::new(None::<(i32, i32, f64, f64)>);
    let dragged = RwSignal::new(false);
    let viewport = NodeRef::<leptos::html::Div>::new();
    let active = Memo::new(move |_| {
        hover.get().or(selected.get()).map(|id| {
            graph.with_value(|g| {
                if id.starts_with('@') {
                    let folded = layout(g, &kinds.get_value(), "", None);
                    highlighted(
                        &Graph {
                            edges: folded.edges,
                            ..Default::default()
                        },
                        &id,
                    )
                } else {
                    let mut set = highlighted(g, &id);
                    for e in &g.edges {
                        if set.contains(&e.src)
                            && set.contains(&e.dst)
                            && !g.principals.contains(&e.dst)
                            && !g.hops.contains(&e.dst)
                        {
                            set.insert(format!("@{}", e.system));
                        }
                    }
                    set
                }
            })
        })
    });
    let zoom_at = move |factor: f64, x: f64, y: f64| {
        let old = zoom.get_untracked();
        let next = (old * factor).clamp(0.35, 4.0);
        pan.update(|(px, py)| {
            *px = x - (x - *px) * next / old;
            *py = y - (y - *py) * next / old;
        });
        zoom.set(next);
    };
    let zoom_center = move |factor| {
        let (x, y) = viewport
            .get()
            .map(|e| {
                (
                    f64::from(e.client_width()) / 2.0,
                    f64::from(e.client_height()) / 2.0,
                )
            })
            .unwrap_or((400.0, 250.0));
        zoom_at(factor, x, y);
    };
    let reset = move || {
        hover.set(None);
        selected.set(None);
        expanded.set(None);
        zoom.set(1.0);
        pan.set((0.0, 0.0));
    };
    let render_lang = lang.clone();
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
        <button class="quiet" aria-label=tr(&lang,"Zoom in") on:click=move |_|zoom_center(1.25)>"+"</button>
        <button class="quiet" aria-label=tr(&lang,"Zoom out") on:click=move |_|zoom_center(0.8)>"−"</button>
        <button class="quiet" on:click=move |_|reset()>{tr(&lang,"Fit view")}</button>
        <button class="quiet" on:click=move |_|{hover.set(None);selected.set(None);}>{tr(&lang,"Clear selection")}</button>
        </div>
        {move||selected.get().map(|id|{
            let href=if let Some(system)=id.strip_prefix('@') {format!("/services?system={}",super::encode(system))} else {let resource=graph.with_value(|g|g.terminals.contains(&id));format!("/{}?{}={}&lang={}",if resource{"resource"}else{"account"},if resource{"resource"}else{"subject"},super::encode(&id),super::encode(&detail_lang))+&detail_scope};
            view!{<a class="entity" href=href>{tr(&detail_lang,"View details")}" · "{id}</a>}
        })}</div>
        <div class="map-viewport" node_ref=viewport class:dragging=move||drag.get().is_some()
            on:wheel=move |e|{e.prevent_default();zoom_center(if e.delta_y()<0.0 {1.1} else {1.0/1.1});}
            on:pointerdown=move |e|{if e.button()==0{let (px,py)=pan.get_untracked();dragged.set(false);drag.set(Some((e.client_x(),e.client_y(),px,py)));}}
            on:pointermove=move |e|{if let Some((x,y,px,py))=drag.get_untracked(){let(dx,dy)=(e.client_x()-x,e.client_y()-y);if dx.abs()+dy.abs()>3{dragged.set(true);pan.set((px+f64::from(dx),py+f64::from(dy)));}}}
            on:pointerup=move |_|drag.set(None) on:pointerleave=move |_|{drag.set(None);hover.set(None);}
            on:keydown=move |e|{if e.key()=="Escape"{reset();}}>
        {move || {
            let l=graph.with_value(|g|layout(g,&kinds.get_value(),&query,expanded.get().as_deref()));
            let positions:BTreeMap<_,_>=l.nodes.iter().map(|n|(n.id.clone(),(n.x,n.y))).collect();
            let edges=l.edges.into_iter().filter_map(|e| {
                let (&(x,y),&(dx,dy))=(positions.get(&e.src)?,positions.get(&e.dst)?);
                let class=format!("map-edge e-{}",tone(&e));
                let (src,dst)=(e.src.clone(),e.dst.clone());
                let title=format!("{} · {}",e.system,if e.note.is_empty(){e.privs.join(", ")}else{e.note.clone()});
                Some(view!{<path data-src=e.src data-dst=e.dst d=route(x,y,dx,dy) class=class
                    class:dim=move||active.get().is_some_and(|s|!s.contains(&src)||!s.contains(&dst))
                    class:lit=move||active.get().is_some() marker-end="url(#map-arrow)"><title>{title}</title></path>})
            }).collect_view();
            let nodes=l.nodes.into_iter().map(|n| {
                let id=n.id.clone(); let id_enter=id.clone();let id_focus=id.clone();let id_click=id.clone();let id_key=id.clone();let id_hot=id.clone();let id_dim=id.clone();let id_selected=id.clone();
                let instance=n.kind=="instance";
                let tag=if instance {format!("{} {} ›",n.count,tr(&render_lang,"Resources"))} else {
                    let envs:BTreeSet<_>=graph.with_value(|g|n.homes.iter().flat_map(|s|g.envs.get(s).into_iter().flatten().cloned()).collect());
                    if envs.len()>1 {envs.into_iter().collect::<Vec<_>>().join("·")} else {envs.into_iter().next().filter(|s|s!="prod").unwrap_or_default()}
                };
                let home_kinds:BTreeSet<_>=n.homes.iter().filter_map(|s|kinds.with_value(|ks|ks.get(s).cloned())).collect();
                let tag_x=W-12-home_kinds.len()*19;
                let room=tag_x.saturating_sub(tag.chars().count()*6+20)/7;
                let label=if n.label.chars().count()>room {n.label.chars().take(room.saturating_sub(1)).collect::<String>()+"…"}else{n.label.clone()};
                let icons=home_kinds.into_iter().enumerate().map(|(i,k)| {
                    let x=W-26-i*19;
                    match k.as_str(){
                        "postgres"=>view!{<image x=x y="8" width="16" height="16" href="/static/postgresql.png"/>}.into_any(),
                        "s3"=>view!{<image x=x y="8" width="16" height="16" href="/static/seaweedfs.png"/>}.into_any(),
                        "clickhouse"=>view!{<text class="map-ch-icon" x=x y="21">"▥"</text>}.into_any(),
                        _=>view!{<text class="map-home-icon" x=x y="21">"◇"</text>}.into_any()
                    }
                }).collect_view();
                view!{<g class=format!("map-node {}",n.kind) data-node-id=id.clone() role="button" tabindex="0" aria-label=id
                    aria-expanded=move||if instance{Some(if expanded.get().as_deref()==id_selected.strip_prefix('@'){"true"}else{"false"})}else{None}
                    class:dim=move||active.get().is_some_and(|s|!s.contains(&id_dim))
                    class:hot=move||active.get().is_some_and(|s|s.contains(&id_hot))
                    class:selected=move||selected.get().as_ref()==Some(&id_click)
                    transform=format!("translate({},{})",n.x,n.y)
                    on:mouseenter=move |_|{if drag.get_untracked().is_none(){hover.set(Some(id_enter.clone()));}}
                    on:mouseleave=move |_|hover.set(None)
                    on:focus=move |_|hover.set(Some(id_focus.clone())) on:blur=move |_|hover.set(None)
                    on:click={let id=n.id.clone();move |_|{if !dragged.get_untracked(){if instance{expanded.update(|s|*s=if s.as_deref()==id.strip_prefix('@'){None}else{id.strip_prefix('@').map(str::to_owned)});}selected.update(|s|*s=if s.as_ref()==Some(&id){None}else{Some(id.clone())});}}}
                    on:keydown=move|e|{if matches!(e.key().as_str(),"Enter"|" "){e.prevent_default();if instance{expanded.update(|s|*s=if s.as_deref()==id_key.strip_prefix('@'){None}else{id_key.strip_prefix('@').map(str::to_owned)});}selected.set(Some(id_key.clone()));}}>
                    <title>{format!("{}\n{}",n.label,n.homes.into_iter().collect::<Vec<_>>().join(", "))}</title>
                    <rect width=W height=H rx="9"/>
                    <text x="12" y="20">{label}</text><text class="map-tag" x=tag_x y="20" text-anchor="end">{tag}</text>{icons}
                </g>}
            }).collect_view();
            let columns=l.columns.into_iter().map(|(x,title,count)|view!{<g><text class="column-title" x=x y=TOP-30>{tr(&render_lang,&title)}</text><text class="column-subtitle" x=x y=TOP-14>{format!("{count} · a–z")}</text></g>}).collect_view();
            let groups=l.groups.into_iter().map(|(x,y,title)|view!{<text class="map-group" x=x y=y+20>{tr(&render_lang,&title)}</text>}).collect_view();
            view!{<svg class="permission-map" role="group" aria-label=tr(&render_lang,"Map") viewBox=format!("0 0 {} {}",l.width,l.height)
                style:transform=move||{let(x,y)=pan.get();format!("translate({x}px,{y}px) scale({})",zoom.get())}>
                <defs><marker id="map-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto" markerUnits="userSpaceOnUse"><path d="M0,0.5 L8,4 L0,7.5 z" fill="context-stroke"/></marker></defs>
                {columns}{groups}{edges}{nodes}
                </svg>{l.limited.then(||view!{<p class="map-limit">{tr(&render_lang,"Rows are limited; narrow the filter to see more.")}</p>})}
            }
        }}
        <div class="map-hint">{tr(&lang,"Click to follow · scroll to zoom · drag to pan · Esc to reset")}</div>
        </div>
        <div class="map-legend">
        {[("human","Users"),("service","Services"),("svc-account","Service accounts"),("role","Roles"),("group","Groups"),("policy","Policies"),("instance","Service instances")].into_iter().map(|(class,label)|view!{<span class=class><i></i>{tr(&lang,label)}</span>}).collect_view()}
        <span class="legend-read">"→ "{tr(&lang,"Read")}</span><span class="legend-write">"→ "{tr(&lang,"Write")}</span><span class="legend-admin">"→ "{tr(&lang,"Admin")}</span>
        </div></section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Graph {
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
