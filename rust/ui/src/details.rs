use super::*;

/// Distinct bounded paths, including bridges; cycle termination is per path.
fn paths(graph: &Graph, start: &str, reverse: bool) -> (Vec<Vec<String>>, bool) {
    let mut out = Vec::new();
    let mut todo = vec![vec![start.to_owned()]];
    while let Some(path) = todo.pop() {
        let last = path.last().unwrap();
        let next: BTreeSet<_> = graph
            .edges
            .iter()
            .filter_map(|e| {
                let (a, b) = if reverse {
                    (&e.dst, &e.src)
                } else {
                    (&e.src, &e.dst)
                };
                (a == last && !path.contains(b)).then_some(b.clone())
            })
            .collect();
        if next.is_empty() || path.len() == 16 {
            out.push(path);
        } else {
            for n in next {
                let mut p = path.clone();
                p.push(n);
                todo.push(p);
            }
        }
        if out.len() + todo.len() >= 200 {
            return (out, true);
        }
    }
    (out, false)
}
fn graph(b: &Bootstrap) -> Graph {
    b.data.graph.scoped(&b.service, &b.environment)
}
fn in_scope(b: &Bootstrap, g: &Grant) -> bool {
    in_recent(b, g)
        && (b.service.is_empty() || g.system == b.service)
        && (b.environment.is_empty()
            || b.data
                .graph
                .envs
                .get(&g.system)
                .is_some_and(|es| es.contains(&b.environment)))
}
fn route_list(b: &Bootstrap, routes: Vec<Vec<String>>, limited: bool) -> AnyView {
    view!{<section class="card"><h2>{tr(&b.lang,"Access routes")}</h2>
    <p class="muted">{tr(&b.lang,"Declared bridges describe a credential hop; they are not a measured login.")}</p>
    <div class="route-list">{routes.into_iter().filter(|p|p.len()>1).map(|p|view!{<p>{p.into_iter().enumerate().map(|(i,n)|{
        let resource=n.contains(':')&&!n.starts_with("service:")&&!n.starts_with("policy:")&&!n.starts_with("group:");
        let href=format!("/{}?{}={}&system={}&environment={}&lang={}",if resource{"resource"}else{"account"},if resource{"resource"}else{"subject"},encode(&n),encode(&b.service),encode(&b.environment),encode(&b.lang));
        view!{{(i>0).then(||view!{<span aria-hidden="true">" → "</span>})}<a class="entity" href=href>{n}</a>}
    }).collect_view()}</p>}).collect_view()}</div>
    {limited.then(||view!{<p class="notice">{tr(&b.lang,"Rows are limited; narrow the filter to see more.")}</p>})}</section>}.into_any()
}
pub(super) fn accounts(b: &Bootstrap) -> AnyView {
    let g = graph(b);
    let query = b.query.to_lowercase();
    let nodes: BTreeSet<_> = g
        .principals
        .iter()
        .chain(&g.hops)
        .filter(|n| {
            query.is_empty()
                || n.to_lowercase().contains(&query)
                || g.names
                    .get(*n)
                    .is_some_and(|name| name.to_lowercase().contains(&query))
        })
        .cloned()
        .collect();
    let limited = nodes.len() > 500;
    view!{<div class="table-scroll"><table><thead><tr>
    <th>{tr(&b.lang,"Subject")}</th><th>{tr(&b.lang,"Service")}</th><th>{tr(&b.lang,"Observed grants")}</th><th>{tr(&b.lang,"Status")}</th>
    </tr></thead><tbody>{nodes.into_iter().take(500).map(|name| {
        let systems = g.homes.get(&name).cloned().unwrap_or_default();
        let unknown = b.data.snapshot.unobserved.iter().any(|u| systems.contains(&u.system)
            && (u.subjects.is_empty() || u.subjects.contains(&name)));
        let count = b.data.plan.observed.iter().filter(|row| row.subject == name && in_scope(b,row)).count();
        let label = g.names.get(&name).map(|label| format!("{name} ({label})")).unwrap_or_else(|| name.clone());
        view!{<tr><td><a class="entity" href=format!("/account?subject={}&system={}&environment={}&lang={}",encode(&name),encode(&b.service),encode(&b.environment),encode(&b.lang))>{label}</a></td>
        <td>{systems.into_iter().collect::<Vec<_>>().join(", ")}</td><td>{count}</td>
        <td><span class=if unknown{"badge warning"}else{"badge"}>{tr(&b.lang,if unknown{"Unknown"}else{"Observed"})}</span></td></tr>}
    }).collect_view()}</tbody></table></div>
    {limited.then(||view!{<p class="notice">{tr(&b.lang,"Rows are limited; narrow the filter to see more.")}</p>})}}.into_any()
}
pub(super) fn subject(b: &Bootstrap) -> AnyView {
    let name = if b.subject.is_empty() {
        &b.query
    } else {
        &b.subject
    };
    let (routes, limited) = paths(&graph(b), name, false);
    let holders: BTreeSet<_> = routes
        .iter()
        .flatten()
        .chain(std::iter::once(name))
        .cloned()
        .collect();
    let rows: Vec<_> = b
        .data
        .plan
        .observed
        .iter()
        .filter(|g| holders.contains(&g.subject) && in_scope(b, g))
        .cloned()
        .collect();
    let direct: Vec<_> = rows
        .iter()
        .filter(|g| g.subject == *name)
        .cloned()
        .collect();
    let inherited: Vec<_> = rows.into_iter().filter(|g| g.subject != *name).collect();
    view!{<section class="card"><h2>{name.clone()}</h2><p class="muted">{b.data.graph.names.get(name).cloned().unwrap_or_default()}</p><h3>{tr(&b.lang,"Direct grants")}</h3>{grants_table(&b.lang,direct)}<h3>{tr(&b.lang,"Inherited grants")}</h3>{grants_table(&b.lang,inherited)}</section>{route_list(b,routes,limited)}}.into_any()
}
pub(super) fn resource(b: &Bootstrap) -> AnyView {
    let name = if b.resource.is_empty() {
        &b.query
    } else {
        &b.resource
    };
    let g = graph(b);
    let resources: BTreeSet<_> = b
        .data
        .plan
        .observed
        .iter()
        .filter(|grant| in_scope(b, grant) && contains(name, &grant.resource))
        .map(|grant| grant.resource.clone())
        .collect();
    let mut routes = Vec::new();
    let mut limited = false;
    for resource in &resources {
        let (found, truncated) = paths(&g, resource, true);
        limited |= truncated;
        routes.extend(found);
        if routes.len() >= 200 {
            routes.truncate(200);
            limited = true;
            break;
        }
    }
    let routes: Vec<_> = routes
        .into_iter()
        .map(|mut p| {
            p.reverse();
            p
        })
        .collect();
    let rows = b
        .data
        .plan
        .observed
        .iter()
        .filter(|g| contains(name, &g.resource) && in_scope(b, g))
        .cloned()
        .collect();
    let children: BTreeSet<_> = resources
        .into_iter()
        .filter_map(|r| child(name, &r))
        .collect();
    view!{<section class="card"><h2>{name.clone()}</h2>{(!children.is_empty()).then(||view!{<h3>{tr(&b.lang,"Child resources")}</h3><div class="entities">{children.into_iter().take(500).map(|r|view!{<a class="entity" href=format!("/resource?system={}&resource={}&lang={}",encode(&b.service),encode(&r),encode(&b.lang))>{r.clone()}</a>}).collect_view()}</div>})}<h3>{tr(&b.lang,"Direct grants")}</h3>{grants_table(&b.lang,rows)}</section>{route_list(b,routes,limited)}}.into_any()
}
fn contains(scope: &str, resource: &str) -> bool {
    resource == scope
        || (scope.starts_with("bucket:")
            && resource.starts_with(&format!("{}/", scope.trim_end_matches('/'))))
        || scope.strip_prefix("db:").is_some_and(|db| {
            ["table:", "column:", "schema:", "default:"]
                .iter()
                .any(|kind| resource.starts_with(&format!("{kind}{db}.")))
        })
        || scope.strip_prefix("schema:").is_some_and(|s| {
            resource.starts_with(&format!("table:{s}."))
                || resource.starts_with(&format!("column:{s}."))
        })
        || scope.strip_prefix("table:").is_some_and(|table| {
            resource
                .strip_prefix("column:")
                .and_then(|c| c.rsplit_once('.'))
                .is_some_and(|(parent, _)| parent == table)
        })
}
fn child(scope: &str, resource: &str) -> Option<String> {
    if scope == resource {
        return None;
    }
    if scope.starts_with("bucket:") {
        let rest = resource.strip_prefix(&format!("{}/", scope.trim_end_matches('/')))?;
        return Some(format!(
            "{}/{}",
            scope.trim_end_matches('/'),
            rest.split('/').next()?
        ));
    }
    if let Some(db) = scope.strip_prefix("db:") {
        for kind in ["table", "column"] {
            if let Some(rest) = resource.strip_prefix(&format!("{kind}:{db}.")) {
                return Some(format!("schema:{db}.{}", rest.split('.').next()?));
            }
        }
    }
    if scope.starts_with("schema:")
        && let Some(column) = resource.strip_prefix("column:")
    {
        return Some(format!("table:{}", column.rsplit_once('.')?.0));
    }
    Some(resource.to_owned())
}
pub(super) fn history_comparison(b: &Bootstrap) -> AnyView {
    let Some(c) = &b.history_comparison else {
        return ().into_any();
    };
    ["added","removed","revealed","obscured"].into_iter().map(|key| {
        let label=match key{"added"=>"Added","removed"=>"Removed","revealed"=>"Visible again","obscured"=>"Unknown now",_=>key};
        let rows=serde_json::from_value::<Vec<Grant>>(c[key].clone()).unwrap_or_default();
        view!{<section class="card"><h2>{tr(&b.lang,label)}</h2>{grants_table(&b.lang,rows)}</section>}
    }).collect_view().into_any()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn account_inventory_shows_unknown_and_empty_accounts_without_fabricating_grants() {
        let owner = Owner::new();
        owner.with(|| {
            let mut b = Bootstrap {
                lang: "en".into(),
                ..Default::default()
            };
            b.data.graph.principals = vec!["empty".into(), "unread".into()];
            for name in ["empty", "unread"] {
                b.data
                    .graph
                    .homes
                    .insert(name.into(), BTreeSet::from(["s3".into()]));
            }
            b.data.snapshot.unobserved.push(Unread {
                system: "s3".into(),
                subjects: BTreeSet::from(["unread".into()]),
                ..Default::default()
            });
            b.data
                .graph
                .names
                .insert("unread".into(), "Example person".into());
            let html = accounts(&b).to_html();
            assert!(html.contains("empty") && html.contains("unread (Example person)"));
            assert!(html.contains("Unknown") && html.contains("Observed"));
            b.query = "example person".into();
            let html = accounts(&b).to_html();
            assert!(!html.contains("subject=empty"));
            assert!(html.contains("subject=unread"));
            assert!(b.data.plan.observed.is_empty());
        });
    }
    #[test]
    fn distinct_inherited_routes_terminate_cycles_without_including_unrelated_siblings() {
        let g = Graph {
            edges: [
                ("alice", "reader"),
                ("reader", "table:db.s.a"),
                ("reader", "table:db.s.b"),
                ("reader", "alice"),
            ]
            .into_iter()
            .map(|(src, dst)| Edge {
                src: src.into(),
                dst: dst.into(),
                ..Default::default()
            })
            .collect(),
            ..Default::default()
        };
        let (p, limited) = paths(&g, "table:db.s.a", true);
        assert!(!limited);
        assert!(p.iter().flatten().any(|n| n == "alice"));
        assert!(!p.iter().flatten().any(|n| n == "table:db.s.b"));
    }
    #[test]
    fn resource_navigation_keeps_scope_boundaries() {
        assert!(contains("bucket:demo/team", "bucket:demo/team/reports"));
        assert!(!contains("bucket:demo/team", "bucket:demo/teammate"));
        assert!(contains("db:demo", "table:demo.app.events"));
        assert!(!contains("db:demo", "table:demo2.app.events"));
        assert!(contains("db:demo", "column:demo.app.events.a"));
        assert!(contains("schema:demo.app", "column:demo.app.events.a"));
        assert!(contains(
            "table:demo.app.events",
            "column:demo.app.events.a"
        ));
        assert!(!contains(
            "table:demo.app.events",
            "column:demo.app.events_extra.a"
        ));
        assert!(!contains(
            "column:demo.app.events.a",
            "column:demo.app.events.a/b"
        ));
        assert_eq!(
            child("db:demo", "column:demo.app.events.a"),
            Some("schema:demo.app".into())
        );
        assert_eq!(
            child("schema:demo.app", "column:demo.app.events.a"),
            Some("table:demo.app.events".into())
        );
        assert_eq!(
            child("bucket:demo", "bucket:demo/team/reports"),
            Some("bucket:demo/team".into())
        );
        assert_eq!(
            child("db:demo", "table:demo.app.events"),
            Some("schema:demo.app".into())
        );
    }
}
