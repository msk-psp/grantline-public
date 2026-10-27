//! Shared Leptos SSR/hydration UI. API data and source diagnostics stay distinct.
mod details;
pub mod i18n;
mod map;
mod observation;
mod verify;
use i18n::tr;
use leptos::prelude::*;
use map::PermissionMap;
pub use map::highlighted;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Grant {
    pub system: String,
    pub subject: String,
    pub resource: String,
    #[serde(rename = "priv")]
    pub privilege: String,
    pub source: String,
    pub grantor: Option<String>,
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Edge {
    pub src: String,
    pub dst: String,
    pub system: String,
    pub privs: Vec<String>,
    pub kind: String,
    pub note: String,
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Graph {
    pub edges: Vec<Edge>,
    pub principals: Vec<String>,
    pub hops: Vec<String>,
    pub terminals: Vec<String>,
    pub names: BTreeMap<String, String>,
    pub kind: BTreeMap<String, String>,
    pub envs: BTreeMap<String, Vec<String>>,
    pub teams: BTreeMap<String, String>,
    pub homes: BTreeMap<String, BTreeSet<String>>,
}
impl Graph {
    fn scoped(&self, service: &str, environment: &str) -> Self {
        let mut graph = self.clone();
        let matches = |s: &str| {
            (service.is_empty() || s == service || s == "*")
                && (environment.is_empty()
                    || s == "*"
                    || self
                        .envs
                        .get(s)
                        .is_some_and(|es| es.iter().any(|e| e == environment)))
        };
        graph.edges.retain(|e| matches(&e.system));
        graph.homes.retain(|_, systems| {
            systems.retain(|s| matches(s));
            !systems.is_empty()
        });
        if !service.is_empty() || !environment.is_empty() {
            let connected: BTreeSet<_> =
                graph.edges.iter().flat_map(|e| [&e.src, &e.dst]).collect();
            graph
                .principals
                .retain(|n| graph.homes.contains_key(n) || connected.contains(n));
            graph
                .hops
                .retain(|n| graph.homes.contains_key(n) || connected.contains(n));
        }
        graph
    }
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Finding {
    pub system: String,
    pub title: String,
    pub detail: String,
    pub level: String,
    pub entities: Vec<String>,
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Change {
    pub action: String,
    pub grant: Grant,
    pub cmd: Option<String>,
    pub command_error: Option<String>,
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Plan {
    pub observed: Vec<Grant>,
    pub changes: Vec<Change>,
    pub findings: Vec<Finding>,
    pub observation_complete: bool,
    pub commands_complete: bool,
    pub unverified: Vec<Grant>,
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Unread {
    pub system: String,
    pub note: String,
    pub subjects: BTreeSet<String>,
    pub prefixes: Vec<String>,
    pub privileges: BTreeSet<String>,
    pub category: String,
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Snapshot {
    pub ts: String,
    pub unobserved: Vec<Unread>,
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Data {
    pub plan: Plan,
    pub graph: Graph,
    pub declared: Vec<Grant>,
    pub snapshot: Snapshot,
    pub services: Vec<String>,
    pub service_kinds: BTreeMap<String, String>,
    pub environments: BTreeMap<String, Vec<String>>,
    pub recent: Option<Value>,
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Actor {
    pub subject: String,
    pub display: String,
    pub authenticated: bool,
    pub csrf: String,
    pub approval_identity: String,
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Bootstrap {
    pub data: Data,
    pub actor: Option<Actor>,
    pub page: String,
    pub lang: String,
    pub query: String,
    pub service: String,
    pub environment: String,
    pub requests: Vec<Value>,
    pub history: Vec<Value>,
    pub workflow: bool,
    pub interactive: bool,
    pub error: Option<String>,
    pub loading: bool,
    pub refresh: bool,
    pub refresh_url: String,
    pub days: String,
    pub subject: String,
    pub resource: String,
    pub action: String,
    pub privilege: String,
    pub history_comparison: Option<Value>,
    pub probe_subjects: BTreeMap<String, Vec<String>>,
}
fn text(v: &Value, key: &str) -> String {
    v[key].as_str().unwrap_or_default().into()
}
fn encode(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}
fn status(lang: &str, value: &str) -> String {
    tr(
        lang,
        match value {
            "legacy" => "Archived; request a new review",
            "pending" => "Pending",
            "approved" => "Approved",
            "denied" => "Denied",
            "proposed" => "PR created",
            "publishing" => "Publishing",
            _ => "Needs inspection",
        },
    )
}
fn in_recent(b: &Bootstrap, g: &Grant) -> bool {
    b.data.recent.is_none()
        || b.data.graph.edges.iter().any(|e| {
            e.system == g.system
                && e.src == g.subject
                && (e.dst == g.resource || g.resource.strip_prefix("role:") == Some(e.dst.as_str()))
                && e.privs.contains(&g.privilege)
        })
}
fn matched(b: &Bootstrap, g: &Grant) -> bool {
    in_recent(b, g)
        && (b.service.is_empty() || b.service == g.system)
        && (b.environment.is_empty()
            || b.data
                .graph
                .envs
                .get(&g.system)
                .is_some_and(|e| e.contains(&b.environment)))
        && (b.query.is_empty()
            || format!("{} {} {} {}", g.system, g.subject, g.resource, g.privilege)
                .to_lowercase()
                .contains(&b.query.to_lowercase()))
}
fn badge(p: String) -> AnyView {
    let class = if matches!(
        p.as_str(),
        "ALL" | "DELETE" | "Write" | "DROP" | "DeleteObjectVersion" | "BypassGovernanceRetention"
    ) {
        "badge danger"
    } else if matches!(p.as_str(), "INSERT" | "UPDATE" | "CREATE") {
        "badge warning"
    } else {
        "badge"
    };
    view! {<span class=class>{p}</span>}.into_any()
}
fn findings(lang: &str, rows: &[Finding]) -> AnyView {
    if rows.is_empty() {
        return view! {<p class="empty">{tr(lang,"No findings")}</p>}.into_any();
    }
    rows.iter().take(500).cloned().map(|r|{let level=match r.level.as_str(){"error"=>("log error","Error"),"info"=>("log info","Information"),_=>("log warning","Warning")};view!{<article class=level.0>
<div class="log-heading">
<span class="log-level">{tr(lang,level.1)}</span>
<strong>{r.title}</strong>
<code class="entity">{r.system}</code>
</div>
<p>{r.detail}</p>
<div class="entities">{r.entities.into_iter().map(|e|view!{<code class="entity">{e}</code>}).collect_view()}</div>
</article>}}).collect_view().into_any()
}
fn grants_table(lang: &str, rows: Vec<Grant>) -> AnyView {
    let limited = rows.len() > 500;
    view!{<div class="table-scroll">
<table>
<thead>
<tr>
<th>{tr(lang,"Service")}</th>
<th>{tr(lang,"Subject")}</th>
<th>{tr(lang,"Resource")}</th>
<th>{tr(lang,"Privilege")}</th>
<th>{tr(lang,"Source")}</th>
</tr>
</thead>
<tbody>{rows.into_iter().take(500).map(|g|view!{<tr>
<td>
<code class="entity">{g.system.clone()}</code>
</td>
<td>
<a href=format!("/account?subject={}&system={}",encode(&g.subject),encode(&g.system))>{g.subject.clone()}</a>
</td>
<td>
<a href=format!("/resource?resource={}&system={}",encode(&g.resource),encode(&g.system))>{g.resource.clone()}</a>
</td>
<td>{badge(g.privilege.clone())}<div class="grant-actions">{(!g.resource.starts_with("column:")).then(||["grant","revoke"].into_iter().map(|action|view!{<a href=format!("/act?system={}&subject={}&resource={}&priv={}&action={}&lang={}",encode(&g.system),encode(&g.subject),encode(&g.resource),encode(&g.privilege),action,encode(lang))>{tr(lang,if action=="grant"{"Grant"}else{"Revoke"})}</a>}).collect_view())}{g.resource.starts_with("column:").then(||view!{<span class="muted">{tr(lang,"Read only")}</span>})}</div></td>
<td><span>{g.source}</span>{g.grantor.map(|who|view!{<span class="muted">" · "{tr(lang,"Grantor")}": "<code class="entity">{who}</code></span>})}</td>
</tr>}).collect_view()}</tbody>
</table>
</div>{limited.then(||view!{<p class="notice">{tr(lang,"Rows are limited; narrow the filter to see more.")}</p>})}}.into_any()
}
#[component]
pub fn Console(bootstrap: Bootstrap) -> impl IntoView {
    let b = bootstrap;
    let lang = b.lang.clone();
    let auth = b.actor.as_ref().is_some_and(|a| a.authenticated);
    let csrf = b.actor.as_ref().map(|a| a.csrf.clone()).unwrap_or_default();
    let nav = [
        ("/", "Map"),
        ("/accounts", "Accounts"),
        ("/resources", "Resources"),
        ("/services", "Services"),
        ("/matrix", "Matrix"),
        ("/changes", "Changes"),
        ("/history", "History"),
        ("/approvals", "Approvals"),
        ("/act", "Request access"),
        ("/verify", "Verify access"),
    ];
    let title = match b.page.as_str() {
        "accounts" | "account" => "Accounts",
        "resources" | "resource" => "Resources",
        "services" => "Services",
        "matrix" => "Matrix",
        "changes" => "Changes",
        "history" => "History",
        "approvals" => "Approvals",
        "act" => "Request access",
        "verify" => "Verify access",
        _ => "Map",
    };
    let body = if b.error.is_some() || b.loading {
        view!{<p class="notice" role="status">{if b.loading{tr(&b.lang,"Loading catalog…")}else{tr(&b.lang,"Catalog unavailable; access is unknown.")}}</p>}.into_any()
    } else {
        match b.page.as_str(){"verify"=>view!{<verify::VerifyForm bootstrap=b.clone()/>}.into_any(),"services"=>services(&b),"matrix"=>matrix_page(&b),"changes"=>changes(&b),"history"=>history(&b),"approvals"=>reviews(&b),"act"=>view!{<RequestForm bootstrap=b.clone()/>}.into_any(),"account"=>details::subject(&b),"resource"=>details::resource(&b),"accounts"=>details::accounts(&b),"resources"=>grants_table(&lang,b.data.plan.observed.iter().filter(|g|matched(&b,g)).cloned().collect()),_=>view!{<PermissionMap graph=b.data.graph.clone() service_kinds=b.data.service_kinds.clone() service=b.service.clone() environment=b.environment.clone() query=b.query.clone() lang=lang.clone()/>}.into_any()}
    };
    let menus = nav
        .into_iter()
        .map(|(href, key)| {
            let active = key == title;
            view! {<a class:current=active href=href>{tr(&lang,key)}</a>}
        })
        .collect_view();
    let environments: BTreeSet<_> = b.data.graph.envs.values().flatten().cloned().collect();
    view! {<div class="app">
    <header>
    <a class="brand" href="/">
    <img src="/static/grantline-icon.svg" alt=""/>"Grantline"</a>
    <span class="tagline">{tr(&b.lang,"Untangle access. Follow the grants.")}</span>
    <div class="header-actions">
    <span class="badge">{tr(&b.lang,if auth{"Authenticated"}else{"Read only"})}</span>
    <button type="button" class="quiet" aria-label=tr(&b.lang,"Theme") on:click=move |_|toggle_theme()>"◐"</button>
    <label class="language">
    <span class="sr-only">{tr(&b.lang,"Language")}</span>
    <select aria-label=tr(&b.lang,"Language") on:change=move |ev|set_language(event_target_value(&ev))>{[("en","English"),("ko","한국어"),("ja","日本語"),("zh-CN","中文")].into_iter().map(|(value,label)|view!{<option value=value selected=value==b.lang>{label}</option>}).collect_view()}</select>
    </label>{if auth{view!{<form method="post" action="/auth/logout">
    <input type="hidden" name="csrf" value=csrf/>
    <button class="quiet">{tr(&b.lang,"Sign out")}</button>
    </form>}.into_any()}else{view!{<a href="/auth/login">{tr(&b.lang,"Sign in")}</a>}.into_any()}}</div>
    </header>
    <nav aria-label="Primary">{menus}</nav>
    <main class:map-page=title=="Map">
    <div class="page-heading">
    <div>
    <p class="eyebrow">{b.actor.as_ref().map(|a|a.display.clone()).unwrap_or_default()}</p>
    <h1>{tr(&b.lang,title)}</h1>
    </div>
    <a class="button secondary" href=b.refresh_url.clone()>{tr(&b.lang,"Refresh")}</a>
    </div>{b.error.as_ref().map(|_|view!{<div role="alert" class="notice error">{tr(&b.lang,"Catalog unavailable; access is unknown.")}</div>})}{observation::notices(&b)}{(!b.interactive).then(||view!{<div class="notice">{tr(&b.lang,"Interactive bundle unavailable; build the UI to enable interactions.")}</div>})}{(!matches!(b.page.as_str(),"history"|"approvals"|"act"|"verify")).then(||view!{<form class="filters" method="get">
    <label>
    <span class="sr-only">{tr(&b.lang,"Search")}</span>
    <input name="q" value=b.query.clone() placeholder=tr(&b.lang,"Search")/>
    </label>
    <select name="system" aria-label=tr(&b.lang,"Service")>
    <option value="">{tr(&b.lang,"All services")}</option>{b.data.services.iter().map(|s|view!{<option value=s.clone() selected=*s==b.service>{s.clone()}</option>}).collect_view()}</select>
    <select name="environment" aria-label=tr(&b.lang,"All environments")>
    <option value="">{tr(&b.lang,"All environments")}</option>{environments.into_iter().map(|e|view!{<option value=e.clone() selected=e==b.environment>{e.clone()}</option>}).collect_view()}</select>
    <input type="hidden" name="subject" value=b.subject.clone()/><input type="hidden" name="resource" value=b.resource.clone()/><input type="hidden" name="lang" value=b.lang.clone()/>
    {matches!(b.page.as_str(),"map"|""|"resources"|"resource").then(||view!{<label><span class="sr-only">{tr(&b.lang,"Recent changes (days)")}</span><input name="days" type="number" min="1" max="3650" step="1" placeholder=tr(&b.lang,"Recent changes (days)") value=b.days.clone()/></label>})}
    <button>{tr(&b.lang,"Filter")}</button>
    </form>})}{b.data.recent.as_ref().map(|info|view!{<p class="notice" role="status">{tr(&b.lang,"Observed change routes")}": "{format!("{}d · +{} / −{}",info["days"],info["added"],info["removed"])}" · "{tr(&b.lang,if info["complete"]==true{"Complete observation window"}else{"Incomplete observation window"})}</p>})}{body}</main>
    <footer>"Grantline · "{tr(&b.lang,"Preview only; no permission has been applied.")}</footer>
    </div>}
}
fn services(b: &Bootstrap) -> AnyView {
    let query = b.query.to_lowercase();
    let matches = |f: &Finding| {
        format!("{} {} {}", f.title, f.detail, f.entities.join(" "))
            .to_lowercase()
            .contains(&query)
    };
    let cards=b.data.services.iter().filter(|name| {
        (b.service.is_empty() || b.service.as_str()==name.as_str())
        && (b.environment.is_empty() || b.data.graph.envs.get(*name).is_some_and(|e|e.contains(&b.environment)))
        && (query.is_empty() || name.to_lowercase().contains(&query) || b.data.plan.findings.iter().any(|f|f.system.as_str()==name.as_str()&&matches(f)))
    }).map(|name| {
        let logs:Vec<_>=b.data.plan.findings.iter().filter(|f|f.system==*name&&(query.is_empty()||name.to_lowercase().contains(&query)||matches(f))).cloned().collect();
        let gaps:Vec<_>=b.data.snapshot.unobserved.iter().filter(|u|u.system==*name).collect();
        let unknown=gaps.iter().any(|u|!u.is_limitation()&&u.subjects.is_empty()&&u.privileges.is_empty()&&u.prefixes.iter().any(|p|p.is_empty()));
        let partial=!gaps.is_empty();
        let kind=b.data.service_kinds.get(name).map(String::as_str).unwrap_or("");
        let icon=match kind {
            "postgres"=>view!{<img class="service-icon" src="/static/postgresql.png" alt="PostgreSQL"/>}.into_any(),
            "s3"=>view!{<img class="service-icon" src="/static/seaweedfs.png" alt="SeaweedFS"/>}.into_any(),
            _=>view!{<span class="service-icon clickhouse" aria-hidden="true">"▥"</span>}.into_any()
        };
        view!{<section class="card"><div class="service-heading">{icon}<h2>{name.clone()}</h2>
        <span class=if unknown{"badge warning"}else{"badge"}>{tr(&b.lang,if unknown{"Unknown"}else if partial{"Partially observed"}else{"Observed"})}</span></div>
        <p class="muted">{b.data.snapshot.ts.clone()}</p>{findings(&b.lang,&logs)}</section>}
    }).collect_view();
    view!{{cards.is_empty().then(||view!{<p class="empty">{tr(&b.lang,"No results")}</p>})}<div class="cards">{cards}</div>}.into_any()
}

fn matrix_table(lang: &str, rows: &[Grant], gaps: &[Unread]) -> AnyView {
    let subjects: BTreeSet<_> = rows
        .iter()
        .map(|g| g.subject.clone())
        .chain(gaps.iter().flat_map(|u| u.subjects.iter().cloned()))
        .collect();
    let columns: BTreeSet<_> = rows
        .iter()
        .map(|g| (g.system.clone(), g.resource.clone()))
        .collect();
    let limited = subjects.len() > 150 || columns.len() > 150;
    let columns: Vec<_> = columns.into_iter().take(150).collect();
    let mut index: BTreeMap<(&str, &str, &str), Vec<String>> = BTreeMap::new();
    for g in rows {
        index
            .entry((&g.subject, &g.system, &g.resource))
            .or_default()
            .push(g.privilege.clone());
    }
    let headings = columns
        .iter()
        .map(|(s, r)| {
            view! {<th>
            <code>{s.clone()}</code>
            <a href=format!("/resource?system={}&resource={}&lang={}",encode(s),encode(r),encode(lang))>{r.clone()}</a>
            </th>}
        })
        .collect_view();
    let body=subjects.into_iter().take(150).map(|s|{let cells=columns.iter().map(|(sys,res)|{let ps:Vec<_>=index.get(&(s.as_str(),sys.as_str(),res.as_str())).into_iter().flatten().map(|p|badge(p.clone())).collect();let unknown=gaps.iter().any(|u|u.system==*sys&&(u.subjects.is_empty()||u.subjects.contains(&s))&&u.prefixes.iter().any(|p|res.starts_with(p))&&(!res.starts_with("role:")||u.privileges.is_empty()||u.privileges.contains("MEMBER")));view!{<td>{if ps.is_empty()&&!unknown{view!{<span class="muted">"—"</span>}.into_any()}else{view!{{ps}{unknown.then(||view!{<span class="badge warning" title=tr(lang,"Unknown") aria-label=tr(lang,"Unknown")>"?"</span>})}}.into_any()}}</td>}}).collect_view();view!{<tr>
<th scope="row"><a href=format!("/account?subject={}&lang={}",encode(&s),encode(lang))>{s.clone()}</a></th>{cells}</tr>}}).collect_view();
    view!{<div class="table-scroll matrix-scroll" tabindex="0" role="region" aria-label=tr(lang,"Matrix")>
<table class="matrix">
<thead>
<tr>
<th>{tr(lang,"Subject")}</th>{headings}</tr>
</thead>
<tbody>{body}</tbody>
</table>
</div>{limited.then(||view!{<p class="notice">{tr(lang,"Rows are limited; narrow the filter to see more.")}</p>})}}.into_any()
}
fn matrix_page(b: &Bootstrap) -> AnyView {
    let gaps: Vec<_> = b
        .data
        .snapshot
        .unobserved
        .iter()
        .filter(|u| {
            (b.service.is_empty() || u.system == b.service)
                && (b.environment.is_empty()
                    || b.data
                        .environments
                        .get(&b.environment)
                        .is_some_and(|ss| ss.contains(&u.system)))
        })
        .cloned()
        .collect();
    let observed: Vec<_> = b
        .data
        .plan
        .observed
        .iter()
        .filter(|g| matched(b, g))
        .cloned()
        .collect();
    let declared: Vec<_> = b
        .data
        .declared
        .iter()
        .filter(|g| matched(b, g))
        .cloned()
        .collect();
    view! {<section class="card">
    <h2>{tr(&b.lang,"Observed grants")}</h2>{matrix_table(&b.lang,&observed,&gaps)}</section>
    <section class="card">
    <h2>{tr(&b.lang,"Declared grants")}</h2>{matrix_table(&b.lang,&declared,&gaps)}</section>}
    .into_any()
}
fn changes(b: &Bootstrap) -> AnyView {
    let rows: Vec<_> = b
        .data
        .plan
        .changes
        .iter()
        .filter(|c| matched(b, &c.grant))
        .collect();
    view!{<p class="notice">{tr(&b.lang,"Preview only; no permission has been applied.")}</p>{rows.is_empty().then(||view!{<p class="empty">{tr(&b.lang,if b.data.snapshot.unobserved.is_empty(){"No changes"}else{"Unknown"})}</p>})}{rows.into_iter().map(|c|view!{<article class="card">
<h2>{tr(&b.lang,if c.action=="grant"{"Grant"}else{"Revoke"})}" · "<code class="entity">{c.grant.subject.clone()}</code>
<code class="entity">{c.grant.system.clone()}</code>
</h2>
<p>
<code class="entity">{c.grant.resource.clone()}</code>{badge(c.grant.privilege.clone())}</p>
<pre>{c.cmd.clone().unwrap_or_else(||tr(&b.lang,"Command unavailable"))}</pre>
</article>}).collect_view()}<h2>{tr(&b.lang,"Findings")}</h2>{findings(&b.lang,&b.data.plan.findings)}}.into_any()
}
fn history(b: &Bootstrap) -> AnyView {
    let busy = RwSignal::new(false);
    let msg = RwSignal::new(String::new());
    let csrf = b.actor.as_ref().map(|a| a.csrf.clone()).unwrap_or_default();
    let enabled = b.actor.as_ref().is_some_and(|a| a.authenticated);
    view!{<button disabled=move||!enabled||busy.get() on:click=move |_|act("/api/snapshots".into(),json!({"csrf":csrf}),busy,msg)>{tr(&b.lang,"Record snapshot")}</button>
<p role="status">{move||msg.get()}</p>
<section class="card">
<h2>{tr(&b.lang,"Snapshots")}</h2><form method="get" class="filters"><label>{tr(&b.lang,"From")}<select name="from">{b.history.iter().map(|r|view!{<option value=text(r,"name")>{text(r,"ts")}</option>}).collect_view()}</select></label><label>{tr(&b.lang,"To")}<select name="to">{b.history.iter().map(|r|view!{<option value=text(r,"name")>{text(r,"ts")}</option>}).collect_view()}</select></label><button>{tr(&b.lang,"Compare")}</button></form>
<div class="table-scroll">
<table>
<thead>
<tr>
<th>{tr(&b.lang,"Time")}</th>
<th>{tr(&b.lang,"Observed")}</th>
<th>{tr(&b.lang,"Added")}</th>
<th>{tr(&b.lang,"Removed")}</th><th>{tr(&b.lang,"Unknown")}</th><th>{tr(&b.lang,"Visibility changes")}</th>
</tr>
</thead>
<tbody>{b.history.iter().map(|r|view!{<tr>
<td>{text(r,"ts")}</td>
<td>{r["grants"].as_u64().unwrap_or_default()}</td>
<td>{r["added"].as_u64().map(|n|n.to_string()).unwrap_or_else(||tr(&b.lang,"No baseline"))}</td>
<td>{r["removed"].as_u64().map(|n|n.to_string()).unwrap_or_else(||tr(&b.lang,"No baseline"))}</td><td>{r["unknown"].as_u64().unwrap_or_default()}</td><td>{r["visibility"].as_u64().map(|n|n.to_string()).unwrap_or_else(||tr(&b.lang,"No baseline"))}</td>
</tr>}).collect_view()}</tbody>
</table>
</div>
</section>{details::history_comparison(b)}}.into_any()
}
#[component]
fn RequestForm(bootstrap: Bootstrap) -> impl IntoView {
    let b = bootstrap;
    let enabled = b.workflow && b.actor.as_ref().is_some_and(|a| a.authenticated) && b.interactive;
    let busy = RwSignal::new(false);
    let msg = RwSignal::new(String::new());
    let system = RwSignal::new(if b.service.is_empty() {
        b.data.services.first().cloned().unwrap_or_default()
    } else {
        b.service.clone()
    });
    let subject = RwSignal::new(b.subject.clone());
    let resource = RwSignal::new(b.resource.clone());
    let kinds = StoredValue::new(b.data.service_kinds.clone());
    let privilege = RwSignal::new(
        if kinds.with_value(|k| k.get(&system.get_untracked()).is_some_and(|s| s == "s3")) {
            "Read"
        } else {
            "SELECT"
        }
        .to_owned(),
    );
    let action = RwSignal::new(
        if b.action == "revoke" {
            "revoke"
        } else {
            "grant"
        }
        .to_owned(),
    );
    if !b.privilege.is_empty() {
        privilege.set(b.privilege.clone());
    }
    let csrf = b.actor.as_ref().map(|a| a.csrf.clone()).unwrap_or_default();
    let working = tr(&b.lang, "Working…");
    let submit = tr(&b.lang, "Submit request");
    view! {<p class="notice">{tr(&b.lang,"Approval and PR creation do not apply IAM permissions.")}</p>{(!enabled).then(||view!{<p class="notice">{tr(&b.lang,"Configure authenticated approvals and a code writer to request changes.")}</p>})}<form class="request-form card" on:submit=move|e|{e.prevent_default();act("/api/requests".into(),json!({"csrf":csrf,"system":system.get(),"subject":subject.get(),"resource":resource.get(),"privilege":privilege.get(),"action":action.get()}),busy,msg);}>
            <fieldset disabled=move||!enabled||busy.get()>
    <label>{tr(&b.lang,"Service")}<select on:change=move|e|{let value=event_target_value(&e);privilege.set(if kinds.with_value(|k|k.get(&value).is_some_and(|s|s=="s3")){"Read"}else{"SELECT"}.into());system.set(value);}>{b.data.services.into_iter().map(|s|view!{<option value=s.clone() selected=move||system.get()==s>{s.clone()}</option>}).collect_view()}</select>
    </label>
    <label>{tr(&b.lang,"Subject")}<input required maxlength="1024" prop:value=move||subject.get() value=b.subject.clone() on:input=move|e|subject.set(event_target_value(&e))/>
    </label>
    <label>{tr(&b.lang,"Resource")}<input required maxlength="1024" prop:value=move||resource.get() value=b.resource.clone() on:input=move|e|resource.set(event_target_value(&e))/>
    </label>
    <label>{tr(&b.lang,"Privilege")}<select on:change=move|e|privilege.set(event_target_value(&e))>{["SELECT","INSERT","UPDATE","DELETE","USAGE","CONNECT","CREATE","MEMBER","TRUNCATE","REFERENCES","TRIGGER","MAINTAIN","TEMPORARY","ALL","ALTER","DROP","SHOW","OPTIMIZE","dictGet","Read","Write","List","Tagging","Admin"].into_iter().map(|p|view!{<option value=p selected=move||privilege.get()==p>{p}</option>}).collect_view()}</select>
    </label>
    <label>{tr(&b.lang,"Action")}<select on:change=move|e|action.set(event_target_value(&e))>
    <option value="grant" selected=move||action.get()=="grant">{tr(&b.lang,"Grant")}</option>
    <option value="revoke" selected=move||action.get()=="revoke">{tr(&b.lang,"Revoke")}</option>
    </select>
    </label>
    <button type="submit">{move||if busy.get(){working.clone()}else{submit.clone()}}</button>
    </fieldset>
    <p role="status">{move||msg.get()}</p>
    </form>}
}
fn reviews(b: &Bootstrap) -> AnyView {
    let actor = b.actor.clone().unwrap_or_default();
    let cards=b.requests.iter().map(|r|{let busy=RwSignal::new(false);let msg=RwSignal::new(String::new());let id=text(r,"id");let hash=text(r,"plan_hash");let csrf=actor.csrf.clone();let who=if actor.approval_identity.is_empty(){&actor.subject}else{&actor.approval_identity};let can_decide=b.interactive&&r["required"].as_array().is_some_and(|a|a.iter().any(|v|v.as_str()==Some(who)))&&r["approved"].as_array().is_none_or(|a|!a.iter().any(|v|v.as_str()==Some(who)))&&r["status"]=="pending";
        let buttons=[("approve","Approve"),("deny","Deny")].into_iter().map(|(decision,label)|{let path=format!("/api/requests/{id}/decide");let hash=hash.clone();let csrf=csrf.clone();view!{<button disabled=move||!can_decide||busy.get() on:click=move |_|act(path.clone(),json!({"csrf":csrf,"plan_hash":hash,"decision":decision}),busy,msg)>{tr(&b.lang,label)}</button>}}).collect_view();let publish_path=format!("/api/requests/{id}/publish");let approved=b.interactive&&r["status"]=="approved";
        view!{<article class="card request">
<div class="request-heading">
<code class="entity">{id.clone()}</code>
<span class="badge">{status(&b.lang,&text(r,"status"))}</span>
</div>
<p>{tr(&b.lang,"Requester")}": "{text(r,"requester")}</p>
<p>
<code class="entity">{text(&r["grant"],"system")}</code>
<code class="entity">{text(&r["grant"],"subject")}</code>
<code class="entity">{text(&r["grant"],"resource")}</code>{badge(text(&r["grant"],"priv"))}</p>
<p>{tr(&b.lang,"Required approvers")}": "{r["required"].as_array().map(|a|a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).unwrap_or_default()}</p>
<a href=format!("/approvals/{}",encode(&id))>{tr(&b.lang,"Review")}</a>
<details>
<summary>{tr(&b.lang,"Plan fingerprint")}" · "{hash}</summary>
<h3>{tr(&b.lang,"Before")}</h3>
<pre>{text(r,"before")}</pre>
<h3>{tr(&b.lang,"After")}</h3>
<pre>{text(r,"after")}</pre>
</details>
<div class="actions">{buttons}<button disabled=move||!approved||busy.get() on:click=move |_|act(publish_path.clone(),json!({"csrf":csrf}),busy,msg)>{tr(&b.lang,"Create PR")}</button>{r["pr_url"].as_str().map(|url|view!{<a class="button" href=url.to_owned() rel="noreferrer">{tr(&b.lang,"Open PR")}</a>})}</div>
<p role="status">{move||msg.get()}</p>
</article>}
    }).collect_view();
    view!{<p class="notice">{tr(&b.lang,"Approval and PR creation do not apply IAM permissions.")}</p>{b.requests.is_empty().then(||view!{<p class="empty">{tr(&b.lang,"No results")}</p>})}{cards}}.into_any()
}
fn act(path: String, value: Value, busy: RwSignal<bool>, message: RwSignal<String>) {
    if busy.get() {
        return;
    }
    busy.set(true);
    #[cfg(feature = "hydrate")]
    leptos::task::spawn_local(async move {
        use wasm_bindgen::{JsCast, JsValue};
        use wasm_bindgen_futures::JsFuture;
        let result: Result<(), JsValue> = async {
            let options = web_sys::RequestInit::new();
            options.set_method("POST");
            options.set_credentials(web_sys::RequestCredentials::SameOrigin);
            options.set_body(&JsValue::from_str(&value.to_string()));
            let request = web_sys::Request::new_with_str_and_init(&path, &options)?;
            request.headers().set("Content-Type", "application/json")?;
            let window = web_sys::window().ok_or(JsValue::NULL)?;
            let response: web_sys::Response = JsFuture::from(window.fetch_with_request(&request))
                .await?
                .dyn_into()?;
            if response.ok() {
                let _ = window.location().assign(if path == "/api/snapshots" {
                    "/history"
                } else {
                    "/approvals"
                });
                Ok(())
            } else {
                let text = JsFuture::from(response.text()?)
                    .await?
                    .as_string()
                    .unwrap_or_default();
                message.set(text.chars().take(1000).collect());
                Ok(())
            }
        }
        .await;
        if result.is_err() {
            message.set("Request failed. Check sign-in and refresh.".into());
        }
        busy.set(false);
    });
    #[cfg(not(feature = "hydrate"))]
    {
        let _ = (path, value);
        message.set("UI hydration is unavailable".into());
        busy.set(false);
    }
}
fn set_language(value: String) {
    #[cfg(feature = "hydrate")]
    {
        if let Some(w) = web_sys::window() {
            if let Ok(url) = web_sys::Url::new(&w.location().href().unwrap_or_default()) {
                url.search_params().set("lang", &value);
                let _ = w.location().assign(&url.href());
            }
        }
    }
    #[cfg(not(feature = "hydrate"))]
    let _ = value;
}
fn toggle_theme() {
    #[cfg(feature = "hydrate")]
    {
        use wasm_bindgen::JsCast;
        if let Some(w) = web_sys::window() {
            if let Some(d) = w.document() {
                if let Some(root) = d.document_element() {
                    let current = root.get_attribute("data-theme").unwrap_or_default();
                    let dark = current == "dark"
                        || (current != "light"
                            && w.match_media("(prefers-color-scheme: dark)")
                                .ok()
                                .flatten()
                                .is_some_and(|m| m.matches()));
                    let next = if dark { "light" } else { "dark" };
                    let _ = root.set_attribute("data-theme", next);
                    if let Some(h) = d.dyn_ref::<web_sys::HtmlDocument>() {
                        let _ = h.set_cookie(&format!(
                            "grantline_theme={next}; Path=/; SameSite=Lax; Max-Age=31536000"
                        ));
                    }
                }
            }
        }
    }
}
#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn hydrate() {
    use wasm_bindgen::JsCast;
    console_error_panic_hook::set_once();
    let Some(document) = web_sys::window().and_then(|w| w.document()) else {
        return;
    };
    let Some(data) = document
        .get_element_by_id("grantline-data")
        .and_then(|e| e.text_content())
    else {
        return;
    };
    let Ok(bootstrap) = serde_json::from_str::<Bootstrap>(&data) else {
        return;
    };
    let Some(root) = document
        .get_element_by_id("grantline-app")
        .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok())
    else {
        return;
    };
    leptos::mount::hydrate_from(root, move || view! {<Root bootstrap/>}).forget();
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matrix_shows_unknown_cells_without_hiding_known_memberships() {
        Owner::new().with(|| {
            let rows = vec![
                Grant {
                    system: "clickhouse".into(),
                    subject: "alice".into(),
                    resource: "table:demo.events".into(),
                    privilege: "SELECT".into(),
                    ..Default::default()
                },
                Grant {
                    system: "clickhouse".into(),
                    subject: "bob".into(),
                    resource: "role:reader".into(),
                    privilege: "MEMBER".into(),
                    ..Default::default()
                },
            ];
            let gaps = vec![Unread {
                system: "clickhouse".into(),
                subjects: BTreeSet::from(["bob".into()]),
                prefixes: vec![String::new()],
                privileges: BTreeSet::from(["SELECT".into()]),
                category: "unsupported".into(),
                ..Default::default()
            }];
            let html = matrix_table("en", &rows, &gaps).to_html();
            assert!(html.contains("Unknown") && html.contains("MEMBER"));
            assert_eq!(html.matches("aria-label=\"Unknown\"").count(), 1);
        });
    }
    #[test]
    fn resource_hover_excludes_siblings_and_terminates_cycles() {
        let g = Graph {
            edges: vec![
                Edge {
                    src: "alice".into(),
                    dst: "role".into(),
                    ..Default::default()
                },
                Edge {
                    src: "role".into(),
                    dst: "bucket:one".into(),
                    ..Default::default()
                },
                Edge {
                    src: "role".into(),
                    dst: "bucket:two".into(),
                    ..Default::default()
                },
                Edge {
                    src: "role".into(),
                    dst: "alice".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let h = highlighted(&g, "bucket:one");
        assert!(h.contains("alice") && h.contains("role"));
        assert!(!h.contains("bucket:two"));
    }
}

#[component]
pub fn Root(bootstrap: Bootstrap) -> impl IntoView {
    let current = RwSignal::new(bootstrap.clone());
    #[cfg(feature = "hydrate")]
    if bootstrap.loading {
        leptos::task::spawn_local(async move {
            use wasm_bindgen::JsCast;
            use wasm_bindgen_futures::JsFuture;
            let result: Result<Data, wasm_bindgen::JsValue> = async {
                let window = web_sys::window().ok_or(wasm_bindgen::JsValue::NULL)?;
                let response: web_sys::Response = JsFuture::from(window.fetch_with_str(&format!(
                    "/api/catalog?days={}{}",
                    encode(&bootstrap.days),
                    if bootstrap.refresh { "&refresh=1" } else { "" }
                )))
                .await?
                .dyn_into()?;
                if !response.ok()
                    || !response
                        .headers()
                        .get("Content-Type")?
                        .unwrap_or_default()
                        .contains("application/json")
                {
                    return Err(wasm_bindgen::JsValue::NULL);
                }
                let text = JsFuture::from(response.text()?)
                    .await?
                    .as_string()
                    .ok_or(wasm_bindgen::JsValue::NULL)?;
                serde_json::from_str(&text).map_err(|_| wasm_bindgen::JsValue::NULL)
            }
            .await;
            current.update(|b| {
                b.loading = false;
                match result {
                    Ok(data) => {
                        b.data = data;
                        b.error = None;
                    }
                    Err(_) => b.error = Some("Catalog unavailable".into()),
                }
            });
        });
    }
    view! {{move||view!{<Console bootstrap=current.get()/>}}}
}
