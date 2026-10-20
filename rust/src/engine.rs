use crate::{
    Result,
    config::{Loaded, relative},
    graph::{Graph, Route},
    model::{Grant, Unobserved},
    planner::{self, Finding, Report},
    snapshot::Snapshot,
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

#[derive(Deserialize)]
struct Atom {
    subject: String,
    resource: String,
    #[serde(rename = "priv")]
    privilege: String,
    #[serde(default = "explicit")]
    source: String,
    #[serde(default)]
    grantor: Option<String>,
}
fn explicit() -> String {
    "explicit".into()
}
#[derive(Default, Deserialize)]
struct Fixture {
    #[serde(default)]
    grants: Vec<Atom>,
    #[serde(default)]
    kinds: BTreeMap<String, String>,
    #[serde(default)]
    unobserved: Vec<Unread>,
    #[serde(default)]
    facts: Facts,
    #[serde(default)]
    routes: Vec<[String; 3]>,
}
#[derive(Default, Deserialize)]
struct Facts {
    #[serde(default)]
    tables: Vec<Table>,
    #[serde(default)]
    databases: Vec<String>,
}
#[derive(Deserialize)]
struct Table {
    name: String,
    owner: String,
    #[serde(default)]
    acl_empty: bool,
}
#[derive(Deserialize)]
struct Unread {
    prefixes: Vec<String>,
    note: String,
    #[serde(default)]
    subjects: std::collections::BTreeSet<String>,
}
#[derive(Clone)]
pub struct Observation {
    pub snapshot: Snapshot,
    pub findings: Vec<Finding>,
    pub kinds: BTreeMap<String, String>,
    pub routes: Vec<Route>,
    pub s3: BTreeMap<String, crate::s3::Observed>,
    pub homes: BTreeMap<String, BTreeSet<String>>,
}
fn unread(system: &str, note: &str) -> Unobserved {
    Unobserved {
        system: system.into(),
        prefixes: vec![String::new()],
        subjects: Default::default(),
        note: note.into(),
    }
}

pub fn observe(loaded: &Loaded, imported: Option<&Path>) -> Result<Observation> {
    observe_with_live(loaded, imported, false)
}
pub fn observe_with_live(
    loaded: &Loaded,
    imported: Option<&Path>,
    live: bool,
) -> Result<Observation> {
    if live && imported.is_some() {
        return Err("--live cannot be combined with --observed".into());
    }
    let mut snapshot = Snapshot::new(loaded.config.adapters.keys().cloned().collect());
    let mut findings = Vec::new();
    let mut kinds = BTreeMap::new();
    let mut routes = Vec::new();
    let mut s3 = BTreeMap::new();
    let mut homes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    if let Some(path) = imported {
        snapshot = Snapshot::load(path, &loaded.kinds)?;
        snapshot
            .grants
            .retain(|g| loaded.config.adapters.contains_key(&g.system));
        snapshot
            .unobserved
            .retain(|u| loaded.config.adapters.contains_key(&u.system));
        snapshot
            .systems
            .retain(|s| loaded.config.adapters.contains_key(s));
        for system in loaded
            .config
            .adapters
            .keys()
            .filter(|s| !snapshot.systems.contains(*s))
        {
            snapshot.unobserved.push(unread(
                system,
                "System absent from imported snapshot; not observed",
            ));
        }
        return Ok(Observation {
            snapshot,
            findings,
            kinds,
            routes,
            s3,
            homes,
        });
    }
    let adapters: Vec<_> = loaded.config.adapters.iter().collect();
    for batch in adapters.chunks(8) {
        let results = std::thread::scope(|scope| {
            let workers: Vec<_> = batch
                .iter()
                .map(|(system, adapter)| {
                    (
                        system,
                        scope.spawn(move || observe_one(loaded, system, adapter, live)),
                    )
                })
                .collect();
            workers
                .into_iter()
                .map(|(system, worker)| (system, worker.join()))
                .collect::<Vec<_>>()
        });
        // Merge in configuration order, independently of completion order.
        for (system, result) in results {
            match result {
                Ok(Ok(mut obs)) => {
                    for node in obs.kinds.keys() {
                        homes
                            .entry(node.clone())
                            .or_default()
                            .insert((*system).clone());
                    }
                    snapshot.grants.append(&mut obs.snapshot.grants);
                    snapshot.unobserved.append(&mut obs.snapshot.unobserved);
                    findings.append(&mut obs.findings);
                    kinds.append(&mut obs.kinds);
                    routes.append(&mut obs.routes);
                    s3.append(&mut obs.s3);
                }
                _ => snapshot
                    .unobserved
                    .push(unread(system, "Observation failed; access remains unknown")),
            }
        }
    }
    Ok(Observation {
        snapshot,
        findings,
        kinds,
        routes,
        s3,
        homes,
    })
}
fn observe_one(
    loaded: &Loaded,
    system: &String,
    adapter: &crate::config::Adapter,
    live: bool,
) -> Result<Observation> {
    let mut snapshot = Snapshot::new([system.clone()].into_iter().collect());
    let mut findings = Vec::new();
    let mut kinds = BTreeMap::new();
    let mut routes = Vec::new();
    let mut s3 = BTreeMap::new();
    for (system, adapter) in std::iter::once((system, adapter)) {
        if adapter.typ(system) == "postgres" && live {
            let obs = crate::postgres::observe(adapter, system);
            snapshot.grants.extend(obs.grants);
            snapshot.unobserved.extend(obs.unknown);
            findings.extend(obs.findings);
            kinds.extend(obs.kinds);
            continue;
        }
        if adapter.typ(system) == "clickhouse" && live {
            let obs = crate::clickhouse::observe(adapter, system);
            snapshot.grants.extend(obs.grants);
            snapshot.unobserved.extend(obs.unknown);
            findings.extend(obs.findings);
            kinds.extend(obs.kinds);
            continue;
        }
        if adapter.typ(system) == "s3" {
            let mut obs = crate::s3::observe_with_live(adapter, &loaded.base, system, live);
            snapshot.grants.append(&mut obs.grants);
            snapshot.unobserved.append(&mut obs.unknown);
            findings.append(&mut obs.findings);
            kinds.append(&mut obs.kinds);
            routes.append(&mut obs.routes);
            s3.insert(system.clone(), obs);
            continue;
        }
        if adapter.typ(system) != "fixture" {
            snapshot.unobserved.push(unread(system,"Native service observation is not implemented in R2; use a saved snapshot or the Python console"));
            continue;
        }
        let path = relative(
            &loaded.base,
            adapter
                .fixture
                .as_deref()
                .ok_or("Fixture path is missing")?,
        )?;
        let fixture: Fixture = match fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
        {
            Some(f) => f,
            None => {
                snapshot.unobserved.push(unread(
                    system,
                    "Fixture is unreadable or invalid JSON/schema",
                ));
                continue;
            }
        };
        let grants: std::collections::BTreeSet<_> = fixture
            .grants
            .into_iter()
            .map(|g| {
                Grant {
                    system: system.clone(),
                    subject: g.subject,
                    resource: g.resource,
                    privilege: g.privilege,
                    source: g.source,
                    grantor: g.grantor,
                }
                .normalized(&loaded.kinds)
            })
            .collect();
        if adapter.kind(system) == "postgres" {
            for table in fixture.facts.tables.iter().filter(|t| t.acl_empty) {
                findings.push(crate::postgres::frozen_finding(
                    "postgres",
                    &table.name,
                    &table.owner,
                ));
            }
        } else if adapter.kind(system) == "clickhouse" {
            findings.extend(crate::clickhouse::stale_findings(
                "clickhouse",
                &grants,
                &fixture.facts.databases,
            ));
        }
        snapshot.grants.extend(grants);
        snapshot
            .unobserved
            .extend(fixture.unobserved.into_iter().map(|u| Unobserved {
                system: system.clone(),
                prefixes: u.prefixes,
                note: crate::snapshot::redact(&u.note),
                subjects: u.subjects,
            }));
        kinds.extend(fixture.kinds);
        routes.extend(
            fixture
                .routes
                .into_iter()
                .map(|[src, dst, label]| [system.clone(), src, dst, label]),
        );
    }
    Ok(Observation {
        snapshot,
        findings,
        kinds,
        routes,
        s3,
        homes: BTreeMap::new(),
    })
}
pub fn plan(loaded: &Loaded, observation: &Observation) -> Report {
    let mut report = planner::build(
        &loaded.intent,
        &observation.snapshot.grants,
        &observation.snapshot.unobserved,
        &loaded.kinds,
        observation.findings.clone(),
    );
    for (system, obs) in &observation.s3 {
        report
            .s3_previews
            .extend(obs.previews(system, &mut report.changes));
    }
    report.commands_complete = report.changes.iter().all(|c| c.cmd.is_some());
    report
}
pub fn graph(loaded: &Loaded, observation: &Observation) -> Result<Graph> {
    let mut graph = Graph::build(
        &observation.snapshot.grants,
        &loaded.config.bridges,
        &observation.kinds,
        &observation.routes,
        &loaded.config.graph,
    )?;
    for (node, systems) in &observation.homes {
        graph
            .homes
            .entry(node.clone())
            .or_default()
            .extend(systems.clone());
    }
    Ok(graph)
}
