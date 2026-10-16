//! Native read-only commands and explicitly selected local IAM application.
use crate::{
    Result, config, engine,
    graph::Paths,
    snapshot::{self, Snapshot},
};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

fn json(value: &impl Serialize) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(|_| "Cannot encode output")?
    );
    Ok(())
}
pub fn apply(
    path: &Path,
    system: &str,
    live: bool,
    write: bool,
    expected: Option<&str>,
    as_json: bool,
) -> Result<()> {
    let loaded = config::load_writer(path)?.0;
    let adapter = loaded
        .config
        .adapters
        .get(system)
        .ok_or("Unknown apply system")?;
    if adapter.typ(system) == "postgres" {
        if !live {
            return Err(
                "PostgreSQL apply preview requires --live and explicit admin_dsn_env".into(),
            );
        }
        let result = crate::postgres::writer::apply(path, system, write, expected)?;
        if as_json {
            return json(&result);
        }
        println!(
            "PostgreSQL {} / {}: {}",
            result.system,
            result.database,
            if result.applied {
                "permission transaction committed"
            } else {
                "dry-run/no change; nothing committed"
            }
        );
        if result.membership_changes_cluster_wide {
            println!("Scope: role memberships affect the entire PostgreSQL cluster");
        }
        if result.default_changes_future_objects_only {
            println!(
                "Scope: defaults affect future relations created by the named role; existing objects are unchanged"
            );
        }
        println!("Plan identifier: {}", result.plan_id);
        for change in &result.changes {
            println!("{}", change.cmd.as_deref().unwrap_or(""));
        }
        return Ok(());
    }
    if adapter.typ(system) == "clickhouse" {
        if !live {
            return Err(
                "ClickHouse apply preview requires --live and explicit admin_url_env".into(),
            );
        }
        let result = crate::clickhouse::writer::apply(path, system, write, expected)?;
        if as_json {
            return json(&result);
        }
        println!(
            "ClickHouse {}: {}",
            result.system,
            if result.applied {
                "single direct ACL change verified on this server"
            } else {
                "dry-run/no change; no statement sent"
            }
        );
        println!("Plan identifier: {}", result.plan_id);
        for c in &result.changes {
            println!("{}", c.cmd.as_deref().unwrap_or(""));
        }
        return Ok(());
    }
    if live {
        return Err("--live apply currently supports PostgreSQL and ClickHouse only".into());
    }
    #[cfg(unix)]
    {
        let result = crate::s3::writer::apply(path, system, write, expected)?;
        writer_output(&result, as_json)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, system, write, expected, as_json);
        Err("Local IAM writer currently supports Unix filesystems only".into())
    }
}
pub fn restore(path: &Path, system: &str, backup: &Path, write: bool, as_json: bool) -> Result<()> {
    #[cfg(unix)]
    {
        let result = crate::s3::writer::restore(path, system, backup, write)?;
        writer_output(&result, as_json)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, system, backup, write, as_json);
        Err("Local IAM writer currently supports Unix filesystems only".into())
    }
}
#[cfg(unix)]
fn writer_output(result: &crate::s3::writer::Receipt, as_json: bool) -> Result<()> {
    if as_json {
        return json(result);
    }
    println!(
        "Local S3 IAM {}: {} — {}",
        result.system,
        result.path.display(),
        if result.applied {
            "file replaced; service reload/application not verified"
        } else if result.restored {
            "original bytes restored; service reload not verified"
        } else {
            "dry-run/no change; IAM file not written"
        }
    );
    println!("Plan identifier: {}", result.plan_id);
    for p in &result.previews {
        println!(
            "{} {}: {} grouped change(s)\nBefore: {}\nAfter: {}",
            p.subject,
            p.kind,
            p.changes.len(),
            p.before.as_ref().unwrap_or(&serde_json::Value::Null),
            p.after.as_ref().unwrap_or(&serde_json::Value::Null)
        );
    }
    if let Some(backup) = &result.backup {
        println!(
            "Private original-byte backup: {} (contains credentials; keep private)",
            backup.display()
        );
    }
    Ok(())
}
#[derive(clap::Args, Default)]
pub struct Source {
    #[arg(long, conflicts_with = "live")]
    pub observed: Option<PathBuf>,
    /// Read configured native PostgreSQL/ClickHouse catalogs and remote S3 IAM; never applies changes.
    #[arg(long)]
    pub live: bool,
}
pub fn plan(path: &Path, source: &Source, as_json: bool, verbose: bool) -> Result<()> {
    let imported = source.observed.as_deref();
    let loaded = config::load(path)?;
    let obs = engine::observe_with_live(&loaded, imported, source.live)?;
    let report = engine::plan(&loaded, &obs);
    if as_json {
        let mut output = serde_json::to_value(&report).map_err(|_| "Cannot encode plan")?;
        output["observed_at"] = serde_json::json!(obs.snapshot.ts);
        output["observation_source"] = serde_json::json!(
            imported
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| if source.live {
                    "configured PostgreSQL/ClickHouse/S3 readers and local inputs".into()
                } else {
                    "local fixtures and IAM files".into()
                })
        );
        output["unobserved"] = serde_json::to_value(&obs.snapshot.unobserved)
            .map_err(|_| "Cannot encode unread scopes")?;
        return json(&output);
    }
    println!(
        "Observed {} grant(s), at {}{}",
        obs.snapshot.grants.len(),
        obs.snapshot.ts,
        if imported.is_some() {
            " (saved observation, not a live read)"
        } else if source.live {
            " (configured PostgreSQL/ClickHouse/S3 readers and local inputs)"
        } else {
            " (local fixtures and IAM files)"
        }
    );
    if !report.observation_complete {
        println!(
            "Partial observation: {} unread scope(s). Unknown is not no access.",
            obs.snapshot.unobserved.len()
        );
    }
    println!(
        "Plan — {} permission change candidate(s); read-only, no changes applied.",
        report.changes.len()
    );
    for group in &report.groups {
        println!(
            "\n[{}] {}: +{} / -{}",
            group.system, group.subject, group.grants, group.revokes
        );
        for change in report
            .changes
            .iter()
            .filter(|c| c.grant.system == group.system && c.grant.subject == group.subject)
        {
            println!(
                "  {} {} on {}",
                change.action, change.grant.privilege, change.grant.resource
            );
            match &change.cmd {
                Some(cmd) => println!("    {cmd}"),
                None => println!(
                    "    Command unavailable: {}",
                    change.command_error.as_deref().unwrap_or("unsupported")
                ),
            }
        }
    }
    for preview in &report.s3_previews {
        println!(
            "\n[S3 {} / {}] {} grouped change(s) — preview only",
            preview.system,
            preview.subject,
            preview.changes.len()
        );
        if let Some(reason) = &preview.blocked {
            println!("  Blocked: {reason}");
        } else {
            println!(
                "  Before: {}\n  After: {}",
                serde_json::to_string_pretty(&preview.before)
                    .map_err(|_| "Cannot encode preview")?,
                serde_json::to_string_pretty(&preview.after)
                    .map_err(|_| "Cannot encode preview")?
            );
        }
    }
    println!("\nUnverified intent: {} grant(s).", report.unverified.len());
    let mut groups: BTreeMap<(&str, &str), Vec<_>> = BTreeMap::new();
    for f in &report.findings {
        groups.entry((&f.system, &f.title)).or_default().push(f);
    }
    println!(
        "Findings: {} in {} kind(s).",
        report.findings.len(),
        groups.len()
    );
    for ((system, title), findings) in groups {
        println!(
            "\n[{}] [{system}] {title} ×{}",
            findings[0].level,
            findings.len()
        );
        for f in findings.iter().take(if verbose { usize::MAX } else { 3 }) {
            println!("  {}", f.detail);
        }
        if !verbose && findings.len() > 3 {
            println!("  … use --verbose to show all");
        }
    }
    Ok(())
}
pub fn record(path: &Path, source: &Source, dir: Option<PathBuf>, as_json: bool) -> Result<()> {
    let loaded = config::load(path)?;
    let obs = engine::observe_with_live(&loaded, source.observed.as_deref(), source.live)?;
    let dir = match dir {
        Some(dir) => dir,
        None if loaded.config.snapshots.is_empty() => {
            return Err("Snapshots disabled; supply --directory".into());
        }
        None => config::relative(&loaded.base, &loaded.config.snapshots)?,
    };
    let saved = obs.snapshot.write(&dir)?;
    if as_json {
        json(
            &serde_json::json!({"path":saved,"observed_at":obs.snapshot.ts,"grants":obs.snapshot.grants.len(),"unobserved":obs.snapshot.unobserved}),
        )
    } else {
        println!(
            "Recorded {} grant(s), {} unread scope(s): {}",
            obs.snapshot.grants.len(),
            obs.snapshot.unobserved.len(),
            saved.display()
        );
        Ok(())
    }
}
pub fn history(
    path: &Path,
    from: Option<&Path>,
    to: Option<&Path>,
    since: Option<&str>,
    as_json: bool,
) -> Result<()> {
    let loaded = config::load(path)?;
    if loaded.config.snapshots.is_empty() {
        return Err("Snapshots are disabled in config".into());
    }
    let dir = config::relative(&loaded.base, &loaded.config.snapshots)?;
    let files = if from.is_some() && to.is_some() {
        Vec::new()
    } else {
        snapshot::list(&dir)?
    };
    if to.is_some() && from.is_none() {
        return Err("--to requires --from".into());
    }
    if from.is_some() && since.is_some() {
        return Err("Choose --from or --since".into());
    }
    if from.is_none() && since.is_none() {
        let snapshots: Vec<_> = files
            .iter()
            .map(|p| Snapshot::load(p, &loaded.kinds))
            .collect::<Result<_>>()?;
        if as_json {
            return json(&snapshots);
        }
        println!("{} snapshot(s) in {}", snapshots.len(), dir.display());
        for s in snapshots {
            println!(
                "{}  {} grants  {}  {}",
                s.ts,
                s.grants.len(),
                s.user,
                s.path.display()
            );
        }
        return Ok(());
    }
    let current = match to {
        Some(path) => dir.join(path),
        None => files.last().ok_or("No snapshots to compare")?.clone(),
    };
    let cur = Snapshot::load(&current, &loaded.kinds)?;
    let prev = if let Some(from) = from {
        Snapshot::load(&dir.join(from), &loaded.kinds)?
    } else {
        let when = snapshot::since(
            since.ok_or("Missing --since")?,
            chrono::Utc::now().fixed_offset(),
        )?;
        let mut found: Option<Snapshot> = None;
        for file in &files {
            let s = Snapshot::load(file, &loaded.kinds)?;
            if s.ts <= when && found.as_ref().is_none_or(|p| p.ts <= s.ts) {
                found = Some(s);
            }
        }
        found.ok_or("No snapshot at or before the requested time")?
    };
    let cmp = snapshot::compare(&prev, &cur);
    if as_json {
        return json(&cmp);
    }
    println!(
        "Between {} and {} ({} seconds apart; no schedule implied)",
        cmp.previous, cmp.current, cmp.gap_seconds
    );
    for (sign, grants) in [("+", &cmp.added), ("-", &cmp.removed)] {
        for g in grants {
            println!(
                "{sign} [{}] {} {} on {}",
                g.system, g.subject, g.privilege, g.resource
            );
        }
    }
    println!(
        "? {} revealed / {} obscured: visibility changed, not permissions",
        cmp.revealed.len(),
        cmp.obscured.len()
    );
    Ok(())
}
pub fn graph(
    path: &Path,
    source: &Source,
    subjects: &[String],
    resources: &[String],
    depth: &[String],
    limit: usize,
    as_json: bool,
) -> Result<()> {
    let imported = source.observed.as_deref();
    if limit == 0 {
        return Err("Route limit must be positive".into());
    }
    let loaded = config::load(path)?;
    let obs = engine::observe_with_live(&loaded, imported, source.live)?;
    let graph = engine::graph(&loaded, &obs)?;
    let routes_from: BTreeMap<String, Paths> = subjects
        .iter()
        .map(|s| (s.clone(), graph.paths(s, false, limit)))
        .collect();
    let paths_to: BTreeMap<String, Paths> = resources
        .iter()
        .map(|s| (s.clone(), graph.paths(s, true, limit)))
        .collect();
    let depths: BTreeMap<String, usize> = depth
        .iter()
        .map(|s| graph.depth(s).map(|d| (s.clone(), d)))
        .collect::<Result<_>>()?;
    if as_json {
        return json(
            &serde_json::json!({"graph":graph,"routes_from":routes_from,"paths_to":paths_to,"depths":depths,"unobserved":obs.snapshot.unobserved,"observed_at":obs.snapshot.ts,"snapshot_metadata_complete":imported.is_none()}),
        );
    }
    println!(
        "{} edges, {} principals, {} hops, {} terminals; {} unread scope(s)",
        graph.edges.len(),
        graph.principals.len(),
        graph.hops.len(),
        graph.terminals.len(),
        obs.snapshot.unobserved.len()
    );
    if imported.is_some() {
        println!(
            "Saved snapshots contain grants and unread scopes, not observer node kinds or policy-route metadata."
        );
    }
    for e in &graph.edges {
        println!(
            "{} → {} [{}; {}] {}",
            graph.label(&e.src),
            graph.label(&e.dst),
            e.system,
            e.kind,
            e.label()
        );
    }
    for (node, paths) in routes_from.iter().chain(&paths_to) {
        println!(
            "\n{node}: {} paths{}",
            paths.paths.len(),
            if paths.truncated { " (truncated)" } else { "" }
        );
        for path in &paths.paths {
            println!("  {}", path.join(" → "));
        }
    }
    for (node, depth) in depths {
        println!("depth({node}) = {depth}");
    }
    Ok(())
}

/// Probe only selected services and observed atoms, never guessed or expanded grants.
pub fn probe(
    path: &Path,
    live: bool,
    imported: Option<&Path>,
    systems: &[String],
    subjects: &[String],
    as_json: bool,
) -> Result<()> {
    use crate::probe::{self, Probe, Verdict};
    let mut loaded = config::load(path)?;
    for system in systems {
        if !loaded.config.adapters.contains_key(system) {
            return Err("Unknown selected probe system".into());
        }
    }
    if !systems.is_empty() {
        loaded.config.adapters.retain(|s, _| systems.contains(s));
    }
    let obs = engine::observe_with_live(&loaded, imported, live && imported.is_none())?;
    let selected: Vec<_> = obs
        .snapshot
        .grants
        .iter()
        .filter(|g| subjects.is_empty() || subjects.contains(&g.subject))
        .cloned()
        .collect();
    if selected.len() > 1000 {
        return Err("Probe selection exceeds 1000 atoms; select a subject/system".into());
    }
    let mut probes = Vec::new();
    for (system, adapter) in &loaded.config.adapters {
        let grants: Vec<_> = selected
            .iter()
            .filter(|g| &g.system == system)
            .cloned()
            .collect();
        if grants.is_empty() {
            continue;
        }
        if live && adapter.typ(system) == "postgres" {
            probes.extend(crate::postgres::probe::run(adapter, &grants));
        } else if live && adapter.typ(system) == "clickhouse" {
            probes.extend(crate::clickhouse::probe::run(adapter, &grants));
        } else if live && adapter.typ(system) == "s3" {
            probes.extend(crate::s3::probe::run(adapter, &grants));
        } else {
            let why = if !live {
                "Network probes disabled; pass --live to opt in"
            } else {
                "Native probes for this adapter are not implemented"
            };
            probes.extend(grants.iter().map(|g| Probe::new(g, Verdict::Unknown, why)));
        }
    }
    let findings = probe::compare(&probes, &obs.snapshot.grants);
    let counts = probe::summary(&probes);
    if as_json {
        return json(
            &serde_json::json!({"probes":probes,"summary":counts,"findings":findings,"observed_at":obs.snapshot.ts,"unobserved":obs.snapshot.unobserved,"baseline_source":if imported.is_some(){"saved observation"}else if live{"configured readers and local inputs"}else{"local inputs"}}),
        );
    }
    println!(
        "Probed {} atoms — allow {}, deny {}, unknown {} (unknown is not no access)",
        probes.len(),
        counts["allow"],
        counts["deny"],
        counts["unknown"]
    );
    for p in probes {
        println!(
            "[{}] {} {} on {}: {:?} — {}",
            p.system, p.subject, p.privilege, p.resource, p.verdict, p.how
        );
    }
    println!(
        "{} baseline unread scopes; {} disagreement finding(s). No data read or permission write attempted.",
        obs.snapshot.unobserved.len(),
        findings.len()
    );
    Ok(())
}
