//! Offline commands. Reads never resolve credentials or invoke live adapters.
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
pub fn plan(path: &Path, imported: Option<&Path>, as_json: bool, verbose: bool) -> Result<()> {
    let loaded = config::load(path)?;
    let obs = engine::observe(&loaded, imported)?;
    let report = engine::plan(&loaded, &obs);
    if as_json {
        let mut output = serde_json::to_value(&report).map_err(|_| "Cannot encode plan")?;
        output["observed_at"] = serde_json::json!(obs.snapshot.ts);
        output["observation_source"] = serde_json::json!(
            imported
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "local fixtures".into())
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
        } else {
            " (local fixtures)"
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
pub fn record(
    path: &Path,
    imported: Option<&Path>,
    dir: Option<PathBuf>,
    as_json: bool,
) -> Result<()> {
    let loaded = config::load(path)?;
    let obs = engine::observe(&loaded, imported)?;
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
    imported: Option<&Path>,
    subjects: &[String],
    resources: &[String],
    depth: &[String],
    limit: usize,
    as_json: bool,
) -> Result<()> {
    if limit == 0 {
        return Err("Route limit must be positive".into());
    }
    let loaded = config::load(path)?;
    let obs = engine::observe(&loaded, imported)?;
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
