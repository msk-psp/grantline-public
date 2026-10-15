use crate::{
    Result,
    model::{Grant, Kinds, Unobserved},
};
use chrono::{DateTime, FixedOffset, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::LazyLock,
};

pub fn redact(text: &str) -> String {
    static CREDENTIAL: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(://[^\s:/@]+:)[^\s@/]+(@)").unwrap());
    CREDENTIAL.replace_all(text, "${1}***${2}").into_owned()
}
#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub path: PathBuf,
    pub ts: DateTime<FixedOffset>,
    pub user: String,
    pub systems: BTreeSet<String>,
    pub grants: BTreeSet<Grant>,
    pub unobserved: Vec<Unobserved>,
}
#[derive(Deserialize, Serialize)]
struct Run {
    ts: DateTime<FixedOffset>,
    #[serde(default)]
    user: String,
    #[serde(default)]
    systems: BTreeSet<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(untagged, deny_unknown_fields)]
enum Record {
    Run { run: Run },
    Grant { grant: Grant },
    Unobserved { unobserved: Unobserved },
}

impl Snapshot {
    pub fn new(systems: BTreeSet<String>) -> Self {
        let user = ["LOGNAME", "USER", "LNAME", "USERNAME"]
            .iter()
            .find_map(|k| std::env::var(k).ok().filter(|s| !s.is_empty()))
            .unwrap_or_else(|| "unknown".into());
        Self {
            path: PathBuf::new(),
            ts: Utc::now().fixed_offset(),
            user,
            systems,
            grants: Default::default(),
            unobserved: Vec::new(),
        }
    }
    pub fn blind_to(&self, g: &Grant) -> bool {
        !self.systems.contains(&g.system) || self.unobserved.iter().any(|u| u.covers(g))
    }
    pub fn load(path: &Path, kinds: &Kinds) -> Result<Self> {
        let text = fs::read_to_string(path)
            .map_err(|_| format!("Cannot read snapshot {}", path.display()))?;
        let mut header = None;
        let mut grants = BTreeSet::new();
        let mut unobserved = Vec::new();
        for (line, text) in text
            .lines()
            .enumerate()
            .filter(|(_, s)| !s.trim().is_empty())
        {
            let record: Record = serde_json::from_str(text)
                .map_err(|_| format!("Invalid snapshot record on line {}", line + 1))?;
            match record {
                Record::Run { run } => {
                    if header.replace(run).is_some() {
                        return Err("Snapshot has multiple run headers".into());
                    }
                }
                Record::Grant { grant } => {
                    grants.insert(grant.normalized(kinds));
                }
                Record::Unobserved { unobserved: mut u } => {
                    u.note = redact(&u.note);
                    unobserved.push(u);
                }
            }
        }
        let run = header.ok_or("Snapshot has no run header")?;
        Ok(Self {
            path: path.into(),
            ts: run.ts,
            user: run.user,
            systems: run.systems,
            grants,
            unobserved,
        })
    }
    pub fn write(&self, dir: &Path) -> Result<PathBuf> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(dir)
            .map_err(|_| "Cannot create snapshot directory")?;
        let mut temp = tempfile::NamedTempFile::new_in(dir)
            .map_err(|_| "Cannot create private snapshot file")?;
        let encode = |record: &Record| -> Result<String> {
            serde_json::to_string(record)
                .map(|s| s + "\n")
                .map_err(|_| "Cannot encode snapshot".into())
        };
        temp.write_all(
            encode(&Record::Run {
                run: Run {
                    ts: self.ts,
                    user: self.user.clone(),
                    systems: self.systems.clone(),
                },
            })?
            .as_bytes(),
        )
        .map_err(|_| "Cannot write snapshot")?;
        for u in &self.unobserved {
            let mut u = u.clone();
            u.note = redact(&u.note);
            temp.write_all(encode(&Record::Unobserved { unobserved: u })?.as_bytes())
                .map_err(|_| "Cannot write snapshot")?;
        }
        for grant in &self.grants {
            temp.write_all(
                encode(&Record::Grant {
                    grant: grant.clone(),
                })?
                .as_bytes(),
            )
            .map_err(|_| "Cannot write snapshot")?;
        }
        temp.as_file()
            .sync_all()
            .map_err(|_| "Cannot sync snapshot")?;
        let stamp = self.ts.with_timezone(&Utc).format("%Y-%m-%dT%H-%M-%SZ");
        for index in 0.. {
            let suffix = if index == 0 {
                String::new()
            } else {
                format!("-{index}")
            };
            let path = dir.join(format!("snapshot-{stamp}{suffix}.jsonl"));
            match temp.persist_noclobber(&path) {
                Ok(_) => return Ok(path),
                Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
                    temp = error.file;
                }
                Err(_) => return Err("Cannot persist snapshot without overwriting".into()),
            }
        }
        unreachable!()
    }
}
#[derive(Debug, Serialize)]
pub struct Comparison {
    pub previous: DateTime<FixedOffset>,
    pub current: DateTime<FixedOffset>,
    pub gap_seconds: i64,
    pub added: Vec<Grant>,
    pub removed: Vec<Grant>,
    pub revealed: Vec<Grant>,
    pub obscured: Vec<Grant>,
}
pub fn compare(prev: &Snapshot, cur: &Snapshot) -> Comparison {
    let (mut added, mut removed, mut revealed, mut obscured) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for g in cur.grants.difference(&prev.grants) {
        if prev.blind_to(g) {
            revealed.push(g.clone());
        } else {
            added.push(g.clone());
        }
    }
    for g in prev.grants.difference(&cur.grants) {
        if cur.blind_to(g) {
            obscured.push(g.clone());
        } else {
            removed.push(g.clone());
        }
    }
    Comparison {
        previous: prev.ts,
        current: cur.ts,
        gap_seconds: (cur.ts - prev.ts).num_seconds(),
        added,
        removed,
        revealed,
        obscured,
    }
}
pub fn list(dir: &Path) -> Result<Vec<PathBuf>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut paths = Vec::new();
    for entry in fs::read_dir(dir).map_err(|_| "Cannot list snapshot directory")? {
        let entry = entry.map_err(|_| "Cannot read snapshot directory entry")?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if entry
            .file_type()
            .map_err(|_| "Cannot inspect snapshot entry")?
            .is_file()
            && name.starts_with("snapshot-")
            && name.ends_with(".jsonl")
        {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}
pub fn since(text: &str, now: DateTime<FixedOffset>) -> Result<DateTime<FixedOffset>> {
    let text = text.trim();
    if let Some(unit) = text.chars().last().filter(|c| "hdw".contains(*c)) {
        let n: i64 = text[..text.len() - 1]
            .parse()
            .map_err(|_| "Expected duration such as 7d")?;
        if n < 0 {
            return Err("Duration must be non-negative".into());
        }
        let seconds = n
            .checked_mul(match unit {
                'h' => 3600,
                'd' => 86400,
                _ => 604800,
            })
            .ok_or("Duration is too large")?;
        return now
            .checked_sub_signed(
                chrono::Duration::try_seconds(seconds).ok_or("Duration is too large")?,
            )
            .ok_or("Duration is too large".into());
    }
    if let Ok(day) = chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d") {
        return Ok(day.and_hms_opt(0, 0, 0).unwrap().and_utc().fixed_offset());
    }
    DateTime::parse_from_rfc3339(text)
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S")
                .map(|d| d.and_utc().fixed_offset())
        })
        .map_err(|_| "Expected an ISO timestamp, date or duration".into())
}
