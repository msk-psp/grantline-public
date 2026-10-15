use crate::{
    Result,
    graph::{Bridge, GraphConfig},
    model::{Grant, Kinds},
};
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub intent: String,
    #[serde(default = "snapshot_dir")]
    pub snapshots: String,
    #[serde(default)]
    pub adapters: indexmap::IndexMap<String, Adapter>,
    #[serde(default)]
    pub bridges: Vec<Bridge>,
    #[serde(default)]
    pub graph: GraphConfig,
}
fn snapshot_dir() -> String {
    "snapshots".into()
}
#[derive(Debug, Deserialize)]
pub struct Adapter {
    #[serde(rename = "type", default)]
    pub typ: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub fixture: Option<String>,
    #[serde(default = "enforced_plane")]
    pub enforced: String,
    #[serde(default)]
    pub planes: indexmap::IndexMap<String, crate::s3::Plane>,
    #[serde(default)]
    pub url_env: Option<String>,
    #[serde(default)]
    pub probe_url_env: Option<String>,
    #[serde(default)]
    pub probe_url_envs: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub dsn_env: Option<String>,
    #[serde(default)]
    pub probe_dsn_envs: std::collections::BTreeMap<String, String>,
    #[serde(default = "all_databases")]
    pub databases: Vec<String>,
    #[serde(default)]
    pub exclude_databases: Vec<String>,
    #[serde(default = "read_timeout")]
    pub read_timeout_seconds: u64,
}
fn all_databases() -> Vec<String> {
    vec!["*".into()]
}
fn read_timeout() -> u64 {
    30
}
fn enforced_plane() -> String {
    "static".into()
}
impl Adapter {
    pub fn typ<'a>(&'a self, system: &'a str) -> &'a str {
        self.typ.as_deref().unwrap_or(system)
    }
    pub fn kind<'a>(&'a self, system: &'a str) -> &'a str {
        self.kind
            .as_deref()
            .unwrap_or(if self.typ(system) == "fixture" {
                system
            } else {
                self.typ(system)
            })
    }
}
#[derive(Debug, Deserialize)]
struct IntentFile {
    #[serde(default)]
    grants: Vec<Declaration>,
    #[serde(default)]
    managed_subjects: BTreeSet<String>,
    #[serde(default)]
    managed_systems: BTreeSet<String>,
    #[serde(default)]
    naming: Naming,
}
#[derive(Debug, Deserialize)]
struct Declaration {
    system: String,
    subject: String,
    resource: String,
    privs: Vec<String>,
}
#[derive(Debug, Deserialize)]
struct Naming {
    #[serde(default = "default_synonyms")]
    synonyms: Vec<Vec<String>>,
}
impl Default for Naming {
    fn default() -> Self {
        Self {
            synonyms: default_synonyms(),
        }
    }
}
pub fn default_synonyms() -> Vec<Vec<String>> {
    [
        vec!["read", "reader", "readonly", "ro", "researcher", "viewer"],
        vec!["write", "writer", "rw", "maintainer", "editor"],
    ]
    .into_iter()
    .map(|g| g.into_iter().map(String::from).collect())
    .collect()
}
#[derive(Debug)]
pub struct Intent {
    pub grants: BTreeSet<Grant>,
    pub managed: BTreeSet<String>,
    pub managed_systems: BTreeSet<String>,
    pub naming_synonyms: Vec<Vec<String>>,
}
pub struct Loaded {
    pub config: Config,
    pub intent: Intent,
    pub base: PathBuf,
    pub kinds: Kinds,
}

pub fn relative(base: &Path, value: &str) -> Result<PathBuf> {
    let path = if value == "~" || value.starts_with("~/") {
        let home = std::env::var_os("HOME").ok_or("HOME is unavailable for path expansion")?;
        PathBuf::from(home).join(value.strip_prefix("~/").unwrap_or(""))
    } else if value.starts_with('~') {
        return Err("Only ~ or ~/ paths are supported".into());
    } else {
        PathBuf::from(value)
    };
    Ok(if path.is_absolute() {
        path
    } else {
        base.join(path)
    })
}
fn read_toml<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let text = fs::read_to_string(path)
        .map_err(|_| format!("Cannot read TOML file {}", path.display()))?;
    // Parser diagnostics may echo credential values; report the boundary only.
    toml::from_str(&text).map_err(|_| format!("Invalid TOML or schema in {}", path.display()))
}
pub fn load(path: &Path) -> Result<Loaded> {
    // Match Python: relative files follow the selected path, even for a symlink.
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|_| "Cannot resolve current directory")?
            .join(path)
    };
    let base = path
        .parent()
        .ok_or("Config has no parent directory")?
        .to_owned();
    let config: Config = read_toml(&path)?;
    let kinds: Kinds = config
        .adapters
        .iter()
        .map(|(s, a)| (s.clone(), a.kind(s).to_owned()))
        .collect();
    for (system, adapter) in &config.adapters {
        if !matches!(
            adapter.typ(system),
            "fixture" | "postgres" | "clickhouse" | "s3"
        ) {
            return Err(format!("Unknown adapter type for {system}"));
        }
        if adapter.typ(system) == "fixture"
            && (!matches!(adapter.kind(system), "postgres" | "clickhouse")
                || adapter.fixture.as_deref().is_none_or(str::is_empty))
        {
            return Err(format!(
                "Fixture {system} needs a postgres/clickhouse kind and a fixture path"
            ));
        }
        if matches!(adapter.typ(system), "clickhouse" | "postgres")
            && adapter.kind(system) != adapter.typ(system)
        {
            return Err(format!("Native adapter {system} type and kind must agree"));
        }
    }
    let input: IntentFile = read_toml(&relative(&base, &config.intent)?)?;
    let mut grants = BTreeSet::new();
    for row in input.grants {
        if !config.adapters.contains_key(&row.system) {
            return Err(format!("Intent names unconfigured system {}", row.system));
        }
        for p in row.privs {
            grants.insert(
                Grant::new(&row.system, &row.subject, &row.resource, &p).normalized(&kinds),
            );
        }
    }
    if !input
        .managed_systems
        .iter()
        .all(|s| config.adapters.contains_key(s))
    {
        return Err("managed_systems names an unconfigured system".into());
    }
    config.graph.validate()?;
    Ok(Loaded {
        config,
        base,
        kinds,
        intent: Intent {
            grants,
            managed: input.managed_subjects,
            managed_systems: input.managed_systems,
            naming_synonyms: input.naming.synonyms,
        },
    })
}
