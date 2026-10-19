//! Private durable approvals. Publication creates a code PR, never applies IAM.
use crate::{
    Result,
    auth::Actor,
    integrations::{self, GitHub, Patch},
    model::Grant,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
};
use subtle::ConstantTimeEq;
use uuid::Uuid;

fn store_path() -> String {
    "approvals".into()
}
fn slack_api() -> String {
    "https://slack.com/api/".into()
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Slack {
    pub bot_token_env: String,
    pub signing_secret_env: String,
    pub team_id: String,
    #[serde(default = "slack_api")]
    pub api_url: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Rule {
    #[serde(rename = "match")]
    pub patterns: Vec<String>,
    pub approvers: Vec<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    #[serde(default = "store_path")]
    pub store: String,
    #[serde(default)]
    pub admin: BTreeSet<String>,
    #[serde(default)]
    pub identities: BTreeMap<String, String>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    pub code_writer: Option<GitHub>,
    pub slack: Option<Slack>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Event {
    pub at: i64,
    pub actor: String,
    pub event: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Record {
    pub version: u8,
    pub id: String,
    pub created_at: i64,
    pub requester: String,
    pub requester_approval_identity: String,
    pub action: String,
    pub grant: Grant,
    pub required: BTreeSet<String>,
    pub approved: BTreeSet<String>,
    pub status: String,
    pub plan_hash: String,
    pub policy_hash: String,
    pub code: Patch,
    pub pr_url: Option<String>,
    pub events: Vec<Event>,
    pub notifications: String,
}
impl Record {
    pub fn view(&self) -> Value {
        json!({"id":self.id,"created_at":self.created_at,"requester":self.requester,"action":self.action,"grant":self.grant,"required":self.required,"approved":self.approved,"status":self.status,"plan_hash":self.plan_hash,"base_commit":self.code.base_commit,"before":self.code.before,"after":self.code.after,"pr_url":self.pr_url,"events":self.events,"notifications":self.notifications,"applied":false})
    }
}
pub struct Workflow {
    pub config: Config,
    root: PathBuf,
    origin: String,
    policy_hash: String,
    _lock: File,
    mutex: Mutex<()>,
}
fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
fn event(r: &mut Record, actor: &str, what: &str) {
    r.events.push(Event {
        at: now(),
        actor: actor.into(),
        event: what.into(),
    });
}
fn valid_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
pub fn private_dir(path: &Path) -> Result<()> {
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("State path cannot traverse parents".into());
    }
    for p in path.ancestors() {
        if let Ok(m) = fs::symlink_metadata(p)
            && (m.is_symlink() || !m.is_dir() || (m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0))
        {
            return Err("State path has an untrusted ancestor".into());
        }
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|_| "Cannot create private state directory")?;
    if fs::metadata(path)
        .map_err(|_| "Cannot inspect state")?
        .mode()
        & 0o077
        != 0
    {
        return Err("State directory must have mode 0700".into());
    }
    Ok(())
}
pub fn private_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let m = fs::symlink_metadata(path).map_err(|_| "Cannot inspect private record")?;
    if !m.is_file() || m.nlink() != 1 || m.mode() & 0o077 != 0 || m.len() > 4 * 1024 * 1024 {
        return Err("State requires a private bounded regular file".into());
    }
    let bytes = crate::config::writer_file(path)?;
    serde_json::from_slice(&bytes).map_err(|_| "Invalid private state record".into())
}
pub fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().ok_or("State parent missing")?;
    private_dir(parent)?;
    if path.exists() {
        let m = fs::symlink_metadata(path).map_err(|_| "Cannot inspect state target")?;
        if !m.is_file() || m.nlink() != 1 || m.mode() & 0o077 != 0 {
            return Err("Unsafe state target".into());
        }
    }
    let mut f =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "Cannot stage private state")?;
    serde_json::to_writer(&mut f, value).map_err(|_| "Cannot encode state")?;
    if f.as_file()
        .metadata()
        .map_err(|_| "Cannot inspect state size")?
        .len()
        > 4 * 1024 * 1024
    {
        return Err("Approval record exceeds limit".into());
    }
    f.flush().map_err(|_| "Cannot flush state")?;
    f.as_file().sync_all().map_err(|_| "Cannot sync state")?;
    f.persist(path).map_err(|_| "Cannot replace state")?;
    File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(|_| "Cannot sync state directory".into())
}
impl Workflow {
    pub fn open(config: Config, base: &Path, origin: &str, binding: &str) -> Result<Self> {
        if config.admin.is_empty()
            || config.admin.len() > 128
            || config.identities.values().collect::<BTreeSet<_>>().len() != config.identities.len()
        {
            return Err("Approvals require independent admins and unique identity mapping".into());
        }
        for r in &config.rules {
            for p in &r.patterns {
                glob::Pattern::new(p).map_err(|_| "Invalid approval scope pattern")?;
            }
        }
        let root = crate::config::relative(base, &config.store)?;
        private_dir(&root)?;
        let path = root.join(".writer.lock");
        if path.exists() {
            let m = fs::symlink_metadata(&path).map_err(|_| "Cannot inspect state lock")?;
            if !m.is_file() || m.nlink() != 1 || m.mode() & 0o077 != 0 {
                return Err("Unsafe state lock".into());
            }
        }
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| "Cannot open state lock")?;
        lock.try_lock()
            .map_err(|_| "Approval state is already in use by another process")?;
        let policy_hash = integrations::sha(
            serde_json::to_vec(&(&config, origin, binding))
                .map_err(|_| "Cannot bind approval policy")?
                .as_slice(),
        );
        let store = Self {
            policy_hash,
            config,
            root,
            origin: origin.trim_end_matches('/').into(),
            _lock: lock,
            mutex: Mutex::new(()),
        };
        store.recover_interrupted()?;
        Ok(store)
    }
    fn recover_interrupted(&self) -> Result<()> {
        let mut count = 0;
        for entry in fs::read_dir(&self.root).map_err(|_| "Cannot inspect approval recovery")? {
            let name = entry
                .map_err(|_| "Cannot inspect approval recovery entry")?
                .file_name()
                .to_string_lossy()
                .into_owned();
            if let Some(id) = name.strip_suffix(".json").filter(|id| valid_id(id)) {
                count += 1;
                if count > 1000 {
                    return Err("Approval recovery limit exceeded".into());
                }
                let mut r = self.load(id)?;
                let mut changed = false;
                if r.status == "publishing" {
                    r.status = "publish_unknown".into();
                    changed = true;
                }
                if r.notifications == "sending" {
                    r.notifications = "unknown".into();
                    changed = true;
                }
                if changed {
                    event(
                        &mut r,
                        "system",
                        "restart requires external outcome inspection",
                    );
                    self.save(&r)?;
                }
            }
        }
        Ok(())
    }
    fn archives(&self) -> Result<Vec<crate::migration::Archive>> {
        let dir = self.root.join("archive");
        if !dir.exists() {
            return Ok(vec![]);
        }
        let meta = fs::symlink_metadata(&dir).map_err(|_| "Cannot inspect archive")?;
        if !meta.is_dir() || meta.is_symlink() || meta.mode() & 0o077 != 0 {
            return Err("Unsafe archive directory".into());
        }
        let mut out = vec![];
        for e in fs::read_dir(dir).map_err(|_| "Cannot list archive")? {
            let e = e.map_err(|_| "Cannot read archive entry")?;
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(id) = name.strip_suffix(".json").filter(|s| valid_id(s)) else {
                return Err("Unexpected archive entry".into());
            };
            let a: crate::migration::Archive = private_json(&e.path())?;
            if a.version != 1 || a.id != id || out.len() >= 1000 {
                return Err("Unsupported archive schema or size".into());
            }
            out.push(a);
        }
        Ok(out)
    }
    fn identity<'a>(&'a self, actor: &'a str) -> &'a str {
        self.config
            .identities
            .get(actor)
            .map(String::as_str)
            .unwrap_or(actor)
    }
    fn path(&self, id: &str) -> Result<PathBuf> {
        if !valid_id(id) {
            return Err("Invalid request ID".into());
        }
        Ok(self.root.join(format!("{id}.json")))
    }
    fn load(&self, id: &str) -> Result<Record> {
        let r: Record = private_json(&self.path(id)?)?;
        if r.version != 1 || r.id != id {
            return Err("Unsupported or mismatched approval version".into());
        }
        Ok(r)
    }
    fn save(&self, r: &Record) -> Result<()> {
        atomic_json(&self.path(&r.id)?, r)
    }
    fn can_read(&self, r: &Record, actor: &str) -> bool {
        r.requester == actor || r.required.contains(self.identity(actor))
    }
    pub fn list(&self, actor: &str) -> Result<Vec<Value>> {
        let _guard = self.mutex.lock().map_err(|_| "Approval lock unavailable")?;
        let mut out = vec![];
        let mut entries = 0;
        for e in fs::read_dir(&self.root).map_err(|_| "Cannot list approvals")? {
            let e = e.map_err(|_| "Cannot list approval entry")?;
            let name = e.file_name().to_string_lossy().into_owned();
            if let Some(id) = name.strip_suffix(".json").filter(|s| valid_id(s)) {
                entries += 1;
                if entries > 1000 {
                    return Err("Approval listing limit exceeded".into());
                }
                let r = self.load(id)?;
                if self.can_read(&r, actor) {
                    let mut summary = r.view();
                    summary.as_object_mut().unwrap().remove("before");
                    summary.as_object_mut().unwrap().remove("after");
                    out.push(summary);
                }
            }
        }
        for a in self.archives()? {
            if a.visible(actor, self.identity(actor)) {
                out.push(a.view());
            }
        }
        out.sort_by(|a, b| b["created_at"].as_i64().cmp(&a["created_at"].as_i64()));
        out.truncate(100);
        Ok(out)
    }
    pub fn get(&self, id: &str, actor: &str) -> Result<Value> {
        let _guard = self.mutex.lock().map_err(|_| "Approval lock unavailable")?;
        if let Some(legacy) = id.strip_prefix("legacy-") {
            return self
                .archives()?
                .into_iter()
                .find(|a| a.id == legacy && a.visible(actor, self.identity(actor)))
                .map(|a| a.view())
                .ok_or("Archive unavailable to this identity".into());
        }
        let record = self.load(id)?;
        if !self.can_read(&record, actor) {
            return Err("Request unavailable to this identity".into());
        }
        Ok(record.view())
    }
    pub fn create(&self, actor: &Actor, g: Grant, action: String) -> Result<Value> {
        if !actor.authenticated {
            return Err("Authenticated requester required".into());
        }
        let mut required = self.config.admin.clone();
        let key = format!("{}:{}", g.system, g.resource);
        for r in &self.config.rules {
            if r.patterns
                .iter()
                .any(|p| glob::Pattern::new(p).is_ok_and(|p| p.matches(&key)))
            {
                required.extend(r.approvers.iter().cloned());
            }
        }
        let who = self.identity(&actor.subject).to_owned();
        if required.contains(&who) || required.is_empty() || required.len() > 128 {
            return Err(
                "Request requires independent approvers; self approval is forbidden".into(),
            );
        }
        let writer = self
            .config
            .code_writer
            .as_ref()
            .ok_or("Code writer is not configured; no permission applied")?;
        let code = writer.preview(&g, &action)?;
        let plan_hash = integrations::sha(
            serde_json::to_vec(&(
                &actor.subject,
                &action,
                &g,
                &required,
                &code.sha256,
                &self.policy_hash,
            ))
            .map_err(|_| "Cannot bind approval plan")?
            .as_slice(),
        );
        let _guard = self.mutex.lock().map_err(|_| "Approval lock unavailable")?;
        let mut count = 0;
        for item in fs::read_dir(&self.root).map_err(|_| "Cannot inspect duplicate requests")? {
            let name = item
                .map_err(|_| "Cannot inspect request")?
                .file_name()
                .to_string_lossy()
                .into_owned();
            if let Some(id) = name.strip_suffix(".json").filter(|s| valid_id(s)) {
                count += 1;
                if count > 1000 {
                    return Err("Approval capacity reached".into());
                }
                let held = self.load(id)?;
                if held.plan_hash == plan_hash
                    && held.requester == actor.subject
                    && held.status != "denied"
                    && held.created_at + 7 * 86400 > now()
                {
                    return Ok(held.view());
                }
            }
        }
        let mut r = Record {
            version: 1,
            id: Uuid::new_v4().simple().to_string(),
            created_at: now(),
            requester: actor.subject.clone(),
            requester_approval_identity: who,
            action,
            grant: g,
            required,
            approved: BTreeSet::new(),
            status: "pending".into(),
            plan_hash,
            policy_hash: self.policy_hash.clone(),
            code,
            pr_url: None,
            events: vec![],
            notifications: "not_configured".into(),
        };
        event(&mut r, &actor.subject, "requested");
        self.save(&r)?;
        if let Some(slack) = &self.config.slack {
            r.notifications = "sending".into();
            self.save(&r)?;
            drop(_guard);
            let sent = self.notify(slack, &r).is_ok();
            let _guard = self.mutex.lock().map_err(|_| "Approval lock unavailable")?;
            // A callback may have approved the request while a DM was in flight.
            let mut current = self.load(&r.id)?;
            current.notifications = if sent { "sent" } else { "unknown" }.into();
            self.save(&current)?;
            return Ok(current.view());
        }
        Ok(r.view())
    }
    fn notify(&self, cfg: &Slack, r: &Record) -> Result<()> {
        let http = integrations::Http::new(&cfg.api_url, &cfg.bot_token_env)?;
        for approver in &r.required {
            let channel = http.request(
                "POST",
                "conversations.open",
                Some(json!({"users":approver})),
            )?;
            if channel["ok"] != true {
                return Err("Slack DM unavailable".into());
            }
            let channel = channel["channel"]["id"]
                .as_str()
                .ok_or("Slack channel missing")?;
            let mut actions = vec![];
            for (decision, label) in [("approve", "Approve"), ("deny", "Deny")] {
                let value =
                    json!({"id":r.id,"decision":decision,"plan_hash":r.plan_hash}).to_string();
                actions.push(json!({"type":"button","text":{"type":"plain_text","text":label},"action_id":decision,"value":value}));
            }
            let text = format!(
                "Access request {}: {} / {} / {} / {}. Review: {}/approvals/{} · Approval creates a PR; it does not apply IAM.",
                r.id,
                r.requester,
                r.grant.system,
                r.grant.subject,
                r.grant.resource,
                self.origin,
                r.id
            );
            let sent=http.request("POST","chat.postMessage",Some(json!({"channel":channel,"text":text,"mrkdwn":false,"unfurl_links":false,"unfurl_media":false,"blocks":[{"type":"section","text":{"type":"plain_text","text":text}},{"type":"actions","elements":actions}]})))?;
            if sent["ok"] != true {
                return Err("Slack notification failed".into());
            }
        }
        Ok(())
    }
    pub fn decide(&self, id: &str, who: &str, plan: &str, approve: bool) -> Result<Value> {
        let _guard = self.mutex.lock().map_err(|_| "Approval lock unavailable")?;
        let mut r = self.load(id)?;
        if r.policy_hash != self.policy_hash
            || r.status != "pending"
            || r.created_at + 7 * 86400 < now()
            || r.requester_approval_identity == who
            || !r.required.contains(who)
            || r.approved.contains(who)
            || !bool::from(r.plan_hash.as_bytes().ct_eq(plan.as_bytes()))
        {
            return Err("Decision rejected: identity, expiry, plan or replay mismatch".into());
        }
        if approve {
            r.approved.insert(who.into());
            if r.required == r.approved {
                r.status = "approved".into();
            }
        } else {
            r.status = "denied".into();
        }
        event(&mut r, who, if approve { "approved" } else { "denied" });
        self.save(&r)?;
        Ok(r.view())
    }
    pub fn decide_actor(
        &self,
        id: &str,
        actor: &Actor,
        plan: &str,
        approve: bool,
    ) -> Result<Value> {
        if !actor.authenticated {
            return Err("Authentication required".into());
        }
        self.decide(id, self.identity(&actor.subject), plan, approve)
    }
    pub fn slack(&self, headers: &axum::http::HeaderMap, body: &[u8]) -> Result<Value> {
        let cfg = self
            .config
            .slack
            .as_ref()
            .ok_or("Slack is not configured")?;
        let timestamp = headers
            .get("X-Slack-Request-Timestamp")
            .and_then(|v| v.to_str().ok())
            .ok_or("Missing Slack timestamp")?;
        if timestamp
            .parse::<i64>()
            .ok()
            .is_none_or(|t| now().abs_diff(t) > 300)
        {
            return Err("Expired Slack request".into());
        }
        let signature = headers
            .get("X-Slack-Signature")
            .and_then(|v| v.to_str().ok())
            .ok_or("Missing Slack signature")?;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(integrations::env(&cfg.signing_secret_env)?.as_bytes())
                .map_err(|_| "Invalid Slack key")?;
        mac.update(format!("v0:{timestamp}:").as_bytes());
        mac.update(body);
        let actual = format!("v0={:x}", mac.finalize().into_bytes());
        if !bool::from(actual.as_bytes().ct_eq(signature.as_bytes())) {
            return Err("Invalid Slack signature".into());
        }
        let pairs: Vec<_> = url::form_urlencoded::parse(body)
            .filter(|(k, _)| k == "payload")
            .collect();
        if pairs.len() != 1 {
            return Err("Invalid Slack payload".into());
        }
        let payload: Value = serde_json::from_str(&pairs[0].1).map_err(|_| "Invalid Slack JSON")?;
        if payload["team"]["id"] != cfg.team_id {
            return Err("Slack workspace mismatch".into());
        }
        let actions = payload["actions"]
            .as_array()
            .filter(|a| a.len() == 1)
            .ok_or("One Slack action required")?;
        let value: Value =
            serde_json::from_str(actions[0]["value"].as_str().ok_or("Missing Slack action")?)
                .map_err(|_| "Invalid Slack action")?;
        let decision = value["decision"]
            .as_str()
            .filter(|s| matches!(*s, "approve" | "deny"))
            .ok_or("Invalid decision")?;
        self.decide(
            value["id"].as_str().ok_or("Missing request")?,
            payload["user"]["id"]
                .as_str()
                .ok_or("Missing Slack identity")?,
            value["plan_hash"].as_str().ok_or("Missing approved plan")?,
            decision == "approve",
        )
    }
    pub fn publish(&self, id: &str, actor: &Actor) -> Result<Value> {
        let _guard = self.mutex.lock().map_err(|_| "Approval lock unavailable")?;
        let mut r = self.load(id)?;
        if r.policy_hash != self.policy_hash
            || !actor.authenticated
            || !self.can_read(&r, &actor.subject)
            || r.status != "approved"
            || r.approved != r.required
            || r.created_at + 7 * 86400 < now()
        {
            return Err("All independent approvals and a fresh request are required".into());
        }
        r.status = "publishing".into();
        event(&mut r, &actor.subject, "publishing");
        self.save(&r)?;
        drop(_guard);
        let result = self
            .config
            .code_writer
            .as_ref()
            .ok_or("Code writer unavailable")?
            .publish(&r.code, &r.id, &r.grant, &r.action);
        let _guard = self.mutex.lock().map_err(|_| "Approval lock unavailable")?;
        let current = self.load(&r.id)?;
        if current.status != "publishing" || current.plan_hash != r.plan_hash {
            return Err("Publication state changed; inspect the external outcome".into());
        }
        r = current;
        match result {
            Ok(url) => {
                r.status = "proposed".into();
                r.pr_url = Some(url);
                event(&mut r, &actor.subject, "pr_created");
            }
            Err(_) => {
                r.status = "publish_unknown".into();
                event(&mut r, &actor.subject, "publication_needs_inspection");
                self.save(&r)?;
                return Err(
                    "Publication needs inspection; no automatic retry and no permission applied"
                        .into(),
                );
            }
        }
        self.save(&r)?;
        Ok(r.view())
    }
}
