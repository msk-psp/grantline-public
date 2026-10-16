//! S3 IAM interpretation, previews and explicit local-file writes. Remote reads are opt-in.
pub mod probe;
mod remote;
#[cfg(unix)]
pub mod writer;
use crate::{
    Result,
    config::{Adapter, relative},
    graph::Route,
    model::{Grant, Kinds, Unobserved},
    planner::{Change, Finding},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

#[derive(Debug, Deserialize)]
pub struct Plane {
    pub file: Option<String>,
    pub dir: Option<String>,
    // A configured remote provider must not silently fall back to a local file.
    pub iam_url_env: Option<String>,
    pub filer_url_env: Option<String>,
    pub url_env: Option<String>,
    pub auth_env: Option<String>,
    pub filer_auth_env: Option<String>,
    pub iam_key_env: Option<String>,
    pub iam_secret_env: Option<String>,
    pub iam_session_token_env: Option<String>,
    pub ca_bundle_env: Option<String>,
}
#[derive(Clone, Debug, Deserialize)]
struct Identity {
    name: String,
    #[serde(default)]
    actions: Vec<String>,
    #[serde(default)]
    policy: Option<Value>,
}
#[derive(Default)]
pub struct Observed {
    pub grants: BTreeSet<Grant>,
    pub findings: Vec<Finding>,
    pub unknown: Vec<Unobserved>,
    pub kinds: BTreeMap<String, String>,
    pub routes: Vec<Route>,
    pub enforced: String,
    identities: BTreeMap<String, Identity>,
    tree: bool,
    remote: bool,
    ready: bool,
}
#[derive(Default)]
struct Document {
    identities: BTreeMap<String, Identity>,
    kinds: BTreeMap<String, String>,
    routes: Vec<[String; 3]>,
    gaps: Vec<(String, String, String)>,
    gap_subjects: BTreeSet<String>,
    policy_docs: BTreeMap<String, Value>,
}
fn listed(v: Option<&Value>) -> Result<Vec<String>> {
    match v {
        None => Ok(vec![]),
        Some(Value::String(s)) => Ok(vec![s.clone()]),
        Some(Value::Array(a)) => a
            .iter()
            .map(|s| {
                s.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| "Expected IAM string list".into())
            })
            .collect(),
        _ => Err("Expected IAM string or string list".into()),
    }
}
fn statements(policy: &Value) -> Result<&Vec<Value>> {
    let object = policy.as_object().ok_or("Invalid IAM policy")?;
    if object
        .keys()
        .any(|k| !["Version", "Id", "Statement"].contains(&k.as_str()))
    {
        return Err("Unrecognized policy fields".into());
    }
    if ["Version", "Id"]
        .iter()
        .any(|k| policy.get(k).is_some_and(|v| !v.is_string()))
    {
        return Err("Invalid policy metadata".into());
    }
    let st = policy
        .get("Statement")
        .and_then(Value::as_array)
        .ok_or("Expected IAM Statement array")?;
    if st.iter().any(|s| {
        s.get("Sid").is_some_and(|v| !v.is_string())
            || s.as_object().is_none_or(|o| {
                o.keys().any(|k| {
                    ![
                        "Sid",
                        "Effect",
                        "Action",
                        "Resource",
                        "Condition",
                        "NotAction",
                        "NotResource",
                        "Principal",
                        "NotPrincipal",
                    ]
                    .contains(&k.as_str())
                })
            })
    }) {
        return Err("Invalid IAM statement".into());
    }
    Ok(st)
}
fn has_policy(ident: &Identity) -> bool {
    ident
        .policy
        .as_ref()
        .is_some_and(|p| p.as_object().is_none_or(|o| !o.is_empty()))
}
fn mapped(action: &str) -> Option<&str> {
    Some(match action {
        "s3:GetObject" => "Read",
        "s3:ListBucket"
        | "s3:GetBucketLocation"
        | "s3:ListMultipartUploadParts"
        | "s3:ListBucketMultipartUploads" => "List",
        "s3:PutObject"
        | "s3:DeleteObject"
        | "s3:CreateMultipartUpload"
        | "s3:UploadPart"
        | "s3:CompleteMultipartUpload"
        | "s3:AbortMultipartUpload" => "Write",
        "s3:GetObjectTagging" | "s3:PutObjectTagging" => "Tagging",
        "s3:ListAllMyBuckets" => "ListAllMyBuckets",
        "s3:*" | "*" => "Admin",
        _ => return None,
    })
}
fn native(system: &str, name: &str, action: &str) -> Grant {
    let (verb, rest) = action.split_once(':').unwrap_or((action, ""));
    let (resource, privilege) = if ["Read", "Write", "List", "Tagging", "Admin"].contains(&verb) {
        (
            format!("bucket:{}", if rest.is_empty() { "*" } else { rest }),
            verb,
        )
    } else if action.contains(':') {
        (format!("capability:{verb}"), rest)
    } else {
        ("bucket:*".into(), action)
    };
    Grant::new(system, name, &resource, privilege)
}
fn canonical(g: Grant, system: &str) -> Grant {
    g.normalized(&Kinds::from([(system.into(), "s3".into())]))
}
fn scopes(policy: &Value, system: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    if let Ok(ss) = statements(policy) {
        for st in ss {
            let Ok(resources) = listed(st.get("Resource")) else {
                return vec!["bucket:".into()];
            };
            if st.get("NotResource").is_some() || resources.is_empty() {
                return vec!["bucket:".into()];
            }
            for resource in resources {
                let Some(scope) = resource.strip_prefix("arn:aws:s3:::") else {
                    return vec!["bucket:".into()];
                };
                let pattern = scope.strip_suffix("/*").unwrap_or(scope);
                if scope == "*" || pattern.contains(['*', '?', '[']) || pattern.contains("${") {
                    return vec!["bucket:".into()];
                }
                out.insert(
                    canonical(
                        Grant::new(system, "", &format!("bucket:{scope}"), ""),
                        system,
                    )
                    .resource,
                );
            }
        }
    }
    if out.is_empty() {
        vec!["bucket:".into()]
    } else {
        out.into_iter().collect()
    }
}
fn prefix_caps(st: &Value) -> Option<BTreeSet<String>> {
    let condition = st.get("Condition")?.as_object()?;
    if condition.len() != 1 {
        return None;
    }
    let body = condition.get("StringLike")?.as_object()?;
    if body.len() != 1 {
        return None;
    }
    let prefixes = listed(body.get("s3:prefix")).ok()?;
    let actions = listed(st.get("Action")).ok()?;
    let resources = listed(st.get("Resource")).ok()?;
    if st.get("Effect")?.as_str()? != "Allow"
        || prefixes.is_empty()
        || actions.is_empty()
        || resources.is_empty()
        || actions
            .iter()
            .any(|a| !["s3:ListBucket", "s3:GetBucketLocation"].contains(&a.as_str()))
        || prefixes.iter().any(|p| p.contains("${"))
    {
        return None;
    }
    let mut out = BTreeSet::new();
    for r in resources {
        let bucket = r.strip_prefix("arn:aws:s3:::")?;
        if bucket.is_empty() || bucket.contains(['/', '\u{003a}', '*', '?', '[', '$', '{']) {
            return None;
        }
        for a in &actions {
            for p in &prefixes {
                out.insert(format!(
                    "{} bucket={bucket} prefix={}",
                    a.strip_prefix("s3:")?,
                    py_repr(p)
                ));
            }
        }
    }
    Some(out)
}
// Python's repr is part of the existing capability identifier, not display text.
fn py_repr(s: &str) -> String {
    static NON_PRINTING: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"[\p{C}\p{Z}]").expect("static Unicode category pattern")
    });
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::from(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if c != ' ' && NON_PRINTING.is_match(&c.to_string()) => {
                out.push_str(&if c as u32 <= 0xff {
                    format!("\\x{:02x}", c as u32)
                } else if c as u32 <= 0xffff {
                    format!("\\u{:04x}", c as u32)
                } else {
                    format!("\\U{:08x}", c as u32)
                })
            }
            _ => out.push(c),
        }
    }
    out.push(quote);
    out
}
type Evaluation = (BTreeSet<Grant>, Vec<Finding>, Vec<Unobserved>, bool);
fn evaluate(ident: &Identity, system: &str) -> Result<Evaluation> {
    let mut grants = BTreeSet::new();
    let mut findings = vec![];
    let mut unknown = vec![];
    if !has_policy(ident) {
        for a in &ident.actions {
            grants.insert(canonical(native(system, &ident.name, a), system));
        }
        return Ok((grants, findings, unknown, false));
    }
    let policy = ident.policy.as_ref().ok_or("Missing policy")?;
    if !ident.actions.is_empty() {
        let mut entities = vec![ident.name.clone()];
        entities.extend(ident.actions.clone());
        findings.push(Finding::new(
            system,
            "native actions shadowed by policy",
            format!(
                "identity '{}': IAM policy wins; native actions are ignored.",
                ident.name
            ),
            entities,
        ));
    }
    let mut allowed = BTreeSet::new();
    let mut denied = BTreeSet::new();
    let mut caps = BTreeSet::new();
    let mut unsupported = false;
    for st in statements(policy)? {
        if ["NotAction", "NotResource", "Principal", "NotPrincipal"]
            .iter()
            .any(|k| st.get(k).is_some())
        {
            unsupported = true;
            continue;
        }
        if st.get("Condition").is_some() {
            match prefix_caps(st) {
                Some(c) => caps.extend(c),
                None => unsupported = true,
            };
            continue;
        }
        let effect = st.get("Effect").and_then(Value::as_str).unwrap_or("");
        if !["Allow", "Deny"].contains(&effect) {
            unsupported = true;
            findings.push(Finding::new(
                system,
                "policy statement with an unknown effect",
                format!(
                    "identity '{}': Effect must be Allow or Deny. Access is unknown.",
                    ident.name
                ),
                vec![ident.name.clone()],
            ));
            continue;
        }
        let actions = listed(st.get("Action"))?;
        let resources = listed(st.get("Resource"))?;
        if actions.is_empty() || resources.is_empty() {
            unsupported = true;
        }
        for action in actions {
            if mapped(&action).is_none() {
                unsupported = true;
            }
            for res in &resources {
                let Some(scope) = res.strip_prefix("arn:aws:s3:::") else {
                    unsupported = true;
                    continue;
                };
                let pattern = scope.strip_suffix("/*").unwrap_or(scope);
                if scope.is_empty()
                    || scope.contains("${")
                    || (scope != "*" && pattern.contains(['*', '?', '[']))
                    || (action == "s3:ListAllMyBuckets" && scope != "*")
                {
                    unsupported = true;
                }
                if effect == "Allow" {
                    allowed.insert((scope.to_owned(), action.clone()));
                } else {
                    denied.insert((scope.to_owned(), action.clone()));
                }
            }
        }
    }
    if !caps.is_empty() && !denied.is_empty() {
        unsupported = true;
    }
    for (ds, da) in &denied {
        for (scope, action) in &allowed {
            // Non-identical denies may overlap after S3 normalization. Keep them unknown.
            if (ds, da) != (scope, action)
                && (ds == scope && mapped(da) == mapped(action)
                    || [ds, da, scope, action]
                        .iter()
                        .any(|s| s.contains(['*', '?', '['])))
            {
                unsupported = true;
            }
        }
    }
    if unsupported {
        findings.push(Finding::new(system,"policy evaluation incomplete",format!("identity '{}': conditional, negative, or overlapping policy is unsupported; access is unknown, not absent. No grants are inferred.",ident.name),vec![ident.name.clone()]));
        let mut prefixes = scopes(policy, system);
        // Dropping a whole policy also obscures discovery/prefix capabilities.
        prefixes.push("capability:s3/".into());
        unknown.push(Unobserved {
            system: system.into(),
            prefixes,
            subjects: BTreeSet::from([ident.name.clone()]),
            note: "unsupported IAM policy".into(),
        });
        return Ok((grants, findings, unknown, true));
    }
    for (scope, action) in allowed.difference(&denied) {
        let resource = if action == "s3:ListAllMyBuckets" {
            "capability:s3/ListAllMyBuckets".into()
        } else {
            format!("bucket:{scope}")
        };
        let mut g = Grant::new(
            system,
            &ident.name,
            &resource,
            mapped(action).ok_or("Unsupported IAM action")?,
        );
        g.source = "policy".into();
        grants.insert(canonical(g, system));
    }
    for cap in caps {
        let privilege = cap.split(' ').next().ok_or("Invalid capability")?;
        let mut g = Grant::new(
            system,
            &ident.name,
            &format!("capability:s3/{cap}"),
            privilege,
        );
        g.source = "policy".into();
        grants.insert(g);
    }
    let cancelled: Vec<_> = allowed.intersection(&denied).collect();
    if !cancelled.is_empty() {
        let mut entities = vec![ident.name.clone()];
        for (s, a) in cancelled.iter().take(4) {
            entities.extend([s.clone(), a.clone()]);
        }
        findings.push(Finding::new(
            system,
            "explicit deny overrides an allow",
            format!(
                "identity '{}': {} allow(s) cancelled by an explicit Deny.",
                ident.name,
                cancelled.len()
            ),
            entities,
        ));
    }
    let count = denied.difference(&allowed).count();
    if count > 0 {
        findings.push(Finding::new(
            system,
            "deny without a matching allow",
            format!(
                "identity '{}': {count} Deny statement(s) cancel no matching Allow.",
                ident.name
            ),
            vec![ident.name.clone()],
        ));
    }
    Ok((grants, findings, unknown, !cancelled.is_empty()))
}
fn read_json(path: &Path) -> Result<Value> {
    serde_json::from_slice(&fs::read(path).map_err(|_| "IAM source unreadable")?)
        .map_err(|_| "Invalid IAM JSON".into())
}
fn identities(v: &Value) -> Result<BTreeMap<String, Identity>> {
    let rows = v
        .get("identities")
        .and_then(Value::as_array)
        .ok_or("Missing identities array")?;
    let mut out = BTreeMap::new();
    for row in rows {
        let ident: Identity =
            serde_json::from_value(row.clone()).map_err(|_| "Invalid identity schema")?;
        if ident.name.is_empty()
            || ident.name.chars().any(char::is_control)
            || out.insert(ident.name.clone(), ident).is_some()
        {
            return Err("Invalid or duplicate IAM identity".into());
        }
    }
    Ok(out)
}
fn files(root: &Path, required: bool) -> Result<BTreeMap<String, Value>> {
    if !root.exists() && !required {
        return Ok(BTreeMap::new());
    }
    let mut out = BTreeMap::new();
    for entry in fs::read_dir(root).map_err(|_| "IAM directory unreadable")? {
        let p = entry.map_err(|_| "IAM directory entry unreadable")?.path();
        if p.extension().is_some_and(|s| s == "json") {
            out.insert(
                p.file_stem()
                    .and_then(|s| s.to_str())
                    .ok_or("Invalid IAM filename")?
                    .into(),
                read_json(&p)?,
            );
        }
    }
    Ok(out)
}
fn tree(root: &Path, system: &str) -> Result<Document> {
    let raw_ids = files(&root.join("identities"), true)?;
    let groups = files(&root.join("groups"), false)?;
    let policies = files(&root.join("policies"), false)?;
    let top = if root.join("policies.json").exists() {
        read_json(&root.join("policies.json"))?
    } else {
        json!({})
    };
    merge_tree(raw_ids, groups, policies, top, system)
}
fn merge_tree(
    raw_ids: BTreeMap<String, Value>,
    groups: BTreeMap<String, Value>,
    mut policies: BTreeMap<String, Value>,
    top: Value,
    system: &str,
) -> Result<Document> {
    top.as_object().ok_or("Invalid IAM index")?;
    if let Some(p) = top.get("policies").filter(|v| !v.is_null()) {
        for (name, doc) in p.as_object().ok_or("Invalid policy index")? {
            policies.entry(name.clone()).or_insert_with(|| doc.clone());
        }
    }
    let empty = serde_json::Map::new();
    let inline = match top.get("inlinePolicies").filter(|v| !v.is_null()) {
        Some(v) => v.as_object().ok_or("Invalid inline policy index")?,
        None => &empty,
    };
    let group_inline = match top.get("groupInlinePolicies").filter(|v| !v.is_null()) {
        Some(v) => v.as_object().ok_or("Invalid group inline policy index")?,
        None => &empty,
    };
    let mut doc = Document::default();
    let mut memberships: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut attached = BTreeMap::new();
    for (stem, g) in groups {
        g.as_object().ok_or("Invalid IAM group")?;
        let name = g
            .get("name")
            .map(|v| v.as_str().ok_or("Invalid group name"))
            .transpose()?
            .unwrap_or(&stem)
            .to_owned();
        let mut pnames = listed(g.get("policy_names"))?;
        if let Some(inline) = group_inline.get(&name).filter(|v| !v.is_null()) {
            for (pname, policy) in inline.as_object().ok_or("Invalid group inline policies")? {
                let route_name = format!("group:{name}:inline:{pname}");
                if policies
                    .insert(route_name.clone(), policy.clone())
                    .is_some()
                {
                    return Err("Conflicting group inline policy name".into());
                }
                pnames.push(route_name);
            }
        }
        for member in listed(g.get("members"))? {
            memberships.entry(member).or_default().push(name.clone());
        }
        doc.kinds.insert(format!("group:{name}"), "group".into());
        for p in &pnames {
            doc.routes.push([
                format!("group:{name}"),
                format!("policy:{p}"),
                "attaches".into(),
            ]);
        }
        if attached.insert(name, pnames).is_some() {
            return Err("Duplicate IAM group".into());
        }
    }
    for (name, p) in &policies {
        policy_routes(&mut doc, name, p, system)?;
    }
    for (_, raw) in raw_ids {
        let direct = listed(raw.get("policy_names"))?;
        let mut ident: Identity =
            serde_json::from_value(raw).map_err(|_| "Invalid IAM identity")?;
        let name = ident.name.clone();
        let mut ss = vec![];
        let mut attached_any = false;
        for pname in direct {
            attached_any = true;
            doc.routes
                .push([name.clone(), format!("policy:{pname}"), "attaches".into()]);
            if let Some(policy) = policies.get(&pname) {
                ss.extend(statements(policy)?.clone());
            } else {
                doc.gap_subjects.insert(name.clone());
                doc.gaps.push((
                    name.clone(),
                    pname.clone(),
                    format!("identity '{name}' attaches policy '{pname}' which has no document"),
                ));
            }
        }
        if let Some(inline) = inline.get(&name).filter(|v| !v.is_null()) {
            for (pname, p) in inline
                .as_object()
                .ok_or("Invalid inline policy collection")?
            {
                attached_any = true;
                ss.extend(statements(p)?.clone());
                doc.routes
                    .push([name.clone(), format!("policy:{pname}"), "inline".into()]);
                policy_routes(&mut doc, pname, p, system)?;
            }
        }
        for group in memberships.get(&name).into_iter().flatten() {
            doc.routes
                .push([name.clone(), format!("group:{group}"), "member".into()]);
            for pname in &attached[group] {
                attached_any = true;
                if let Some(p) = policies.get(pname) {
                    ss.extend(statements(p)?.clone());
                } else {
                    doc.gap_subjects.insert(name.clone());
                    doc.gaps.push((
                        group.clone(),
                        pname.clone(),
                        format!("group '{group}' attaches policy '{pname}' which has no document"),
                    ));
                }
            }
        }
        ident.policy = attached_any.then(|| json!({"Version":"2012-10-17","Statement":ss}));
        doc.kinds.insert(name.clone(), "account".into());
        if name.is_empty()
            || name.chars().any(char::is_control)
            || doc.identities.insert(name, ident).is_some()
        {
            return Err("Invalid or duplicate identity".into());
        }
    }
    doc.routes.sort();
    doc.routes.dedup();
    doc.gaps.sort();
    doc.gaps.dedup();
    Ok(doc)
}
fn policy_routes(doc: &mut Document, name: &str, policy: &Value, system: &str) -> Result<()> {
    if doc.policy_docs.get(name).is_some_and(|p| p != policy) {
        return Err(
            "Conflicting policy route names; cannot merge identity-specific policies".into(),
        );
    }
    doc.policy_docs.insert(name.into(), policy.clone());
    doc.kinds.insert(format!("policy:{name}"), "policy".into());
    let ident = Identity {
        name: name.into(),
        actions: vec![],
        policy: Some(policy.clone()),
    };
    for g in evaluate(&ident, system)?.0 {
        doc.routes
            .push([format!("policy:{name}"), g.resource, "allows".into()]);
    }
    Ok(())
}
impl Plane {
    fn remote(&self) -> bool {
        self.iam_url_env.is_some() || self.filer_url_env.is_some() || self.url_env.is_some()
    }
}
fn plane(p: &Plane, base: &Path, system: &str, live: bool, timeout: u64) -> Result<Document> {
    if p.remote() {
        if !live {
            return Err("Remote S3 observation requires --live".into());
        }
        return remote::read(p, system, timeout);
    }
    if let Some(dir) = &p.dir {
        return tree(&relative(base, dir)?, system);
    }
    let path = p
        .file
        .as_ref()
        .ok_or("No local IAM source; remote providers are not implemented in R3a")?;
    let v = read_json(&relative(base, path)?)?;
    document(v, system)
}
fn document(v: Value, system: &str) -> Result<Document> {
    // Metadata from an already-merged source is not a substitute for a complete tree.
    if ["_gaps", "_gap_subjects", "_routes", "_kinds"]
        .iter()
        .any(|k| v.get(k).is_some())
    {
        return Err("Use dir for a mirrored IAM tree".into());
    }
    let ids = identities(&v)?;
    let mut doc = Document::default();
    for ident in ids.values() {
        evaluate(ident, system)?;
        doc.kinds.insert(ident.name.clone(), "account".into());
    }
    doc.identities = ids;
    Ok(doc)
}
pub fn observe(adapter: &Adapter, base: &Path, system: &str) -> Observed {
    observe_with_live(adapter, base, system, false)
}
pub fn observe_with_live(adapter: &Adapter, base: &Path, system: &str, live: bool) -> Observed {
    let mut out = Observed {
        enforced: adapter.enforced.clone(),
        ..Default::default()
    };
    let mut docs = BTreeMap::new();
    for (name, p) in &adapter.planes {
        match plane(p, base, system, live, adapter.read_timeout_seconds) {
            Ok(doc) => {
                docs.insert(name.clone(), doc);
            }
            Err(reason) if name == &adapter.enforced => out.unknown.push(Unobserved {
                system: system.into(),
                prefixes: vec![String::new()],
                subjects: BTreeSet::new(),
                note: format!("enforced plane '{name}' unreadable: {reason}"),
            }),
            Err(_) => out.findings.push(Finding::new(
                system,
                "auth plane unreachable",
                format!("plane '{name}' could not be read; cross-plane identity check skipped."),
                vec![name.clone()],
            )),
        }
    }
    if !adapter.planes.contains_key(&adapter.enforced) {
        out.unknown.push(Unobserved {
            system: system.into(),
            prefixes: vec![String::new()],
            subjects: BTreeSet::new(),
            note: "Enforced S3 plane has no configuration".into(),
        });
    }
    if let Some(doc) = docs.get(&adapter.enforced) {
        out.ready = true;
        out.tree = adapter.planes[&adapter.enforced].dir.is_some();
        out.remote = adapter.planes[&adapter.enforced].remote();
        out.identities = doc.identities.clone();
        out.kinds = doc.kinds.clone();
        let mut blind = doc.gap_subjects.clone();
        for ident in doc.identities.values() {
            match evaluate(ident, system) {
                Ok((grants, findings, unknown, hide_routes)) => {
                    out.grants.extend(grants);
                    out.findings.extend(findings);
                    out.unknown.extend(unknown);
                    if hide_routes {
                        blind.insert(ident.name.clone());
                    }
                }
                Err(_) => {
                    blind.insert(ident.name.clone());
                    out.unknown.push(Unobserved {
                        system: system.into(),
                        prefixes: vec![String::new()],
                        subjects: BTreeSet::from([ident.name.clone()]),
                        note: "Invalid identity policy schema".into(),
                    });
                }
            }
        }
        for (group, policy, detail) in &doc.gaps {
            out.findings.push(Finding::new(
                system,
                "policy document missing",
                detail.clone(),
                vec![group.clone(), policy.clone()],
            ));
        }
        if !doc.gaps.is_empty() {
            out.unknown.push(Unobserved {
                system: system.into(),
                prefixes: vec![String::new()],
                subjects: doc.gap_subjects.clone(),
                note: "policy documents missing".into(),
            });
        }
        out.grants
            .retain(|g| !out.unknown.iter().any(|u| u.covers(g)));
        out.routes = doc
            .routes
            .iter()
            .filter(|r| !blind.contains(&r[0]))
            .map(|[s, d, l]| [system.into(), s.clone(), d.clone(), l.clone()])
            .collect();
        let enforced_names: BTreeSet<_> = doc.identities.keys().collect();
        for (name, d) in &docs {
            if name == &adapter.enforced {
                continue;
            }
            let orphans: Vec<_> = d
                .identities
                .keys()
                .filter(|n| !enforced_names.contains(n))
                .cloned()
                .collect();
            if !orphans.is_empty() {
                let mut entities = vec![name.clone(), adapter.enforced.clone()];
                entities.extend(orphans.iter().take(8).cloned());
                out.findings.push(Finding::new(system,"identity missing from the enforced plane",format!("{} identity(ies) exist only in plane '{name}': {}. Their keys are absent from enforced plane '{}'.",orphans.len(),orphans.iter().take(8).cloned().collect::<Vec<_>>().join(", "),adapter.enforced),entities));
            }
        }
    }
    out
}

pub fn policy_with(policy: &Value, g: &Grant, add: bool) -> Result<Value> {
    let scope = g
        .resource
        .strip_prefix("bucket:")
        .ok_or("S3 capabilities are observation-only; use the IAM client")?;
    let actions: BTreeSet<String> = match g.privilege.as_str() {
        "Read" => vec!["s3:GetObject"],
        "List" => vec!["s3:ListBucket"],
        "Write" => vec!["s3:PutObject", "s3:DeleteObject"],
        "Admin" => vec!["s3:*"],
        _ => return Err("Unsupported S3 privilege for policy preview".into()),
    }
    .into_iter()
    .map(str::to_owned)
    .collect();
    if scope.is_empty()
        || scope.chars().any(char::is_control)
        || scope.contains("${")
        || (scope != "*" && scope.contains(['*', '?', '[']))
    {
        return Err("Unsupported S3 resource pattern".into());
    }
    // The existing List model cannot express a request-prefix condition for writes.
    if g.privilege == "List" && scope.contains('/') {
        return Err("Prefix List requires an explicit IAM condition; cannot generate an unconditional bucket grant".into());
    }
    let arn = format!(
        "arn:aws:s3:::{scope}{}",
        if scope == "*" || g.privilege == "List" {
            ""
        } else {
            "/*"
        }
    );
    let mut ss = vec![];
    for st in statements(policy)? {
        if ["NotAction", "NotResource", "Principal", "NotPrincipal"]
            .iter()
            .any(|k| st.get(k).is_some())
        {
            return Err("Negative or principal-based policy previews are unsupported".into());
        }
        if !matches!(
            st.get("Effect").and_then(Value::as_str),
            Some("Allow" | "Deny")
        ) {
            return Err("Unknown IAM effect".into());
        }
        let mut copy = st.clone();
        copy["Action"] = json!(listed(st.get("Action"))?);
        copy["Resource"] = json!(listed(st.get("Resource"))?);
        ss.push(copy);
    }
    if add {
        if let Some(st) = ss.iter_mut().find(|s| {
            s["Effect"] == "Allow" && s["Resource"] == json!([arn]) && s.get("Condition").is_none()
        }) {
            let mut all: BTreeSet<_> = listed(st.get("Action"))?.into_iter().collect();
            all.extend(actions);
            st["Action"] = json!(all);
        } else {
            ss.push(json!({"Effect":"Allow","Action":actions,"Resource":[arn]}));
        }
    } else {
        let mut split = vec![];
        for st in ss {
            let resources = listed(st.get("Resource"))?;
            if st["Effect"] == "Allow" && resources.contains(&arn) {
                // Removing a conditional grant without request context could broaden intent.
                if st.get("Condition").is_some() {
                    return Err("Conditional policy revokes require the IAM client".into());
                }
                let rest: Vec<_> = resources.into_iter().filter(|r| r != &arn).collect();
                if !rest.is_empty() {
                    let mut copy = st.clone();
                    copy["Resource"] = json!(rest);
                    split.push(copy);
                }
                let kept: Vec<_> = listed(st.get("Action"))?
                    .into_iter()
                    .filter(|a| !actions.contains(a))
                    .collect();
                if !kept.is_empty() {
                    let mut copy = st;
                    copy["Resource"] = json!([arn]);
                    copy["Action"] = json!(kept);
                    split.push(copy);
                }
            } else {
                split.push(st);
            }
        }
        ss = split;
    }
    let mut out = policy.clone();
    out["Statement"] = json!(ss);
    Ok(out)
}
#[derive(Debug, Serialize)]
pub struct Preview {
    pub system: String,
    pub plane: String,
    pub subject: String,
    pub kind: String,
    pub creates_identity: bool,
    pub changes: Vec<usize>,
    pub before: Option<Value>,
    pub after: Option<Value>,
    pub blocked: Option<String>,
}
impl Observed {
    pub fn previews(&self, system: &str, changes: &mut [Change]) -> Vec<Preview> {
        let mut by: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (i, c) in changes
            .iter()
            .enumerate()
            .filter(|(_, c)| c.grant.system == system)
        {
            by.entry(c.grant.subject.clone()).or_default().push(i);
        }
        let mut out = vec![];
        for (subject, indices) in by {
            let ident = self.identities.get(&subject);
            let policy = ident.is_some_and(has_policy);
            let result: Result<(Value, Value)> = (|| {
                if !self.ready {
                    return Err("S3 observation source unavailable".into());
                }
                if self.remote {
                    return Err("Remote IAM observations are read-only; no local document write preview is available".into());
                }
                if self.tree {
                    return Err("IAM tree is read-only; edit the owning inline/group policy. Inherited grants must not become per-user policy writes".into());
                }
                if indices
                    .iter()
                    .any(|&i| !changes[i].grant.resource.starts_with("bucket:"))
                {
                    return Err("S3 capabilities are observation-only; use the IAM client".into());
                }
                let before = if policy {
                    ident
                        .and_then(|i| i.policy.clone())
                        .ok_or("Missing policy")?
                } else {
                    json!(ident.map(|i| i.actions.clone()).unwrap_or_default())
                };
                let mut after = before.clone();
                for &i in &indices {
                    let c = &changes[i];
                    if policy {
                        after = policy_with(&after, &c.grant, c.action == "grant")?;
                    } else {
                        if !["Read", "Write", "List", "Tagging", "Admin"]
                            .contains(&c.grant.privilege.as_str())
                        {
                            return Err("Unsupported native S3 privilege".into());
                        }
                        let scope = c
                            .grant
                            .resource
                            .strip_prefix("bucket:")
                            .ok_or("Unsupported S3 resource")?;
                        if scope.is_empty()
                            || scope.contains(['*', '?', '[']) && scope != "*"
                            || scope.chars().any(char::is_control)
                        {
                            return Err("Unsupported native S3 scope".into());
                        }
                        // SeaweedFS requires a wildcard for descendants; bare paths do not grant them.
                        let suffix = if scope.contains('/') { "/*" } else { "" };
                        let atom = format!("{}:{scope}{suffix}", c.grant.privilege);
                        let mut actions = listed(Some(&after))?;
                        actions.retain(|a| {
                            canonical(native(system, &subject, a), system).key() != c.grant.key()
                        });
                        if c.action == "grant" {
                            actions.push(atom);
                        }
                        after = json!(actions);
                    }
                }
                let empty = Identity {
                    name: subject.clone(),
                    actions: vec![],
                    policy: None,
                };
                let current = ident.unwrap_or(&empty);
                let (held, _, unknown, _) = evaluate(current, system)?;
                if !unknown.is_empty() {
                    return Err("Current policy is not fully evaluable".into());
                }
                let mut wanted: BTreeSet<_> = held.iter().map(Grant::key).collect();
                for &i in &indices {
                    if changes[i].action == "grant" {
                        wanted.insert(changes[i].grant.key());
                    } else {
                        wanted.remove(&changes[i].grant.key());
                    }
                }
                let mut planned = current.clone();
                if policy {
                    planned.policy = Some(after.clone());
                } else {
                    planned.actions = listed(Some(&after))?;
                }
                let (effective, _, unknown, _) = evaluate(&planned, system)?;
                if !unknown.is_empty()
                    || effective.iter().map(Grant::key).collect::<BTreeSet<_>>() != wanted
                {
                    return Err("Preview cannot represent the requested normalized grants exactly; use the IAM client".into());
                }
                Ok((before, after))
            })();
            let (before, after, blocked) = match result {
                Ok((b, a)) => (Some(b), Some(a), None),
                Err(e) => (None, None, Some(e)),
            };
            for &i in &indices {
                changes[i].cmd=blocked.is_none().then(||format!("s3-iam[{}]: preview {} for identity {} — grouped document in s3_previews (no write)",self.enforced,if policy {"policy"} else {"actions"},json!(subject)));
                changes[i].command_error = blocked.clone();
            }
            out.push(Preview {
                system: system.into(),
                plane: self.enforced.clone(),
                subject,
                creates_identity: ident.is_none(),
                kind: if policy {
                    "policy".into()
                } else {
                    "actions".into()
                },
                changes: indices,
                before,
                after,
                blocked,
            });
        }
        out
    }
}
