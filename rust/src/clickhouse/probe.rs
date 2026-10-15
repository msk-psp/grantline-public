//! Resolve ACLs on the server, without impersonation, SET ROLE or application queries.
use super::{Http, MAX_ROWS, quoted};
use crate::{
    Result,
    config::Adapter,
    model::Grant,
    probe::{Probe, Verdict},
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Word(String),
    Ident(String),
    Punct(char),
}
impl Token {
    fn keyword(&self, word: &str) -> bool {
        matches!(self,Self::Word(w) if w.eq_ignore_ascii_case(word))
    }
    fn name(&self) -> Result<&str> {
        match self {
            Self::Word(w) | Self::Ident(w)
                if !w.is_empty() && w.len() <= 1024 && !w.chars().any(char::is_control) =>
            {
                Ok(w)
            }
            _ => Err("Invalid SHOW GRANTS identifier".into()),
        }
    }
}
fn tokens(line: &str) -> Result<Vec<Token>> {
    if line.len() > 65536 {
        return Err("SHOW GRANTS statement exceeds parser limit".into());
    }
    let mut out = Vec::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_whitespace() {
            continue;
        }
        if matches!(c, '`' | '\'' | '"') {
            let mut name = String::new();
            let mut ended = false;
            while let Some(d) = chars.next() {
                if d == '\\' {
                    let escaped = chars.next().ok_or("Invalid SHOW GRANTS escape")?;
                    if escaped != '\\' && escaped != c {
                        return Err("Unsupported SHOW GRANTS escape".into());
                    }
                    name.push(escaped);
                } else if d == c {
                    if chars.peek() == Some(&c) {
                        chars.next();
                        name.push(c);
                    } else {
                        ended = true;
                        break;
                    }
                } else {
                    name.push(d);
                }
            }
            if !ended {
                return Err("Invalid SHOW GRANTS quoting".into());
            }
            out.push(Token::Ident(name));
        } else if matches!(c, '.' | '*' | ',' | '(' | ')' | ';') {
            out.push(Token::Punct(c));
        } else {
            let mut word = String::from(c);
            while chars.peek().is_some_and(|c| {
                !c.is_whitespace()
                    && !matches!(c, '.' | '*' | ',' | '(' | ')' | ';' | '`' | '\'' | '"')
            }) {
                word.push(chars.next().unwrap());
            }
            out.push(Token::Word(word));
        }
    }
    if out.last() == Some(&Token::Punct(';')) {
        out.pop();
    }
    Ok(out)
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Scope {
    Global,
    Db(String),
    Table(String, String),
    Named,
}
fn scope(tokens: &[Token]) -> Result<Scope> {
    match tokens {
        [Token::Punct('*'), Token::Punct('.'), Token::Punct('*')] => Ok(Scope::Global),
        [db, Token::Punct('.'), Token::Punct('*')] => Ok(Scope::Db(db.name()?.into())),
        [db, Token::Punct('.'), table] => Ok(Scope::Table(db.name()?.into(), table.name()?.into())),
        [Token::Punct('*')] | [Token::Word(_)] | [Token::Ident(_)] => Ok(Scope::Named),
        _ => {
            Err("Unrepresentable SHOW GRANTS scope, prefix wildcard or parameterized target".into())
        }
    }
}
impl Scope {
    fn covers(&self, other: &Self) -> bool {
        self == other
            || matches!(
                (self, other),
                (Self::Global, Self::Global | Self::Db(_) | Self::Table(..))
            )
            || matches!((self,other),(Self::Db(a),Self::Table(b,_)) if a==b)
    }
}
#[derive(Default)]
struct Effective {
    permissions: BTreeSet<(String, Scope)>,
    roles: BTreeSet<String>,
}
impl Effective {
    fn parse(lines: &[String], subject: &str) -> Result<Self> {
        let mut out = Self::default();
        for line in lines {
            let t = tokens(line)?;
            if !t.first().is_some_and(|t| t.keyword("GRANT")) {
                return Err("Unresolved revoke or unrecognized SHOW GRANTS statement".into());
            }
            let to = t
                .iter()
                .position(|t| t.keyword("TO"))
                .ok_or("Missing SHOW GRANTS recipient")?;
            let body = &t[1..to];
            let permission_grant = body.iter().any(|t| t.keyword("ON"));
            let suffix = &t[to + 1..];
            if suffix.is_empty() || suffix[0].name()? != subject {
                return Err("SHOW GRANTS recipient does not match subject".into());
            }
            if suffix.len() != 1
                && !(suffix.len() == 4
                    && suffix[1].keyword("WITH")
                    && suffix[2].keyword(if permission_grant { "GRANT" } else { "ADMIN" })
                    && suffix[3].keyword("OPTION"))
            {
                return Err("Unknown SHOW GRANTS suffix".into());
            }
            if !permission_grant {
                if body.is_empty() {
                    return Err("Empty role grant".into());
                }
                for role in body.split(|t| *t == Token::Punct(',')) {
                    if role.len() != 1 {
                        return Err("Unrecognized role grant".into());
                    }
                    out.roles.insert(role[0].name()?.into());
                    if out.roles.len() > MAX_ROWS {
                        return Err("SHOW GRANTS exceeds parsed role limit".into());
                    }
                }
                continue;
            }
            let mut pos = 0;
            while pos < body.len() {
                let on = body[pos..]
                    .iter()
                    .position(|t| t.keyword("ON"))
                    .map(|i| i + pos)
                    .ok_or("Missing grant scope")?;
                let mut privileges = Vec::new();
                for privilege in body[pos..on].split(|t| *t == Token::Punct(',')) {
                    if privilege.is_empty() || privilege.iter().any(|t| {
                        !matches!(t,Token::Word(w) if w.chars().all(|c|c.is_ascii_alphabetic() || c=='_'))
                    }) {
                        return Err("Column or unrecognized privilege grants remain unknown".into());
                    }
                    let privilege = privilege
                        .iter()
                        .map(|t| t.name().map(str::to_ascii_uppercase))
                        .collect::<Result<Vec<_>>>()?
                        .join(" ");
                    privileges.push(if privilege == "ALL PRIVILEGES" {
                        "ALL".into()
                    } else {
                        privilege
                    });
                }
                let end = body[on + 1..]
                    .iter()
                    .position(|t| *t == Token::Punct(','))
                    .map(|i| i + on + 1)
                    .unwrap_or(body.len());
                let scope = scope(&body[on + 1..end])?;
                if out.permissions.len() + privileges.len() > MAX_ROWS {
                    return Err("SHOW GRANTS exceeds parsed permission limit".into());
                }
                out.permissions
                    .extend(privileges.into_iter().map(|p| (p, scope.clone())));
                pos = if end < body.len() { end + 1 } else { end };
                if pos == body.len() && end < body.len() {
                    return Err("Trailing SHOW GRANTS comma".into());
                }
            }
        }
        Ok(out)
    }
    fn verdict(&self, g: &Grant) -> Result<Verdict> {
        let (kind, rest) = g
            .resource
            .split_once(':')
            .ok_or("Invalid ClickHouse resource")?;
        if kind == "role" {
            if g.privilege != "MEMBER"
                || rest.is_empty()
                || rest.len() > 1024
                || rest.chars().any(char::is_control)
            {
                return Err("Unsupported role probe".into());
            }
            return Ok(if self.roles.contains(rest) {
                Verdict::Allow
            } else {
                Verdict::Deny
            });
        }
        let component = |s: &str| {
            !s.is_empty()
                && s.len() <= 1024
                && !s.contains(['*', '?', '['])
                && !s.chars().any(char::is_control)
        };
        let scope = match kind {
            "global" if rest == "*" => Scope::Global,
            "db" if component(rest) && !rest.contains('.') => Scope::Db(rest.into()),
            "table" => {
                let (db, table) = rest.split_once('.').ok_or("Invalid table probe resource")?;
                if !component(db) || !component(table) {
                    return Err("Wildcard or invalid table probe resource".into());
                }
                Scope::Table(db.into(), table.into())
            }
            _ => return Err("Unsupported ClickHouse probe resource".into()),
        };
        let privilege = g.privilege.to_ascii_uppercase();
        if !matches!(
            privilege.as_str(),
            "SELECT"
                | "INSERT"
                | "OPTIMIZE"
                | "TRUNCATE"
                | "DICTGET"
                | "ALTER"
                | "CREATE"
                | "DROP"
                | "SHOW"
                | "ALL"
                | "SHOW ACCESS"
                | "SHOW DATABASES"
                | "SHOW TABLES"
                | "SHOW COLUMNS"
                | "SHOW USERS"
                | "SHOW ROLES"
                | "ALTER UPDATE"
                | "ALTER DELETE"
                | "CREATE TABLE"
                | "CREATE DATABASE"
                | "DROP TABLE"
                | "DROP DATABASE"
        ) {
            return Err("Unsupported ClickHouse probe privilege".into());
        }
        if self
            .permissions
            .iter()
            .any(|(p, s)| (p == &privilege || p == "ALL") && s.covers(&scope))
        {
            return Ok(Verdict::Allow);
        }
        // SHOW GRANTS may aggregate groups. Absence is definite only for these leaf rights.
        if matches!(
            privilege.as_str(),
            "SELECT" | "INSERT" | "OPTIMIZE" | "TRUNCATE" | "DICTGET"
        ) {
            Ok(Verdict::Deny)
        } else {
            Err("No exact grant; privilege-group expansion is not implemented".into())
        }
    }
}
#[derive(Deserialize)]
struct Login {
    user: String,
}
fn show(http: &Http, sql: &str, subject: &str) -> Result<Effective> {
    let rows = http.query::<BTreeMap<String, String>>(sql)?;
    let mut lines = Vec::new();
    for row in rows {
        if row.len() != 1 {
            return Err("Invalid SHOW GRANTS row".into());
        }
        lines.push(row.into_values().next().unwrap());
    }
    Effective::parse(&lines, subject)
}
pub fn run(adapter: &Adapter, grants: &[Grant]) -> Vec<Probe> {
    let started = Instant::now();
    let mut groups = BTreeMap::new();
    for g in grants {
        groups.entry(&g.subject).or_insert_with(Vec::new).push(g);
    }
    if grants.len() > 1000
        || groups.len() > 128
        || !(1..=120).contains(&adapter.read_timeout_seconds)
    {
        return grants
            .iter()
            .map(|g| {
                Probe::new(
                    g,
                    Verdict::Unknown,
                    "Invalid ClickHouse probe count, subject count or deadline limit",
                )
            })
            .collect();
    }
    let mut out = Vec::new();
    for (subject, gs) in groups {
        let login = adapter.probe_url_envs.contains_key(subject);
        let result: Result<Effective> = (|| {
            if subject.is_empty() || subject.len() > 1024 || subject.chars().any(char::is_control) {
                return Err("Invalid ClickHouse probe subject".into());
            }
            let key = if login {
                adapter.probe_url_envs.get(subject)
            } else {
                adapter.probe_url_env.as_ref().or(adapter.url_env.as_ref())
            }
            .filter(|s| !s.is_empty())
            .ok_or("ClickHouse probe credential is not configured")?;
            let http = Http::from_env(key, adapter.read_timeout_seconds, started)?;
            if login {
                let rows = http.query::<Login>("SELECT currentUser() AS user LIMIT 1")?;
                if !matches!(rows.as_slice(),[Login{user}] if user==subject) {
                    return Err("Credential does not log in as the requested subject".into());
                }
            }
            let query = if login {
                "SHOW GRANTS".into()
            } else {
                format!("SHOW GRANTS FOR {}", quoted(subject))
            };
            let mut effective = show(&http, &format!("{query} WITH IMPLICIT FINAL"), subject)?;
            if gs.iter().any(|g| g.resource.starts_with("role:")) {
                effective.roles = show(&http, &query, subject)?.roles;
            }
            Ok(effective)
        })();
        let how = if login {
            "subject HTTP login + server-resolved ACLs (all granted roles; no data read or write)"
        } else {
            "server-resolved ACLs (SHOW GRANTS WITH IMPLICIT FINAL; all granted roles), not a login"
        };
        for g in gs {
            out.push(match &result {
                Ok(effective)=>match effective.verdict(g) {
                    Ok(verdict)=>Probe::new(g,verdict,if g.resource.starts_with("role:"){if login{"subject HTTP login + directly granted role membership (not activation)"}else{"server-resolved directly granted role membership, not a login or activation"}}else{how}),
                    Err(reason)=>Probe::new(g,Verdict::Unknown,&reason),
                },
                Err(reason)=>Probe::new(g,Verdict::Unknown,reason),
            });
        }
        if started.elapsed() >= Duration::from_secs(adapter.read_timeout_seconds) {
            return grants
                .iter()
                .map(|g| {
                    Probe::new(
                        g,
                        Verdict::Unknown,
                        "ClickHouse probe deadline exceeded; partial results discarded",
                    )
                })
                .collect();
        }
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    fn lines(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }
    #[test]
    fn resolved_scopes_and_direct_roles_are_exact() {
        let e=Effective::parse(&lines(&["GRANT SELECT, INSERT ON `data space`.*, OPTIMIZE ON db.table TO `a``b` WITH GRANT OPTION", "GRANT `r ON x`, `odd\\`role` TO `a``b` WITH ADMIN OPTION", "GRANT TABLE ENGINE ON `Null` TO `a``b`"]),"a`b").unwrap();
        for (resource, privilege, want) in [
            ("table:data space.events", "SELECT", Verdict::Allow),
            ("db:data space2", "SELECT", Verdict::Deny),
            ("table:db.table", "OPTIMIZE", Verdict::Allow),
            ("role:r ON x", "MEMBER", Verdict::Allow),
            ("role:missing", "MEMBER", Verdict::Deny),
        ] {
            assert_eq!(
                e.verdict(&Grant::new("ch", "a`b", resource, privilege))
                    .unwrap(),
                want
            );
        }
        assert!(
            e.verdict(&Grant::new("ch", "a`b", "global:*", "ALL"))
                .is_err()
        );
        assert!(
            e.verdict(&Grant::new("ch", "a`b", "table:data space.*", "SELECT"))
                .is_err()
        );
    }
    #[test]
    fn partial_column_prefix_or_unrecognized_grants_never_allow() {
        for value in [
            "REVOKE SELECT ON db.t FROM demo",
            "GRANT SELECT(a) ON db.t TO demo",
            "GRANT SELECT ON prefix*.* TO demo",
            "GRANT SELECT ON db.t* TO demo",
            "GRANT SELECT ON db.t TO another",
            "GRANT SELECT ON db.t TO demo garbage",
            "GRANT SELECT ON `unfinished",
            "garbage",
            "GRANT SELECT ON db.t, TO demo",
            "GRANT SELECT ON db.t TO demo WITH ADMIN OPTION",
            "GRANT reader TO demo WITH GRANT OPTION",
            "GRANT `role\\n` TO demo",
        ] {
            assert!(
                Effective::parse(&lines(&[value]), "demo").is_err(),
                "{value}"
            );
        }
        let all =
            Effective::parse(&lines(&["GRANT ALL PRIVILEGES ON *.* TO demo"]), "demo").unwrap();
        for privilege in ["", "NOT REAL", "MEMBER"] {
            assert!(
                all.verdict(&Grant::new("ch", "demo", "table:db.t", privilege))
                    .is_err()
            );
        }
        assert_eq!(
            all.verdict(&Grant::new("ch", "demo", "table:db.t", "SELECT"))
                .unwrap(),
            Verdict::Allow
        );
    }
}
