//! Drift notifications use fresh observations and distinguish visibility from access changes.
use crate::{
    Result, config, engine,
    snapshot::{self, Snapshot},
};
use serde::Deserialize;
use serde_json::json;
use std::path::Path;

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Config {
    pub slack: Option<Slack>,
}
#[derive(Clone, Debug, Deserialize)]
pub struct Slack {
    pub bot_token_env: Option<String>,
    pub channel: Option<String>,
    pub redirect_to: Option<String>,
    #[serde(default = "api_url")]
    pub api_url: String,
}
fn api_url() -> String {
    "https://slack.com/api/".into()
}
pub fn run(path: &Path, live: bool, send: bool, as_json: bool) -> Result<()> {
    let loaded = config::load(path)?;
    let dir = config::relative(&loaded.base, &loaded.config.snapshots)?;
    let previous = snapshot::list(&dir)?
        .last()
        .map(|p| Snapshot::load(p, &loaded.kinds))
        .transpose()?;
    let current = engine::observe_with_live(&loaded, None, live)?.snapshot;
    let comparison = previous.as_ref().map(|p| snapshot::compare(p, &current));
    let mut lines = vec!["[grantline] ".to_owned()];
    if let Some(c) = &comparison {
        lines[0].push_str(&format!("{} → {}", c.previous, c.current));
        for (sign, grants) in [("+", &c.added), ("-", &c.removed)] {
            for g in grants {
                lines.push(format!(
                    "  {sign} [{}] {} {} on {}",
                    g.system, g.subject, g.privilege, g.resource
                ));
            }
        }
        if !c.obscured.is_empty() {
            lines.push(format!(
                "  ? {} grants unknown now, not revoked",
                c.obscured.len()
            ));
        }
        if !c.revealed.is_empty() {
            lines.push(format!(
                "  ? {} grants visible again, not newly granted",
                c.revealed.len()
            ));
        }
        if lines.len() == 1 {
            lines.push("  nothing moved".into());
        }
    } else {
        lines[0].push_str("first run — no previous observation to compare");
    }
    let saved = current.write(&dir)?;
    let text = lines.join("\n");
    let mut sent = false;
    if send && comparison.is_some() {
        let slack = loaded
            .config
            .notify
            .slack
            .as_ref()
            .ok_or("notify.slack is not configured")?;
        let channel = slack
            .channel
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or("Slack notification channel is not configured")?;
        let token = slack
            .bot_token_env
            .as_deref()
            .ok_or("Slack notification token is not configured")?;
        let (channel, message) =
            if let Some(to) = slack.redirect_to.as_deref().filter(|to| *to != channel) {
                (to, format!("(for {channel} — pilot redirect)\n{text}"))
            } else {
                (channel, text.clone())
            };
        let message = if message.chars().count() > 3500 {
            format!(
                "{}\n… truncated; inspect the saved snapshot for the complete diff",
                message.chars().take(3400).collect::<String>()
            )
        } else {
            message
        };
        let response = crate::integrations::Http::new(&slack.api_url, token)?.request(
            "POST",
            "chat.postMessage",
            Some(json!({"channel":channel,"text":message,"parse":"none","mrkdwn":false,"link_names":false,"unfurl_links":false,"unfurl_media":false})),
        )?;
        if response["ok"] != true {
            return Err("Slack notification refused; inspect before retry".into());
        }
        sent = true;
    }
    if as_json {
        println!(
            "{}",
            json!({"text":text,"sent":sent,"snapshot":saved,"comparison":comparison})
        );
    } else {
        println!(
            "{text}\nSlack: {}",
            if sent {
                "sent"
            } else {
                "not sent; --send is required for external delivery"
            }
        );
    }
    Ok(())
}
