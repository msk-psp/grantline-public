//! Native approval rules. The playground's PR writer is deliberately simulated.
use crate::model::Grant;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use subtle::ConstantTimeEq;
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pending,
    Approved,
    Denied,
    Proposed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Request {
    pub id: String,
    pub created_at: String,
    pub requester: String,
    pub grant: Grant,
    pub note: String,
    pub status: Status,
    // Never serialize bearer tokens into a requester response.
    #[serde(skip)]
    tokens: BTreeMap<String, String>,
    pub approved: BTreeSet<String>,
    pub plan: String,
    pub plan_hash: String,
}

impl Request {
    pub fn create(
        requester: &str,
        approvers: &[&str],
        grant: Grant,
        note: String,
    ) -> Result<Self, &'static str> {
        if requester.is_empty()
            || approvers.is_empty()
            || approvers.iter().any(|a| a.is_empty() || *a == requester)
        {
            return Err("A request needs independent approvers.");
        }
        let plan = serde_json::to_string_pretty(&grant).map_err(|_| "Cannot encode plan.")?;
        let hash = format!("{:x}", Sha256::digest(plan.as_bytes()));
        Ok(Self {
            id: Uuid::new_v4().simple().to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            requester: requester.into(),
            grant,
            note,
            status: Status::Pending,
            tokens: approvers
                .iter()
                .map(|a| ((*a).into(), Uuid::new_v4().simple().to_string()))
                .collect(),
            approved: BTreeSet::new(),
            plan,
            plan_hash: hash,
        })
    }
    pub fn token_for(&self, actor: &str) -> Option<&str> {
        self.tokens.get(actor).map(String::as_str)
    }
    pub fn authorize(&self, actor: &str, token: &str) -> Result<(), &'static str> {
        if actor == self.requester {
            return Err("Self approval is forbidden.");
        }
        let expected = self
            .token_for(actor)
            .ok_or("This identity is not an approver.")?;
        if !bool::from(expected.as_bytes().ct_eq(token.as_bytes())) {
            return Err("Invalid approval token.");
        }
        Ok(())
    }
    pub fn decide(&mut self, actor: &str, token: &str, approve: bool) -> Result<(), &'static str> {
        self.authorize(actor, token)?;
        if self.status != Status::Pending || self.approved.contains(actor) {
            return Err("This decision is already final.");
        }
        if !approve {
            self.status = Status::Denied;
            return Ok(());
        }
        self.approved.insert(actor.into());
        if self.tokens.keys().all(|a| self.approved.contains(a)) {
            self.status = Status::Approved;
        }
        Ok(())
    }
    pub fn propose(&mut self, current_plan: &str) -> Result<(), &'static str> {
        if self.status != Status::Approved {
            return Err("All approvals are required before proposing.");
        }
        let hash = format!("{:x}", Sha256::digest(current_plan.as_bytes()));
        if hash != self.plan_hash || current_plan != self.plan {
            return Err("Plan changed; create a new request.");
        }
        self.status = Status::Proposed;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        Request::create(
            "requester",
            &["reviewer", "owner"],
            Grant::new("s3", "demo-user", "bucket:demo/team", "Read"),
            String::new(),
        )
        .unwrap()
    }
    #[test]
    fn binding_all_approvers_and_immutable_plan() {
        let mut r = request();
        let token = r.token_for("reviewer").unwrap().to_owned();
        assert!(r.decide("requester", &token, true).is_err());
        assert!(r.decide("owner", &token, true).is_err());
        assert!(r.decide("reviewer", "invalid", true).is_err());
        r.decide("reviewer", &token, true).unwrap();
        assert_eq!(r.status, Status::Pending);
        assert!(r.propose(&r.plan.clone()).is_err());
        assert!(r.decide("reviewer", &token, true).is_err());
        let owner = r.token_for("owner").unwrap().to_owned();
        r.decide("owner", &owner, true).unwrap();
        assert!(r.propose("different plan").is_err());
        assert_eq!(r.status, Status::Approved);
        r.propose(&r.plan.clone()).unwrap();
        assert_eq!(r.status, Status::Proposed);
        assert!(r.decide("owner", &owner, false).is_err());
        assert!(!serde_json::to_string(&r).unwrap().contains(&token));
    }
    #[test]
    fn denial_is_terminal_and_self_approval_cannot_be_configured() {
        let mut r = request();
        let token = r.token_for("reviewer").unwrap().to_owned();
        r.decide("reviewer", &token, false).unwrap();
        assert!(r.decide("reviewer", &token, true).is_err());
        assert!(r.propose(&r.plan.clone()).is_err());
        assert!(Request::create("requester", &["requester"], r.grant, String::new()).is_err());
    }
}
