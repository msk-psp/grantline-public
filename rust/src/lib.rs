pub mod approval;
pub mod auth;
mod cache;
pub mod cli;
pub mod clickhouse;
pub mod commands;
pub mod config;
pub mod console;
pub mod engine;
pub mod graph;
pub mod integrations;
#[cfg(unix)]
pub mod migration;
pub mod model;
pub mod notify;
pub mod planner;
pub mod postgres;
pub mod probe;
pub mod recent;
pub mod s3;
pub mod snapshot;
pub mod tls;
pub mod web;
#[cfg(unix)]
pub mod workflow;

pub type Result<T> = std::result::Result<T, String>;
