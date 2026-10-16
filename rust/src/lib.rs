pub mod approval;
pub mod auth;
pub mod cli;
pub mod clickhouse;
pub mod commands;
pub mod config;
pub mod console;
pub mod engine;
pub mod graph;
pub mod integrations;
pub mod model;
pub mod planner;
pub mod postgres;
pub mod probe;
pub mod s3;
pub mod snapshot;
pub mod web;
#[cfg(unix)]
pub mod workflow;

pub type Result<T> = std::result::Result<T, String>;
