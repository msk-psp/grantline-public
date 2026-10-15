pub mod approval;
pub mod cli;
pub mod clickhouse;
pub mod commands;
pub mod config;
pub mod engine;
pub mod graph;
pub mod model;
pub mod planner;
pub mod postgres;
pub mod s3;
pub mod snapshot;
pub mod web;

pub type Result<T> = std::result::Result<T, String>;
