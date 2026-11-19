//! SecretTrace server library. The binary in `main.rs` is a thin CLI over this crate,
//! which keeps everything reachable from integration tests.

pub mod app;
pub mod audit;
pub mod auth;
pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod extract;
pub mod logging;
pub mod model;
pub mod openapi;
pub mod pagination;
pub mod policy;
pub mod registry;
pub mod routes;
pub mod users;
