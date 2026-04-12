mod actions;
mod app;
mod bootstrap;
mod error;
mod helpers;
mod known_servers;
mod known_servers_ui;
mod local_config;
mod logging;
mod login;
mod login_flow;
mod panels;
mod python;
mod state;
mod tasks;
mod theme;
mod tls;
mod transport;
mod ui;

pub(crate) use helpers::*;
pub(crate) use state::*;
pub(crate) use tasks::*;

pub(crate) use app::{
    AppPhase, ClientApp, SESSION_GRAPH_HEIGHT, SESSION_GRAPH_MAX_ZOOM, SESSION_GRAPH_MIN_ZOOM,
    SESSION_GRAPH_ROOT_ID, SESSION_TTL, SESSION_WARN_BEFORE,
};
pub(crate) use bootstrap::Cli;
#[cfg(test)]
pub(crate) use bootstrap::DEFAULT_SERVER_URL;
pub(crate) use error::ClientError;

// Re-export agent helpers defined in the agents panel so that `main_tests`
// (which uses `use super::*`) can find them without modification.
#[cfg(test)]
pub(crate) use panels::agents::{
    agent_ip, agent_matches_filter, agent_sleep_jitter, sort_agents, sort_button_label,
};

// Additional imports used only in the test module via `use super::*`.
#[cfg(test)]
use base64::Engine;
#[cfg(test)]
use eframe::egui::Color32;
#[cfg(test)]
use python::{ScriptLoadStatus, ScriptOutputStream};
#[cfg(test)]
use red_cell_common::operator::ListenerInfo;
#[cfg(test)]
use std::collections::BTreeMap;
#[cfg(test)]
use std::path::Path;
#[cfg(test)]
use transport::{LootKind, ProcessEntry};
#[cfg(test)]
use zeroize::Zeroizing;

fn main() -> Result<(), ClientError> {
    bootstrap::run()
}

#[cfg(test)]
mod main_tests;
