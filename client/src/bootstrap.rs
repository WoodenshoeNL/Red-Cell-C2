//! CLI parsing and native window bootstrap for the operator client.

use std::path::PathBuf;

use anyhow::{Result, anyhow};
use clap::Parser;
use eframe::egui;

use crate::app::ClientApp;
use crate::known_servers::KnownServersStore;
use crate::local_config::LocalConfig;
use crate::logging;
use crate::theme;

/// Default WebSocket URL shown in CLI help and used when no `--server` is passed.
pub(crate) const DEFAULT_SERVER_URL: &str = "wss://127.0.0.1:40056/havoc";

const WINDOW_TITLE: &str = "Red Cell Client";
const INITIAL_WINDOW_SIZE: [f32; 2] = [1600.0, 900.0];
const MINIMUM_WINDOW_SIZE: [f32; 2] = [1280.0, 720.0];

#[derive(Debug, Clone, Parser, PartialEq, Eq)]
#[command(name = "red-cell-client", about = "Red Cell operator client")]
pub(crate) struct Cli {
    /// Teamserver WebSocket URL.
    #[arg(long, default_value = DEFAULT_SERVER_URL)]
    pub(crate) server: String,
    /// Directory containing client-side Python scripts.
    #[arg(long)]
    pub(crate) scripts_dir: Option<PathBuf>,
    /// Path to a PEM-encoded CA certificate for teamserver verification.
    #[arg(long)]
    pub(crate) ca_cert: Option<PathBuf>,
    /// SHA-256 fingerprint (hex) of the pinned teamserver certificate.
    #[arg(long)]
    pub(crate) cert_fingerprint: Option<String>,
    /// Disable TLS certificate verification entirely. DANGEROUS: makes connections
    /// vulnerable to man-in-the-middle attacks. Prefer --ca-cert or --cert-fingerprint.
    /// Deprecated: TOFU is now the default — this flag will be removed in a future release.
    #[arg(long, default_value_t = false, hide = true)]
    pub(crate) accept_invalid_certs: bool,
    /// Remove a previously trusted server from the known-servers store and exit.
    /// Specify the host:port (e.g. "10.0.0.1:40056") to purge.
    #[arg(long)]
    pub(crate) purge_known_server: Option<String>,
}

/// Entry point after [`Cli`] parsing: optional purge, then GUI.
pub(crate) fn run() -> Result<()> {
    let cli = Cli::parse();
    let local_config = LocalConfig::load();
    logging::init(&local_config);

    // Handle --purge-known-server: remove the entry and exit.
    if let Some(host_port) = &cli.purge_known_server {
        let mut store = KnownServersStore::load();
        if store.remove(host_port) {
            store.save().map_err(|e| anyhow::anyhow!("failed to save known-servers: {e}"))?;
            println!("Removed {host_port} from known servers.");
        } else {
            println!("No entry found for {host_port} in known servers.");
        }
        return Ok(());
    }

    launch_client(cli)
}

pub(crate) fn launch_client(cli: Cli) -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(INITIAL_WINDOW_SIZE)
            .with_min_inner_size(MINIMUM_WINDOW_SIZE),
        ..Default::default()
    };

    eframe::run_native(
        WINDOW_TITLE,
        options,
        Box::new(move |creation_context| {
            creation_context.egui_ctx.set_visuals(theme::havoc_dark_theme());
            let app = ClientApp::new(cli)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            Ok(Box::new(app) as Box<dyn eframe::App>)
        }),
    )
    .map_err(|error| anyhow!("failed to start egui application: {error}"))
}
