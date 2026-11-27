mod admin;
mod body;
mod config;
mod http;
mod listener;
mod proxy;
mod rate_limit;
mod runtime;
mod static_files;
mod stream;
mod tls;

use std::{
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::signal::unix::{SignalKind, signal};
use tracing_subscriber::EnvFilter;

use crate::{config::Config, runtime::Runtime};

#[derive(Parser)]
#[command(version, about = "Linux web server and reverse proxy")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the daemon.
    Run {
        #[arg(long)]
        config: PathBuf,
    },
    /// Validate configuration and read required input files offline.
    Check {
        #[arg(long)]
        config: PathBuf,
    },
    /// Reload the daemon's startup configuration.
    Reload {
        #[arg(long)]
        admin_socket: PathBuf,
    },
    /// Show the active generation, readiness, and metrics.
    Status {
        #[arg(long)]
        admin_socket: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Run { config } => run(std::path::absolute(config)?).await,
        Command::Check { config } => {
            Runtime::check(&std::path::absolute(config)?)?;
            println!("Configuration is valid");
            Ok(())
        }
        Command::Reload { admin_socket } => {
            print_json(admin::command(&admin_socket, "reload\n").await?)
        }
        Command::Status { admin_socket } => {
            print_json(admin::command(&admin_socket, "status\n").await?)
        }
    }
}

fn print_json(value: serde_json::Value) -> Result<()> {
    let mut output = io::stdout().lock();
    serde_json::to_writer_pretty(&mut output, &value)?;
    output.write_all(b"\n")?;
    Ok(())
}

async fn run(path: PathBuf) -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let mut terminate = signal(SignalKind::terminate()).context("register SIGTERM handler")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("register SIGINT handler")?;
    let config = Config::load(&path)?;
    let admin = admin::Admin::bind(&config.admin_socket)?;
    let runtime = Runtime::start(path, config)?;
    let result = tokio::select! {
        result = admin.serve(Arc::clone(&runtime)) => result,
        _ = terminate.recv() => Ok(()),
        _ = interrupt.recv() => Ok(()),
    };
    runtime.shutdown().await;
    result
}
