mod formatter;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use sbc_core::SnapshotRunner;
use formatter::{format_text, format_json};

#[derive(Parser)]
#[command(name = "sbc-snapshot")]
#[command(author = "SBC Snapshot Contributors")]
#[command(version)]
#[command(about = "Security & Exposure Snapshot Tool for Single Board Computers", long_about = None)]
struct Cli {
    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Output file (stdout if not specified)
    #[arg(short, long)]
    output: Option<String>,

    /// Include raw data in output
    #[arg(long)]
    raw: bool,

    /// Redact sensitive information (IPs, hostnames, usernames)
    #[arg(long)]
    redact: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    /// Human-readable text format
    Text,
    /// JSON format
    Json,
    /// JSON with pretty printing
    JsonPretty,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Check if running as root
    if !nix::unistd::Uid::effective().is_root() {
        eprintln!("Warning: Not running as root. Some checks may be incomplete.");
        eprintln!("         Run with 'sudo' for full analysis.\n");
    }

    // Run the snapshot
    let runner = SnapshotRunner::new()
        .with_raw_data(cli.raw);

    let snapshot = runner.run()?;

    // Format output
    let output = match cli.format {
        OutputFormat::Text => format_text(&snapshot, cli.redact),
        OutputFormat::Json => format_json(&snapshot, false, cli.redact)?,
        OutputFormat::JsonPretty => format_json(&snapshot, true, cli.redact)?,
    };

    // Write output
    if let Some(path) = cli.output {
        std::fs::write(path, output)?;
    } else {
        print!("{}", output);
    }

    Ok(())
}
