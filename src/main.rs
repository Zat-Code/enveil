use clap::{Parser, Subcommand};

mod detector;
mod git_hooks;
mod protector;

use detector::{SecretDetector, SecretFinding};
use git_hooks::GitHooks;
use protector::{FileProtector, ProtectOption, ProtectResult, SensitiveFiles};

#[derive(Parser)]
#[command(name = "enveil")]
#[command(about = "Secret detection and protection tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a directory for secrets
    Scan {
        /// Path to scan
        path: Option<String>,
        
        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
        
        /// Output format (text/json)
        #[arg(short, long, default_value = "text")]
        format: String,
    },
    /// Protect a project from secret exposure
    Protect {
        /// Path to protect
        path: Option<String>,
    },
    /// Install Git hooks
    Install {
        /// Path to install hooks
        path: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Scan { path, verbose, format } => {
            println!("Enveil scan");
            println!("Path: {:?}", path);
            println!("Verbose: {}", verbose);
            println!("Format: {}", format);
        }
        Commands::Protect { path } => {
            println!("Enveil protect");
            println!("Path: {:?}", path);
        }
        Commands::Install { path } => {
            println!("Enveil install");
            println!("Path: {:?}", path);
        }
    }
}
