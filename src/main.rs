use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

const VERSION: &str = "0.1.0";

#[derive(Parser)]
#[command(name = "enveil")]
#[command(about = "Secret detection and protection tool", long_about = None)]
#[command(version = VERSION)]
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

#[derive(Serialize, Deserialize)]
struct ScanResult {
    tool: String,
    version: String,
    path: Option<String>,
    format: String,
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Scan { path, verbose, format } => {
            if *verbose {
                println!("Enveil v{} - verbose mode enabled", VERSION);
            }
            if format == "json" {
                let result = ScanResult {
                    tool: "enveil".to_string(),
                    version: VERSION.to_string(),
                    path: path.clone(),
                    format: format.clone(),
                };
                println!("{}", serde_json::to_string_pretty(&result).unwrap());
            } else {
                println!("Enveil scan");
                println!("Path: {:?}", path);
                println!("Verbose: {}", verbose);
                println!("Format: {}", format);
            }
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
