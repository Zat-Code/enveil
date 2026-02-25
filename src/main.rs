use clap::{Parser, Subcommand};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use serde::Serialize;

mod git_hooks;

use git_hooks::GitHooks;

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
        
        /// Force reinstall hooks
        #[arg(short, long)]
        force: bool,
        
        /// Uninstall hooks
        #[arg(long)]
        uninstall: bool,
        
        /// Check hook status
        #[arg(long)]
        status: bool,
    },
}

#[derive(Serialize)]
struct ScanResult {
    path: String,
    file_type: String,
    risk_level: String,
}

#[derive(Serialize)]
struct ScanReport {
    total_files: usize,
    risky_files: usize,
    files: Vec<ScanResult>,
}

fn get_risky_extensions() -> HashSet<&'static str> {
    let mut extensions = HashSet::new();
    // Secrets & Config
    extensions.insert(".env");
    extensions.insert(".env.local");
    extensions.insert(".env.prod");
    extensions.insert(".env.dev");
    extensions.insert(".env.example");
    extensions.insert(".json");
    extensions.insert(".yaml");
    extensions.insert(".yml");
    extensions.insert(".toml");
    extensions.insert(".ini");
    extensions.insert(".conf");
    extensions.insert(".config");
    // Keys & Credentials
    extensions.insert(".pem");
    extensions.insert(".key");
    extensions.insert(".pub");
    extensions.insert(".p12");
    extensions.insert(".pfx");
    extensions.insert(".crt");
    extensions.insert(".cer");
    // Sensitive
    extensions.insert(".sql");
    extensions.insert(".db");
    extensions.insert(".sqlite");
    extensions.insert(".log");
    extensions.insert(".bak");
    extensions.insert(".backup");
    extensions
}

fn get_file_risk_level(extension: &str) -> &'static str {
    match extension {
        ".env" | ".env.local" | ".env.prod" | ".env.dev" | ".pem" | ".key" | ".p12" | ".pfx" => "high",
        ".env.example" | ".json" | ".yaml" | ".yml" | ".toml" | ".sql" | ".db" => "medium",
        _ => "low",
    }
}

fn scan_directory(dir_path: &Path, verbose: bool) -> Result<ScanReport, String> {
    let risky_extensions = get_risky_extensions();
    let mut results: Vec<ScanResult> = Vec::new();
    
    if !dir_path.exists() {
        return Err(format!("Path does not exist: {}", dir_path.display()));
    }
    
    if !dir_path.is_dir() {
        return Err(format!("Path is not a directory: {}", dir_path.display()));
    }
    
    scan_recursive(dir_path, &risky_extensions, &mut results, verbose);
    
    let total_files = results.len();
    let risky_files = results.len();
    
    Ok(ScanReport {
        total_files,
        risky_files,
        files: results,
    })
}

fn scan_recursive(dir_path: &Path, extensions: &HashSet<&str>, results: &mut Vec<ScanResult>, verbose: bool) {
    // Skip hidden directories and common non-relevant dirs
    let skip_dirs = [".git", "node_modules", "target", "dist", "build", "vendor"];
    
    if let Ok(entries) = fs::read_dir(dir_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            
            if path.is_dir() {
                let dir_name = path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");
                
                if !dir_name.starts_with('.') && !skip_dirs.contains(&dir_name) {
                    scan_recursive(&path, extensions, results, verbose);
                }
            } else if path.is_file() {
                let extension = path.extension()
                    .and_then(|e| e.to_str())
                    .map(|e| format!(".{}", e))
                    .unwrap_or_default();
                
                let file_name = path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");
                
                // Check for .env files by name
                let is_env_file = file_name.starts_with(".env") || extension == ".env";
                
                if extensions.contains(&extension.as_str()) || is_env_file {
                    let risk_level = if is_env_file {
                        "high"
                    } else {
                        get_file_risk_level(&extension)
                    };
                    
                    results.push(ScanResult {
                        path: path.to_string_lossy().to_string(),
                        file_type: if is_env_file { ".env".to_string() } else { extension },
                        risk_level: risk_level.to_string(),
                    });
                    
                    if verbose {
                        eprintln!("[{}] Found: {}", risk_level.to_uppercase(), path.display());
                    }
                }
            }
        }
    }
}

fn print_text_report(report: ScanReport, verbose: bool) {
    println!("\n📁 Enveil Scan Report\n");
    println!("Total risky files found: {}\n", report.risky_files);
    
    if report.files.is_empty() {
        println!("✅ No risky files detected!");
        return;
    }
    
    // Sort by risk level (high first)
    let mut files = report.files;
    files.sort_by(|a, b| {
        let order = |r: &str| match r {
            "high" => 0,
            "medium" => 1,
            _ => 2,
        };
        order(&a.risk_level).cmp(&order(&b.risk_level))
    });
    
    for file in &files {
        let icon = match file.risk_level.as_str() {
            "high" => "🔴",
            "medium" => "🟡",
            _ => "🟢",
        };
        
        println!("{} [{}] {}", icon, file.risk_level.to_uppercase(), file.path);
        
        if verbose {
            println!("   Type: {}", file.file_type);
        }
    }
}

fn print_json_report(report: ScanReport) {
    if let Ok(json) = serde_json::to_string_pretty(&report) {
        println!("{}", json);
    }
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Scan { path, verbose, format } => {
            let scan_path = path.as_deref().unwrap_or(".");
            
            match scan_directory(Path::new(scan_path), *verbose) {
                Ok(report) => {
                    match format.as_str() {
                        "json" => print_json_report(report),
                        _ => print_text_report(report, *verbose),
                    }
                }
                Err(e) => {
                    eprintln!("❌ Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Protect { path } => {
            println!("Enveil protect");
            println!("Path: {:?}", path);
        }
        Commands::Install { path, force, uninstall, status } => {
            let install_path = path.as_deref().unwrap_or(".");
            let hooks = GitHooks::new(install_path);
            
            if *uninstall {
                match hooks.uninstall() {
                    Ok(_) => {},
                    Err(e) => {
                        eprintln!("❌ Error: {}", e);
                        std::process::exit(1);
                    }
                }
            } else if *status {
                if hooks.is_installed() {
                    println!("✅ Git hooks are installed");
                } else {
                    println!("ℹ️  Git hooks are not installed");
                }
            } else {
                match hooks.install(*force) {
                    Ok(_) => {},
                    Err(e) => {
                        eprintln!("❌ Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
    }
}
