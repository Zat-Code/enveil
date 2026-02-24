use clap::{Parser, Subcommand};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use serde::Serialize;

mod detector;
mod protector;

use detector::{SecretDetector, SecretFinding};
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
        
        /// Action: move, encrypt, or both (default: move)
        #[arg(short, long, default_value = "move")]
        action: String,
        
        /// Secure directory path (default: ./enveil_secure)
        #[arg(short, long)]
        secure_dir: Option<String>,
        
        /// Encryption key (32 bytes, base64 encoded) - auto-generated if not provided
        #[arg(short, long)]
        key: Option<String>,
        
        /// Preview only, don't actually protect
        #[arg(short, long)]
        dry_run: bool,
        
        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },
    /// Install Git hooks
    Install {
        /// Path to install hooks
        path: Option<String>,
    },
}

#[derive(Serialize)]
struct ScanResult {
    path: String,
    file_type: String,
    risk_level: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    secrets: Vec<SecretFinding>,
}

#[derive(Serialize)]
struct ScanReport {
    total_files: usize,
    risky_files: usize,
    files_with_secrets: usize,
    total_secrets_found: usize,
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
    
    // First, scan for risky files by extension
    scan_recursive(dir_path, &risky_extensions, &mut results, verbose);
    
    // Then, scan all text files for secrets using the detector
    let detector = SecretDetector::new();
    let secret_results = detector.scan_directory(dir_path, verbose);
    
    // Merge secret findings into results
    let mut files_with_secrets = 0;
    let mut total_secrets = 0;
    
    for (file_path, secrets) in secret_results {
        let secret_count = secrets.len();
        if let Some(result) = results.iter_mut().find(|r| r.path == file_path) {
            result.secrets = secrets;
            files_with_secrets += 1;
            total_secrets += secret_count;
        } else {
            // File not in risky list but contains secrets - add it
            let path = Path::new(&file_path);
            let extension = path.extension()
                .and_then(|e| e.to_str())
                .map(|e| format!(".{}", e))
                .unwrap_or_default();
            
            results.push(ScanResult {
                path: file_path,
                file_type: extension,
                risk_level: "high".to_string(),
                secrets,
            });
            files_with_secrets += 1;
            total_secrets += secret_count;
        }
    }
    
    let total_files = results.len();
    let risky_files = results.iter().filter(|r| r.risk_level == "high" || !r.secrets.is_empty()).count();
    
    Ok(ScanReport {
        total_files,
        risky_files,
        files_with_secrets,
        total_secrets_found: total_secrets,
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
                        secrets: Vec::new(),
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
    println!("Total risky files found: {}", report.risky_files);
    println!("Files with secrets: {}", report.files_with_secrets);
    println!("Total secrets found: {}\n", report.total_secrets_found);
    
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
        
        // Display secrets found in this file
        if !file.secrets.is_empty() {
            for secret in &file.secrets {
                println!("   ⚠️  [{}] Line {}: {}", secret.secret_type, secret.line_number, secret.line_content);
            }
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
        Commands::Protect { path, action, secure_dir, key, dry_run, verbose } => {
            let protect_path = path.as_deref().unwrap_or(".");
            let protect_path = Path::new(protect_path);
            
            let secure_dir = secure_dir
                .as_deref()
                .unwrap_or("./enveil_secure");
            
            let action = ProtectOption::from_str(action);
            
            // Parse key if provided (base64 encoded, 32 bytes)
            let encryption_key: Option<[u8; 32]> = if let Some(key_str) = key {
                use base64::Engine;
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(key_str)
                    .ok();
                if let Some(bytes) = decoded {
                    if bytes.len() == 32 {
                        let mut key_array = [0u8; 32];
                        key_array.copy_from_slice(&bytes);
                        Some(key_array)
                    } else {
                        eprintln!("⚠️  Key must be 32 bytes (base64 encoded)");
                        std::process::exit(1);
                    }
                } else {
                    eprintln!("⚠️  Invalid base64 key");
                    std::process::exit(1);
                }
            } else {
                None
            };
            
            // Show what will be protected
            println!("\n🔒 Enveil Protect\n");
            println!("Path: {}", protect_path.display());
            println!("Action: {:?}", action);
            println!("Secure directory: {}", secure_dir);
            println!();
            
            // Scan for sensitive files first
            if protect_path.is_dir() {
                let mut sensitive_files = Vec::new();
                scan_sensitive_files(protect_path, &mut sensitive_files);
                
                if sensitive_files.is_empty() {
                    println!("✅ No sensitive files found to protect!");
                    return;
                }
                
                println!("Found {} sensitive files:\n", sensitive_files.len());
                for (i, file) in sensitive_files.iter().enumerate() {
                    println!("  {}. {}", i + 1, file);
                }
                println!();
            }
            
            if *dry_run {
                println!("🔍 Dry run mode - no files were protected");
                println!("Use without --dry-run to actually protect files");
                return;
            }
            
            // Create protector
            let protector = FileProtector::new(Path::new(secure_dir).to_path_buf());
            
            if protect_path.is_file() {
                // Protect single file
                let result = protector.protect_file(protect_path, &action, encryption_key.as_ref());
                print_protect_result(&result, *verbose);
            } else if protect_path.is_dir() {
                // Protect directory
                let results = protector.protect_directory(protect_path, &action, encryption_key.as_ref());
                
                let success_count = results.iter().filter(|r| r.success).count();
                let fail_count = results.len() - success_count;
                
                println!("\n📊 Protection Summary:");
                println!("  ✅ Protected: {}", success_count);
                println!("  ❌ Failed: {}", fail_count);
                println!();
                
                for result in &results {
                    print_protect_result(result, *verbose);
                }
            } else {
                eprintln!("❌ Error: Invalid path");
                std::process::exit(1);
            }
        }
        Commands::Install { path } => {
            println!("Enveil install");
            println!("Path: {:?}", path);
        }
    }
}

/// Scan directory for sensitive files
fn scan_sensitive_files(dir_path: &Path, files: &mut Vec<String>) {
    let skip_dirs = [".git", "node_modules", "target", "dist", "build", "vendor", "enveil_secure"];
    
    if let Ok(entries) = fs::read_dir(dir_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            
            if path.is_dir() {
                let dir_name = path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");
                
                if !dir_name.starts_with('.') && !skip_dirs.contains(&dir_name) {
                    scan_sensitive_files(&path, files);
                }
            } else if path.is_file() && SensitiveFiles::is_sensitive(&path) {
                files.push(path.to_string_lossy().to_string());
            }
        }
    }
}

/// Print protect result
fn print_protect_result(result: &ProtectResult, verbose: bool) {
    if result.success {
        let icon = match result.action {
            protector::ProtectAction::Moved => "📦",
            protector::ProtectAction::Encrypted => "🔐",
            protector::ProtectAction::Secured => "🛡️",
        };
        println!("{} {} -> {}", icon, result.original_path, result.protected_path);
        if verbose {
            println!("   {}", result.message);
        }
    } else {
        println!("❌ {}: {}", result.original_path, result.message);
    }
}
