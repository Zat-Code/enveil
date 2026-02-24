use regex::Regex;
use serde::Serialize;
use std::path::Path;

/// Represents a detected secret
#[derive(Debug, Clone, Serialize)]
pub struct SecretFinding {
    pub secret_type: String,
    pub line_number: usize,
    pub line_content: String,
    pub matched_pattern: String,
}

/// Secret detector module with regex patterns for various secret types
pub struct SecretDetector {
    patterns: Vec<(&'static str, Regex)>,
}

impl SecretDetector {
    pub fn new() -> Self {
        let patterns = vec![
            // AWS Access Key ID
            (
                "AWS_ACCESS_KEY_ID",
                Regex::new(r#"(?i)(?:aws_access_key_id|aws_secret_access_key)\s*=\s*['"]?([A-Z0-9]{20})['"]?"#).unwrap(),
            ),
            // AWS Secret Access Key
            (
                "AWS_SECRET_KEY",
                Regex::new(r#"(?i)aws_secret_access_key\s*=\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#).unwrap(),
            ),
            // AWS Session Token
            (
                "AWS_SESSION_TOKEN",
                Regex::new(r#"(?i)aws_session_token\s*=\s*['"]?([A-Za-z0-9/+=]{200,})['"]?"#).unwrap(),
            ),
            // GitHub Personal Access Token
            (
                "GITHUB_TOKEN",
                Regex::new(r"(?i)ghp_[a-zA-Z0-9]{36}").unwrap(),
            ),
            // GitHub OAuth Token
            (
                "GITHUB_OAUTH",
                Regex::new(r"(?i)gho_[a-zA-Z0-9]{36}").unwrap(),
            ),
            // GitHub App Token
            (
                "GITHUB_APP",
                Regex::new(r"(?i)ghu_[a-zA-Z0-9]{36}").unwrap(),
            ),
            // Generic API Key
            (
                "API_KEY",
                Regex::new(r#"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?"#).unwrap(),
            ),
            // Generic Secret
            (
                "SECRET",
                Regex::new(r#"(?i)(?:secret|secret[_-]?key)\s*[:=]\s*['"]?([a-zA-Z0-9_-]{8,})['"]?"#).unwrap(),
            ),
            // Password in code
            (
                "PASSWORD",
                Regex::new(r#"(?i)(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]{4,})['"]"#).unwrap(),
            ),
            // Private Key RSA
            (
                "RSA_PRIVATE_KEY",
                Regex::new(r"-----BEGIN (?:RSA )?PRIVATE KEY-----").unwrap(),
            ),
            // SSH Private Key
            (
                "SSH_PRIVATE_KEY",
                Regex::new(r"-----BEGIN OPENSSH PRIVATE KEY-----").unwrap(),
            ),
            // Generic Private Key
            (
                "PRIVATE_KEY",
                Regex::new(r"-----BEGIN PRIVATE KEY-----").unwrap(),
            ),
            // PostgreSQL Connection String
            (
                "POSTGRES_URL",
                Regex::new(r"(?i)postgres(ql)?://[^\s]+").unwrap(),
            ),
            // MySQL Connection String
            (
                "MYSQL_URL",
                Regex::new(r"(?i)mysql://[^\s]+").unwrap(),
            ),
            // Redis Connection String
            (
                "REDIS_URL",
                Regex::new(r"(?i)redis://[^\s]+").unwrap(),
            ),
            // MongoDB Connection String
            (
                "MONGO_URL",
                Regex::new(r"(?i)mongodb(\+srv)?://[^\s]+").unwrap(),
            ),
            // JWT Token
            (
                "JWT_TOKEN",
                Regex::new(r"(?i)eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*").unwrap(),
            ),
            // Slack Token
            (
                "SLACK_TOKEN",
                Regex::new(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*").unwrap(),
            ),
            // Stripe API Key
            (
                "STRIPE_KEY",
                Regex::new(r"(?i)(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{24,}").unwrap(),
            ),
            // Google API Key
            (
                "GOOGLE_API_KEY",
                Regex::new(r"AIza[0-9A-Za-z_-]{35}").unwrap(),
            ),
            // Azure Storage Account Key
            (
                "AZURE_STORAGE_KEY",
                Regex::new(r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+").unwrap(),
            ),
            // Twilio API Key
            (
                "TWILIO_KEY",
                Regex::new(r"(?i)SK[a-f0-9]{32}").unwrap(),
            ),
            // SendGrid API Key
            (
                "SENDGRID_KEY",
                Regex::new(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}").unwrap(),
            ),
            // Generic Bearer Token
            (
                "BEARER_TOKEN",
                Regex::new(r"(?i)bearer\s+[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+").unwrap(),
            ),
            // Basic Auth
            (
                "BASIC_AUTH",
                Regex::new(r"(?i)authorization\s*:\s*basic\s+[a-zA-Z0-9+/=]+").unwrap(),
            ),
            // Hex Secret (32+ chars)
            (
                "HEX_SECRET",
                Regex::new(r"(?i)(?:token|key|secret)\s*[:=]\s*['\"]?([a-fA-F0-9]{32,})['\"]?").unwrap(),
            ),
        ];

        Self { patterns }
    }

    /// Scan a file for secrets
    pub fn scan_file(&self, file_path: &Path) -> Vec<SecretFinding> {
        let mut findings = Vec::new();

        // Skip binary files and certain extensions
        if let Some(ext) = file_path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            if matches!(ext_str.as_str(), "exe" | "dll" | "so" | "bin" | "jpg" | "png" | "gif" | "zip" | "tar" | "gz") {
                return findings;
            }
        }

        // Read file content
        let content = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => return findings,
        };

        // Scan each line
        for (line_num, line) in content.lines().enumerate() {
            for (secret_type, pattern) in &self.patterns {
                if pattern.is_match(line) {
                    // Create a masked version of the line for display
                    let masked_line = mask_secret_in_line(line);

                    findings.push(SecretFinding {
                        secret_type: secret_type.to_string(),
                        line_number: line_num + 1,
                        line_content: masked_line,
                        matched_pattern: format!("{:?}", pattern),
                    });
                }
            }
        }

        findings
    }

    /// Scan a directory recursively for secrets
    pub fn scan_directory(&self, dir_path: &Path, verbose: bool) -> Vec<(String, Vec<SecretFinding>)> {
        let mut results = Vec::new();
        let skip_dirs = [".git", "node_modules", "target", "dist", "build", "vendor"];

        self.scan_dir_recursive(dir_path, &skip_dirs, &mut results, verbose);

        results
    }

    fn scan_dir_recursive(
        &self,
        dir_path: &Path,
        skip_dirs: &[&str],
        results: &mut Vec<(String, Vec<SecretFinding>)>,
        verbose: bool,
    ) {
        if let Ok(entries) = std::fs::read_dir(dir_path) {
            for entry in entries.flatten() {
                let path = entry.path();

                if path.is_dir() {
                    let dir_name = path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");

                    if !dir_name.starts_with('.') && !skip_dirs.contains(&dir_name) {
                        self.scan_dir_recursive(&path, skip_dirs, results, verbose);
                    }
                } else if path.is_file() {
                    let findings = self.scan_file(&path);
                    if !findings.is_empty() {
                        if verbose {
                            eprintln!("[SECRETS] Found {} secrets in: {}", findings.len(), path.display());
                        }
                        results.push((path.to_string_lossy().to_string(), findings));
                    }
                }
            }
        }
    }
}

impl Default for SecretDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Mask secrets in a line for safe display
fn mask_secret_in_line(line: &str) -> String {
    // Replace potential secrets with masked versions
    let masked = line
        .replace(|c: char| c.is_alphanumeric() || c == '-' || c == '_' || c == '+' || c == '/' || c == '=' , "*".chars().take(1).collect::<String>());

    // Keep first few chars for context
    if masked.len() > 50 {
        format!("{}...", &masked[..50])
    } else {
        masked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_aws_key() {
        let detector = SecretDetector::new();
        
        let test_content = r#"
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"#;
        
        std::fs::write("/tmp/test_aws.txt", test_content).unwrap();
        let findings = detector.scan_file(Path::new("/tmp/test_aws.txt"));
        
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_detect_github_token() {
        let detector = SecretDetector::new();
        
        let test_content = r#"
github_token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"#;
        
        std::fs::write("/tmp/test_github.txt", test_content).unwrap();
        let findings = detector.scan_file(Path::new("/tmp/test_github.txt"));
        
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_detect_private_key() {
        let detector = SecretDetector::new();
        
        let test_content = r#"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
# Some content
-----END OPENSSH PRIVATE KEY-----
"#;
        
        std::fs::write("/tmp/test_ssh.txt", test_content).unwrap();
        let findings = detector.scan_file(Path::new("/tmp/test_ssh.txt"));
        
        assert!(!findings.is_empty());
    }
}
