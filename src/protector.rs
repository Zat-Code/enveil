use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::Engine;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Result of protecting a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectResult {
    pub original_path: String,
    pub protected_path: String,
    pub action: ProtectAction,
    pub success: bool,
    pub message: String,
}

/// Action taken to protect a file
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProtectAction {
    Moved,
    Encrypted,
    Secured,
}

/// Sensitive file types that should be protected
pub struct SensitiveFiles;

impl SensitiveFiles {
    /// Get set of sensitive file extensions
    pub fn get_extensions() -> HashSet<&'static str> {
        let mut extensions = HashSet::new();
        // Environment files
        extensions.insert(".env");
        extensions.insert(".env.local");
        extensions.insert(".env.prod");
        extensions.insert(".env.dev");
        extensions.insert(".env.example");
        extensions.insert(".env.sample");
        // Configuration
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
        // Database
        extensions.insert(".sql");
        extensions.insert(".db");
        extensions.insert(".sqlite");
        extensions.insert(".sqlite3");
        // Backup
        extensions.insert(".log");
        extensions.insert(".bak");
        extensions.insert(".backup");
        extensions.insert(".old");
        extensions
    }

    /// Get set of sensitive file names
    pub fn get_sensitive_names() -> HashSet<&'static str> {
        let mut names = HashSet::new();
        names.insert(".env");
        names.insert(".env.local");
        names.insert(".env.production");
        names.insert(".env.development");
        names.insert("id_rsa");
        names.insert("id_ed25519");
        names.insert("id_dsa");
        names.insert("id_ecdsa");
        names.insert("known_hosts");
        names.insert("authorized_keys");
        names.insert("npmrc");
        names.insert(".npmrc");
        names.insert("pip.conf");
        names.insert(".netrc");
        names.insert(".git-credentials");
        names.insert("service-account.json");
        names.insert("credentials.json");
        names.insert("secrets.yaml");
        names.insert("secrets.yml");
        names
    }

    /// Check if a file is sensitive
    pub fn is_sensitive(path: &Path) -> bool {
        let file_name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        
        let extension = path.extension()
            .and_then(|e| e.to_str())
            .map(|e| format!(".{}", e))
            .unwrap_or_default();

        // Check by name first
        if Self::get_sensitive_names().contains(&file_name) || file_name.starts_with(".env") {
            return true;
        }

        // Check by extension
        Self::get_extensions().contains(&extension.as_str())
    }
}

/// File protector for securing sensitive files
pub struct FileProtector {
    secure_dir: PathBuf,
}

impl FileProtector {
    /// Create a new file protector
    pub fn new(secure_dir: PathBuf) -> Self {
        Self { secure_dir }
    }

    /// Protect a file (move or encrypt based on option)
    pub fn protect_file(
        &self,
        source_path: &Path,
        action: &ProtectOption,
        key: Option<&[u8; 32]>,
    ) -> ProtectResult {
        let source_path = source_path.to_path_buf();
        
        if !source_path.exists() {
            return ProtectResult {
                original_path: source_path.to_string_lossy().to_string(),
                protected_path: String::new(),
                action: ProtectAction::Secured,
                success: false,
                message: "Source file does not exist".to_string(),
            };
        }

        // Create secure directory if it doesn't exist
        if !self.secure_dir.exists() {
            if let Err(e) = fs::create_dir_all(&self.secure_dir) {
                return ProtectResult {
                    original_path: source_path.to_string_lossy().to_string(),
                    protected_path: String::new(),
                    action: ProtectAction::Secured,
                    success: false,
                    message: format!("Failed to create secure directory: {}", e),
                };
            }
        }

        match action {
            ProtectOption::Move => self.move_to_secure(&source_path),
            ProtectOption::Encrypt => self.encrypt_file(&source_path, key),
            ProtectOption::Both => {
                // First encrypt, then move
                let encrypt_result = self.encrypt_file(&source_path, key);
                if encrypt_result.success {
                    // Remove original file after encryption
                    let _ = fs::remove_file(&source_path);
                    encrypt_result
                } else {
                    encrypt_result
                }
            }
        }
    }

    /// Move file to secure directory
    fn move_to_secure(&self, source: &Path) -> ProtectResult {
        let file_name = source.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        
        let dest_path = self.secure_dir.join(file_name);

        // Handle naming conflicts
        let dest_path = self.get_unique_path(&dest_path);

        match fs::copy(source, &dest_path) {
            Ok(_) => {
                // Remove original
                let remove_result = fs::remove_file(source);
                
                ProtectResult {
                    original_path: source.to_string_lossy().to_string(),
                    protected_path: dest_path.to_string_lossy().to_string(),
                    action: ProtectAction::Moved,
                    success: true,
                    message: if remove_result.is_ok() {
                        "File moved to secure directory".to_string()
                    } else {
                        "File copied to secure directory (original removal failed)".to_string()
                    },
                }
            }
            Err(e) => ProtectResult {
                original_path: source.to_string_lossy().to_string(),
                protected_path: String::new(),
                action: ProtectAction::Moved,
                success: false,
                message: format!("Failed to move file: {}", e),
            },
        }
    }

    /// Encrypt file with AES-256-GCM
    fn encrypt_file(&self, source: &Path, key: Option<&[u8; 32]>) -> ProtectResult {
        let file_name = source.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        
        // Generate random key if not provided
        let key = match key {
            Some(k) => *k,
            None => {
                let mut key = [0u8; 32];
                rand::thread_rng().fill(&mut key);
                // In production, this key should be stored securely
                // For now, we'll print it (in production, use proper key management)
                eprintln!("⚠️  Generated encryption key (save this!): {}", base64::engine::general_purpose::STANDARD.encode(key));
                key
            }
        };

        // Read file content
        let plaintext = match fs::read(source) {
            Ok(data) => data,
            Err(e) => {
                return ProtectResult {
                    original_path: source.to_string_lossy().to_string(),
                    protected_path: String::new(),
                    action: ProtectAction::Encrypted,
                    success: false,
                    message: format!("Failed to read file: {}", e),
                };
            }
        };

        // Create cipher
        let cipher = match Aes256Gcm::new_from_slice(&key) {
            Ok(c) => c,
            Err(e) => {
                return ProtectResult {
                    original_path: source.to_string_lossy().to_string(),
                    protected_path: String::new(),
                    action: ProtectAction::Encrypted,
                    success: false,
                    message: format!("Failed to create cipher: {}", e),
                };
            }
        };

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = match cipher.encrypt(nonce, plaintext.as_ref()) {
            Ok(ct) => ct,
            Err(e) => {
                return ProtectResult {
                    original_path: source.to_string_lossy().to_string(),
                    protected_path: String::new(),
                    action: ProtectAction::Encrypted,
                    success: false,
                    message: format!("Encryption failed: {}", e),
                };
            }
        };

        // Prepend nonce to ciphertext
        let mut encrypted_data = Vec::with_capacity(12 + ciphertext.len());
        encrypted_data.extend_from_slice(&nonce_bytes);
        encrypted_data.extend_from_slice(&ciphertext);

        // Write encrypted file with .enc extension
        let enc_file_name = format!("{}.enc", file_name);
        let dest_path = self.secure_dir.join(&enc_file_name);
        let dest_path = self.get_unique_path(&dest_path);

        match fs::write(&dest_path, &encrypted_data) {
            Ok(_) => {
                // Remove original
                let _ = fs::remove_file(source);
                
                ProtectResult {
                    original_path: source.to_string_lossy().to_string(),
                    protected_path: dest_path.to_string_lossy().to_string(),
                    action: ProtectAction::Encrypted,
                    success: true,
                    message: "File encrypted and moved to secure directory".to_string(),
                }
            }
            Err(e) => ProtectResult {
                original_path: source.to_string_lossy().to_string(),
                protected_path: String::new(),
                action: ProtectAction::Encrypted,
                success: false,
                message: format!("Failed to write encrypted file: {}", e),
            },
        }
    }

    /// Get unique path by appending number if file exists
    fn get_unique_path(&self, path: &Path) -> PathBuf {
        if !path.exists() {
            return path.to_path_buf();
        }

        let stem = path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("file");
        let ext = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        
        let mut counter = 1;
        loop {
            let new_name = if ext.is_empty() {
                format!("{}_{}", stem, counter)
            } else {
                format!("{}_{}.{}", stem, counter, ext)
            };
            let new_path = path.with_file_name(&new_name);
            if !new_path.exists() {
                return new_path;
            }
            counter += 1;
        }
    }

    /// Scan and protect all sensitive files in a directory
    pub fn protect_directory(
        &self,
        dir_path: &Path,
        action: &ProtectOption,
        key: Option<&[u8; 32]>,
    ) -> Vec<ProtectResult> {
        let mut results = Vec::new();
        
        if !dir_path.exists() || !dir_path.is_dir() {
            results.push(ProtectResult {
                original_path: dir_path.to_string_lossy().to_string(),
                protected_path: String::new(),
                action: ProtectAction::Secured,
                success: false,
                message: "Invalid directory path".to_string(),
            });
            return results;
        }

        self.scan_and_protect_recursive(dir_path, action, key, &mut results);
        results
    }

    fn scan_and_protect_recursive(
        &self,
        dir_path: &Path,
        action: &ProtectOption,
        key: Option<&[u8; 32]>,
        results: &mut Vec<ProtectResult>,
    ) {
        let skip_dirs = [".git", "node_modules", "target", "dist", "build", "vendor", "enveil_secure"];

        if let Ok(entries) = fs::read_dir(dir_path) {
            for entry in entries.flatten() {
                let path = entry.path();

                if path.is_dir() {
                    let dir_name = path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");
                    
                    if !dir_name.starts_with('.') && !skip_dirs.contains(&dir_name) {
                        self.scan_and_protect_recursive(&path, action, key, results);
                    }
                } else if path.is_file() && SensitiveFiles::is_sensitive(&path) {
                    // Skip if already in secure directory
                    if path.parent().map(|p| p == self.secure_dir).unwrap_or(false) {
                        continue;
                    }
                    
                    let result = self.protect_file(&path, action, key);
                    results.push(result);
                }
            }
        }
    }
}

/// Protection options
#[derive(Debug, Clone, PartialEq)]
pub enum ProtectOption {
    Move,
    Encrypt,
    Both,
}

impl ProtectOption {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "move" => ProtectOption::Move,
            "encrypt" => ProtectOption::Encrypt,
            "both" => ProtectOption::Both,
            _ => ProtectOption::Move, // Default
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_is_sensitive_env() {
        let path = Path::new("/project/.env");
        assert!(SensitiveFiles::is_sensitive(path));
    }

    #[test]
    fn test_is_sensitive_json() {
        let path = Path::new("/project/credentials.json");
        assert!(SensitiveFiles::is_sensitive(path));
    }

    #[test]
    fn test_is_sensitive_rsa_key() {
        let path = Path::new("/project/id_rsa");
        assert!(SensitiveFiles::is_sensitive(path));
    }

    #[test]
    fn test_is_not_sensitive() {
        let path = Path::new("/project/readme.txt");
        assert!(!SensitiveFiles::is_sensitive(path));
    }
}
