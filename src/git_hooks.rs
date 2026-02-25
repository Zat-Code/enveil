use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Git hooks manager for Enveil
pub struct GitHooks {
    project_path: PathBuf,
    hooks_dir: PathBuf,
}

impl GitHooks {
    pub fn new<P: AsRef<Path>>(project_path: P) -> Self {
        let project_path = project_path.as_ref().to_path_buf();
        let hooks_dir = project_path.join(".git").join("hooks");
        
        Self {
            project_path,
            hooks_dir,
        }
    }
    
    /// Install git hooks for the project
    pub fn install(&self, force: bool) -> Result<(), String> {
        // Check if .git directory exists
        if !self.project_path.join(".git").exists() {
            return Err("Not a git repository. Initialize with 'git init' first.".to_string());
        }
        
        // Create hooks directory if it doesn't exist
        if !self.hooks_dir.exists() {
            fs::create_dir_all(&self.hooks_dir)
                .map_err(|e| format!("Failed to create hooks directory: {}", e))?;
        }
        
        // Create pre-commit hook
        self.create_pre_commit_hook(force)?;
        
        // Create pre-push hook
        self.create_pre_push_hook(force)?;
        
        println!("✅ Git hooks installed successfully!");
        println!("   - Pre-commit hook: {}", self.hooks_dir.join("pre-commit").display());
        println!("   - Pre-push hook: {}", self.hooks_dir.join("pre-push").display());
        
        Ok(())
    }
    
    /// Uninstall git hooks
    pub fn uninstall(&self) -> Result<(), String> {
        let pre_commit = self.hooks_dir.join("pre-commit");
        let pre_push = self.hooks_dir.join("pre-push");
        
        let mut removed = 0;
        
        if pre_commit.exists() {
            if let Some(content) = fs::read_to_string(&pre_commit).ok() {
                if content.contains("enveil") {
                    fs::remove_file(&pre_commit)
                        .map_err(|e| format!("Failed to remove pre-commit: {}", e))?;
                    removed += 1;
                }
            }
        }
        
        if pre_push.exists() {
            if let Some(content) = fs::read_to_string(&pre_push).ok() {
                if content.contains("enveil") {
                    fs::remove_file(&pre_push)
                        .map_err(|e| format!("Failed to remove pre-push: {}", e))?;
                    removed += 1;
                }
            }
        }
        
        if removed > 0 {
            println!("✅ Removed {} hook(s)", removed);
        } else {
            println!("ℹ️  No Enveil hooks found to remove");
        }
        
        Ok(())
    }
    
    /// Check if hooks are installed
    pub fn is_installed(&self) -> bool {
        let pre_commit = self.hooks_dir.join("pre-commit");
        let pre_push = self.hooks_dir.join("pre-push");
        
        let pre_commit_ok = pre_commit.exists() && 
            fs::read_to_string(&pre_commit).map(|c| c.contains("enveil")).unwrap_or(false);
        let pre_push_ok = pre_push.exists() && 
            fs::read_to_string(&pre_push).map(|c| c.contains("enveil")).unwrap_or(false);
        
        pre_commit_ok || pre_push_ok
    }
    
    /// Create pre-commit hook
    fn create_pre_commit_hook(&self, force: bool) -> Result<(), String> {
        let hook_path = self.hooks_dir.join("pre-commit");
        
        // Check if hook already exists
        if hook_path.exists() && !force {
            let content = fs::read_to_string(&hook_path)
                .map_err(|e| format!("Failed to read hook: {}", e))?;
            
            if content.contains("enveil") {
                println!("ℹ️  Pre-commit hook already installed");
                return Ok(());
            }
            
            return Err("Pre-commit hook already exists. Use --force to overwrite.".to_string());
        }
        
        let hook_content = self.generate_pre_commit_hook();
        
        fs::write(&hook_path, hook_content)
            .map_err(|e| format!("Failed to write hook: {}", e))?;
        
        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&hook_path)
                .map_err(|e| format!("Failed to get permissions: {}", e))?
                .permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&hook_path, perms)
                .map_err(|e| format!("Failed to set permissions: {}", e))?;
        }
        
        Ok(())
    }
    
    /// Create pre-push hook
    fn create_pre_push_hook(&self, force: bool) -> Result<(), String> {
        let hook_path = self.hooks_dir.join("pre-push");
        
        // Check if hook already exists
        if hook_path.exists() && !force {
            let content = fs::read_to_string(&hook_path)
                .map_err(|e| format!("Failed to read hook: {}", e))?;
            
            if content.contains("enveil") {
                println!("ℹ️  Pre-push hook already installed");
                return Ok(());
            }
            
            return Err("Pre-push hook already exists. Use --force to overwrite.".to_string());
        }
        
        let hook_content = self.generate_pre_push_hook();
        
        fs::write(&hook_path, hook_content)
            .map_err(|e| format!("Failed to write hook: {}", e))?;
        
        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&hook_path)
                .map_err(|e| format!("Failed to get permissions: {}", e))?
                .permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&hook_path, perms)
                .map_err(|e| format!("Failed to set permissions: {}", e))?;
        }
        
        Ok(())
    }
    
    /// Generate pre-commit hook script
    fn generate_pre_commit_hook(&self) -> String {
        let project_path = self.project_path.display().to_string();
        
        format!(r#"#!/bin/bash
# Enveil pre-commit hook
# Scans staged files for secrets before commit

# Check if enfveil binary exists
if ! command -v enfveil &> /dev/null; then
    # Try to find it in common locations
    if [ -f "./target/release/enveil" ]; then
        ENVEIL="./target/release/enveil"
    elif [ -f "./target/debug/enveil" ]; then
        ENVEIL="./target/debug/enveil"
    else
        echo "⚠️  Enveil not found. Skipping secret scan."
        exit 0
    fi
else
    ENVEIL="enveil"
fi

# Check for --force flag
for arg in "$@"; do
    if [ "$arg" = "--force" ] || [ "$arg" = "-n" ]; then
        echo "ℹ️  Skipping Enveil scan (--force or dry-run detected)"
        exit 0
    fi
done

# Get staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
    echo "ℹ️  No staged files to scan"
    exit 0
fi

echo "🔍 Scanning staged files for secrets..."

# Create temp file for scanning
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Copy staged files to temp directory
echo "$STAGED_FILES" | while read file; do
    if [ -f "$file" ]; then
        mkdir -p "$(dirname "$TEMP_DIR/$file")"
        git show ":$file" > "$TEMP_DIR/$file" 2>/dev/null
    fi
done

# Scan for secrets
SCAN_RESULT=$("$ENVEIL" scan "$TEMP_DIR" 2>&1)
SCAN_EXIT=$?

if [ $SCAN_EXIT -ne 0 ]; then
    echo "❌ Error running Enveil scan"
    echo "$SCAN_RESULT"
    exit 1
fi

# Check if secrets were found
if echo "$SCAN_RESULT" | grep -q "secrets found"; then
    COUNT=$(echo "$SCAN_RESULT" | grep -oP '\d+(?= secrets found)' || echo "0")
    if [ "$COUNT" -gt 0 ]; then
        echo "❌ ABORTING COMMIT: $COUNT secret(s) detected in staged files!"
        echo ""
        echo "$SCAN_RESULT"
        echo ""
        echo "To commit anyway, use: git commit --no-verify"
        echo "Or fix the secrets and commit again"
        exit 1
    fi
fi

echo "✅ No secrets detected in staged files"
exit 0
"#
        )
    }
    
    /// Generate pre-push hook script
    fn generate_pre_push_hook(&self) -> String {
        let project_path = self.project_path.display().to_string();
        
        format!(r#"#!/bin/bash
# Enveil pre-push hook
# Scans all files for secrets before push

# Get remote and URL
REMOTE="$1"
URL="$2"

# Check if enfveil binary exists
if ! command -v enfveil &> /dev/null; then
    # Try to find it in common locations
    if [ -f "./target/release/enveil" ]; then
        ENVEIL="./target/release/enveil"
    elif [ -f "./target/debug/enveil" ]; then
        ENVEIL="./target/debug/enveil"
    else
        echo "⚠️  Enveil not found. Skipping secret scan."
        exit 0
    fi
else
    ENVEIL="enveil"
fi

# Check for --force flag
for arg in "$@"; do
    if [ "$arg" = "--force" ]; then
        echo "ℹ️  Skipping Enveil scan (--force detected)"
        exit 0
    fi
done

echo "🔍 Scanning entire project for secrets..."

# Scan for secrets
SCAN_RESULT=$("$ENVEIL" scan . 2>&1)
SCAN_EXIT=$?

if [ $SCAN_EXIT -ne 0 ]; then
    echo "❌ Error running Enveil scan"
    echo "$SCAN_RESULT"
    exit 1
fi

# Check if secrets were found
if echo "$SCAN_RESULT" | grep -q "secrets found"; then
    COUNT=$(echo "$SCAN_RESULT" | grep -oP '\d+(?= secrets found)' || echo "0")
    if [ "$COUNT" -gt 0 ]; then
        echo "❌ ABORTING PUSH: $COUNT secret(s) detected in project!"
        echo ""
        echo "$SCAN_RESULT"
        echo ""
        echo "To push anyway, use: git push --no-verify"
        echo "Or fix the secrets and push again"
        exit 1
    fi
fi

echo "✅ No secrets detected in project"
exit 0
"#
        )
    }
}

/// Check if current directory is a git repository
pub fn is_git_repo() -> bool {
    Path::new(".git").exists()
}

/// Run git hook manually (for testing)
pub fn run_hook(hook_type: &str, force: bool) -> Result<(), String> {
    if !is_git_repo() {
        return Err("Not a git repository".to_string());
    }
    
    let hooks = GitHooks::new(".");
    
    match hook_type {
        "install" => hooks.install(force),
        "uninstall" => hooks.uninstall(),
        "status" => {
            if hooks.is_installed() {
                println!("✅ Git hooks are installed");
            } else {
                println!("ℹ️  Git hooks are not installed");
            }
            Ok(())
        }
        _ => Err(format!("Unknown hook command: {}", hook_type)),
    }
}
