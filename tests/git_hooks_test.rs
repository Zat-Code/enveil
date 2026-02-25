// Unit tests for Git hooks module

#[cfg(test)]
mod git_hooks_tests {
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;
    
    #[test]
    fn test_is_git_repo() {
        let temp_dir = TempDir::new().unwrap();
        // Create a git repo
        std::process::Command::new("git")
            .args(&["init"])
            .current_dir(temp_dir.path())
            .output()
            .expect("Failed to init git");
        
        // Check that we can detect a git repo
        let git_dir = temp_dir.path().join(".git");
        assert!(git_dir.exists());
    }
}
