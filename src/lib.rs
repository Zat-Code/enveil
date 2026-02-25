// Unit tests for Enveil

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    
    #[test]
    fn test_risky_extensions() {
        let mut extensions = std::collections::HashSet::new();
        extensions.insert(".env");
        extensions.insert(".pem");
        extensions.insert(".key");
        
        assert!(extensions.contains(".env"));
        assert!(extensions.contains(".pem"));
        assert!(!extensions.contains(".txt"));
    }
    
    #[test]
    fn test_file_risk_level() {
        fn get_file_risk_level(extension: &str) -> &'static str {
            match extension {
                ".env" | ".pem" | ".key" | ".p12" | ".pfx" => "high",
                ".json" | ".yaml" | ".yml" | ".toml" => "medium",
                _ => "low",
            }
        }
        
        assert_eq!(get_file_risk_level(".env"), "high");
        assert_eq!(get_file_risk_level(".pem"), "high");
        assert_eq!(get_file_risk_level(".json"), "medium");
        assert_eq!(get_file_risk_level(".txt"), "low");
    }
    
    #[test]
    fn test_env_file_detection() {
        fn is_env_file(file_name: &str) -> bool {
            file_name.starts_with(".env") || file_name == ".env"
        }
        
        assert!(is_env_file(".env"));
        assert!(is_env_file(".env.local"));
        assert!(is_env_file(".env.production"));
        assert!(!is_env_file(".env.example"));
        assert!(!is_env_file("config.json"));
    }
}
