// Integration tests for Enveil CLI

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

#[test]
fn test_scan_no_files() {
    let temp_dir = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("enveil").unwrap();
    cmd.arg("scan")
        .arg(temp_dir.path())
        .assert()
        .success();
}

#[test]
fn test_scan_with_env_file() {
    let temp_dir = TempDir::new().unwrap();
    let env_file = temp_dir.path().join(".env");
    fs::write(&env_file, "API_KEY=secret123\n").unwrap();
    
    let mut cmd = Command::cargo_bin("enveil").unwrap();
    cmd.arg("scan")
        .arg(temp_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains(".env"));
}

#[test]
fn test_scan_verbose() {
    let temp_dir = TempDir::new().unwrap();
    let env_file = temp_dir.path().join(".env");
    fs::write(&env_file, "DATABASE_URL=postgres://localhost\n").unwrap();
    
    let mut cmd = Command::cargo_bin("enveil").unwrap();
    cmd.arg("scan")
        .arg(temp_dir.path())
        .arg("--verbose")
        .assert()
        .success();
}

#[test]
fn test_scan_json_format() {
    let temp_dir = TempDir::new().unwrap();
    let env_file = temp_dir.path().join(".env");
    fs::write(&env_file, "SECRET=abc123\n").unwrap();
    
    let mut cmd = Command::cargo_bin("enveil").unwrap();
    cmd.arg("scan")
        .arg(temp_dir.path())
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"total_files\""));
}

#[test]
fn test_install_not_a_repo() {
    let temp_dir = TempDir::new().unwrap();
    
    let mut cmd = Command::cargo_bin("enveil").unwrap();
    cmd.arg("install")
        .arg(temp_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("Not a git repository"));
}

#[test]
fn test_protect_command() {
    let temp_dir = TempDir::new().unwrap();
    let env_file = temp_dir.path().join(".env");
    fs::write(&env_file, "MY_SECRET=password123\n").unwrap();
    
    let mut cmd = Command::cargo_bin("enveil").unwrap();
    cmd.arg("protect")
        .arg(temp_dir.path())
        .arg("--dry-run")
        .assert()
        .success();
}
