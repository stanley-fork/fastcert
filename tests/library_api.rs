//! Integration tests for the library API

mod common;

use common::get_test_lock;
use fastcert::{CA, KeyType, Result};
use std::env;
use std::fs;
use tempfile::TempDir;

/// Test 1: Test CA::load_or_create() in a temp directory
#[test]
fn test_ca_load_or_create() -> Result<()> {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();

    unsafe {
        env::set_var("CAROOT", temp_dir.path());
    }

    let ca = CA::load_or_create()?;

    // Verify CA files were created
    assert!(ca.cert_path().exists(), "CA certificate should exist");
    assert!(ca.key_path().exists(), "CA key should exist");

    // Verify the paths are in the temp directory
    assert!(ca.cert_path().starts_with(temp_dir.path()));
    assert!(ca.key_path().starts_with(temp_dir.path()));

    unsafe {
        env::remove_var("CAROOT");
    }
    Ok(())
}

/// Test 2: Test CA with custom location
#[test]
fn test_ca_custom_location() -> Result<()> {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();
    let ca_path = temp_dir.path().join("custom-ca");

    let mut ca = CA::new(ca_path.clone());
    ca.init_ca()?;

    // Verify CA was created in the custom location
    assert!(ca.cert_path().exists(), "CA certificate should exist");
    assert_eq!(
        ca.root_path(),
        ca_path.as_path(),
        "Root path should match custom path"
    );

    // Verify files are in the custom directory
    assert!(ca.cert_path().starts_with(&ca_path));
    assert!(ca.key_path().starts_with(&ca_path));

    Ok(())
}

/// Test 3: Test basic certificate generation with the builder
#[test]
fn test_issue_certificate_basic() -> Result<()> {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    unsafe {
        env::set_var("CAROOT", temp_dir.path());
    }

    let ca = CA::load_or_create()?;

    let cert_file = output_dir.path().join("test.pem");
    let key_file = output_dir.path().join("test-key.pem");

    ca.issue_certificate()?
        .domains(vec!["example.com".to_string()])
        .cert_file(cert_file.to_str().unwrap())
        .key_file(key_file.to_str().unwrap())
        .build()?;

    // Verify certificate and key files were created
    assert!(cert_file.exists(), "Certificate file should exist");
    assert!(key_file.exists(), "Key file should exist");

    // Verify files contain PEM-formatted data
    let cert_content = fs::read_to_string(&cert_file)?;
    let key_content = fs::read_to_string(&key_file)?;

    assert!(
        cert_content.contains("BEGIN CERTIFICATE"),
        "Cert should be in PEM format"
    );
    assert!(
        key_content.contains("PRIVATE KEY"),
        "Key should be in PEM format"
    );

    unsafe {
        env::remove_var("CAROOT");
    }
    Ok(())
}

/// Test 4: Test ECDSA key type
#[test]
fn test_issue_certificate_with_ecdsa() -> Result<()> {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    unsafe {
        env::set_var("CAROOT", temp_dir.path());
    }

    let ca = CA::load_or_create()?;

    let cert_file = output_dir.path().join("ecdsa.pem");
    let key_file = output_dir.path().join("ecdsa-key.pem");

    ca.issue_certificate()?
        .domains(vec!["example.com".to_string()])
        .key_type(KeyType::ECDSA)
        .cert_file(cert_file.to_str().unwrap())
        .key_file(key_file.to_str().unwrap())
        .build()?;

    // Verify certificate and key files were created
    assert!(cert_file.exists(), "ECDSA certificate file should exist");
    assert!(key_file.exists(), "ECDSA key file should exist");

    // Verify the key is EC (ECDSA)
    let key_content = fs::read_to_string(&key_file)?;
    assert!(
        key_content.contains("EC PRIVATE KEY") || key_content.contains("PRIVATE KEY"),
        "Key should be an EC private key"
    );

    unsafe {
        env::remove_var("CAROOT");
    }
    Ok(())
}

/// Test 5: Test client certificates
#[test]
fn test_issue_certificate_client_cert() -> Result<()> {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    unsafe {
        env::set_var("CAROOT", temp_dir.path());
    }

    let ca = CA::load_or_create()?;

    let cert_file = output_dir.path().join("client.pem");
    let key_file = output_dir.path().join("client-key.pem");

    ca.issue_certificate()?
        .domains(vec!["user@example.com".to_string()])
        .client_cert(true)
        .cert_file(cert_file.to_str().unwrap())
        .key_file(key_file.to_str().unwrap())
        .build()?;

    // Verify certificate and key files were created
    assert!(cert_file.exists(), "Client certificate file should exist");
    assert!(key_file.exists(), "Client key file should exist");

    // Verify files contain valid PEM data
    let cert_content = fs::read_to_string(&cert_file)?;
    assert!(
        cert_content.contains("BEGIN CERTIFICATE"),
        "Client cert should be in PEM format"
    );

    unsafe {
        env::remove_var("CAROOT");
    }
    Ok(())
}

/// Test 6: Test error when no domains specified
#[test]
fn test_issue_certificate_no_domains_error() {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();

    unsafe {
        env::set_var("CAROOT", temp_dir.path());
    }

    let ca = CA::load_or_create().unwrap();

    // Try to build without specifying domains
    let result = ca.issue_certificate().unwrap().build();

    // Should return an error
    assert!(
        result.is_err(),
        "Building without domains should return an error"
    );

    // Error message should mention domains
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("No domains") || error_msg.contains("domains"),
        "Error message should mention domains, got: {}",
        error_msg
    );

    unsafe {
        env::remove_var("CAROOT");
    }
}

/// Test 7: Test the convenience generate_cert() function
#[test]
fn test_convenience_generate_cert() -> Result<()> {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    unsafe {
        env::set_var("CAROOT", temp_dir.path());
    }

    // Change to output directory to avoid polluting current directory
    let original_dir = env::current_dir()?;
    env::set_current_dir(&output_dir)?;

    // Generate certificate using convenience function
    let result = fastcert::generate_cert(&["example.com".to_string()]);

    // Restore original directory
    env::set_current_dir(original_dir)?;

    unsafe {
        env::remove_var("CAROOT");
    }

    // Clean up auto-generated files
    let _ = fs::remove_file(output_dir.path().join("example.com.pem"));
    let _ = fs::remove_file(output_dir.path().join("example.com-key.pem"));

    // Should succeed
    result
}

/// Test 8: Test certificate generation with multiple domains
#[test]
fn test_issue_certificate_multiple_domains() -> Result<()> {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    unsafe {
        env::set_var("CAROOT", temp_dir.path());
    }

    let ca = CA::load_or_create()?;

    let cert_file = output_dir.path().join("multi.pem");
    let key_file = output_dir.path().join("multi-key.pem");

    ca.issue_certificate()?
        .domains(vec![
            "example.com".to_string(),
            "*.example.com".to_string(),
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])
        .cert_file(cert_file.to_str().unwrap())
        .key_file(key_file.to_str().unwrap())
        .build()?;

    // Verify certificate was created
    assert!(cert_file.exists(), "Multi-domain certificate should exist");
    assert!(key_file.exists(), "Multi-domain key should exist");

    unsafe {
        env::remove_var("CAROOT");
    }
    Ok(())
}

/// Test 9: Test RSA2048 key type explicitly
#[test]
fn test_issue_certificate_with_rsa() -> Result<()> {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    unsafe {
        env::set_var("CAROOT", temp_dir.path());
    }

    let ca = CA::load_or_create()?;

    let cert_file = output_dir.path().join("rsa.pem");
    let key_file = output_dir.path().join("rsa-key.pem");

    ca.issue_certificate()?
        .domains(vec!["example.com".to_string()])
        .key_type(KeyType::RSA2048)
        .cert_file(cert_file.to_str().unwrap())
        .key_file(key_file.to_str().unwrap())
        .build()?;

    // Verify certificate and key files were created
    assert!(cert_file.exists(), "RSA certificate file should exist");
    assert!(key_file.exists(), "RSA key file should exist");

    // Verify the key is RSA
    let key_content = fs::read_to_string(&key_file)?;
    assert!(
        key_content.contains("RSA PRIVATE KEY") || key_content.contains("PRIVATE KEY"),
        "Key should be an RSA private key"
    );

    unsafe {
        env::remove_var("CAROOT");
    }
    Ok(())
}
