//! Java keystore

use crate::{Error, Result};
use super::TrustStore;
use std::path::{Path, PathBuf};
use std::env;

pub struct JavaTrustStore {
    cert_path: PathBuf,
    unique_name: String,
}

impl JavaTrustStore {
    pub fn new(cert_path: &Path, unique_name: String) -> Self {
        Self {
            cert_path: cert_path.to_path_buf(),
            unique_name,
        }
    }

    /// Detect JAVA_HOME and related paths
    fn detect_java() -> Option<JavaConfig> {
        let java_home = env::var("JAVA_HOME").ok()?;
        let java_home_path = PathBuf::from(&java_home);

        if !java_home_path.exists() {
            return None;
        }

        // Determine keytool path
        #[cfg(target_os = "windows")]
        let keytool_name = "keytool.exe";
        #[cfg(not(target_os = "windows"))]
        let keytool_name = "keytool";

        let keytool_path = java_home_path.join("bin").join(keytool_name);
        if !keytool_path.exists() {
            return None;
        }

        // Determine cacerts path
        // Try modern Java location first (lib/security/cacerts)
        let mut cacerts_path = java_home_path.join("lib/security/cacerts");
        if !cacerts_path.exists() {
            // Try older Java location (jre/lib/security/cacerts)
            cacerts_path = java_home_path.join("jre/lib/security/cacerts");
            if !cacerts_path.exists() {
                return None;
            }
        }

        Some(JavaConfig {
            java_home: java_home_path,
            keytool_path,
            cacerts_path,
        })
    }

    /// Check if Java is available
    pub fn is_available() -> bool {
        Self::detect_java().is_some()
    }

    /// Check if keytool is available
    pub fn has_keytool() -> bool {
        Self::detect_java()
            .map(|cfg| cfg.keytool_path.exists())
            .unwrap_or(false)
    }
}

#[derive(Debug)]
struct JavaConfig {
    java_home: PathBuf,
    keytool_path: PathBuf,
    cacerts_path: PathBuf,
}

impl TrustStore for JavaTrustStore {
    fn check(&self) -> Result<bool> {
        Ok(false)
    }

    fn install(&self) -> Result<()> {
        Ok(())
    }

    fn uninstall(&self) -> Result<()> {
        Ok(())
    }
}
