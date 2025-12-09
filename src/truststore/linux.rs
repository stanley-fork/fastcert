//! Linux trust store

use crate::{Error, Result};
use super::TrustStore;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Supported Linux distributions
#[derive(Debug, Clone, Copy, PartialEq)]
enum LinuxDistro {
    /// RHEL, Fedora, CentOS - uses update-ca-trust
    RedHat,
    /// Debian, Ubuntu - uses update-ca-certificates
    Debian,
    /// Arch Linux - uses trust command
    Arch,
    /// OpenSUSE - uses update-ca-certificates
    OpenSUSE,
    /// Unknown distribution
    Unknown,
}

impl LinuxDistro {
    /// Detect the Linux distribution by checking for existence of update commands
    fn detect() -> Self {
        // Check for RHEL/Fedora/CentOS (update-ca-trust)
        if Path::new("/etc/pki/ca-trust/source/anchors/").exists() {
            return Self::RedHat;
        }

        // Check for Debian/Ubuntu (update-ca-certificates)
        if Path::new("/usr/local/share/ca-certificates/").exists() {
            return Self::Debian;
        }

        // Check for Arch Linux (trust extract-compat)
        if Path::new("/etc/ca-certificates/trust-source/anchors/").exists() {
            return Self::Arch;
        }

        // Check for OpenSUSE (update-ca-certificates)
        if Path::new("/usr/share/pki/trust/anchors").exists() {
            return Self::OpenSUSE;
        }

        Self::Unknown
    }

    /// Get the certificate directory path for this distribution
    fn cert_dir(&self) -> Option<&'static str> {
        match self {
            Self::RedHat => Some("/etc/pki/ca-trust/source/anchors/"),
            Self::Debian => Some("/usr/local/share/ca-certificates/"),
            Self::Arch => Some("/etc/ca-certificates/trust-source/anchors/"),
            Self::OpenSUSE => Some("/usr/share/pki/trust/anchors/"),
            Self::Unknown => None,
        }
    }

    /// Get the certificate file extension for this distribution
    fn cert_extension(&self) -> &'static str {
        match self {
            Self::RedHat | Self::OpenSUSE => "pem",
            Self::Debian | Self::Arch => "crt",
            Self::Unknown => "pem",
        }
    }

    /// Get the certificate file path for a given name
    fn cert_path(&self, cert_name: &str) -> Option<PathBuf> {
        let dir = self.cert_dir()?;
        let ext = self.cert_extension();
        Some(PathBuf::from(format!("{}{}.{}", dir, cert_name, ext)))
    }

    /// Get the update command for this distribution
    fn update_command(&self) -> Option<Vec<&'static str>> {
        match self {
            Self::RedHat => Some(vec!["update-ca-trust", "extract"]),
            Self::Debian | Self::OpenSUSE => Some(vec!["update-ca-certificates"]),
            Self::Arch => Some(vec!["trust", "extract-compat"]),
            Self::Unknown => None,
        }
    }
}

pub struct LinuxTrustStore {
    cert_path: PathBuf,
    distro: LinuxDistro,
}

impl LinuxTrustStore {
    pub fn new(cert_path: &Path) -> Self {
        Self {
            cert_path: cert_path.to_path_buf(),
            distro: LinuxDistro::detect(),
        }
    }

    /// Get the system trust store path for the certificate
    fn system_cert_path(&self) -> Option<PathBuf> {
        self.distro.cert_path("rscert-rootCA")
    }
}

impl TrustStore for LinuxTrustStore {
    fn check(&self) -> Result<bool> {
        // Check if the distribution is supported
        if self.distro == LinuxDistro::Unknown {
            return Ok(false);
        }

        // Check if the certificate file exists in the system trust store
        if let Some(sys_path) = self.system_cert_path() {
            Ok(sys_path.exists())
        } else {
            Ok(false)
        }
    }

    fn install(&self) -> Result<()> {
        Ok(())
    }

    fn uninstall(&self) -> Result<()> {
        Ok(())
    }
}
