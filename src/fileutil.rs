//! File and path utilities

use crate::{Error, Result};
use std::path::PathBuf;

/// Get the CAROOT directory path
pub fn get_ca_root() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("CAROOT") {
        return Ok(PathBuf::from(path));
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            return Ok(home.join("Library/Application Support/fastcert"));
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(local_app_data) = dirs::data_local_dir() {
            return Ok(local_app_data.join("fastcert"));
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            return Ok(PathBuf::from(xdg).join("fastcert"));
        }
        if let Some(home) = dirs::home_dir() {
            return Ok(home.join(".local/share/fastcert"));
        }
    }

    Err(Error::CARootNotFound)
}

/// Get the name of the current binary executable
pub fn get_binary_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "rscert".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_ca_root() {
        let result = get_ca_root();
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_binary_name() {
        let name = get_binary_name();
        assert!(!name.is_empty());
        assert!(name == "rscert" || name.contains("rscert"));
    }
}
