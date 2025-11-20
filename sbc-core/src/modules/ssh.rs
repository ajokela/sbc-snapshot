use crate::types::{Finding, Severity};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// SSH Configuration Analyzer
///
/// Analyzes /etc/ssh/sshd_config for security issues
pub struct SshAnalyzer {
    config_path: String,
}

impl SshAnalyzer {
    pub fn new() -> Self {
        Self {
            config_path: "/etc/ssh/sshd_config".to_string(),
        }
    }

    pub fn with_config_path(mut self, path: impl Into<String>) -> Self {
        self.config_path = path.into();
        self
    }

    /// Parse SSH config file into key-value pairs
    fn parse_config(&self) -> Result<HashMap<String, String>> {
        let content = fs::read_to_string(&self.config_path)
            .context("Failed to read SSH config file")?;

        let mut config = HashMap::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse key-value pairs
            if let Some((key, value)) = line.split_once(char::is_whitespace) {
                let key = key.trim().to_lowercase();
                let value = value.trim().to_string();
                config.insert(key, value);
            }
        }

        Ok(config)
    }

    /// Get effective value for a config option (handles defaults)
    fn get_config_value<'a>(&self, config: &'a HashMap<String, String>, key: &str, default: &'a str) -> &'a str {
        config.get(key).map(|s| s.as_str()).unwrap_or(default)
    }

    pub fn analyze(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check if config file exists
        if !Path::new(&self.config_path).exists() {
            findings.push(
                Finding::new(
                    "ssh-001",
                    "ssh",
                    Severity::Medium,
                    "SSH configuration file not found"
                )
                .with_details(format!("Expected at: {}", self.config_path))
            );
            return Ok(findings);
        }

        let config = match self.parse_config() {
            Ok(c) => c,
            Err(e) => {
                findings.push(
                    Finding::new(
                        "ssh-002",
                        "ssh",
                        Severity::Medium,
                        "Failed to parse SSH configuration"
                    )
                    .with_details(format!("Error: {}", e))
                );
                return Ok(findings);
            }
        };

        // Check PermitRootLogin
        let permit_root_login = self.get_config_value(&config, "permitrootlogin", "prohibit-password");
        match permit_root_login.to_lowercase().as_str() {
            "yes" => {
                findings.push(
                    Finding::new(
                        "ssh-100",
                        "ssh",
                        Severity::High,
                        "Root login via SSH is permitted with password"
                    )
                    .with_details("PermitRootLogin is set to 'yes'")
                    .with_remediation("Set PermitRootLogin to 'prohibit-password' or 'no' in /etc/ssh/sshd_config")
                );
            }
            "prohibit-password" | "without-password" => {
                findings.push(
                    Finding::new(
                        "ssh-101",
                        "ssh",
                        Severity::Info,
                        "Root login via SSH requires public key authentication"
                    )
                    .with_details("PermitRootLogin is set to 'prohibit-password'")
                );
            }
            "no" => {
                findings.push(
                    Finding::new(
                        "ssh-102",
                        "ssh",
                        Severity::Info,
                        "Root login via SSH is disabled"
                    )
                );
            }
            _ => {}
        }

        // Check PasswordAuthentication
        let password_auth = self.get_config_value(&config, "passwordauthentication", "yes");
        if password_auth.to_lowercase() == "yes" {
            findings.push(
                Finding::new(
                    "ssh-110",
                    "ssh",
                    Severity::Medium,
                    "Password authentication is enabled"
                )
                .with_details("PasswordAuthentication is set to 'yes'")
                .with_remediation("Consider disabling password authentication and using public key authentication only")
            );
        } else {
            findings.push(
                Finding::new(
                    "ssh-111",
                    "ssh",
                    Severity::Info,
                    "Password authentication is disabled"
                )
            );
        }

        // Check PermitEmptyPasswords
        let permit_empty = self.get_config_value(&config, "permitemptypasswords", "no");
        if permit_empty.to_lowercase() == "yes" {
            findings.push(
                Finding::new(
                    "ssh-120",
                    "ssh",
                    Severity::Critical,
                    "Empty passwords are permitted"
                )
                .with_details("PermitEmptyPasswords is set to 'yes'")
                .with_remediation("Set PermitEmptyPasswords to 'no' immediately")
            );
        }

        // Check PubkeyAuthentication
        let pubkey_auth = self.get_config_value(&config, "pubkeyauthentication", "yes");
        if pubkey_auth.to_lowercase() != "yes" {
            findings.push(
                Finding::new(
                    "ssh-130",
                    "ssh",
                    Severity::Medium,
                    "Public key authentication is disabled"
                )
                .with_details("PubkeyAuthentication is not enabled")
                .with_remediation("Enable PubkeyAuthentication for better security")
            );
        }

        // Check X11Forwarding
        let x11_forwarding = self.get_config_value(&config, "x11forwarding", "no");
        if x11_forwarding.to_lowercase() == "yes" {
            findings.push(
                Finding::new(
                    "ssh-140",
                    "ssh",
                    Severity::Low,
                    "X11 forwarding is enabled"
                )
                .with_details("X11Forwarding is set to 'yes'")
                .with_remediation("Disable X11Forwarding unless specifically needed")
            );
        }

        // Check Port
        if let Some(port) = config.get("port") {
            if port != "22" {
                findings.push(
                    Finding::new(
                        "ssh-150",
                        "ssh",
                        Severity::Info,
                        format!("SSH is running on non-standard port {}", port)
                    )
                    .with_details("Security through obscurity - may help reduce automated attacks")
                );
            }
        }

        // Check for weak ciphers and MACs (simplified check)
        if let Some(ciphers) = config.get("ciphers") {
            if ciphers.contains("3des") || ciphers.contains("arcfour") || ciphers.contains("blowfish") {
                findings.push(
                    Finding::new(
                        "ssh-160",
                        "ssh",
                        Severity::High,
                        "Weak ciphers are enabled"
                    )
                    .with_details(format!("Ciphers: {}", ciphers))
                    .with_remediation("Remove weak ciphers (3des, arcfour, blowfish) from the Ciphers directive")
                );
            }
        }

        Ok(findings)
    }
}

impl Default for SshAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl super::Analyzer for SshAnalyzer {
    fn analyze(&self) -> Result<Vec<Finding>> {
        self.analyze()
    }

    fn category(&self) -> &'static str {
        "ssh"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        // This would need a mock config file for proper testing
        // Just checking the struct can be created
        let analyzer = SshAnalyzer::new();
        assert_eq!(analyzer.config_path, "/etc/ssh/sshd_config");
    }
}
