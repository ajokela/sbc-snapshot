use crate::types::{Finding, Severity};
use anyhow::Result;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Filesystem Security Analyzer
///
/// Checks file permissions, SSH keys, and world-writable files
pub struct FilesystemAnalyzer;

impl FilesystemAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Check SSH host keys
    fn check_ssh_host_keys(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let ssh_dir = Path::new("/etc/ssh");

        if !ssh_dir.exists() {
            return Ok(findings);
        }

        let key_types = [
            ("ssh_host_rsa_key", "RSA"),
            ("ssh_host_ecdsa_key", "ECDSA"),
            ("ssh_host_ed25519_key", "Ed25519"),
        ];

        for (filename, key_type) in &key_types {
            let key_path = ssh_dir.join(filename);

            if key_path.exists() {
                // Check permissions
                if let Ok(metadata) = fs::metadata(&key_path) {
                    let mode = metadata.permissions().mode();

                    // Private key should be 0600 or 0400
                    if mode & 0o077 != 0 {
                        findings.push(
                            Finding::new(
                                format!("filesystem-100-{}", filename),
                                "filesystem",
                                Severity::Critical,
                                format!("SSH host key {} has overly permissive permissions", filename)
                            )
                            .with_details(format!("Permissions: {:o} (should be 0600)", mode & 0o777))
                            .with_remediation(format!("Run: sudo chmod 600 /etc/ssh/{}", filename))
                        );
                    }
                }

                // Check key age and algorithm (informational)
                findings.push(
                    Finding::new(
                        format!("filesystem-101-{}", filename),
                        "filesystem",
                        Severity::Info,
                        format!("{} SSH host key present", key_type)
                    )
                );
            }
        }

        // Check for weak DSA keys (deprecated)
        if ssh_dir.join("ssh_host_dsa_key").exists() {
            findings.push(
                Finding::new(
                    "filesystem-102",
                    "filesystem",
                    Severity::High,
                    "Weak DSA SSH host key detected"
                )
                .with_details("DSA keys are deprecated and should not be used")
                .with_remediation("Remove DSA key and regenerate with: sudo rm /etc/ssh/ssh_host_dsa_key* && sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ''")
            );
        }

        Ok(findings)
    }

    /// Check home directories for SSH key permissions
    fn check_user_ssh_keys(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Common home directory locations
        let home_bases = ["/home", "/root"];

        for base in &home_bases {
            if let Ok(entries) = fs::read_dir(base) {
                for entry in entries.flatten() {
                    let ssh_dir = entry.path().join(".ssh");

                    if ssh_dir.exists() {
                        self.check_ssh_directory(&ssh_dir, &mut findings)?;
                    }
                }
            }
        }

        // Check root separately
        let root_ssh = Path::new("/root/.ssh");
        if root_ssh.exists() {
            self.check_ssh_directory(root_ssh, &mut findings)?;
        }

        Ok(findings)
    }

    fn check_ssh_directory(&self, ssh_dir: &Path, findings: &mut Vec<Finding>) -> Result<()> {
        let username = ssh_dir
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        // Check .ssh directory permissions (should be 700)
        if let Ok(metadata) = fs::metadata(ssh_dir) {
            let mode = metadata.permissions().mode();

            if mode & 0o077 != 0 {
                findings.push(
                    Finding::new(
                        format!("filesystem-200-{}", username),
                        "filesystem",
                        Severity::High,
                        format!("User '{}'s .ssh directory has insecure permissions", username)
                    )
                    .with_details(format!("Permissions: {:o} (should be 0700)", mode & 0o777))
                    .with_remediation(format!("Run: chmod 700 {}", ssh_dir.display()))
                );
            }
        }

        // Check authorized_keys
        let auth_keys = ssh_dir.join("authorized_keys");
        if auth_keys.exists() {
            if let Ok(metadata) = fs::metadata(&auth_keys) {
                let mode = metadata.permissions().mode();

                if mode & 0o077 != 0 {
                    findings.push(
                        Finding::new(
                            format!("filesystem-201-{}", username),
                            "filesystem",
                            Severity::High,
                            format!("User '{}'s authorized_keys has insecure permissions", username)
                        )
                        .with_details(format!("Permissions: {:o} (should be 0600)", mode & 0o777))
                        .with_remediation(format!("Run: chmod 600 {}", auth_keys.display()))
                    );
                }
            }

            // Count keys
            if let Ok(content) = fs::read_to_string(&auth_keys) {
                let key_count = content.lines()
                    .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
                    .count();

                findings.push(
                    Finding::new(
                        format!("filesystem-202-{}", username),
                        "filesystem",
                        Severity::Info,
                        format!("User '{}' has {} authorized SSH key(s)", username, key_count)
                    )
                );
            }
        }

        // Check for private keys
        let private_key_patterns = ["id_rsa", "id_ecdsa", "id_ed25519", "id_dsa"];

        for pattern in &private_key_patterns {
            let key_path = ssh_dir.join(pattern);

            if key_path.exists() {
                if let Ok(metadata) = fs::metadata(&key_path) {
                    let mode = metadata.permissions().mode();

                    if mode & 0o077 != 0 {
                        findings.push(
                            Finding::new(
                                format!("filesystem-203-{}-{}", username, pattern),
                                "filesystem",
                                Severity::Critical,
                                format!("User '{}'s private key {} has insecure permissions", username, pattern)
                            )
                            .with_details(format!("Permissions: {:o} (should be 0600)", mode & 0o777))
                            .with_remediation(format!("Run: chmod 600 {}", key_path.display()))
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Find world-writable directories in sensitive locations
    fn check_world_writable(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Directories to check
        let check_dirs = [
            "/etc",
            "/usr/local/bin",
            "/usr/local/sbin",
            "/opt",
        ];

        let mut found_writable = Vec::new();

        for dir_path in &check_dirs {
            if let Ok(entries) = fs::read_dir(dir_path) {
                for entry in entries.flatten().take(100) {  // Limit to avoid long scans
                    if let Ok(metadata) = entry.metadata() {
                        let mode = metadata.permissions().mode();

                        // Check if world-writable (0o002)
                        if mode & 0o002 != 0 {
                            found_writable.push(entry.path());
                        }
                    }
                }
            }
        }

        if !found_writable.is_empty() {
            let paths: Vec<String> = found_writable.iter()
                .take(10)
                .map(|p| p.display().to_string())
                .collect();

            findings.push(
                Finding::new(
                    "filesystem-300",
                    "filesystem",
                    Severity::High,
                    format!("{} world-writable file(s) found in sensitive directories", found_writable.len())
                )
                .with_details(format!("Examples: {}{}",
                    paths.join(", "),
                    if found_writable.len() > 10 { " (and more...)" } else { "" }
                ))
                .with_remediation("Review and remove world-write permissions: chmod o-w <file>")
            );
        }

        Ok(findings)
    }

    /// Check /tmp permissions and sticky bit
    fn check_tmp_directory(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let tmp_path = Path::new("/tmp");

        if let Ok(metadata) = fs::metadata(tmp_path) {
            let mode = metadata.permissions().mode();

            // Check for sticky bit (should be 1777)
            if mode & 0o1000 == 0 {
                findings.push(
                    Finding::new(
                        "filesystem-400",
                        "filesystem",
                        Severity::Medium,
                        "/tmp directory missing sticky bit"
                    )
                    .with_details(format!("Permissions: {:o} (should be 1777)", mode & 0o7777))
                    .with_remediation("Run: sudo chmod 1777 /tmp")
                );
            }
        }

        Ok(findings)
    }

    pub fn analyze(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check SSH host keys
        findings.extend(self.check_ssh_host_keys()?);

        // Check user SSH keys
        findings.extend(self.check_user_ssh_keys()?);

        // Check for world-writable files
        findings.extend(self.check_world_writable()?);

        // Check /tmp directory
        findings.extend(self.check_tmp_directory()?);

        Ok(findings)
    }
}

impl Default for FilesystemAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl super::Analyzer for FilesystemAnalyzer {
    fn analyze(&self) -> Result<Vec<Finding>> {
        self.analyze()
    }

    fn category(&self) -> &'static str {
        "filesystem"
    }
}
