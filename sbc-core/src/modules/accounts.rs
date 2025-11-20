use crate::types::{Finding, Severity};
use anyhow::{Context, Result};
use std::fs;

/// Common default usernames found on SBC images
const DEFAULT_USERNAMES: &[&str] = &[
    "pi",           // Raspberry Pi OS
    "orangepi",     // Orange Pi
    "rock",         // Radxa
    "odroid",       // Odroid
    "dietpi",       // DietPi
    "linaro",       // Linaro
    "alarm",        // Arch Linux ARM
    "debian",       // Generic Debian images
    "ubuntu",       // Generic Ubuntu images
];

/// Account and Authentication Analyzer
///
/// Examines user accounts, passwords, and authentication configuration
pub struct AccountsAnalyzer;

impl AccountsAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Parse /etc/passwd to get user accounts
    fn get_users(&self) -> Result<Vec<UserAccount>> {
        let content = fs::read_to_string("/etc/passwd")
            .context("Failed to read /etc/passwd")?;

        let mut users = Vec::new();

        for line in content.lines() {
            if let Some(user) = UserAccount::from_passwd_line(line) {
                users.push(user);
            }
        }

        Ok(users)
    }

    /// Check if a user has a password set (requires reading /etc/shadow)
    fn check_shadow_status(&self, username: &str) -> Option<PasswordStatus> {
        let content = fs::read_to_string("/etc/shadow").ok()?;

        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 2 && parts[0] == username {
                let password_field = parts[1];

                return Some(if password_field == "!" || password_field == "*" {
                    PasswordStatus::Locked
                } else if password_field.is_empty() {
                    PasswordStatus::Empty
                } else if password_field.starts_with('$') {
                    PasswordStatus::HasPassword
                } else {
                    PasswordStatus::Unknown
                });
            }
        }

        None
    }

    pub fn analyze(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let users = self.get_users()?;

        // Filter to users with login shells
        let login_users: Vec<_> = users.iter()
            .filter(|u| u.has_login_shell())
            .collect();

        // Check for default vendor usernames
        for username in DEFAULT_USERNAMES {
            if login_users.iter().any(|u| u.username == *username) {
                let password_status = self.check_shadow_status(username);

                let severity = match password_status {
                    Some(PasswordStatus::HasPassword) | Some(PasswordStatus::Empty) => Severity::High,
                    Some(PasswordStatus::Locked) => Severity::Low,
                    _ => Severity::Medium,
                };

                let mut finding = Finding::new(
                    format!("accounts-100-{}", username),
                    "accounts",
                    severity,
                    format!("Default vendor username '{}' exists", username)
                );

                if let Some(status) = password_status {
                    finding = finding.with_details(format!(
                        "User '{}' has login shell and password status: {}",
                        username, status
                    ));

                    if matches!(status, PasswordStatus::HasPassword | PasswordStatus::Empty) {
                        finding = finding.with_remediation(format!(
                            "Consider disabling password login for '{}', removing the account, or at minimum ensuring a strong password is set",
                            username
                        ));
                    }
                }

                findings.push(finding);
            }
        }

        // Check for users with UID 0 (root equivalents)
        let root_users: Vec<_> = login_users.iter()
            .filter(|u| u.uid == 0)
            .collect();

        if root_users.len() > 1 {
            findings.push(
                Finding::new(
                    "accounts-200",
                    "accounts",
                    Severity::High,
                    format!("Multiple users have UID 0 (root privileges): {}",
                        root_users.iter().map(|u| u.username.as_str()).collect::<Vec<_>>().join(", ")
                    )
                )
                .with_remediation("Only the 'root' user should have UID 0")
            );
        }

        // Check if root has a password
        if let Some(status) = self.check_shadow_status("root") {
            match status {
                PasswordStatus::Empty => {
                    findings.push(
                        Finding::new(
                            "accounts-300",
                            "accounts",
                            Severity::Critical,
                            "Root account has an empty password"
                        )
                        .with_remediation("Set a strong password for root immediately or lock the account")
                    );
                }
                PasswordStatus::HasPassword => {
                    findings.push(
                        Finding::new(
                            "accounts-301",
                            "accounts",
                            Severity::Info,
                            "Root account has a password set"
                        )
                        .with_details("Ensure it's a strong password and consider using sudo instead of direct root login")
                    );
                }
                PasswordStatus::Locked => {
                    findings.push(
                        Finding::new(
                            "accounts-302",
                            "accounts",
                            Severity::Info,
                            "Root account is locked"
                        )
                    );
                }
                _ => {}
            }
        }

        // Summary: total users with login shells
        if login_users.len() > 5 {
            findings.push(
                Finding::new(
                    "accounts-400",
                    "accounts",
                    Severity::Low,
                    format!("{} users have login shells", login_users.len())
                )
                .with_details(format!("Users: {}",
                    login_users.iter().map(|u| u.username.as_str()).collect::<Vec<_>>().join(", ")
                ))
                .with_remediation("Review user accounts and remove unnecessary ones")
            );
        }

        Ok(findings)
    }
}

impl Default for AccountsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl super::Analyzer for AccountsAnalyzer {
    fn analyze(&self) -> Result<Vec<Finding>> {
        self.analyze()
    }

    fn category(&self) -> &'static str {
        "accounts"
    }
}

/// Represents a user account from /etc/passwd
#[derive(Debug, Clone)]
struct UserAccount {
    username: String,
    uid: u32,
    #[allow(dead_code)]
    gid: u32,
    #[allow(dead_code)]
    home: String,
    shell: String,
}

impl UserAccount {
    fn from_passwd_line(line: &str) -> Option<Self> {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 7 {
            Some(Self {
                username: parts[0].to_string(),
                uid: parts[2].parse().ok()?,
                gid: parts[3].parse().ok()?,
                home: parts[5].to_string(),
                shell: parts[6].to_string(),
            })
        } else {
            None
        }
    }

    fn has_login_shell(&self) -> bool {
        !self.shell.contains("nologin") &&
        !self.shell.contains("false") &&
        !self.shell.is_empty()
    }
}

/// Password status from /etc/shadow
#[derive(Debug, Clone, Copy)]
enum PasswordStatus {
    HasPassword,
    Locked,
    Empty,
    Unknown,
}

impl std::fmt::Display for PasswordStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordStatus::HasPassword => write!(f, "has password"),
            PasswordStatus::Locked => write!(f, "locked"),
            PasswordStatus::Empty => write!(f, "empty/no password"),
            PasswordStatus::Unknown => write!(f, "unknown"),
        }
    }
}
