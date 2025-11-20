use crate::types::{Finding, Severity};
use anyhow::Result;
use std::process::Command;

/// Systemd Services Analyzer
///
/// Examines enabled and running services for security issues
pub struct ServicesAnalyzer;

impl ServicesAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Get list of enabled services
    fn get_enabled_services(&self) -> Result<Vec<String>> {
        let output = Command::new("systemctl")
            .args(&["list-unit-files", "--type=service", "--state=enabled", "--no-pager"])
            .output()?;

        if !output.status.success() {
            anyhow::bail!("systemctl command failed");
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut services = Vec::new();

        for line in stdout.lines() {
            // Skip header and footer
            if line.contains("UNIT FILE") || line.trim().is_empty() || line.contains("unit files listed") {
                continue;
            }

            // Parse: "service-name.service  enabled"
            if let Some(service_name) = line.split_whitespace().next() {
                if service_name.ends_with(".service") {
                    services.push(service_name.trim_end_matches(".service").to_string());
                }
            }
        }

        Ok(services)
    }

    /// Get list of running services
    fn get_running_services(&self) -> Result<Vec<String>> {
        let output = Command::new("systemctl")
            .args(&["list-units", "--type=service", "--state=running", "--no-pager"])
            .output()?;

        if !output.status.success() {
            anyhow::bail!("systemctl command failed");
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut services = Vec::new();

        for line in stdout.lines() {
            // Skip header and footer
            if line.contains("UNIT") || line.trim().is_empty() || line.contains("loaded units listed") {
                continue;
            }

            // Parse: "  service-name.service  loaded active running Description"
            if let Some(service_name) = line.split_whitespace().next() {
                if service_name.ends_with(".service") {
                    services.push(service_name.trim_end_matches(".service").to_string());
                }
            }
        }

        Ok(services)
    }

    pub fn analyze(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Try to get services (may fail if systemd not available or no permissions)
        let enabled_services = match self.get_enabled_services() {
            Ok(s) => s,
            Err(e) => {
                findings.push(
                    Finding::new(
                        "services-001",
                        "services",
                        Severity::Low,
                        "Unable to enumerate systemd services"
                    )
                    .with_details(format!("Error: {}. System may not use systemd or lacks permissions.", e))
                );
                return Ok(findings);
            }
        };

        let running_services = self.get_running_services().unwrap_or_default();

        // Check for dangerous legacy services
        let dangerous_services = [
            ("telnet", Severity::Critical, "Unencrypted remote access - use SSH instead"),
            ("rsh", Severity::Critical, "Insecure remote shell - use SSH instead"),
            ("rlogin", Severity::Critical, "Insecure remote login - use SSH instead"),
            ("rexec", Severity::Critical, "Insecure remote execution - use SSH instead"),
            ("ftp", Severity::High, "Unencrypted file transfer - use SFTP or FTPS instead"),
            ("vsftpd", Severity::High, "FTP server - consider SFTP instead"),
        ];

        for (service_name, severity, message) in &dangerous_services {
            if enabled_services.iter().any(|s| s.contains(service_name)) {
                findings.push(
                    Finding::new(
                        format!("services-100-{}", service_name),
                        "services",
                        *severity,
                        format!("Dangerous service '{}' is enabled", service_name)
                    )
                    .with_details(*message)
                    .with_remediation(format!("Disable with: sudo systemctl disable --now {}", service_name))
                );
            }
        }

        // Check for services that might not be needed on headless SBC
        let potentially_unnecessary = [
            ("cups", "Printing service - usually not needed on headless SBC"),
            ("bluetooth", "Bluetooth service - disable if not using Bluetooth"),
            ("avahi-daemon", "mDNS service - disable if not needed for network discovery"),
            ("ModemManager", "Modem management - usually not needed"),
            ("cups-browsed", "Printer discovery - usually not needed on headless SBC"),
        ];

        for (service_name, reason) in &potentially_unnecessary {
            if running_services.iter().any(|s| s.contains(service_name)) {
                findings.push(
                    Finding::new(
                        format!("services-200-{}", service_name),
                        "services",
                        Severity::Low,
                        format!("Service '{}' is running", service_name)
                    )
                    .with_details(*reason)
                    .with_remediation(format!("Consider disabling if not needed: sudo systemctl disable --now {}", service_name))
                );
            }
        }

        // Check for database services (might want to be localhost-only)
        let database_services = [
            ("mysql", "MySQL"),
            ("mariadb", "MariaDB"),
            ("postgresql", "PostgreSQL"),
            ("mongodb", "MongoDB"),
            ("redis", "Redis"),
        ];

        for (service_name, display_name) in &database_services {
            if running_services.iter().any(|s| s.contains(service_name)) {
                findings.push(
                    Finding::new(
                        format!("services-300-{}", service_name),
                        "services",
                        Severity::Info,
                        format!("{} database is running", display_name)
                    )
                    .with_details("Ensure it's bound to localhost only if not needed externally (check network analyzer)")
                );
            }
        }

        // Check for web servers
        let web_services = [
            ("apache2", "Apache"),
            ("httpd", "Apache"),
            ("nginx", "Nginx"),
            ("lighttpd", "Lighttpd"),
        ];

        for (service_name, display_name) in &web_services {
            if running_services.iter().any(|s| s.contains(service_name)) {
                findings.push(
                    Finding::new(
                        format!("services-400-{}", service_name),
                        "services",
                        Severity::Info,
                        format!("{} web server is running", display_name)
                    )
                    .with_details("Ensure it's properly configured with HTTPS if exposed to network")
                );
            }
        }

        // Check for Docker/containers
        if running_services.iter().any(|s| s.contains("docker") || s.contains("containerd")) {
            findings.push(
                Finding::new(
                    "services-500",
                    "services",
                    Severity::Info,
                    "Docker/container runtime is running"
                )
                .with_details("Ensure containers are from trusted sources and kept updated")
            );
        }

        // Summary
        let enabled_count = enabled_services.len();
        let running_count = running_services.len();

        findings.push(
            Finding::new(
                "services-900",
                "services",
                Severity::Info,
                format!("{} services enabled, {} currently running", enabled_count, running_count)
            )
        );

        Ok(findings)
    }
}

impl Default for ServicesAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl super::Analyzer for ServicesAnalyzer {
    fn analyze(&self) -> Result<Vec<Finding>> {
        self.analyze()
    }

    fn category(&self) -> &'static str {
        "services"
    }
}
