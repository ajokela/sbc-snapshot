use crate::types::{Finding, Severity};
use anyhow::{Context, Result};
use std::process::Command;

/// Network and Listening Services Analyzer
///
/// Examines open ports, listening services, and network exposure
pub struct NetworkAnalyzer;

impl NetworkAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Get listening ports using ss (preferred) or netstat (fallback)
    fn get_listening_ports(&self) -> Result<Vec<ListeningPort>> {
        // Try ss first (modern)
        if let Ok(ports) = self.try_ss() {
            return Ok(ports);
        }

        // Fallback to netstat
        if let Ok(ports) = self.try_netstat() {
            return Ok(ports);
        }

        // If both fail, return empty (we'll create a finding about this)
        Ok(Vec::new())
    }

    fn try_ss(&self) -> Result<Vec<ListeningPort>> {
        let output = Command::new("ss")
            .args(&["-tuln"])
            .output()
            .context("Failed to run ss")?;

        if !output.status.success() {
            anyhow::bail!("ss command failed");
        }

        self.parse_ss_output(&String::from_utf8_lossy(&output.stdout))
    }

    fn try_netstat(&self) -> Result<Vec<ListeningPort>> {
        let output = Command::new("netstat")
            .args(&["-tuln"])
            .output()
            .context("Failed to run netstat")?;

        if !output.status.success() {
            anyhow::bail!("netstat command failed");
        }

        self.parse_netstat_output(&String::from_utf8_lossy(&output.stdout))
    }

    fn parse_ss_output(&self, output: &str) -> Result<Vec<ListeningPort>> {
        let mut ports = Vec::new();

        for line in output.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();

            // ss output: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port
            if parts.len() >= 5 {
                let state = parts.get(1).unwrap_or(&"");
                if *state == "LISTEN" || *state == "UNCONN" {
                    let proto = parts[0];
                    let local = parts[4];

                    if let Some(port) = self.parse_address(local, proto) {
                        ports.push(port);
                    }
                }
            }
        }

        Ok(ports)
    }

    fn parse_netstat_output(&self, output: &str) -> Result<Vec<ListeningPort>> {
        let mut ports = Vec::new();

        for line in output.lines().skip(2) {
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() >= 6 {
                let proto = parts[0];
                let state = parts.get(5).unwrap_or(&"");

                if *state == "LISTEN" || proto.starts_with("udp") {
                    let local = parts[3];

                    if let Some(port) = self.parse_address(local, proto) {
                        ports.push(port);
                    }
                }
            }
        }

        Ok(ports)
    }

    fn parse_address(&self, addr: &str, proto: &str) -> Option<ListeningPort> {
        let protocol = if proto.starts_with("tcp") {
            Protocol::Tcp
        } else if proto.starts_with("udp") {
            Protocol::Udp
        } else {
            return None;
        };

        let (ip, port_str) = if addr.starts_with('[') {
            // IPv6: [::]:22 or [::1]:22
            let parts: Vec<&str> = addr.rsplitn(2, "]:").collect();
            if parts.len() == 2 {
                (parts[1].trim_start_matches('['), parts[0])
            } else {
                return None;
            }
        } else {
            // IPv4: 0.0.0.0:22 or 127.0.0.1:22
            let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
            if parts.len() == 2 {
                (parts[1], parts[0])
            } else {
                return None;
            }
        };

        let port = port_str.parse().ok()?;

        let is_wildcard = ip == "0.0.0.0" || ip == "::" || ip == "*";
        let is_localhost = ip == "127.0.0.1" || ip == "::1" || ip == "localhost";

        Some(ListeningPort {
            address: ip.to_string(),
            port,
            protocol,
            is_wildcard,
            is_localhost,
        })
    }

    /// Try to identify common services by port number
    fn identify_service(&self, port: u16) -> Option<&'static str> {
        match port {
            22 => Some("SSH"),
            23 => Some("Telnet"),
            21 => Some("FTP"),
            20 => Some("FTP-DATA"),
            25 => Some("SMTP"),
            53 => Some("DNS"),
            80 => Some("HTTP"),
            443 => Some("HTTPS"),
            445 => Some("SMB"),
            139 => Some("NetBIOS"),
            3306 => Some("MySQL"),
            5432 => Some("PostgreSQL"),
            6379 => Some("Redis"),
            8080 => Some("HTTP-Alt"),
            3389 => Some("RDP"),
            5900 => Some("VNC"),
            631 => Some("CUPS/IPP"),
            111 => Some("RPC"),
            2049 => Some("NFS"),
            _ => None,
        }
    }

    pub fn analyze(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let ports = match self.get_listening_ports() {
            Ok(p) if !p.is_empty() => p,
            Ok(_) => {
                findings.push(
                    Finding::new(
                        "network-001",
                        "network",
                        Severity::Medium,
                        "Unable to enumerate listening ports"
                    )
                    .with_details("Neither 'ss' nor 'netstat' commands are available or returned results")
                    .with_remediation("Install iproute2 (for ss) or net-tools (for netstat)")
                );
                return Ok(findings);
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "network-002",
                        "network",
                        Severity::Low,
                        "Failed to enumerate listening ports"
                    )
                    .with_details(format!("Error: {}", e))
                );
                return Ok(findings);
            }
        };

        // Check for services on all interfaces
        let wildcard_ports: Vec<_> = ports.iter()
            .filter(|p| p.is_wildcard)
            .collect();

        if !wildcard_ports.is_empty() {
            let port_list: Vec<String> = wildcard_ports.iter()
                .map(|p| {
                    let service = self.identify_service(p.port)
                        .map(|s| format!(" ({})", s))
                        .unwrap_or_default();
                    format!("{}/{}{}", p.port, p.protocol, service)
                })
                .collect();

            findings.push(
                Finding::new(
                    "network-100",
                    "network",
                    Severity::Medium,
                    format!("{} service(s) listening on all interfaces", wildcard_ports.len())
                )
                .with_details(format!("Services: {}", port_list.join(", ")))
                .with_remediation("Review services and bind to localhost (127.0.0.1) if not needed externally, or configure a firewall")
            );
        }

        // Check for dangerous/legacy services
        let dangerous_services = [
            (23, "Telnet", Severity::Critical, "unencrypted remote access"),
            (21, "FTP", Severity::High, "unencrypted file transfer"),
            (20, "FTP-DATA", Severity::High, "unencrypted file transfer"),
            (69, "TFTP", Severity::High, "insecure file transfer"),
            (512, "rexec", Severity::Critical, "legacy remote execution"),
            (513, "rlogin", Severity::Critical, "legacy remote login"),
            (514, "rsh", Severity::Critical, "legacy remote shell"),
        ];

        for (port_num, service_name, severity, reason) in &dangerous_services {
            if ports.iter().any(|p| p.port == *port_num && p.is_wildcard) {
                findings.push(
                    Finding::new(
                        format!("network-200-{}", port_num),
                        "network",
                        *severity,
                        format!("{} (port {}) is exposed on all interfaces", service_name, port_num)
                    )
                    .with_details(format!("Security risk: {}", reason))
                    .with_remediation(format!("Disable {} service immediately and use secure alternatives", service_name))
                );
            }
        }

        // Check for database services exposed
        let database_ports = [
            (3306, "MySQL"),
            (5432, "PostgreSQL"),
            (27017, "MongoDB"),
            (6379, "Redis"),
            (5984, "CouchDB"),
            (9200, "Elasticsearch"),
        ];

        for (port_num, db_name) in &database_ports {
            if ports.iter().any(|p| p.port == *port_num && p.is_wildcard) {
                findings.push(
                    Finding::new(
                        format!("network-300-{}", port_num),
                        "network",
                        Severity::High,
                        format!("{} database is exposed on all interfaces", db_name)
                    )
                    .with_details(format!("Port {} is listening on 0.0.0.0 or ::", port_num))
                    .with_remediation(format!("Bind {} to localhost only or use firewall rules to restrict access", db_name))
                );
            }
        }

        // Check for web admin panels
        let admin_ports = [
            (8080, "HTTP-Alt"),
            (8443, "HTTPS-Alt"),
            (9090, "Cockpit/Admin"),
            (10000, "Webmin"),
        ];

        for (port_num, service_name) in &admin_ports {
            if ports.iter().any(|p| p.port == *port_num && p.is_wildcard) {
                findings.push(
                    Finding::new(
                        format!("network-400-{}", port_num),
                        "network",
                        Severity::Medium,
                        format!("{} web interface exposed on all interfaces", service_name)
                    )
                    .with_details(format!("Port {}", port_num))
                    .with_remediation("Restrict web admin panels to localhost or use VPN/SSH tunnel for access")
                );
            }
        }

        // Info: Localhost-only services (good!)
        let localhost_count = ports.iter()
            .filter(|p| p.is_localhost)
            .count();

        if localhost_count > 0 {
            findings.push(
                Finding::new(
                    "network-500",
                    "network",
                    Severity::Info,
                    format!("{} service(s) bound to localhost only", localhost_count)
                )
                .with_details("These services are not exposed to the network")
            );
        }

        Ok(findings)
    }
}

impl Default for NetworkAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl super::Analyzer for NetworkAnalyzer {
    fn analyze(&self) -> Result<Vec<Finding>> {
        self.analyze()
    }

    fn category(&self) -> &'static str {
        "network"
    }
}

#[derive(Debug, Clone)]
struct ListeningPort {
    #[allow(dead_code)]
    address: String,
    port: u16,
    protocol: Protocol,
    is_wildcard: bool,
    is_localhost: bool,
}

#[derive(Debug, Clone, Copy)]
enum Protocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}
