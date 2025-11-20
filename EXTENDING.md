# Extending SBC Snapshot

This guide shows how to add new analyzers to the tool.

## Creating a New Analyzer Module

Let's create a network analyzer as an example.

### 1. Create the Module File

Create `sbc-core/src/modules/network.rs`:

```rust
use crate::types::{Finding, Severity};
use anyhow::{Context, Result};
use std::process::Command;

pub struct NetworkAnalyzer;

impl NetworkAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Get listening ports using ss or netstat
    fn get_listening_ports(&self) -> Result<Vec<ListeningPort>> {
        let output = Command::new("ss")
            .args(&["-tuln"])
            .output()
            .context("Failed to run ss command")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut ports = Vec::new();

        for line in stdout.lines().skip(1) {
            // Parse ss output
            // Format: tcp   LISTEN 0  128  0.0.0.0:22  0.0.0.0:*
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 && parts[1] == "LISTEN" {
                if let Some(port) = Self::parse_address(parts[4]) {
                    ports.push(port);
                }
            }
        }

        Ok(ports)
    }

    fn parse_address(addr: &str) -> Option<ListeningPort> {
        // Handle both IPv4 and IPv6
        let (ip, port_str) = if addr.starts_with('[') {
            // IPv6: [::]:22
            let parts: Vec<&str> = addr.rsplitn(2, "]:").collect();
            if parts.len() == 2 {
                (parts[1].trim_start_matches('['), parts[0])
            } else {
                return None;
            }
        } else {
            // IPv4: 0.0.0.0:22
            let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
            if parts.len() == 2 {
                (parts[1], parts[0])
            } else {
                return None;
            }
        };

        let port = port_str.parse().ok()?;

        Some(ListeningPort {
            address: ip.to_string(),
            port,
            is_wildcard: ip == "0.0.0.0" || ip == "::" || ip == "*",
        })
    }

    pub fn analyze(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let ports = self.get_listening_ports()?;

        // Check for services on all interfaces
        let wildcard_ports: Vec<_> = ports.iter()
            .filter(|p| p.is_wildcard)
            .collect();

        if !wildcard_ports.is_empty() {
            let port_list: Vec<String> = wildcard_ports.iter()
                .map(|p| p.port.to_string())
                .collect();

            findings.push(
                Finding::new(
                    "network-100",
                    "network",
                    Severity::Medium,
                    format!("{} services listening on all interfaces", wildcard_ports.len())
                )
                .with_details(format!("Ports: {}", port_list.join(", ")))
                .with_remediation("Consider restricting services to specific interfaces or use a firewall")
            );
        }

        // Check for common risky ports
        let risky_ports = [
            (23, "telnet"),
            (21, "ftp"),
            (445, "smb"),
            (3389, "rdp"),
        ];

        for (port_num, service) in &risky_ports {
            if ports.iter().any(|p| p.port == *port_num && p.is_wildcard) {
                findings.push(
                    Finding::new(
                        format!("network-200-{}", port_num),
                        "network",
                        Severity::High,
                        format!("{} ({}) is exposed on all interfaces", service, port_num)
                    )
                    .with_remediation(format!("Disable {} service or restrict to localhost", service))
                );
            }
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
    address: String,
    port: u16,
    is_wildcard: bool,
}
```

### 2. Register the Module

Add to `sbc-core/src/modules/mod.rs`:

```rust
pub mod network;  // Add this line
```

### 3. Integrate in the Runner

Update `sbc-core/src/lib.rs`:

```rust
// In the run() method, add:
let network_findings = modules::network::NetworkAnalyzer::new().analyze()?;

// Combine with SSH findings or create separate report
let mut all_network_findings = ssh_findings;
all_network_findings.extend(network_findings);

let network = NetworkReport {
    findings: all_network_findings,
    raw: None,
};
```

### 4. Build and Test

```bash
cargo build
sudo ./target/debug/sbc-snapshot
```

## Analyzer Best Practices

### 1. Error Handling

Always handle errors gracefully:

```rust
fn analyze(&self) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // If a check fails, report it as a finding instead of failing
    match self.check_something() {
        Ok(result) => {
            // Process result
        }
        Err(e) => {
            findings.push(
                Finding::new(
                    "module-000",
                    "category",
                    Severity::Medium,
                    "Failed to check something"
                )
                .with_details(format!("Error: {}", e))
            );
        }
    }

    Ok(findings)
}
```

### 2. Finding IDs

Use a consistent naming scheme:
- `module-NNN` where NNN is a unique number
- Group related findings (e.g., `ssh-100` through `ssh-199` for config issues)

### 3. Severity Guidelines

- **Critical**: Immediate security risk (empty passwords, root without password)
- **High**: Serious misconfiguration (default passwords, root SSH access)
- **Medium**: Potential security concern (password auth enabled, no firewall)
- **Low**: Minor issue or hardening opportunity (extra services, non-standard config)
- **Info**: Informational only (good configurations, status messages)

### 4. Remediation Advice

Always provide actionable remediation:

```rust
Finding::new(...)
    .with_remediation("Set PermitRootLogin to 'no' in /etc/ssh/sshd_config and restart sshd")
```

### 5. Testing Without Root

Make analyzers degrade gracefully:

```rust
fn check_shadow(&self) -> Result<()> {
    if !Path::new("/etc/shadow").exists() {
        return Ok(()); // Skip if can't access
    }

    // Check requires root
    let content = fs::read_to_string("/etc/shadow")
        .context("Reading /etc/shadow requires root")?;

    // ... rest of logic
}
```

## Adding Optional Raw Data

If your analyzer produces structured data worth including:

```rust
use serde_json::json;

pub fn analyze(&self) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let ports = self.get_listening_ports()?;

    // Create findings...

    // Optionally store raw data
    let raw = json!({
        "ports": ports,
        "timestamp": Utc::now(),
    });

    Ok((findings, Some(raw)))
}
```

Then update the return type and runner accordingly.

## Example: Systemd Service Analyzer

Here's a complete minimal analyzer for systemd services:

```rust
use crate::types::{Finding, Severity};
use anyhow::Result;
use std::process::Command;

pub struct ServicesAnalyzer;

impl ServicesAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Get enabled services
        let output = Command::new("systemctl")
            .args(&["list-unit-files", "--type=service", "--state=enabled"])
            .output()?;

        let services = String::from_utf8_lossy(&output.stdout);

        // Check for unexpected services
        let suspicious = ["telnet", "rsh", "rlogin"];

        for service_name in suspicious {
            if services.contains(service_name) {
                findings.push(
                    Finding::new(
                        format!("services-100-{}", service_name),
                        "services",
                        Severity::High,
                        format!("Insecure service '{}' is enabled", service_name)
                    )
                    .with_remediation(format!("Disable with: sudo systemctl disable {}", service_name))
                );
            }
        }

        Ok(findings)
    }
}
```

## Questions?

See existing analyzers in `sbc-core/src/modules/` for more examples.
