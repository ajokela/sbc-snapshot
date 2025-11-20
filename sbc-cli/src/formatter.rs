use anyhow::Result;
use sbc_core::types::{Snapshot, Severity};

/// Format snapshot as human-readable text
pub fn format_text(snapshot: &Snapshot, _redact: bool) -> String {
    let mut output = String::new();

    // Header
    output.push_str("═══════════════════════════════════════════════════════════════\n");
    output.push_str("        Security & Exposure Snapshot for SBC\n");
    output.push_str("═══════════════════════════════════════════════════════════════\n\n");

    // Metadata
    output.push_str(&format!("Snapshot Version: {}\n", snapshot.metadata.version));
    output.push_str(&format!("Timestamp: {}\n", snapshot.metadata.timestamp.format("%Y-%m-%d %H:%M:%S UTC")));
    output.push_str(&format!("Hostname: {}\n", snapshot.metadata.hostname));
    output.push_str(&format!("Run as root: {}\n", if snapshot.metadata.run_as_root { "Yes" } else { "No" }));
    output.push_str("\n");

    // System Information
    output.push_str("─────────────────────────────────────────────────────────────\n");
    output.push_str("SYSTEM INFORMATION\n");
    output.push_str("─────────────────────────────────────────────────────────────\n");

    if let Some(ref os) = snapshot.system.os_name {
        output.push_str(&format!("OS: {}", os));
        if let Some(ref version) = snapshot.system.os_version {
            output.push_str(&format!(" {}", version));
        }
        output.push('\n');
    }

    if let Some(ref kernel) = snapshot.system.kernel_version {
        output.push_str(&format!("Kernel: {}\n", kernel));
    }

    if let Some(ref arch) = snapshot.system.architecture {
        output.push_str(&format!("Architecture: {}\n", arch));
    }

    if let Some(ref board) = snapshot.system.board_model {
        output.push_str(&format!("Board: {}\n", board));
    }

    if let Some(ref cpu) = snapshot.system.cpu_info {
        output.push_str(&format!("CPU: {}\n", cpu));
    }

    if let Some(mem) = snapshot.system.memory_total_kb {
        output.push_str(&format!("Memory: {} MB\n", mem / 1024));
    }

    output.push('\n');

    // Security Score
    output.push_str("─────────────────────────────────────────────────────────────\n");
    output.push_str("SECURITY ASSESSMENT\n");
    output.push_str("─────────────────────────────────────────────────────────────\n");
    output.push_str(&format!("Overall Risk Level: {}\n", snapshot.security_score.risk_level));
    output.push_str(&format!("Total Score: {}\n\n", snapshot.security_score.total_score));

    output.push_str("Findings by Severity:\n");
    if snapshot.security_score.critical_count > 0 {
        output.push_str(&format!("  CRITICAL: {}\n", snapshot.security_score.critical_count));
    }
    if snapshot.security_score.high_count > 0 {
        output.push_str(&format!("  HIGH:     {}\n", snapshot.security_score.high_count));
    }
    if snapshot.security_score.medium_count > 0 {
        output.push_str(&format!("  MEDIUM:   {}\n", snapshot.security_score.medium_count));
    }
    if snapshot.security_score.low_count > 0 {
        output.push_str(&format!("  LOW:      {}\n", snapshot.security_score.low_count));
    }
    if snapshot.security_score.info_count > 0 {
        output.push_str(&format!("  INFO:     {}\n", snapshot.security_score.info_count));
    }

    output.push('\n');

    // Findings by category
    let sections = vec![
        ("ACCOUNTS & AUTHENTICATION", &snapshot.accounts.findings),
        ("NETWORK & SSH", &snapshot.network.findings),
        ("SERVICES & DAEMONS", &snapshot.services.findings),
        ("FILESYSTEM & PERMISSIONS", &snapshot.filesystem.findings),
        ("PACKAGES & UPDATES", &snapshot.packages.findings),
    ];

    for (title, findings) in sections {
        if findings.is_empty() {
            continue;
        }

        output.push_str("─────────────────────────────────────────────────────────────\n");
        output.push_str(&format!("{}\n", title));
        output.push_str("─────────────────────────────────────────────────────────────\n");

        // Group by severity
        let mut sorted_findings = findings.clone();
        sorted_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

        for finding in sorted_findings {
            // Skip INFO in text output unless it's interesting
            if finding.severity == Severity::Info {
                continue;
            }

            output.push_str(&format!("\n[{}] {}\n", finding.severity, finding.description));

            if let Some(ref details) = finding.details {
                output.push_str(&format!("    Details: {}\n", details));
            }

            if let Some(ref remediation) = finding.remediation {
                output.push_str(&format!("    → {}\n", remediation));
            }
        }

        output.push('\n');
    }

    output.push_str("═══════════════════════════════════════════════════════════════\n");
    output.push_str("                    End of Report\n");
    output.push_str("═══════════════════════════════════════════════════════════════\n");

    output
}

/// Format snapshot as JSON
pub fn format_json(snapshot: &Snapshot, pretty: bool, _redact: bool) -> Result<String> {
    if pretty {
        Ok(serde_json::to_string_pretty(snapshot)?)
    } else {
        Ok(serde_json::to_string(snapshot)?)
    }
}
