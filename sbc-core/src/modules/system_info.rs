use crate::types::SystemInfo;
use anyhow::Result;
use std::fs;
use std::collections::HashMap;

/// System Information Collector
///
/// Gathers basic system identification and hardware information
pub struct SystemInfoCollector;

impl SystemInfoCollector {
    pub fn new() -> Self {
        Self
    }

    /// Parse /etc/os-release file
    fn parse_os_release(&self) -> Result<HashMap<String, String>> {
        let mut info = HashMap::new();

        if let Ok(content) = fs::read_to_string("/etc/os-release") {
            for line in content.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    let value = value.trim_matches('"').to_string();
                    info.insert(key.to_string(), value);
                }
            }
        }

        Ok(info)
    }

    /// Read kernel version
    fn get_kernel_version(&self) -> Option<String> {
        fs::read_to_string("/proc/version")
            .ok()
            .and_then(|s| s.split_whitespace().nth(2).map(String::from))
    }

    /// Read system architecture
    fn get_architecture(&self) -> Option<String> {
        // Try uname -m equivalent via /proc or direct uname call would be better
        // For now, we'll read from os-release or use a simple heuristic
        fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|content| {
                // Look for architecture indicators
                if content.contains("ARMv7") {
                    Some("armv7l".to_string())
                } else if content.contains("ARMv8") || content.contains("aarch64") {
                    Some("aarch64".to_string())
                } else if content.contains("x86_64") {
                    Some("x86_64".to_string())
                } else {
                    None
                }
            })
    }

    /// Try to detect board model
    fn get_board_model(&self) -> Option<String> {
        // Raspberry Pi
        if let Ok(model) = fs::read_to_string("/proc/device-tree/model") {
            return Some(model.trim_end_matches('\0').to_string());
        }

        // Try /sys/firmware/devicetree/base/model
        if let Ok(model) = fs::read_to_string("/sys/firmware/devicetree/base/model") {
            return Some(model.trim_end_matches('\0').to_string());
        }

        // Fallback to DMI for x86
        if let Ok(product) = fs::read_to_string("/sys/class/dmi/id/product_name") {
            return Some(product.trim().to_string());
        }

        None
    }

    /// Get CPU info summary
    fn get_cpu_info(&self) -> Option<String> {
        fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|content| {
                // Extract model name or hardware
                for line in content.lines() {
                    if line.starts_with("model name") || line.starts_with("Hardware") {
                        if let Some((_, value)) = line.split_once(':') {
                            return Some(value.trim().to_string());
                        }
                    }
                }
                None
            })
    }

    /// Get total memory in KB
    fn get_memory_total(&self) -> Option<u64> {
        fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|content| {
                for line in content.lines() {
                    if line.starts_with("MemTotal:") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            return parts[1].parse::<u64>().ok();
                        }
                    }
                }
                None
            })
    }

    pub fn collect(&self) -> Result<SystemInfo> {
        let os_release = self.parse_os_release()?;

        Ok(SystemInfo {
            os_name: os_release.get("NAME").cloned(),
            os_version: os_release.get("VERSION").cloned()
                .or_else(|| os_release.get("VERSION_ID").cloned()),
            kernel_version: self.get_kernel_version(),
            architecture: self.get_architecture(),
            board_model: self.get_board_model(),
            cpu_info: self.get_cpu_info(),
            memory_total_kb: self.get_memory_total(),
        })
    }
}

impl Default for SystemInfoCollector {
    fn default() -> Self {
        Self::new()
    }
}
