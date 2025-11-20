use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity level for security findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Convert severity to a numeric score for aggregation
    pub fn score(&self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 3,
            Severity::High => 7,
            Severity::Critical => 10,
        }
    }

    /// Get a colored representation for terminal output
    pub fn colored_str(&self) -> String {
        match self {
            Severity::Info => "INFO".to_string(),
            Severity::Low => "LOW".to_string(),
            Severity::Medium => "MEDIUM".to_string(),
            Severity::High => "HIGH".to_string(),
            Severity::Critical => "CRITICAL".to_string(),
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}
