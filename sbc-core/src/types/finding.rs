use serde::{Deserialize, Serialize};
use super::Severity;

/// A single security or configuration finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier for this type of finding
    pub id: String,

    /// Category (e.g., "accounts", "network", "services")
    pub category: String,

    /// Severity level
    pub severity: Severity,

    /// Short description of the finding
    pub description: String,

    /// Optional detailed information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,

    /// Optional remediation advice
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl Finding {
    /// Create a new finding
    pub fn new(
        id: impl Into<String>,
        category: impl Into<String>,
        severity: Severity,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            category: category.into(),
            severity,
            description: description.into(),
            details: None,
            remediation: None,
        }
    }

    /// Add details to the finding
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// Add remediation advice to the finding
    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }
}
