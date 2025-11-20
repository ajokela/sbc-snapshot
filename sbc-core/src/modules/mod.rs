pub mod ssh;
pub mod accounts;
pub mod system_info;
pub mod network;
pub mod firewall;
pub mod services;
pub mod sudoers;
pub mod packages;
pub mod filesystem;

use crate::types::*;
use anyhow::Result;

/// Trait that all analyzer modules must implement
pub trait Analyzer {
    /// Run the analysis and return findings
    fn analyze(&self) -> Result<Vec<Finding>>;

    /// Get the category name for this analyzer
    fn category(&self) -> &'static str;
}
