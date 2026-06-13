//! Capability-based Security for WASM Sandbox
//!
//! This module implements capability-based security for the WASM sandbox,
//! limiting what sandboxed code can do.

use std::collections::HashSet;

/// Set of capabilities granted to the sandbox
#[derive(Debug, Clone)]
pub struct CapabilitySet {
    capabilities: HashSet<String>,
}

impl Default for CapabilitySet {
    fn default() -> Self {
        let mut caps = HashSet::new();
        // Default: minimal capabilities
        caps.insert("stdio".to_string());
        caps.insert("clock".to_string());
        Self { capabilities: caps }
    }
}

impl CapabilitySet {
    /// Create empty capability set
    pub fn empty() -> Self {
        Self {
            capabilities: HashSet::new(),
        }
    }

    /// Add a capability
    pub fn add(&mut self, cap: &str) {
        self.capabilities.insert(cap.to_string());
    }

    /// Remove a capability
    pub fn remove(&mut self, cap: &str) {
        self.capabilities.remove(cap);
    }

    /// Check if has capability
    pub fn has(&self, cap: &str) -> bool {
        self.capabilities.contains(cap)
    }

    /// Get all capabilities
    pub fn list(&self) -> Vec<&String> {
        self.capabilities.iter().collect()
    }

    /// Create a standard validator capability set
    pub fn validator() -> Self {
        let mut caps = Self::empty();
        caps.add("stdio");
        caps.add("clock");
        caps.add("random");
        caps.add("read-tarball");
        caps
    }

    /// Create an unrestricted capability set (dangerous!)
    pub fn unrestricted() -> Self {
        let mut caps = Self::empty();
        caps.add("stdio");
        caps.add("clock");
        caps.add("random");
        caps.add("filesystem-read");
        caps.add("filesystem-write");
        caps.add("network");
        caps.add("exec");
        caps
    }
}
