//! Access Control for Private Registries
//!
//! Defines policies and access rules for organization members
//! and package access control.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Access policy for an organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicy {
    /// Whether admin approval is required for packages
    pub requires_approval: bool,
    /// Maximum package size in bytes
    pub max_package_size: u64,
    /// Minimum stake required for publishers
    pub min_stake: u64,
    /// Whether external (non-member) publishers are allowed
    pub allow_external_publishers: bool,
    /// Allowed ecosystems (empty = all allowed)
    pub allowed_ecosystems: Vec<String>,
    /// Custom policy rules
    #[serde(default)]
    pub custom_rules: HashMap<String, String>,
}

impl Default for AccessPolicy {
    fn default() -> Self {
        Self {
            requires_approval: true,
            max_package_size: 100 * 1024 * 1024, // 100MB
            min_stake: 0,
            allow_external_publishers: false,
            allowed_ecosystems: vec![],
            custom_rules: HashMap::new(),
        }
    }
}

impl AccessPolicy {
    /// Create a new strict policy
    pub fn strict() -> Self {
        Self {
            requires_approval: true,
            max_package_size: 10 * 1024 * 1024, // 10MB
            min_stake: 100_000,                 // 0.001 ETH in wei
            allow_external_publishers: false,
            allowed_ecosystems: vec!["npm".to_string(), "pypi".to_string()],
            custom_rules: HashMap::new(),
        }
    }

    /// Create a relaxed policy
    pub fn relaxed() -> Self {
        Self {
            requires_approval: false,
            max_package_size: 500 * 1024 * 1024, // 500MB
            min_stake: 0,
            allow_external_publishers: true,
            allowed_ecosystems: vec![],
            custom_rules: HashMap::new(),
        }
    }

    /// Check if a package meets the policy requirements
    pub fn validate_package(
        &self,
        size: u64,
        ecosystem: &str,
        publisher_stake: u64,
    ) -> Result<(), String> {
        // Check size
        if size > self.max_package_size {
            return Err(format!(
                "Package size {} exceeds maximum {}",
                size, self.max_package_size
            ));
        }

        // Check ecosystem
        if !self.allowed_ecosystems.is_empty()
            && !self.allowed_ecosystems.contains(&ecosystem.to_string())
        {
            return Err(format!(
                "Ecosystem '{}' not allowed. Allowed: {:?}",
                ecosystem, self.allowed_ecosystems
            ));
        }

        // Check stake
        if publisher_stake < self.min_stake {
            return Err(format!(
                "Insufficient stake: {} < {}",
                publisher_stake, self.min_stake
            ));
        }

        Ok(())
    }

    /// Add a custom rule
    pub fn with_custom_rule(mut self, key: &str, value: &str) -> Self {
        self.custom_rules.insert(key.to_string(), value.to_string());
        self
    }
}

/// Role-based access control for organization members
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    /// Organization administrator
    Admin,
    /// Can publish packages
    Publisher,
    /// Can decrypt packages
    Reader,
    /// Can validate packages
    Validator,
    /// Observer (read-only metadata)
    Observer,
}

impl Role {
    /// Check if this role has a specific permission
    pub fn has_permission(&self, permission: Permission) -> bool {
        match (self, permission) {
            (Role::Admin, _) => true,
            (Role::Publisher, Permission::Publish) => true,
            (Role::Publisher, Permission::Read) => true,
            (Role::Reader, Permission::Read) => true,
            (Role::Reader, Permission::Decrypt) => true,
            (Role::Validator, Permission::Validate) => true,
            (Role::Validator, Permission::Read) => true,
            (Role::Observer, Permission::Read) => true,
            _ => false,
        }
    }
}

/// Permissions in the system
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// Can publish packages
    Publish,
    /// Can read package metadata
    Read,
    /// Can decrypt package content
    Decrypt,
    /// Can validate packages
    Validate,
    /// Can manage organization
    Manage,
}

/// Member of an organization with roles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    /// Member address/ID
    pub id: String,
    /// Member roles
    pub roles: Vec<Role>,
    /// When member was added
    pub added_at: u64,
    /// Who added this member
    pub added_by: String,
}

impl Member {
    /// Create new member
    pub fn new(id: String, roles: Vec<Role>, added_by: String) -> Self {
        Self {
            id,
            roles,
            added_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            added_by,
        }
    }

    /// Check if member has a permission
    pub fn has_permission(&self, permission: Permission) -> bool {
        self.roles
            .iter()
            .any(|role| role.has_permission(permission))
    }

    /// Add a role
    pub fn add_role(&mut self, role: Role) {
        if !self.roles.contains(&role) {
            self.roles.push(role);
        }
    }

    /// Remove a role
    pub fn remove_role(&mut self, role: Role) {
        self.roles.retain(|r| r != &role);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_policy_validation() {
        let policy = AccessPolicy::strict();

        // Too large
        assert!(policy
            .validate_package(100 * 1024 * 1024, "npm", 200_000)
            .is_err());

        // Wrong ecosystem
        assert!(policy.validate_package(1000, "cargo", 200_000).is_err());

        // Insufficient stake
        assert!(policy.validate_package(1000, "npm", 50_000).is_err());

        // Valid
        assert!(policy.validate_package(1000, "npm", 200_000).is_ok());
    }

    #[test]
    fn test_role_permissions() {
        assert!(Role::Admin.has_permission(Permission::Manage));
        assert!(Role::Admin.has_permission(Permission::Publish));

        assert!(Role::Publisher.has_permission(Permission::Publish));
        assert!(!Role::Publisher.has_permission(Permission::Manage));

        assert!(Role::Reader.has_permission(Permission::Decrypt));
        assert!(!Role::Reader.has_permission(Permission::Publish));
    }

    #[test]
    fn test_member_permissions() {
        let member = Member::new(
            "user1".to_string(),
            vec![Role::Publisher, Role::Reader],
            "admin".to_string(),
        );

        assert!(member.has_permission(Permission::Publish));
        assert!(member.has_permission(Permission::Read));
        assert!(member.has_permission(Permission::Decrypt));
        assert!(!member.has_permission(Permission::Manage));
    }
}
