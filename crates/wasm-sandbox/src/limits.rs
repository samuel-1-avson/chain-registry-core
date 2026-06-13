//! Resource Limits for WASM Sandbox
//!
//! This module provides resource limiting for the WASM sandbox to prevent
/// Resource limits for sandbox execution
#[derive(Debug, Clone, Copy)]
pub struct ResourceLimits {
    /// Maximum memory in bytes
    pub max_memory: usize,
    /// Maximum execution time in milliseconds
    pub max_time_ms: u64,
    /// Maximum file size in bytes
    pub max_file_size: usize,
    /// Maximum number of open files
    pub max_open_files: u32,
    /// Maximum number of syscalls per execution
    pub max_syscalls: u64,
    /// Maximum stack size in bytes
    pub max_stack_size: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory: 256 * 1024 * 1024,    // 256 MB
            max_time_ms: 30000,               // 30 seconds
            max_file_size: 100 * 1024 * 1024, // 100 MB
            max_open_files: 10,
            max_syscalls: 10000,
            max_stack_size: 8 * 1024 * 1024, // 8 MB
        }
    }
}

impl ResourceLimits {
    /// Create strict limits (for untrusted code)
    pub fn strict() -> Self {
        Self {
            max_memory: 64 * 1024 * 1024,    // 64 MB
            max_time_ms: 10000,              // 10 seconds
            max_file_size: 10 * 1024 * 1024, // 10 MB
            max_open_files: 5,
            max_syscalls: 1000,
            max_stack_size: 2 * 1024 * 1024, // 2 MB
        }
    }

    /// Create relaxed limits (for trusted validators)
    pub fn relaxed() -> Self {
        Self {
            max_memory: 512 * 1024 * 1024,    // 512 MB
            max_time_ms: 60000,               // 60 seconds
            max_file_size: 500 * 1024 * 1024, // 500 MB
            max_open_files: 50,
            max_syscalls: 100000,
            max_stack_size: 16 * 1024 * 1024, // 16 MB
        }
    }

    /// Set memory limit
    pub fn with_memory(mut self, bytes: usize) -> Self {
        self.max_memory = bytes;
        self
    }

    /// Set time limit
    pub fn with_time_ms(mut self, ms: u64) -> Self {
        self.max_time_ms = ms;
        self
    }
}
