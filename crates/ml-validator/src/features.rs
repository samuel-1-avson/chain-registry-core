//! Feature Extraction for ML-Based Threat Detection
//!
//! This module provides AST-based feature extraction for multiple programming languages.

use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, instrument};

/// Errors during feature extraction
#[derive(Error, Debug)]
pub enum FeatureError {
    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Unsupported language: {0}")]
    UnsupportedLanguage(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Features extracted from a package for ML analysis
#[derive(Debug, Clone, Default)]
pub struct PackageFeatures {
    // Basic metrics
    pub file_count: u32,
    pub total_lines: u32,
    pub code_lines: u32,
    pub comment_lines: u32,
    pub blank_lines: u32,

    // AST metrics
    pub ast_depth: u32,
    pub function_count: u32,
    pub class_count: u32,
    pub dependency_count: u32,

    // Security indicators
    pub eval_count: u32,
    pub network_calls: u32,
    pub file_system_ops: u32,
    pub dynamic_imports: u32,
    pub obfuscation_indicators: u32,

    // Code complexity
    pub cyclomatic_complexity: f32,
    pub cognitive_complexity: f32,
    pub entropy: f32,

    // Behavioral indicators
    pub string_literals: u32,
    pub hex_strings: u32,
    pub base64_strings: u32,
    pub regex_patterns: u32,

    // Additional features for extensibility
    pub custom_features: HashMap<String, f32>,
}

impl PackageFeatures {
    /// Convert features to a normalized vector for ML model
    pub fn to_vector(&self) -> Vec<f32> {
        vec![
            // Normalize to 0-1 range
            (self.file_count as f32 / 100.0).min(1.0),
            (self.total_lines as f32 / 10000.0).min(1.0),
            (self.code_lines as f32 / 10000.0).min(1.0),
            (self.comment_lines as f32 / 10000.0).min(1.0),
            (self.blank_lines as f32 / 10000.0).min(1.0),
            (self.ast_depth as f32 / 50.0).min(1.0),
            (self.function_count as f32 / 500.0).min(1.0),
            (self.class_count as f32 / 100.0).min(1.0),
            (self.dependency_count as f32 / 200.0).min(1.0),
            (self.eval_count as f32 / 10.0).min(1.0),
            (self.network_calls as f32 / 50.0).min(1.0),
            (self.file_system_ops as f32 / 50.0).min(1.0),
            (self.dynamic_imports as f32 / 20.0).min(1.0),
            (self.obfuscation_indicators as f32 / 50.0).min(1.0),
            (self.cyclomatic_complexity / 100.0).min(1.0),
            (self.cognitive_complexity / 100.0).min(1.0),
            (self.entropy / 8.0).min(1.0),
            (self.string_literals as f32 / 1000.0).min(1.0),
            (self.hex_strings as f32 / 100.0).min(1.0),
            (self.base64_strings as f32 / 100.0).min(1.0),
            (self.regex_patterns as f32 / 50.0).min(1.0),
        ]
    }

    /// Add a custom feature
    pub fn add_feature(&mut self, name: &str, value: f32) {
        self.custom_features.insert(name.to_string(), value);
    }

    /// Merge features from multiple files
    pub fn merge(&mut self, other: &PackageFeatures) {
        self.file_count += other.file_count;
        self.total_lines += other.total_lines;
        self.code_lines += other.code_lines;
        self.comment_lines += other.comment_lines;
        self.blank_lines += other.blank_lines;
        self.ast_depth = self.ast_depth.max(other.ast_depth);
        self.function_count += other.function_count;
        self.class_count += other.class_count;
        self.dependency_count += other.dependency_count;
        self.eval_count += other.eval_count;
        self.network_calls += other.network_calls;
        self.file_system_ops += other.file_system_ops;
        self.dynamic_imports += other.dynamic_imports;
        self.obfuscation_indicators += other.obfuscation_indicators;
        self.cyclomatic_complexity += other.cyclomatic_complexity;
        self.cognitive_complexity += other.cognitive_complexity;
        self.entropy = (self.entropy + other.entropy) / 2.0;
        self.string_literals += other.string_literals;
        self.hex_strings += other.hex_strings;
        self.base64_strings += other.base64_strings;
        self.regex_patterns += other.regex_patterns;
    }
}

/// Feature extractor for different programming languages
pub struct FeatureExtractor;

impl FeatureExtractor {
    /// Extract features from a package based on its ecosystem
    #[instrument(skip(code), level = "debug")]
    pub fn extract(ecosystem: &str, code: &str) -> Result<PackageFeatures, FeatureError> {
        debug!("Extracting features for ecosystem: {}", ecosystem);

        match ecosystem {
            "npm" | "node" | "javascript" | "typescript" => Self::extract_js_features(code),
            "pypi" | "python" => Self::extract_python_features(code),
            "cargo" | "rust" => Self::extract_rust_features(code),
            _ => Err(FeatureError::UnsupportedLanguage(ecosystem.to_string())),
        }
    }

    /// Extract features from JavaScript/TypeScript code
    pub fn extract_js_features(code: &str) -> Result<PackageFeatures, FeatureError> {
        use tree_sitter::Parser;

        let mut parser = Parser::new();
        parser
            .set_language(tree_sitter_javascript::language())
            .map_err(|e| FeatureError::ParseError(e.to_string()))?;

        let tree = parser
            .parse(code, None)
            .ok_or_else(|| FeatureError::ParseError("Failed to parse JS code".to_string()))?;

        let root = tree.root_node();
        let mut features = PackageFeatures::default();

        // Basic metrics
        features.total_lines = code.lines().count() as u32;
        features.code_lines = code
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.trim().starts_with("//"))
            .count() as u32;
        features.comment_lines = code
            .lines()
            .filter(|l| l.trim().starts_with("//") || l.trim().starts_with("/*"))
            .count() as u32;
        features.blank_lines = code.lines().filter(|l| l.trim().is_empty()).count() as u32;

        // AST analysis
        features.ast_depth = Self::calculate_ast_depth(&root);
        features.function_count = Self::count_nodes(&root, "function") as u32;
        features.class_count = Self::count_nodes(&root, "class") as u32;

        // Security indicators
        features.eval_count = Self::count_pattern(code, r"eval\s*\(") as u32;
        features.eval_count += Self::count_pattern(code, r"Function\s*\(") as u32;
        features.network_calls = Self::count_pattern(code, r"fetch\s*\(") as u32;
        features.network_calls += Self::count_pattern(code, r"axios\.") as u32;
        features.network_calls += Self::count_pattern(code, r"https?\.") as u32;
        features.file_system_ops = Self::count_pattern(code, r"fs\.") as u32;
        // Detect fs require
        features.file_system_ops += code.matches("require(").count() as u32;
        features.dynamic_imports = Self::count_pattern(code, r"import\s*\(") as u32;
        features.dynamic_imports += Self::count_pattern(code, r"require\s*\(") as u32;

        // Obfuscation detection
        features.obfuscation_indicators = Self::count_obfuscation_indicators(code) as u32;

        // Entropy calculation
        features.entropy = Self::shannon_entropy(code);

        // String analysis
        features.string_literals = Self::count_pattern(code, r#"['"`][^'"`]*['"`]"#) as u32;
        features.hex_strings = Self::count_pattern(code, r"0x[0-9a-fA-F]{8,}") as u32;
        features.base64_strings = Self::count_pattern(code, r"[A-Za-z0-9+/]{40,}={0,2}") as u32;
        features.regex_patterns = Self::count_pattern(code, r"/[^/]+/[gimuy]*") as u32;

        // Complexity metrics (simplified)
        features.cyclomatic_complexity = features.function_count as f32 * 1.5;
        features.cognitive_complexity = features.ast_depth as f32 * 2.0;

        Ok(features)
    }

    /// Extract features from Python code
    pub fn extract_python_features(code: &str) -> Result<PackageFeatures, FeatureError> {
        use tree_sitter::Parser;

        let mut parser = Parser::new();
        parser
            .set_language(tree_sitter_python::language())
            .map_err(|e| FeatureError::ParseError(e.to_string()))?;

        let tree = parser
            .parse(code, None)
            .ok_or_else(|| FeatureError::ParseError("Failed to parse Python code".to_string()))?;

        let root = tree.root_node();
        let mut features = PackageFeatures::default();

        // Basic metrics
        features.total_lines = code.lines().count() as u32;
        features.code_lines = code
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.trim().starts_with("#"))
            .count() as u32;

        // AST analysis
        features.ast_depth = Self::calculate_ast_depth(&root);
        features.function_count = Self::count_nodes(&root, "function_definition") as u32;
        features.class_count = Self::count_nodes(&root, "class_definition") as u32;

        // Security indicators
        features.eval_count = Self::count_pattern(code, r"eval\s*\(") as u32;
        features.eval_count += Self::count_pattern(code, r"exec\s*\(") as u32;
        features.network_calls = Self::count_pattern(code, r"requests\.") as u32;
        features.network_calls += Self::count_pattern(code, r"urllib") as u32;
        features.file_system_ops = Self::count_pattern(code, r"open\s*\(") as u32;
        features.file_system_ops += Self::count_pattern(code, r"os\.(path|remove|rename)") as u32;
        features.dynamic_imports = Self::count_pattern(code, r"__import__") as u32;
        features.dynamic_imports += Self::count_pattern(code, r"importlib") as u32;

        // Obfuscation and entropy
        features.obfuscation_indicators = Self::count_obfuscation_indicators(code) as u32;
        features.entropy = Self::shannon_entropy(code);

        // String analysis
        features.string_literals = Self::count_pattern(code, r#"['"][^'"]*['""#) as u32;
        features.hex_strings = Self::count_pattern(code, r"0x[0-9a-fA-F]{8,}") as u32;
        features.base64_strings = Self::count_pattern(code, r"[A-Za-z0-9+/]{40,}={0,2}") as u32;

        Ok(features)
    }

    /// Extract features from Rust code
    pub fn extract_rust_features(code: &str) -> Result<PackageFeatures, FeatureError> {
        use tree_sitter::Parser;

        let mut parser = Parser::new();
        parser
            .set_language(tree_sitter_rust::language())
            .map_err(|e| FeatureError::ParseError(e.to_string()))?;

        let tree = parser
            .parse(code, None)
            .ok_or_else(|| FeatureError::ParseError("Failed to parse Rust code".to_string()))?;

        let root = tree.root_node();
        let mut features = PackageFeatures::default();

        // Basic metrics
        features.total_lines = code.lines().count() as u32;
        features.code_lines = code
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.trim().starts_with("//"))
            .count() as u32;

        // AST analysis
        features.ast_depth = Self::calculate_ast_depth(&root);
        features.function_count = Self::count_nodes(&root, "function_item") as u32;
        features.class_count = Self::count_nodes(&root, "struct_item") as u32;
        features.class_count += Self::count_nodes(&root, "enum_item") as u32;

        // Security indicators (less relevant for compiled langs but still useful)
        features.network_calls = Self::count_pattern(code, r"std::net::") as u32;
        features.network_calls += Self::count_pattern(code, r"tokio::net::") as u32;
        features.file_system_ops = Self::count_pattern(code, r"std::fs::") as u32;
        features.dynamic_imports = Self::count_pattern(code, r"unsafe") as u32;

        // Entropy
        features.entropy = Self::shannon_entropy(code);

        Ok(features)
    }

    /// Calculate AST depth recursively
    fn calculate_ast_depth(node: &tree_sitter::Node) -> u32 {
        let mut max_depth = 0u32;
        let mut cursor = node.walk();

        for child in node.children(&mut cursor) {
            let child_depth = Self::calculate_ast_depth(&child);
            max_depth = max_depth.max(child_depth + 1);
        }

        max_depth
    }

    /// Count nodes of a specific type
    fn count_nodes(node: &tree_sitter::Node, node_type: &str) -> usize {
        let mut count = if node.kind() == node_type { 1 } else { 0 };
        let mut cursor = node.walk();

        for child in node.children(&mut cursor) {
            count += Self::count_nodes(&child, node_type);
        }

        count
    }

    /// Count regex pattern matches in code
    fn count_pattern(code: &str, pattern: &str) -> usize {
        use regex::Regex;

        Regex::new(pattern)
            .ok()
            .map(|re| re.find_iter(code).count())
            .unwrap_or(0)
    }

    /// Count obfuscation indicators
    fn count_obfuscation_indicators(code: &str) -> usize {
        let mut count = 0;

        // Hex string concatenation
        count += Self::count_pattern(code, r"String\.fromCharCode");
        count += Self::count_pattern(code, r"\\x[0-9a-fA-F]{2}");

        // String splitting/obfuscation
        count += Self::count_pattern(code, r"\.split\s*\(");
        count += Self::count_pattern(code, r"\.join\s*\(");

        // Excessive character codes
        count += Self::count_pattern(code, r"charCodeAt");

        // Base64 indicators
        count += Self::count_pattern(code, r"atob|btoa");
        count += Self::count_pattern(code, r"Buffer\.from\s*\([^,]+,\s*base64\s*\)");

        count
    }

    /// Calculate Shannon entropy of text
    fn shannon_entropy(text: &str) -> f32 {
        use std::collections::HashMap;

        let len = text.len() as f32;
        if len == 0.0 {
            return 0.0;
        }

        let mut char_counts: HashMap<char, u32> = HashMap::new();
        for c in text.chars() {
            *char_counts.entry(c).or_insert(0) += 1;
        }

        let mut entropy = 0.0f32;
        for &count in char_counts.values() {
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }

        entropy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_js_feature_extraction() {
        let code = r#"
            function greet(name) {
                console.log("Hello, " + name);
            }
            
            // Safe code
            const result = eval("1 + 1"); // Suspicious
        "#;

        let features = FeatureExtractor::extract_js_features(code).unwrap();

        assert!(features.total_lines > 0);
        assert!(features.function_count >= 1);
        assert!(features.eval_count >= 1);
    }

    #[test]
    fn test_entropy_calculation() {
        let low_entropy = "hello world hello world";
        let high_entropy = "a8f4e2b9c1d7e3f5a2b8c4d6e1f9a3b7";

        let low = FeatureExtractor::shannon_entropy(low_entropy);
        let high = FeatureExtractor::shannon_entropy(high_entropy);

        assert!(high > low, "Random string should have higher entropy");
    }
}
