//! Bounded, sanitized compiler diagnostics.
//!
//! Diagnostics never carry ANSI escapes, absolute host paths, raw source
//! excerpts, or Rust debug formatting. Only canonical pack-relative origins are
//! preserved so that reports stay deterministic across platforms.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::PatternCompilerError;

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(rename_all = "snake_case")]
pub enum PatternDiagnosticSeverity {
    Error,
    Warning,
}

impl PatternDiagnosticSeverity {
    /// Errors sort before warnings so the most severe entry survives truncation.
    fn rank(self) -> u8 {
        match self {
            Self::Error => 0,
            Self::Warning => 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct PatternCompilerDiagnostic {
    pub severity: PatternDiagnosticSeverity,
    pub code: String,
    pub title: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
}

/// Remove ANSI escape sequences and control characters, collapse the result to
/// single-space-separated text, and truncate on a char boundary.
///
/// Truncation is byte-bounded but never splits a UTF-8 scalar, so the output is
/// always valid UTF-8 and identical for identical input.
pub fn sanitize_text(value: &str, max_bytes: usize) -> String {
    let mut out = String::with_capacity(value.len().min(max_bytes));
    let mut chars = value.chars().peekable();
    let mut pending_space = false;
    while let Some(character) = chars.next() {
        // Drop CSI/OSC style escape sequences introduced by colorized output.
        if character == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                let _ = chars.next();
                for terminator in chars.by_ref() {
                    if terminator.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        if character.is_control() || character.is_whitespace() {
            if !out.is_empty() {
                pending_space = true;
            }
            continue;
        }
        if pending_space {
            if out.len() + 1 > max_bytes {
                return out;
            }
            out.push(' ');
            pending_space = false;
        }
        if out.len() + character.len_utf8() > max_bytes {
            return out;
        }
        out.push(character);
    }
    out
}

/// Where a diagnostic points, expressed only in pack-relative terms.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiagnosticOrigin<'a> {
    pub source_path: Option<&'a str>,
    pub line: Option<u32>,
    pub column: Option<u32>,
}

impl<'a> DiagnosticOrigin<'a> {
    pub fn at(source_path: &'a str, line: u32, column: u32) -> Self {
        Self {
            source_path: Some(source_path),
            line: Some(line),
            column: Some(column),
        }
    }
}

impl PatternCompilerDiagnostic {
    /// Build a diagnostic with every text field sanitized and bounded.
    pub fn sanitized(
        severity: PatternDiagnosticSeverity,
        code: &str,
        title: &str,
        message: &str,
        origin: DiagnosticOrigin<'_>,
        max_message_bytes: usize,
    ) -> Self {
        Self {
            severity,
            code: sanitize_text(code, 128),
            title: sanitize_text(title, 256),
            message: sanitize_text(message, max_message_bytes),
            source_path: origin.source_path.map(|path| sanitize_text(path, 4096)),
            line: origin.line,
            column: origin.column,
        }
    }

    /// Reject diagnostics whose content or origin would break the privacy and
    /// determinism rules for versioned reports.
    pub fn validate(&self, max_message_bytes: usize) -> Result<(), PatternCompilerError> {
        if self.code.is_empty() || self.code.len() > 128 {
            return Err(PatternCompilerError::ReportValidation(
                "diagnostic code is out of bounds".into(),
            ));
        }
        if self.title.len() > 256 || self.message.len() > max_message_bytes {
            return Err(PatternCompilerError::ReportValidation(
                "diagnostic text exceeds configured bounds".into(),
            ));
        }
        for text in [&self.code, &self.title, &self.message] {
            if text.chars().any(|c| c.is_control()) {
                return Err(PatternCompilerError::ReportValidation(
                    "diagnostic text contains control characters".into(),
                ));
            }
        }
        if let Some(path) = &self.source_path {
            // Only canonical pack-relative origins may appear in a report.
            pasol_patterns::normalize_relative_path(path).map_err(|_| {
                PatternCompilerError::ReportValidation(
                    "diagnostic origin is not a canonical pack-relative path".into(),
                )
            })?;
        }
        Ok(())
    }
}

/// Sort diagnostics into the stable documented order.
pub fn sort_diagnostics(diagnostics: &mut [PatternCompilerDiagnostic]) {
    diagnostics.sort_by(|a, b| {
        a.severity
            .rank()
            .cmp(&b.severity.rank())
            .then_with(|| a.code.cmp(&b.code))
            .then_with(|| a.source_path.cmp(&b.source_path))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.column.cmp(&b.column))
            .then_with(|| a.message.cmp(&b.message))
    });
}

/// Truncate a sorted diagnostic list to `max`, reporting whether entries were
/// dropped so the report can record the omission explicitly.
pub fn truncate_diagnostics(diagnostics: &mut Vec<PatternCompilerDiagnostic>, max: usize) -> bool {
    if diagnostics.len() > max {
        diagnostics.truncate(max);
        return true;
    }
    false
}
