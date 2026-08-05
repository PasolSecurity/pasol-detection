//! I3.1 contract tests: policy, limits, report determinism, schema validation,
//! diagnostic sanitization, and the compiled proof boundary.

use pasol_pattern_compiler::diagnostics::{sanitize_text, sort_diagnostics};
use pasol_pattern_compiler::{
    ALLOWED_MODULES, COMPILER_ADAPTER_ID, COMPILER_ENGINE, COMPILER_ENGINE_VERSION,
    COMPILER_REPORT_SCHEMA_VERSION, CompilerLimits, CompilerPolicy, DiagnosticOrigin,
    PatternCompileFailure, PatternCompilerDiagnostic, PatternCompilerError, PatternCompilerReport,
    PatternCompilerStatus, PatternDiagnosticSeverity, report::PatternCompilerDescriptor,
};
use pasol_patterns::{PatternEngineDescriptor, PatternPackIdentity, PatternSignatureState};

fn identity(state: PatternSignatureState) -> PatternPackIdentity {
    PatternPackIdentity {
        id: "pasol.test.patterns".into(),
        version: "1.0.0".into(),
        sha256: "a".repeat(64),
        signature_state: state,
    }
}

fn report(status: PatternCompilerStatus) -> PatternCompilerReport {
    let policy = CompilerPolicy::default();
    PatternCompilerReport {
        schema_version: COMPILER_REPORT_SCHEMA_VERSION.into(),
        adapter: PatternCompilerDescriptor::default(),
        engine: PatternEngineDescriptor {
            id: COMPILER_ENGINE.into(),
            version: COMPILER_ENGINE_VERSION.into(),
        },
        policy: policy.descriptor(),
        pattern_pack: identity(PatternSignatureState::Verified),
        status,
        source_count: 1,
        namespace_count: 1,
        rule_count: 0,
        public_rule_count: 0,
        private_rule_count: 0,
        global_rule_count: 0,
        pattern_count: 0,
        imported_modules: Vec::new(),
        warnings: Vec::new(),
        errors: Vec::new(),
        diagnostics_truncated: false,
    }
}

fn compiled_report() -> PatternCompilerReport {
    let mut value = report(PatternCompilerStatus::Compiled);
    value.rule_count = 2;
    value.public_rule_count = 1;
    value.private_rule_count = 1;
    value.pattern_count = 3;
    value.imported_modules = vec!["pe".into()];
    value
}

fn diagnostic(
    severity: PatternDiagnosticSeverity,
    code: &str,
    path: Option<&str>,
    line: Option<u32>,
) -> PatternCompilerDiagnostic {
    let origin = DiagnosticOrigin {
        source_path: path,
        line,
        column: Some(1),
    };
    PatternCompilerDiagnostic::sanitized(severity, code, "title", "message", origin, 4096)
}

#[test]
fn default_policy_is_valid_and_pins_the_approved_engine_and_modules() {
    let policy = CompilerPolicy::default();
    policy.validate().expect("default policy is valid");
    assert_eq!(policy.engine, "yara-x");
    assert_eq!(policy.engine_version, "1.19.0");
    assert_eq!(
        policy.engine_semver().expect("engine semver"),
        semver::Version::new(1, 19, 0)
    );
    assert_eq!(policy.allowed_modules, vec!["hash", "math", "pe", "string"]);
    for module in ALLOWED_MODULES {
        assert!(policy.permits_module(module));
    }
    for module in [
        "console", "cuckoo", "dotnet", "elf", "macho", "magic", "time",
    ] {
        assert!(!policy.permits_module(module), "{module} must be forbidden");
    }
}

#[test]
fn policy_identity_engine_and_module_drift_is_rejected() {
    let base = CompilerPolicy::default();

    let mut wrong_engine = base.clone();
    wrong_engine.engine = "yara".into();
    assert!(matches!(
        wrong_engine.validate(),
        Err(PatternCompilerError::UnsupportedEngine(_))
    ));

    let mut wrong_version = base.clone();
    wrong_version.engine_version = "1.20.0".into();
    assert!(matches!(
        wrong_version.validate(),
        Err(PatternCompilerError::UnsupportedEngine(_))
    ));

    // A future engine module must stay prohibited until an explicit decision.
    let mut extra_module = base.clone();
    extra_module.allowed_modules.push("dotnet".into());
    assert!(matches!(
        extra_module.validate(),
        Err(PatternCompilerError::InvalidPolicy(_))
    ));

    let mut missing_module = base.clone();
    missing_module.allowed_modules.retain(|m| m != "pe");
    assert!(matches!(
        missing_module.validate(),
        Err(PatternCompilerError::InvalidPolicy(_))
    ));

    let mut duplicate_module = base.clone();
    duplicate_module.allowed_modules.push("pe".into());
    assert!(matches!(
        duplicate_module.validate(),
        Err(PatternCompilerError::InvalidPolicy(_))
    ));

    for (field, value) in [
        ("policy_id", "other"),
        ("policy_version", "2.0.0"),
        ("metadata_policy", "other"),
        ("limits_profile", "other"),
    ] {
        let mut policy = base.clone();
        match field {
            "policy_id" => policy.policy_id = value.into(),
            "policy_version" => policy.policy_version = value.into(),
            "metadata_policy" => policy.metadata_policy = value.into(),
            _ => policy.limits_profile = value.into(),
        }
        assert!(
            matches!(
                policy.validate(),
                Err(PatternCompilerError::InvalidPolicy(_))
            ),
            "{field} drift must be rejected"
        );
    }
}

#[test]
fn limits_reject_zero_and_values_above_the_hard_ceiling() {
    CompilerLimits::default()
        .validate()
        .expect("defaults are valid");
    CompilerLimits::ceilings()
        .validate()
        .expect("ceilings are valid");

    let zero = CompilerLimits {
        max_rules: 0,
        ..Default::default()
    };
    assert!(matches!(
        zero.validate(),
        Err(PatternCompilerError::InvalidPolicy(_))
    ));

    let over = CompilerLimits {
        max_rules: CompilerLimits::ceilings().max_rules + 1,
        ..Default::default()
    };
    assert!(matches!(
        over.validate(),
        Err(PatternCompilerError::InvalidPolicy(_))
    ));

    let over_report = CompilerLimits {
        max_report_bytes: CompilerLimits::ceilings().max_report_bytes + 1,
        ..Default::default()
    };
    assert!(matches!(
        over_report.validate(),
        Err(PatternCompilerError::InvalidPolicy(_))
    ));
}

#[test]
fn compiled_report_validates_against_schema_and_round_trips_byte_stably() {
    let limits = CompilerLimits::default();
    let value = compiled_report();
    let json = value
        .to_validated_json(&limits)
        .expect("compiled report validates");
    let parsed = PatternCompilerReport::from_validated_json(&json, &limits)
        .expect("compiled report parses back");
    assert_eq!(parsed, value);

    // Serialize, deserialize, reserialize must be byte-stable.
    let first = serde_json::to_vec(&value).expect("serialize");
    let round: PatternCompilerReport = serde_json::from_slice(&first).expect("deserialize");
    let second = serde_json::to_vec(&round).expect("reserialize");
    assert_eq!(first, second);
}

#[test]
fn compiled_report_cannot_carry_errors_warnings_or_global_rules() {
    let limits = CompilerLimits::default();

    let mut with_error = compiled_report();
    with_error.errors.push(diagnostic(
        PatternDiagnosticSeverity::Error,
        "e",
        None,
        None,
    ));
    assert!(matches!(
        with_error.validate(&limits),
        Err(PatternCompilerError::ReportValidation(_))
    ));

    // Zero-warning policy: any surviving warning rejects the pack.
    let mut with_warning = compiled_report();
    with_warning.warnings.push(diagnostic(
        PatternDiagnosticSeverity::Warning,
        "w",
        None,
        None,
    ));
    assert!(matches!(
        with_warning.validate(&limits),
        Err(PatternCompilerError::ReportValidation(_))
    ));

    let mut with_global = compiled_report();
    with_global.global_rule_count = 1;
    assert!(matches!(
        with_global.validate(&limits),
        Err(PatternCompilerError::GlobalRuleForbidden(_))
    ));
}

#[test]
fn rejected_report_cannot_claim_compiled_rules() {
    let limits = CompilerLimits::default();
    let mut rejected = report(PatternCompilerStatus::Rejected);
    rejected.errors.push(diagnostic(
        PatternDiagnosticSeverity::Error,
        "syntax",
        Some("rules/marker.yar"),
        Some(3),
    ));
    rejected
        .to_validated_json(&limits)
        .expect("rejected report validates");

    let mut claiming = rejected.clone();
    claiming.rule_count = 1;
    claiming.public_rule_count = 1;
    assert!(matches!(
        claiming.validate(&limits),
        Err(PatternCompilerError::ReportValidation(_))
    ));
}

#[test]
fn rule_counts_must_sum_and_bounds_are_enforced() {
    let limits = CompilerLimits::default();

    let mut mismatched = compiled_report();
    mismatched.public_rule_count = 5;
    assert!(matches!(
        mismatched.validate(&limits),
        Err(PatternCompilerError::ReportValidation(_))
    ));

    let mut too_many = compiled_report();
    too_many.rule_count = limits.max_rules + 1;
    too_many.public_rule_count = too_many.rule_count;
    too_many.private_rule_count = 0;
    assert!(matches!(
        too_many.validate(&limits),
        Err(PatternCompilerError::ResourceLimit(_))
    ));

    let mut too_many_patterns = compiled_report();
    too_many_patterns.pattern_count = limits.max_patterns_total + 1;
    assert!(matches!(
        too_many_patterns.validate(&limits),
        Err(PatternCompilerError::ResourceLimit(_))
    ));
}

#[test]
fn reducing_a_limit_cannot_make_an_oversized_report_valid() {
    let mut value = compiled_report();
    value.rule_count = 100;
    value.public_rule_count = 100;
    value.private_rule_count = 0;

    let generous = CompilerLimits::default();
    assert!(value.validate(&generous).is_ok());

    let tight = CompilerLimits {
        max_rules: 10,
        ..Default::default()
    };
    assert!(matches!(
        value.validate(&tight),
        Err(PatternCompilerError::ResourceLimit(_))
    ));
}

#[test]
fn non_allowlisted_imports_are_rejected_in_reports() {
    let limits = CompilerLimits::default();
    let mut value = compiled_report();
    value.imported_modules = vec!["dotnet".into()];
    assert!(matches!(
        value.validate(&limits),
        Err(PatternCompilerError::ModuleForbidden(_))
    ));
}

#[test]
fn unsupported_schema_and_engine_are_rejected() {
    let limits = CompilerLimits::default();

    let mut bad_schema = compiled_report();
    bad_schema.schema_version = "2.0.0".into();
    assert!(matches!(
        bad_schema.validate(&limits),
        Err(PatternCompilerError::ReportValidation(_))
    ));

    let mut bad_engine = compiled_report();
    bad_engine.engine.id = "yara".into();
    assert!(matches!(
        bad_engine.validate(&limits),
        Err(PatternCompilerError::UnsupportedEngine(_))
    ));

    let mut bad_adapter = compiled_report();
    bad_adapter.adapter.id = "other".into();
    assert!(matches!(
        bad_adapter.validate(&limits),
        Err(PatternCompilerError::ReportValidation(_))
    ));
}

#[test]
fn normalization_is_deterministic_idempotent_and_order_independent() {
    let limits = CompilerLimits::default();
    let mut first = report(PatternCompilerStatus::Rejected);
    first.imported_modules = vec!["pe".into(), "hash".into(), "pe".into()];
    first.errors = vec![
        diagnostic(
            PatternDiagnosticSeverity::Error,
            "b",
            Some("rules/z.yar"),
            Some(9),
        ),
        diagnostic(
            PatternDiagnosticSeverity::Error,
            "a",
            Some("rules/a.yar"),
            Some(1),
        ),
    ];

    let mut second = first.clone();
    second.imported_modules.reverse();
    second.errors.reverse();

    first.normalize(&limits);
    second.normalize(&limits);
    assert_eq!(first, second, "diagnostic order must not affect the report");
    assert_eq!(first.imported_modules, vec!["hash", "pe"]);
    assert_eq!(first.errors[0].code, "a");

    let mut again = first.clone();
    again.normalize(&limits);
    assert_eq!(first, again, "normalize must be idempotent");

    let a = serde_json::to_vec(&first).expect("serialize");
    let b = serde_json::to_vec(&second).expect("serialize");
    assert_eq!(a, b, "identical inputs must produce identical bytes");
}

#[test]
fn diagnostics_sort_errors_before_warnings_and_truncate_deterministically() {
    let limits = CompilerLimits {
        max_diagnostics: 2,
        ..Default::default()
    };

    let mut value = report(PatternCompilerStatus::Rejected);
    value.errors = vec![
        diagnostic(PatternDiagnosticSeverity::Error, "c", None, None),
        diagnostic(PatternDiagnosticSeverity::Error, "a", None, None),
        diagnostic(PatternDiagnosticSeverity::Error, "b", None, None),
    ];
    value.normalize(&limits);
    assert_eq!(value.errors.len(), 2);
    assert_eq!(value.errors[0].code, "a");
    assert_eq!(value.errors[1].code, "b");
    assert!(
        value.diagnostics_truncated,
        "dropped diagnostics must be recorded explicitly"
    );

    let mut mixed = vec![
        diagnostic(PatternDiagnosticSeverity::Warning, "a", None, None),
        diagnostic(PatternDiagnosticSeverity::Error, "z", None, None),
    ];
    sort_diagnostics(&mut mixed);
    assert_eq!(mixed[0].severity, PatternDiagnosticSeverity::Error);
}

#[test]
fn diagnostic_text_is_sanitized_of_ansi_controls_and_bounded() {
    // Every control or whitespace run collapses to a single separator. NUL
    // separates rather than disappearing, so distinct tokens never silently
    // merge into one identifier.
    let dirty = "\u{1b}[31merror\u{1b}[0m\tin\nrule\u{0}name";
    let clean = sanitize_text(dirty, 4096);
    assert_eq!(clean, "error in rule name");
    assert!(!clean.contains('\u{1b}'));
    assert!(!clean.chars().any(|c| c.is_control()));

    // Truncation is byte-bounded but never splits a UTF-8 scalar.
    let multibyte = "é".repeat(64);
    let truncated = sanitize_text(&multibyte, 9);
    assert!(truncated.len() <= 9);
    assert_eq!(truncated, "é".repeat(4));

    let built = PatternCompilerDiagnostic::sanitized(
        PatternDiagnosticSeverity::Error,
        "code",
        "title",
        &"m".repeat(9_000),
        DiagnosticOrigin::at("rules/a.yar", 1, 2),
        4_096,
    );
    assert_eq!(built.message.len(), 4_096);
    built.validate(4_096).expect("bounded diagnostic is valid");
}

#[test]
fn diagnostic_origins_must_be_canonical_pack_relative_paths() {
    for bad in [
        "/abs/rules/a.yar",
        "C:/rules/a.yar",
        "rules\\a.yar",
        "../rules/a.yar",
    ] {
        let value = PatternCompilerDiagnostic {
            severity: PatternDiagnosticSeverity::Error,
            code: "c".into(),
            title: "t".into(),
            message: "m".into(),
            source_path: Some(bad.into()),
            line: None,
            column: None,
        };
        assert!(
            matches!(
                value.validate(4096),
                Err(PatternCompilerError::ReportValidation(_))
            ),
            "{bad} must be rejected as a report origin"
        );
    }

    let good = PatternCompilerDiagnostic {
        severity: PatternDiagnosticSeverity::Error,
        code: "c".into(),
        title: "t".into(),
        message: "m".into(),
        source_path: Some("rules/a.yar".into()),
        line: Some(1),
        column: Some(2),
    };
    good.validate(4096).expect("canonical origin is accepted");
}

#[test]
fn oversized_report_is_rejected_by_serialized_byte_length() {
    let limits = CompilerLimits {
        max_report_bytes: 256,
        ..Default::default()
    };
    let mut value = report(PatternCompilerStatus::Rejected);
    for index in 0..64 {
        value.errors.push(diagnostic(
            PatternDiagnosticSeverity::Error,
            &format!("code-{index:03}"),
            Some("rules/a.yar"),
            Some(index),
        ));
    }
    assert!(matches!(
        value.validate(&limits),
        Err(PatternCompilerError::ResourceLimit(_))
    ));
}

#[test]
fn development_and_verified_identities_both_serialize_and_validate() {
    let limits = CompilerLimits::default();
    for state in [
        PatternSignatureState::Verified,
        PatternSignatureState::Development,
    ] {
        let mut value = compiled_report();
        value.pattern_pack = identity(state);
        value
            .to_validated_json(&limits)
            .expect("both trust states produce valid reports");
    }
}

#[test]
fn error_codes_are_stable_and_distinguish_policy_rejections() {
    assert_eq!(
        PatternCompilerError::IncludeForbidden.code(),
        "include_forbidden"
    );
    assert_eq!(
        PatternCompilerError::ModuleForbidden("dotnet".into()).code(),
        "module_forbidden"
    );
    assert!(PatternCompilerError::WarningRejected.is_policy_rejection());
    assert!(!PatternCompilerError::Internal("x".into()).is_policy_rejection());
    assert!(!PatternCompilerError::UnverifiedInput.is_policy_rejection());
}

#[test]
fn failure_carries_evidence_without_a_compiled_pack() {
    let failure = PatternCompileFailure::new(
        report(PatternCompilerStatus::Rejected),
        PatternCompilerError::CompilerRejected,
    );
    assert_eq!(failure.report.status, PatternCompilerStatus::Rejected);
    assert_eq!(failure.error, PatternCompilerError::CompilerRejected);
    assert_eq!(failure.to_string(), "compiler rejected the pattern pack");
}

/// The compiled proof object must not be constructible or forgeable from
/// outside the crate, and must not be deserializable from untrusted JSON.
///
/// `CompiledPatternPack` has no public constructor and no public fields, so a
/// forging attempt fails to compile. That is enforced structurally here by
/// inspecting every `derive` attribute in the crate root for serde support.
#[test]
fn compiled_pack_proof_boundary_holds() {
    let source = include_str!("../src/lib.rs");

    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("#[derive(") {
            assert!(
                !trimmed.contains("Serialize") && !trimmed.contains("Deserialize"),
                "proof types must never derive serde support: {trimmed}"
            );
        }
    }
    assert!(
        !source.contains("impl Serialize") && !source.contains("impl Deserialize"),
        "proof types must never hand-implement serde"
    );
    let impl_block = source
        .split_once("impl CompiledPatternPack {")
        .and_then(|(_, rest)| rest.split_once("\n}"))
        .map(|(block, _)| block)
        .expect("CompiledPatternPack impl block is present");
    assert!(
        impl_block.contains("pub(crate) fn new("),
        "CompiledPatternPack construction must remain crate-private"
    );
    assert!(
        !impl_block.contains("pub fn new("),
        "CompiledPatternPack must expose no public constructor"
    );
}

#[test]
fn adapter_identity_is_fixed() {
    assert_eq!(COMPILER_ADAPTER_ID, "pasol-pattern-compiler");
    assert_eq!(PatternCompilerDescriptor::default().id, COMPILER_ADAPTER_ID);
}
