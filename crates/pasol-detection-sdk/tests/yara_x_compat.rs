#![forbid(unsafe_code)]

#[test]
fn pinned_yara_x_compiles_and_scans_harmless_bytes() {
    let mut compiler = yara_x::Compiler::new();
    compiler
        .add_source(
            r#"
rule pasol_phase_i_compat {
    meta:
        id = "pasol.phase_i.compat"
        category = "synthetic_test"
    strings:
        $marker = "PASOL_PHASE_I_COMPAT"
    condition:
        $marker
}
"#,
        )
        .expect("harmless compatibility rule compiles");

    let rules = compiler.build();
    let mut scanner = yara_x::Scanner::new(&rules);
    let results = scanner
        .scan(b"prefix PASOL_PHASE_I_COMPAT suffix")
        .expect("harmless compatibility input scans");

    assert!(
        results
            .matching_rules()
            .any(|rule| rule.identifier() == "pasol_phase_i_compat")
    );
}
