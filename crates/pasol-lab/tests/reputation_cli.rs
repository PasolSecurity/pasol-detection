#![allow(clippy::unwrap_used)]

use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_pasol-lab"))
        .args(args)
        .current_dir(root())
        .output()
        .unwrap()
}
fn temp() -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "pasol-reputation-cli-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn actual_binary_reputation_matrix_and_import_export() {
    let dir = temp();
    let store = dir.join("store.json");
    let imported = dir.join("import.json");
    let exported = dir.join("export.json");
    let benign = "a".repeat(64);
    let malicious = "b".repeat(64);
    let suspicious = "c".repeat(64);
    for (hash, state) in [
        (&benign, "known_benign"),
        (&malicious, "known_malicious"),
        (&suspicious, "suspicious"),
    ] {
        let output = run(&[
            "reputation",
            "add",
            hash,
            "--state",
            state,
            "--source",
            "fixture",
            "--store",
            store.to_str().unwrap(),
            "--format",
            "json",
        ]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
    }
    let unknown = run(&[
        "reputation",
        "lookup",
        &"d".repeat(64),
        "--store",
        store.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(unknown.status.success());
    assert!(String::from_utf8_lossy(&unknown.stdout).contains("\"state\":\"unknown\""));
    assert!(unknown.stderr.is_empty());
    let conflict = run(&[
        "reputation",
        "add",
        &benign,
        "--state",
        "known_malicious",
        "--source",
        "fixture",
        "--store",
        store.to_str().unwrap(),
    ]);
    assert!(conflict.status.success());
    let lookup = run(&[
        "reputation",
        "lookup",
        &benign,
        "--store",
        store.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(String::from_utf8_lossy(&lookup.stdout).contains("\"state\":\"suspicious\""));

    assert!(
        run(&[
            "reputation",
            "export",
            exported.to_str().unwrap(),
            "--store",
            store.to_str().unwrap(),
            "--format",
            "json"
        ])
        .status
        .success()
    );
    assert!(
        run(&[
            "reputation",
            "export",
            imported.to_str().unwrap(),
            "--store",
            store.to_str().unwrap(),
            "--format",
            "json"
        ])
        .status
        .success()
    );
    assert_eq!(fs::read(&exported).unwrap(), fs::read(&imported).unwrap());

    let invalid = run(&[
        "reputation",
        "lookup",
        "not-a-hash",
        "--store",
        store.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(invalid.status.code(), Some(4));
    assert!(invalid.stdout.is_empty());
    let bad_format = run(&[
        "reputation",
        "list",
        "--store",
        store.to_str().unwrap(),
        "--format",
        "yaml",
    ]);
    assert_eq!(bad_format.status.code(), Some(4));
    let corrupt = dir.join("corrupt.json");
    fs::write(&corrupt, b"not-json").unwrap();
    let invalid_store = run(&[
        "reputation",
        "validate-store",
        "--store",
        corrupt.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(invalid_store.status.code(), Some(4));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn import_rejects_exact_duplicates_without_changing_store() {
    let dir = temp();
    let store = dir.join("store.json");
    let input = dir.join("input.json");
    let hash = "e".repeat(64);
    assert!(
        run(&[
            "reputation",
            "add",
            &hash,
            "--state",
            "known_benign",
            "--source",
            "fixture",
            "--store",
            store.to_str().unwrap()
        ])
        .status
        .success()
    );
    fs::copy(&store, &input).unwrap();
    let before = fs::read(&store).unwrap();
    let rejected = run(&[
        "reputation",
        "import",
        input.to_str().unwrap(),
        "--store",
        store.to_str().unwrap(),
        "--mode",
        "reject-duplicates",
    ]);
    assert_eq!(rejected.status.code(), Some(4));
    assert_eq!(before, fs::read(&store).unwrap());
    let _ = fs::remove_dir_all(dir);
}
