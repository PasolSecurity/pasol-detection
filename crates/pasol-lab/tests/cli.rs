#![allow(clippy::unwrap_used)]

use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_pasol-lab"))
        .args(args)
        .current_dir(root())
        .output()
        .expect("pasol-lab runs")
}
fn temp_dir() -> PathBuf {
    let serial = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("pasol-lab-cli-{}-{serial}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("temp directory");
    path
}
fn copy_pack(dir: &std::path::Path) -> PathBuf {
    let pack = dir.join("pack.json");
    fs::copy(root().join("rule-packs/pasol-starter.json"), &pack).expect("copy pack");
    pack
}
fn text(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string() + &String::from_utf8_lossy(&output.stderr)
}

#[test]
fn signed_pack_cli_matrix_rejects_tampering_and_unknown_or_revoked_keys() {
    let dir = temp_dir();
    let private = dir.join("private.key");
    let public = dir.join("public.key");
    let store = dir.join("trusted.json");
    let signed = dir.join("signed.json");
    let pack = copy_pack(&dir);
    let generated = run(&[
        "rules",
        "key",
        "generate",
        "cli-key",
        private.to_str().unwrap(),
        public.to_str().unwrap(),
    ]);
    assert!(generated.status.success());
    assert!(!text(&generated).contains(&fs::read_to_string(&private).unwrap()));
    assert!(
        run(&[
            "rules",
            "key",
            "trust",
            "cli-key",
            public.to_str().unwrap(),
            "--store",
            store.to_str().unwrap()
        ])
        .status
        .success()
    );
    let signed_out = run(&[
        "rules",
        "pack",
        "sign",
        pack.to_str().unwrap(),
        "--key",
        private.to_str().unwrap(),
        "--key-id",
        "cli-key",
        "--output",
        signed.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(signed_out.status.success());
    assert!(text(&signed_out).contains("\"status\":\"signed\""));
    assert!(!text(&signed_out).contains(&fs::read_to_string(&private).unwrap()));
    let first = fs::read(&signed).unwrap();
    assert!(
        run(&[
            "rules",
            "pack",
            "verify",
            signed.to_str().unwrap(),
            "--store",
            store.to_str().unwrap(),
            "--format",
            "json"
        ])
        .status
        .success()
    );
    let second = run(&[
        "rules",
        "pack",
        "sign",
        pack.to_str().unwrap(),
        "--key",
        private.to_str().unwrap(),
        "--key-id",
        "cli-key",
        "--output",
        signed.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(second.status.success());
    assert_eq!(first, fs::read(&signed).unwrap());
    let mut changed = fs::read_to_string(&signed).unwrap();
    changed = changed.replace("pasol-starter-rules", "changed");
    fs::write(&signed, changed).unwrap();
    assert_eq!(
        run(&[
            "rules",
            "pack",
            "verify",
            signed.to_str().unwrap(),
            "--store",
            store.to_str().unwrap()
        ])
        .status
        .code(),
        Some(4)
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn revoked_unknown_invalid_and_unsigned_packs_fail_without_private_key_leakage() {
    let dir = temp_dir();
    let private = dir.join("private.key");
    let public = dir.join("public.key");
    let store = dir.join("trusted.json");
    let signed = dir.join("signed.json");
    let pack = copy_pack(&dir);
    assert!(
        run(&[
            "rules",
            "key",
            "generate",
            "cli-key",
            private.to_str().unwrap(),
            public.to_str().unwrap()
        ])
        .status
        .success()
    );
    let trusted = run(&[
        "rules",
        "key",
        "trust",
        "cli-key",
        public.to_str().unwrap(),
        "--store",
        store.to_str().unwrap(),
    ]);
    assert!(trusted.status.success(), "{}", text(&trusted));
    assert!(
        run(&[
            "rules",
            "pack",
            "sign",
            pack.to_str().unwrap(),
            "--key",
            private.to_str().unwrap(),
            "--key-id",
            "cli-key",
            "--output",
            signed.to_str().unwrap()
        ])
        .status
        .success()
    );
    assert!(
        run(&[
            "rules",
            "key",
            "revoke",
            "cli-key",
            "--store",
            store.to_str().unwrap()
        ])
        .status
        .success()
    );
    let revoked = run(&[
        "rules",
        "pack",
        "verify",
        signed.to_str().unwrap(),
        "--store",
        store.to_str().unwrap(),
    ]);
    assert_eq!(revoked.status.code(), Some(4));
    let unknown_store = dir.join("unknown.json");
    let unknown = run(&[
        "rules",
        "pack",
        "verify",
        signed.to_str().unwrap(),
        "--store",
        unknown_store.to_str().unwrap(),
    ]);
    assert_eq!(unknown.status.code(), Some(4));
    let bad_private = dir.join("bad.key");
    fs::write(&bad_private, "not-a-private-key").unwrap();
    let bad = run(&[
        "rules",
        "pack",
        "sign",
        pack.to_str().unwrap(),
        "--key",
        bad_private.to_str().unwrap(),
        "--key-id",
        "cli-key",
        "--output",
        dir.join("bad.json").to_str().unwrap(),
    ]);
    assert_eq!(bad.status.code(), Some(4));
    assert!(!text(&bad).contains("not-a-private-key"));
    let unsigned = run(&[
        "rules",
        "pack",
        "verify",
        pack.to_str().unwrap(),
        "--store",
        store.to_str().unwrap(),
    ]);
    assert_eq!(unsigned.status.code(), Some(4));
    let _ = fs::remove_dir_all(dir);
}
