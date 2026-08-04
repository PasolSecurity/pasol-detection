#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use pasol_detection_sdk::{FeatureExtractor, ParserReport, validate_feature_report_json};
use pasol_features::PeFeatureExtractor;
use pasol_reputation::{
    LocalStore, ReputationEntry, ReputationState, now_utc, report, validate_report_json,
    validate_sha256, validate_store_json,
};
use pasol_rules::{
    KeyStatus, RuleLimits, SignedRulePack, TrustedKey, TrustedKeyStore, evaluate, load_pack,
    sign_pack, validate_rule_pack_json, validate_rule_report_json, verify_signed_pack,
};
use pasol_static_score::score;
use rand_core::OsRng;

#[derive(Debug, Parser)]
#[command(
    name = "pasol-lab",
    version,
    about = "PasolSecurity Stage 2 development and validation CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Features {
        parser_report: PathBuf,
        #[arg(long)]
        format: Option<String>,
    },
    Rules {
        #[command(subcommand)]
        command: RuleCommands,
    },
    Score {
        feature_report: PathBuf,
    },
    Reputation {
        #[command(subcommand)]
        command: ReputationCommands,
    },
}

#[derive(Debug, Subcommand)]
enum ReputationCommands {
    Lookup {
        sha256: String,
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        format: Option<String>,
    },
    List {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        format: Option<String>,
    },
    Add {
        sha256: String,
        #[arg(long)]
        state: String,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        store: PathBuf,
    },
    Remove {
        sha256: String,
        #[arg(long)]
        store: PathBuf,
    },
    ValidateStore {
        #[arg(long)]
        store: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum RuleCommands {
    Evaluate {
        feature_report: PathBuf,
        pack: PathBuf,
    },
    Key {
        #[command(subcommand)]
        command: KeyCommands,
    },
    Pack {
        #[command(subcommand)]
        command: PackCommands,
    },
}
#[derive(Debug, Subcommand)]
enum PackCommands {
    Sign {
        pack: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        format: Option<String>,
    },
    Verify {
        pack: PathBuf,
        #[arg(long, default_value = "trusted-keys.json")]
        store: PathBuf,
        #[arg(long)]
        format: Option<String>,
    },
}
#[derive(Debug, Subcommand)]
enum KeyCommands {
    Generate {
        key_id: String,
        private_key: PathBuf,
        public_key: PathBuf,
    },
    List {
        #[arg(long, default_value = "trusted-keys.json")]
        store: PathBuf,
    },
    Trust {
        key_id: String,
        public_key: PathBuf,
        #[arg(long, default_value = "trusted-keys.json")]
        store: PathBuf,
    },
    Revoke {
        key_id: String,
        #[arg(long, default_value = "trusted-keys.json")]
        store: PathBuf,
    },
    Remove {
        key_id: String,
        #[arg(long, default_value = "trusted-keys.json")]
        store: PathBuf,
    },
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::from(4)
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Features {
            parser_report,
            format,
        } => {
            if format.as_deref().is_some_and(|value| value != "json") {
                return Err("only --format json is supported".into());
            }
            let report: ParserReport = serde_json::from_slice(&std::fs::read(parser_report)?)?;
            let extracted = PeFeatureExtractor.extract(&report)?;
            let value = serde_json::to_value(&extracted)?;
            validate_feature_report_json(&value)
                .map_err(|error| format!("feature schema validation failed: {error}"))?;
            println!("{}", serde_json::to_string(&extracted)?);
        }
        Commands::Rules {
            command:
                RuleCommands::Evaluate {
                    feature_report,
                    pack,
                },
        } => {
            let report_value: serde_json::Value =
                serde_json::from_slice(&std::fs::read(feature_report)?)?;
            let report = serde_json::from_value(report_value)?;
            let pack_value: serde_json::Value = serde_json::from_slice(&std::fs::read(&pack)?)?;
            validate_rule_pack_json(&pack_value)
                .map_err(|error| format!("rule-pack schema validation failed: {error}"))?;
            let pack = load_pack(&serde_json::to_vec(&pack_value)?)?;
            let output = evaluate(&pack, &report);
            let output_value = serde_json::to_value(&output)?;
            validate_rule_report_json(&output_value)
                .map_err(|error| format!("rule-report schema validation failed: {error}"))?;
            println!("{}", serde_json::to_string(&output_value)?);
        }
        Commands::Rules {
            command: RuleCommands::Key { command },
        } => match command {
            KeyCommands::Generate {
                key_id,
                private_key,
                public_key,
            } => {
                let signing = SigningKey::generate(&mut OsRng);
                std::fs::write(private_key, hex(&signing.to_bytes()))?;
                std::fs::write(public_key, hex(&signing.verifying_key().to_bytes()))?;
                eprintln!("generated Ed25519 key {key_id}; protect the private-key file");
            }
            KeyCommands::List { store } => {
                let store = if store.exists() {
                    TrustedKeyStore::load(&store)?
                } else {
                    TrustedKeyStore::empty()
                };
                println!("{}", serde_json::to_string(&store)?);
            }
            KeyCommands::Trust {
                key_id,
                public_key,
                store,
            } => {
                let mut keys = if store.exists() {
                    TrustedKeyStore::load(&store)?
                } else {
                    TrustedKeyStore::empty()
                };
                let value = String::from_utf8(std::fs::read(public_key)?)?;
                keys.add(TrustedKey {
                    key_id,
                    algorithm: "ed25519".into(),
                    public_key_hex: value.trim().into(),
                    status: KeyStatus::Active,
                    trusted_from: "manual".into(),
                    revoked_at: None,
                    replacement_key_id: None,
                })?;
                keys.save_atomic(&store)?;
            }
            KeyCommands::Revoke { key_id, store } => {
                let mut keys = TrustedKeyStore::load(&store)?;
                keys.revoke(&key_id, "manual".into())?;
                keys.save_atomic(&store)?;
            }
            KeyCommands::Remove { key_id, store } => {
                let mut keys = TrustedKeyStore::load(&store)?;
                keys.remove(&key_id)?;
                keys.save_atomic(&store)?;
            }
        },
        Commands::Rules {
            command: RuleCommands::Pack { command },
        } => match command {
            PackCommands::Sign {
                pack,
                key,
                key_id,
                output,
                format,
            } => {
                if format.as_deref().is_some_and(|value| value != "json") {
                    return Err("only --format json is supported".into());
                }
                let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&pack)?)?;
                validate_rule_pack_json(&value)
                    .map_err(|error| format!("rule-pack schema validation failed: {error}"))?;
                let model = load_pack(&serde_json::to_vec(&value)?)?;
                let private_hex = String::from_utf8(std::fs::read(key)?)?;
                let secret = parse_hex_32(private_hex.trim()).ok_or("invalid private-key data")?;
                let signing = SigningKey::from_bytes(&secret);
                let signed = sign_pack(&model, &key_id, &signing, &RuleLimits::default())?;
                let bytes = serde_json::to_vec_pretty(&signed)?;
                let temp = output.with_extension("tmp");
                std::fs::write(&temp, &bytes)?;
                std::fs::rename(&temp, &output)?;
                let mut keys = std::collections::BTreeMap::new();
                keys.insert(key_id, signing.verifying_key());
                let _ = verify_signed_pack(&bytes, &keys, &RuleLimits::default())?;
                if format.as_deref() == Some("json") {
                    println!(
                        "{{\"status\":\"signed\",\"manifest_sha256\":\"{}\"}}",
                        signed.manifest_sha256
                    );
                } else {
                    println!("signed");
                }
            }
            PackCommands::Verify {
                pack,
                store,
                format,
            } => {
                if format.as_deref().is_some_and(|value| value != "json") {
                    return Err("only --format json is supported".into());
                }
                let bytes = std::fs::read(&pack)?;
                let signed: SignedRulePack = serde_json::from_slice(&bytes)?;
                let store = TrustedKeyStore::load(&store)?;
                let keys = store.verifying_keys()?;
                let verified = verify_signed_pack(&bytes, &keys, &RuleLimits::default())?;
                if format.as_deref() == Some("json") {
                    println!(
                        "{{\"status\":\"verified\",\"key_id\":\"{}\",\"pack_id\":\"{}\"}}",
                        signed.key_id, verified.id
                    );
                } else {
                    println!("verified: {}", signed.key_id);
                }
            }
        },
        Commands::Score { feature_report } => {
            let report = serde_json::from_slice(&std::fs::read(feature_report)?)?;
            println!("{}", serde_json::to_string(&score(&report))?);
        }
        Commands::Reputation { command } => match command {
            ReputationCommands::Lookup { sha256, store, .. } => {
                validate_sha256(&sha256)?;
                let result = LocalStore::load(&store)?.lookup(&sha256)?;
                let output = report(&sha256, result)?;
                let value = serde_json::to_value(&output)?;
                validate_report_json(&value)
                    .map_err(|e| format!("reputation schema validation failed: {e}"))?;
                println!("{}", serde_json::to_string(&output)?);
            }
            ReputationCommands::List { store, .. } => {
                let value = serde_json::to_value(LocalStore::load(&store)?)?;
                validate_store_json(&value)
                    .map_err(|e| format!("store schema validation failed: {e}"))?;
                println!("{}", serde_json::to_string(&value)?);
            }
            ReputationCommands::Add {
                sha256,
                state,
                reason,
                source,
                store,
            } => {
                validate_sha256(&sha256)?;
                let state = serde_json::from_str::<ReputationState>(&format!("\"{state}\""))?;
                let mut local = if store.exists() {
                    LocalStore::load(&store)?
                } else {
                    LocalStore::empty()
                };
                local.entries.push(ReputationEntry {
                    sha256,
                    state,
                    reason,
                    source,
                    labels: Vec::new(),
                    created_at: now_utc(),
                    expires_at: None,
                    enabled: true,
                });
                local.save_atomic(&store)?;
                println!("ok");
            }
            ReputationCommands::Remove { sha256, store } => {
                validate_sha256(&sha256)?;
                let mut local = LocalStore::load(&store)?;
                local.entries.retain(|entry| entry.sha256 != sha256);
                local.save_atomic(&store)?;
                println!("ok");
            }
            ReputationCommands::ValidateStore { store } => {
                let value = serde_json::to_value(LocalStore::load(&store)?)?;
                validate_store_json(&value)
                    .map_err(|e| format!("store schema validation failed: {e}"))?;
                println!("ok");
            }
        },
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_hex_32(input: &str) -> Option<[u8; 32]> {
    if input.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, pair) in input.as_bytes().chunks_exact(2).enumerate() {
        out[index] = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
    }
    Some(out)
}
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
