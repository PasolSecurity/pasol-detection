#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use pasol_detection_sdk::{FeatureExtractor, ParserReport, validate_feature_report_json};
use pasol_features::PeFeatureExtractor;
use pasol_rules::{
    KeyStatus, TrustedKey, TrustedKeyStore, evaluate, load_pack, validate_rule_pack_json,
    validate_rule_report_json,
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
        Commands::Score { feature_report } => {
            let report = serde_json::from_slice(&std::fs::read(feature_report)?)?;
            println!("{}", serde_json::to_string(&score(&report))?);
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
