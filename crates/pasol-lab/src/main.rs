#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use pasol_detection_sdk::{FeatureExtractor, ParserReport, validate_feature_report_json};
use pasol_features::PeFeatureExtractor;
use pasol_rules::{evaluate, load_pack, validate_rule_pack_json, validate_rule_report_json};
use pasol_static_score::score;

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
        feature_report: PathBuf,
        pack: PathBuf,
    },
    Score {
        feature_report: PathBuf,
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
            feature_report,
            pack,
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
        Commands::Score { feature_report } => {
            let report = serde_json::from_slice(&std::fs::read(feature_report)?)?;
            println!("{}", serde_json::to_string(&score(&report))?);
        }
    }
    Ok(())
}
