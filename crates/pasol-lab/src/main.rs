#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use pasol_detection_sdk::{FeatureExtractor, ParserReport};
use pasol_features::PeFeatureExtractor;
use pasol_rules::{evaluate, load_pack};
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
            println!("{}", serde_json::to_string(&extracted)?);
        }
        Commands::Rules {
            feature_report,
            pack,
        } => {
            let report = serde_json::from_slice(&std::fs::read(feature_report)?)?;
            let pack = load_pack(&std::fs::read(pack)?)?;
            println!("{}", serde_json::to_string(&evaluate(&pack, &report))?);
        }
        Commands::Score { feature_report } => {
            let report = serde_json::from_slice(&std::fs::read(feature_report)?)?;
            println!("{}", serde_json::to_string(&score(&report))?);
        }
    }
    Ok(())
}
