//! `libid-deploy` — apply per-network desired-state configuration to
//! chains. See the repository README for the full model.

use std::path::PathBuf;

use anyhow::{
    bail,
    Result,
};
use clap::{
    Parser,
    Subcommand,
};
use libid_deploy::{
    apply,
    config::NetworkConfig,
    plan,
    signer::SignerSource,
};

#[derive(Parser)]
#[command(name = "libid-deploy", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parse a network file and run sanity checks. Sends nothing.
    Validate {
        /// Path to the network TOML file.
        #[arg(long)]
        network: PathBuf,
        /// Also connect to the RPC and check it reports the configured
        /// chain id.
        #[arg(long)]
        check_rpc: bool,
    },
    /// Compare desired state with the chain, read-only. Sends nothing.
    Plan {
        /// Path to the network TOML file.
        #[arg(long)]
        network: PathBuf,
        /// Emit the plan as JSON instead of the human rendering.
        #[arg(long)]
        json: bool,
    },
    /// Converge the chain onto the network file, then record the deployed
    /// addresses back into it.
    Apply {
        /// Path to the network TOML file.
        #[arg(long)]
        network: PathBuf,
        /// Signer spec: 64 hex chars = local private key, anything else =
        /// AWS KMS key id/alias/ARN. Defaults to `aws.kms_deployer` from
        /// the network file.
        #[arg(long)]
        signer: Option<String>,
        /// Comma-separated components to explicitly upgrade:
        /// registry, wallet-factory, notary, bank, oidc-verifier.
        #[arg(long, value_delimiter = ',')]
        upgrade: Vec<apply::Upgrade>,
        /// Proceed without the interactive confirmation prompt.
        #[arg(long)]
        yes: bool,
        /// Required when [contracts] is entirely empty: a fresh deploy
        /// orphans anything already on the chain.
        #[arg(long)]
        confirm_fresh_deploy: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Validate { network, check_rpc } => {
            let cfg = NetworkConfig::load(&network)?;
            println!(
                "{} parses and validates (network {}, chain {})",
                network.display(),
                cfg.network.name,
                cfg.network.chain_id
            );
            if check_rpc {
                let built = plan::build(&cfg).await?;
                if built.chain_id_actual != built.chain_id_expected {
                    bail!(
                        "RPC reports chain {} but the file says {}",
                        built.chain_id_actual,
                        built.chain_id_expected
                    );
                }
                println!(
                    "RPC {} reachable and reports chain {}",
                    cfg.network.rpc_url, built.chain_id_actual
                );
            }
        }
        Command::Plan { network, json } => {
            let cfg = NetworkConfig::load(&network)?;
            let built = plan::build(&cfg).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&built)?);
            } else {
                print!("{}", built.render());
            }
        }
        Command::Apply {
            network,
            signer,
            upgrade,
            yes,
            confirm_fresh_deploy,
        } => {
            let cfg = NetworkConfig::load(&network)?;
            let spec = signer.unwrap_or_else(|| cfg.aws.kms_deployer.clone());
            let signer = SignerSource::from_spec(&spec)?;

            if !yes {
                println!(
                    "About to APPLY {} against chain {} via {}.",
                    network.display(),
                    cfg.network.chain_id,
                    signer.describe()
                );
                println!("Type 'yes' to continue:");
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                if line.trim() != "yes" {
                    bail!("aborted — nothing was sent");
                }
            }

            let opts = apply::Options {
                upgrades: upgrade,
                confirm_fresh_deploy,
            };
            let summary = apply::run(&network, &cfg, &signer, &opts).await?;
            print!("{}", summary.render());
        }
    }
    Ok(())
}
