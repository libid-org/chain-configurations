//! `libid-deploy` — apply per-network desired-state configuration to
//! chains. See the repository README for the full model.

use std::path::PathBuf;

use anyhow::{
    bail,
    Result,
};
use clap::{
    Args,
    Parser,
    Subcommand,
};
use libid_deploy::{
    apply,
    config::NetworkConfig,
    plan,
    rpc::RpcEndpoint,
    signer::SignerSource,
};

#[derive(Parser)]
#[command(name = "libid-deploy", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Where the JSON-RPC calls go — shared by every subcommand that contacts
/// a chain.
#[derive(Args)]
struct Rpc {
    /// JSON-RPC endpoint to use instead of the file's `network.rpc_url`,
    /// for a caller outside the environment the file names (e.g.
    /// http://127.0.0.1:8545 for a bare anvil on the host). Wins outright;
    /// the file is the default. Only the transport changes: the declared
    /// chain id and every address stay the file's. An unusable value is an
    /// error, never a fallback.
    #[arg(long, value_name = "URL")]
    rpc_url: Option<String>,
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
        #[command(flatten)]
        rpc: Rpc,
    },
    /// Compare desired state with the chain, read-only. Sends nothing.
    Plan {
        /// Path to the network TOML file.
        #[arg(long)]
        network: PathBuf,
        /// Emit the plan as JSON instead of the human rendering.
        #[arg(long)]
        json: bool,
        /// Print the canonical predicted address table (network-invariant,
        /// computed offline — works before the chain even exists) and exit
        /// without contacting the RPC. For config pre-fill.
        #[arg(long, conflicts_with = "rpc_url")]
        print_addresses: bool,
        #[command(flatten)]
        rpc: Rpc,
    },
    /// Converge the chain onto the network file. The file is declarative
    /// and never rewritten: everything deploys at its declared address.
    Apply {
        /// Path to the network TOML file.
        #[arg(long)]
        network: PathBuf,
        #[command(flatten)]
        rpc: Rpc,
        /// Signer spec: 64 hex chars = local private key, anything else =
        /// AWS KMS key id/alias/ARN. Defaults to `aws.kms_deployer` from
        /// the network file.
        #[arg(long)]
        signer: Option<String>,
        /// Comma-separated components to explicitly upgrade:
        /// notary-service, proof-verifier, identity-names,
        /// google-jwt-roots, x-platform-verifier,
        /// github-platform-verifier, google-platform-verifier. Each is a
        /// UUPS proxy; the entry address, its storage and its owner all
        /// survive.
        #[arg(long, value_delimiter = ',')]
        upgrade: Vec<apply::Upgrade>,
        /// Proceed without the interactive confirmation prompt.
        #[arg(long)]
        yes: bool,
        /// Required when the LibidFactory has no code on-chain (a virgin
        /// network): that first apply publishes the entire declared stack.
        /// With the factory present, apply converges incrementally.
        #[arg(long)]
        confirm_fresh_deploy: bool,
        /// Dev-chain mode: allow taking factory ownership from the baked
        /// genesis admin by impersonation. Only honoured when the RPC's
        /// web3_clientVersion reports anvil/hardhat; a real chain refuses.
        #[arg(long)]
        dev: bool,
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
        Command::Validate {
            network,
            check_rpc,
            rpc,
        } => {
            let cfg = NetworkConfig::load(&network)?;
            let rpc = RpcEndpoint::resolve(&cfg, rpc.rpc_url.as_deref())?;
            println!(
                "{} parses and validates (network {}, chain {}, canonical \
                 addresses); RPC endpoint {}",
                network.display(),
                cfg.network.name,
                cfg.network.chain_id,
                rpc.describe()
            );
            if check_rpc {
                let built = plan::build(&cfg, &rpc).await?;
                if built.chain_id_actual != built.chain_id_expected {
                    bail!(
                        "{} reports chain {} but the file says {}",
                        rpc.describe(),
                        built.chain_id_actual,
                        built.chain_id_expected
                    );
                }
                println!(
                    "RPC {} reachable and reports chain {}",
                    rpc.describe(),
                    built.chain_id_actual
                );
            }
        }
        Command::Plan {
            network,
            json,
            print_addresses,
            rpc,
        } => {
            if print_addresses {
                print!("{}", libid_deploy::names::render_address_table()?);
                return Ok(());
            }
            let cfg = NetworkConfig::load(&network)?;
            let rpc = RpcEndpoint::resolve(&cfg, rpc.rpc_url.as_deref())?;
            let built = plan::build(&cfg, &rpc).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&built)?);
            } else {
                print!("{}", built.render());
            }
        }
        Command::Apply {
            network,
            rpc,
            signer,
            upgrade,
            yes,
            confirm_fresh_deploy,
            dev,
        } => {
            let cfg = NetworkConfig::load(&network)?;
            let rpc = RpcEndpoint::resolve(&cfg, rpc.rpc_url.as_deref())?;
            let spec = signer.unwrap_or_else(|| cfg.aws.kms_deployer.clone());
            let signer = SignerSource::from_spec(&spec)?;

            if !yes {
                println!(
                    "About to APPLY {} against chain {} at {} via {}.",
                    network.display(),
                    cfg.network.chain_id,
                    rpc.describe(),
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
                dev,
            };
            let summary = apply::run(&network, &cfg, &rpc, &signer, &opts).await?;
            print!("{}", summary.render());
        }
    }
    Ok(())
}
