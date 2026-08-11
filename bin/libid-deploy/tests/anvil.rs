//! Anvil integration tests. The critical one is the full cycle: an empty
//! network file → `apply --confirm-fresh-deploy` → the file is rewritten
//! with the deployed addresses → a second apply deploys nothing and the
//! plan is clean. Requires the `anvil` binary on PATH (foundry).

use std::path::PathBuf;

use alloy::{
    node_bindings::AnvilInstance,
    primitives::Address,
    providers::{
        Provider,
        ProviderBuilder,
    },
};
use libid_contracts::{
    bindings::login::{
        IRegistryAdmin,
        WalletFactory,
    },
    deploy::{
        deploy_behind_proxy,
        deploy_contract,
    },
    Artifacts,
};
use libid_deploy::{
    apply,
    config::NetworkConfig,
    plan::{
        self,
        Status,
    },
    signer::SignerSource,
};

// The canonical anvil account #0 key. Public test material, not a secret.
const ANVIL_KEY: &str =
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Anvil with the code-size limit off: the generated UltraHonk verifiers
/// exceed EIP-170, exactly like the real target chains that raise it.
fn spawn_anvil() -> AnvilInstance {
    alloy::node_bindings::Anvil::new()
        .arg("--disable-code-size-limit")
        .try_spawn()
        .expect("anvil spawns (is foundry on PATH?)")
}

/// A network file with an empty [contracts] section, everything requested:
/// both login verifiers and the full identity stack.
fn empty_network_file(dir: &std::path::Path, rpc: &str) -> PathBuf {
    let path = dir.join("anvil-local.toml");
    let text = format!(
        r#"# Test network file — comments must survive the apply rewrite.
[network]
name = "anvil-local"
chain_id = 31337
rpc_url = "{rpc}"

[aws]
region = "eu-central-1"
kms_deployer = "alias/never-used-in-tests"

[accounts]
notary = "0x1111111111111111111111111111111111111111"
oidc_notary = "0x3333333333333333333333333333333333333333"
backend = "0x2222222222222222222222222222222222222222"

[contracts]
bank = ""
registry = ""
wallet_factory = ""
notary_registry = ""
x_zk_verifier = ""
google_oidc_verifier = ""

[identity]
identity_names = ""
github_identity_verifier = ""
x_identity_verifier = ""
google_identity_verifier = ""

[platforms]
x_client_id = "test-x-client-id"
google_client_id = "test-google-client-id.apps.googleusercontent.com"
github_bot_handle = "testbot"
x_bot_handle = "testbot"

[[tokens]]
symbol = "$TIA"
address = "0x0000000000000000000000000000000000000000"

[templates]
"api.x.com" = [
    "@testbot honor @{{recipient}} with {{amount}} of {{token}}",
    "@testbot honor with {{amount}} {{token}}",
]
"api.github.com" = "@testbot honor @{{recipient}} with {{amount}} of {{token}}"
"#
    );
    std::fs::write(&path, text).expect("test config writes");
    path
}

/// The critical test: empty config → fresh apply → config rewritten →
/// second apply is a no-op and the plan is clean → explicit upgrades work.
#[tokio::test]
async fn full_apply_cycle_converges_and_records() {
    let anvil = spawn_anvil();
    let dir = tempfile::tempdir().unwrap();
    let path = empty_network_file(dir.path(), &anvil.endpoint());
    let signer = SignerSource::from_spec(ANVIL_KEY).unwrap();

    // Without --confirm-fresh-deploy an empty [contracts] must refuse.
    let cfg = NetworkConfig::load(&path).unwrap();
    assert!(cfg.contracts_all_empty().unwrap());
    let err = apply::run(&path, &cfg, &signer, &apply::Options::default())
        .await
        .unwrap_err();
    assert!(format!("{err}").contains("FRESH DEPLOY"), "got: {err}");

    // First apply: everything deploys.
    let opts = apply::Options {
        upgrades: vec![],
        confirm_fresh_deploy: true,
    };
    let summary = apply::run(&path, &cfg, &signer, &opts).await.unwrap();
    let deployed: Vec<&str> = summary.deployed.iter().map(|(c, _)| c.as_str()).collect();
    for component in [
        "contracts.wallet_factory",
        "contracts.registry",
        "contracts.notary_registry",
        "contracts.bank",
        "contracts.x_zk_verifier",
        "contracts.google_oidc_verifier",
        "identity.identity_names",
        "identity.github_identity_verifier",
        "identity.x_identity_verifier",
        "identity.identity_jwks_roots",
        "identity.google_identity_verifier",
    ] {
        assert!(
            deployed.contains(&component),
            "missing {component}: {deployed:?}"
        );
    }
    assert_eq!(summary.recorded.len(), summary.deployed.len());

    // The file was rewritten: every output key populated, comments intact.
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("# Test network file — comments must survive"));
    let cfg = NetworkConfig::load(&path).unwrap();
    assert!(!cfg.contracts_all_empty().unwrap());
    let identity = cfg.identity.as_ref().unwrap();
    assert!(!identity.identity_names.is_empty());
    assert!(!identity.github_identity_verifier.is_empty());
    assert!(identity
        .identity_jwks_roots
        .as_deref()
        .is_some_and(|v| !v.is_empty()));

    // The plan against the converged chain has nothing to deploy and no
    // warnings.
    let built = plan::build(&cfg).await.unwrap();
    assert!(
        !built.has_deploys(),
        "plan still wants deploys:\n{}",
        built.render()
    );
    assert!(
        !built.items.iter().any(|i| i.status == Status::Warn),
        "plan warns:\n{}",
        built.render()
    );

    // Second apply: pure reconcile — nothing deployed, config untouched.
    let before = std::fs::read_to_string(&path).unwrap();
    let summary = apply::run(&path, &cfg, &signer, &opts).await.unwrap();
    assert!(
        summary.deployed.is_empty(),
        "re-apply deployed: {:?}",
        summary.deployed
    );
    assert!(summary.recorded.is_empty());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), before);

    // Explicit upgrades: UUPS for the registry, facet REPLACE for the bank,
    // redeploy+repoint for the OIDC verifier (its address must change).
    let oidc_before = cfg.contracts.google_oidc_verifier.clone();
    let opts = apply::Options {
        upgrades: vec![
            apply::Upgrade::Registry,
            apply::Upgrade::Bank,
            apply::Upgrade::OidcVerifier,
        ],
        confirm_fresh_deploy: false,
    };
    let summary = apply::run(&path, &cfg, &signer, &opts).await.unwrap();
    assert!(summary.upgraded.iter().any(|u| u == "registry"));
    assert!(summary.upgraded.iter().any(|u| u == "bank"));
    assert!(summary
        .upgraded
        .iter()
        .any(|u| u.contains("google_oidc_verifier")));
    let cfg = NetworkConfig::load(&path).unwrap();
    assert_ne!(
        cfg.contracts.google_oidc_verifier, oidc_before,
        "the OIDC verifier REPLACE must record its new address"
    );

    // And the chain is still coherent afterwards.
    let built = plan::build(&cfg).await.unwrap();
    assert!(!built.has_deploys());
    assert!(!built.items.iter().any(|i| i.status == Status::Warn));
}

/// Plan against a partially-deployed chain: the login stack exists (deployed
/// with the crate directly), the bank does not — the plan must say so.
#[tokio::test]
async fn plan_reports_missing_and_present_components() {
    let anvil = spawn_anvil();
    let provider = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(
            ANVIL_KEY
                .parse::<alloy::signers::local::PrivateKeySigner>()
                .unwrap(),
        ))
        .connect_http(anvil.endpoint().parse().unwrap());
    let deployer = provider.get_accounts().await.unwrap()[0];
    let artifacts = Artifacts::embedded();

    let wallet_impl = deploy_contract(
        &provider,
        artifacts.bytecode("WebWallet").unwrap(),
        "WebWallet (impl)",
    )
    .await
    .unwrap();
    let factory = deploy_behind_proxy(
        &provider,
        &artifacts,
        "WalletFactory",
        &WalletFactory::initializeCall {
            owner_: deployer,
            walletImpl_: wallet_impl,
            registry_: Address::ZERO,
        },
        None,
    )
    .await
    .unwrap();
    let registry = deploy_behind_proxy(
        &provider,
        &artifacts,
        "Registry",
        &IRegistryAdmin::initializeCall {
            _notary: Address::repeat_byte(0x11),
            _backend: Address::repeat_byte(0x22),
            _walletFactory: factory,
            _owner: deployer,
        },
        None,
    )
    .await
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("partial.toml");
    std::fs::write(
        &path,
        format!(
            r#"[network]
name = "anvil-partial"
chain_id = 31337
rpc_url = "{rpc}"

[aws]
region = "eu-central-1"
kms_deployer = "alias/never-used-in-tests"

[accounts]
notary = "0x1111111111111111111111111111111111111111"
backend = "0x2222222222222222222222222222222222222222"

[contracts]
registry = "{registry:#x}"
wallet_factory = "{factory:#x}"

[platforms]
x_client_id = "test-x-client-id"
"#,
            rpc = anvil.endpoint(),
        ),
    )
    .unwrap();

    let cfg = NetworkConfig::load(&path).unwrap();
    let built = plan::build(&cfg).await.unwrap();
    let status_of = |component: &str| {
        built
            .items
            .iter()
            .find(|i| i.component == component)
            .unwrap_or_else(|| {
                panic!("no plan item for {component}:\n{}", built.render())
            })
            .status
    };
    assert_eq!(status_of("contracts.registry"), Status::Ok);
    assert_eq!(status_of("contracts.wallet_factory"), Status::Ok);
    assert_eq!(status_of("contracts.bank"), Status::Deploy);
    assert_eq!(status_of("contracts.notary_registry"), Status::Deploy);
    // x_client_id is set and nothing is wired: a deploy is pending.
    assert_eq!(status_of("contracts.x_zk_verifier"), Status::Deploy);
    // No OIDC notary/client id: skipped, not deployed.
    assert_eq!(status_of("contracts.google_oidc_verifier"), Status::Skipped);
    // Identity section absent: skipped.
    assert_eq!(status_of("identity"), Status::Skipped);
}
