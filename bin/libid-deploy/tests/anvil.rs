//! Anvil integration tests. The critical one is the DECLARATIVE cycle: a
//! config pre-filled with the canonical address table → `apply
//! --confirm-fresh-deploy` on a VIRGIN anvil → everything lands AT the
//! declared addresses → a second apply (no flag needed: the factory now has
//! code) is a no-op — and the config file is byte-identical through the
//! whole cycle, because apply never rewrites it. Requires the `anvil`
//! binary on PATH (foundry).
//!
//! Every anvil here starts with `--disable-default-create2-deployer`, so
//! the tests prove the full bootstrap: keyless deployer install → factory
//! at its canonical predicted address → dev ownership impersonation →
//! every entry contract CREATE3-deployed at `predict_address(factory,
//! name)` — exactly the addresses the file declared before the chain even
//! existed.

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
    bindings::{
        factory::LibidFactory,
        login::{
            IRegistryAdmin,
            Registry,
            WalletFactory,
        },
        notary::Notary,
    },
    deploy::{
        deploy_behind_proxy,
        deploy_contract,
    },
    factory::{
        predict_address,
        predict_factory_address,
    },
    Artifacts,
};
use libid_deploy::{
    apply,
    config::NetworkConfig,
    names,
    plan::{
        self,
        Status,
    },
    signer::SignerSource,
};

// The canonical anvil account #0 key. Public test material, not a secret.
const ANVIL_KEY: &str =
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
// The address of anvil account #0 — the declared operational owner in the
// local dev config, exactly as the real local-dev files describe it.
const ANVIL_OWNER: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

/// Anvil with the code-size limit off (the generated UltraHonk verifiers
/// exceed EIP-170, exactly like the real target chains that raise it) and
/// WITHOUT its predeployed CREATE2 deployer, so apply's install path is
/// what puts it there.
fn spawn_anvil() -> AnvilInstance {
    alloy::node_bindings::Anvil::new()
        .arg("--disable-code-size-limit")
        .arg("--disable-default-create2-deployer")
        .try_spawn()
        .expect("anvil spawns (is foundry on PATH?)")
}

/// A network file PRE-FILLED with the full canonical address table —
/// written before the chain has anything on it, because every address is a
/// pure function of its name. Everything requested: both login verifiers
/// and the full identity stack. Owner: the anvil #0 wallet, explicitly.
fn prefilled_network_file(dir: &std::path::Path, rpc: &str) -> PathBuf {
    let artifacts = Artifacts::embedded();
    let factory = predict_factory_address(&artifacts).unwrap();
    let addr = |name: &str| format!("{:#x}", predict_address(factory, name));
    let path = dir.join("anvil-local.toml");
    let text = format!(
        r#"# Test network file — apply must NEVER rewrite it.
[network]
name = "anvil-local"
chain_id = 31337
rpc_url = "{rpc}"

[aws]
region = "eu-central-1"
kms_deployer = "alias/never-used-in-tests"

[accounts]
notary = "0x1111111111111111111111111111111111111111"
backend = "0x2222222222222222222222222222222222222222"
# The operational owner: the anvil #0 wallet, explicitly.
owner = "{ANVIL_OWNER}"

# Declared canonical addresses — identical on every EVM network.
[contracts]
factory = "{factory:#x}"
notary = "{notary}"
bank = "{bank}"
registry = "{registry}"
wallet_factory = "{wallet_factory}"
x_zk_verifier = "{x_zk}"
google_oidc_verifier = "{oidc}"

[identity]
identity_names = "{id_names}"
github_identity_verifier = "{gh}"
x_identity_verifier = "{x_id}"
google_identity_verifier = "{g_id}"
identity_jwks_roots = "{jwks}"

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
"#,
        notary = addr(names::NOTARY),
        bank = addr(names::BANK),
        registry = addr(names::REGISTRY),
        wallet_factory = addr(names::WALLET_FACTORY),
        x_zk = addr(names::X_ZK_VERIFIER),
        oidc = addr(names::GOOGLE_OIDC_VERIFIER),
        id_names = addr(names::IDENTITY_NAMES),
        gh = addr(names::GITHUB_IDENTITY_VERIFIER),
        x_id = addr(names::X_IDENTITY_VERIFIER),
        g_id = addr(names::GOOGLE_IDENTITY_VERIFIER),
        jwks = addr(names::IDENTITY_JWKS_ROOTS),
    );
    std::fs::write(&path, text).expect("test config writes");
    path
}

/// Every canonical component the full config declares, as `(config value,
/// factory name)` pairs read from the network file.
fn canonical_pairs(cfg: &NetworkConfig) -> Vec<(String, &'static str)> {
    let identity = cfg.identity.as_ref().expect("identity stack declared");
    vec![
        (cfg.contracts.notary.clone(), names::NOTARY),
        (cfg.contracts.wallet_factory.clone(), names::WALLET_FACTORY),
        (cfg.contracts.registry.clone(), names::REGISTRY),
        (cfg.contracts.bank.clone(), names::BANK),
        (cfg.contracts.x_zk_verifier.clone(), names::X_ZK_VERIFIER),
        (
            cfg.contracts.google_oidc_verifier.clone(),
            names::GOOGLE_OIDC_VERIFIER,
        ),
        (identity.identity_names.clone(), names::IDENTITY_NAMES),
        (
            identity.github_identity_verifier.clone(),
            names::GITHUB_IDENTITY_VERIFIER,
        ),
        (
            identity.x_identity_verifier.clone().unwrap_or_default(),
            names::X_IDENTITY_VERIFIER,
        ),
        (
            identity
                .google_identity_verifier
                .clone()
                .unwrap_or_default(),
            names::GOOGLE_IDENTITY_VERIFIER,
        ),
        (
            identity.identity_jwks_roots.clone().unwrap_or_default(),
            names::IDENTITY_JWKS_ROOTS,
        ),
    ]
}

/// Assert every declared canonical address equals
/// `predict_address(factory, name)` — the CREATE3 name-determinism proof —
/// and that the chain has CODE at each of them.
async fn assert_declared_and_present<P: Provider>(
    cfg: &NetworkConfig,
    factory: Address,
    provider: &P,
) {
    for (declared, name) in canonical_pairs(cfg) {
        let predicted = predict_address(factory, name);
        assert_eq!(
            declared.to_lowercase(),
            format!("{predicted:#x}"),
            "{name} must be declared at its predicted CREATE3 address"
        );
        let code = provider.get_code_at(predicted).await.unwrap();
        assert!(
            !code.is_empty(),
            "{name} declared at {predicted:#x} must have code after apply"
        );
    }
}

/// The critical test: pre-filled declarative config → fresh apply on a
/// virgin anvil lands everything AT the declared addresses → second apply
/// is a no-op without any flag → the config file is BYTE-IDENTICAL through
/// the whole cycle → factory ownership ends at `[accounts].owner` →
/// explicit upgrades stay green.
#[tokio::test]
async fn declarative_apply_cycle_never_touches_the_config() {
    let anvil = spawn_anvil();
    let dir = tempfile::tempdir().unwrap();
    let path = prefilled_network_file(dir.path(), &anvil.endpoint());
    let original_bytes = std::fs::read_to_string(&path).unwrap();
    let signer = SignerSource::from_spec(ANVIL_KEY).unwrap();
    let cfg = NetworkConfig::load(&path).unwrap();

    // The chain is VIRGIN (no factory code), so apply without
    // --confirm-fresh-deploy must refuse — the guard keys on CHAIN STATE,
    // not on config emptiness (the config is fully populated!).
    let err = apply::run(&path, &cfg, &signer, &apply::Options::default())
        .await
        .unwrap_err();
    assert!(format!("{err}").contains("FRESH DEPLOY"), "got: {err}");
    assert!(format!("{err}").contains("VIRGIN"), "got: {err}");

    // First apply: everything deploys, at exactly the declared addresses.
    let fresh = apply::Options {
        upgrades: vec![],
        confirm_fresh_deploy: true,
        dev: false, // anvil is auto-detected; the flag must not be needed
    };
    let summary = apply::run(&path, &cfg, &signer, &fresh).await.unwrap();
    let deployed: Vec<&str> = summary.deployed.iter().map(|(c, _)| c.as_str()).collect();
    for component in [
        "contracts.factory",
        "contracts.notary",
        "contracts.wallet_factory",
        "contracts.registry",
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

    // THE determinism assertion: apply never rewrote the file.
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        original_bytes,
        "apply must leave the config byte-identical"
    );

    // Everything sits where the file declared it before the chain existed.
    let artifacts = Artifacts::embedded();
    let factory_addr = predict_factory_address(&artifacts).unwrap();
    let read_provider =
        ProviderBuilder::new().connect_http(anvil.endpoint().parse().unwrap());
    assert_eq!(
        cfg.contracts.factory.to_lowercase(),
        format!("{factory_addr:#x}"),
        "the declared factory must be the canonical predicted one"
    );
    assert_declared_and_present(&cfg, factory_addr, &read_provider).await;

    // Factory ownership ended at the declared operational owner.
    let owner = LibidFactory::new(factory_addr, &read_provider)
        .owner()
        .call()
        .await
        .unwrap();
    assert_eq!(
        owner,
        ANVIL_OWNER.parse::<Address>().unwrap(),
        "factory ownership must end at [accounts].owner"
    );

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

    // Second apply: NO --confirm-fresh-deploy needed (the factory has
    // code), nothing deploys, and the file is still byte-identical.
    let incremental = apply::Options::default();
    let summary = apply::run(&path, &cfg, &signer, &incremental)
        .await
        .unwrap();
    assert!(
        summary.deployed.is_empty(),
        "re-apply deployed: {:?}",
        summary.deployed
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original_bytes);

    // Notary signer rotation, declaratively: edit accounts.notary in the
    // file (an OPERATOR edit — the only kind of change the file ever
    // sees), the plan diffs Notary.notary() against it, apply setNotary's.
    let rotated = "0x4444444444444444444444444444444444444444";
    let rotated_bytes =
        original_bytes.replace("0x1111111111111111111111111111111111111111", rotated);
    std::fs::write(&path, &rotated_bytes).unwrap();
    let cfg = NetworkConfig::load(&path).unwrap();
    let built = plan::build(&cfg).await.unwrap();
    let signer_item = built
        .items
        .iter()
        .find(|i| i.component == "contracts.notary.signer")
        .expect("the plan diffs the notary signer");
    assert_eq!(
        signer_item.status,
        Status::Configure,
        "a signer mismatch is a planned rotation:\n{}",
        built.render()
    );
    assert!(!built.has_deploys(), "rotation must not redeploy anything");

    let summary = apply::run(&path, &cfg, &signer, &incremental)
        .await
        .unwrap();
    assert!(summary.deployed.is_empty());
    assert!(
        summary
            .configured
            .iter()
            .any(|c| c.contains("notary signer rotated")),
        "apply must report the rotation: {summary:?}"
    );
    let notary_proxy: Address = cfg.contracts.notary.parse().unwrap();
    let on_chain = Notary::new(notary_proxy, &read_provider)
        .notary()
        .call()
        .await
        .unwrap();
    assert_eq!(on_chain, rotated.parse::<Address>().unwrap());
    // The rotation came from the operator's edit; apply changed nothing.
    assert_eq!(std::fs::read_to_string(&path).unwrap(), rotated_bytes);

    // A further apply is a no-op again: the signer already matches.
    let summary = apply::run(&path, &cfg, &signer, &incremental)
        .await
        .unwrap();
    assert!(summary.configured.is_empty(), "{summary:?}");

    // Explicit upgrades: UUPS for the registry and the Notary (whose state
    // — the rotated signer — must survive), facet REPLACE for the bank,
    // redeploy+repoint for the OIDC verifier. The REPLACE's new address is
    // recorded ON-CHAIN ONLY (Registry.oidcVerifierOf); the config keeps
    // declaring the canonical address and stays byte-identical.
    let canonical_oidc: Address = cfg.contracts.google_oidc_verifier.parse().unwrap();
    let upgrades = apply::Options {
        upgrades: vec![
            apply::Upgrade::Registry,
            apply::Upgrade::Notary,
            apply::Upgrade::Bank,
            apply::Upgrade::OidcVerifier,
        ],
        confirm_fresh_deploy: false,
        dev: false,
    };
    let summary = apply::run(&path, &cfg, &signer, &upgrades).await.unwrap();
    assert!(summary.upgraded.iter().any(|u| u == "registry"));
    assert!(summary.upgraded.iter().any(|u| u == "notary"));
    assert!(summary.upgraded.iter().any(|u| u == "bank"));
    assert!(summary
        .upgraded
        .iter()
        .any(|u| u.contains("google_oidc_verifier")));
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        rotated_bytes,
        "an upgrade run must not rewrite the config either"
    );

    // The chain records the replacement: the Registry points away from the
    // canonical declaration now.
    let registry_addr: Address = cfg.contracts.registry.parse().unwrap();
    let live_oidc = Registry::new(registry_addr, &read_provider)
        .oidcVerifierOf("www.googleapis.com".into())
        .call()
        .await
        .unwrap();
    assert_ne!(
        live_oidc, canonical_oidc,
        "the OIDC verifier REPLACE must move the Registry pointer"
    );

    // The Notary implementation changed; the proxy (address AND state,
    // i.e. the rotated signer) did not.
    let on_chain = Notary::new(notary_proxy, &read_provider)
        .notary()
        .call()
        .await
        .unwrap();
    assert_eq!(
        on_chain,
        rotated.parse::<Address>().unwrap(),
        "the stored signer must survive the UUPS upgrade"
    );

    // Upgrades never move an entry address: every canonical contract still
    // has code at its declared CREATE3 address (the replaced OIDC verifier
    // keeps its canonical predecessor's code in place too).
    assert_declared_and_present(&cfg, factory_addr, &read_provider).await;

    // And the plan is still clean afterwards: the diverged OIDC pointer is
    // a known, expected consequence of the REPLACE — not a warning.
    let built = plan::build(&cfg).await.unwrap();
    assert!(!built.has_deploys(), "{}", built.render());
    assert!(
        !built.items.iter().any(|i| i.status == Status::Warn),
        "plan warns after upgrades:\n{}",
        built.render()
    );
}

/// The network-invariance proof: run the SAME pre-filled declarative apply
/// against two completely separate bare anvils (both without even the
/// CREATE2 deployer) and assert both chains end up with code at the SAME
/// declared canonical addresses. Integration tests can therefore use
/// identical config data regardless of which chain they run on.
#[tokio::test]
async fn fresh_apply_addresses_are_network_invariant() {
    let artifacts = Artifacts::embedded();
    let factory_addr = predict_factory_address(&artifacts).unwrap();
    let mut runs: Vec<Vec<(String, &'static str)>> = Vec::new();

    for run in 0..2 {
        let anvil = spawn_anvil();
        let dir = tempfile::tempdir().unwrap();
        let path = prefilled_network_file(dir.path(), &anvil.endpoint());
        let original_bytes = std::fs::read_to_string(&path).unwrap();
        let signer = SignerSource::from_spec(ANVIL_KEY).unwrap();
        let cfg = NetworkConfig::load(&path).unwrap();
        let opts = apply::Options {
            upgrades: vec![],
            confirm_fresh_deploy: true,
            dev: false,
        };
        apply::run(&path, &cfg, &signer, &opts)
            .await
            .unwrap_or_else(|e| panic!("fresh apply #{run} failed: {e:#}"));

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            original_bytes,
            "run #{run}: apply must not rewrite the config"
        );
        let provider =
            ProviderBuilder::new().connect_http(anvil.endpoint().parse().unwrap());
        assert_declared_and_present(&cfg, factory_addr, &provider).await;
        runs.push(canonical_pairs(&cfg));
        drop(anvil);
    }

    assert_eq!(
        runs[0], runs[1],
        "two fresh chains must carry identical canonical addresses"
    );
}

/// Plan against a partially-deployed LEGACY chain: the login stack exists
/// (deployed with the crate directly, at non-canonical addresses — hence
/// `legacy_addresses = true`), the bank does not — the plan must say so.
/// This mirrors the committed eden-testnet.toml record.
#[tokio::test]
async fn plan_reports_missing_and_present_components_on_a_legacy_file() {
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

    let notary_contract = deploy_behind_proxy(
        &provider,
        &artifacts,
        "Notary",
        &Notary::initializeCall {
            owner_: deployer,
            notary_: Address::repeat_byte(0x11),
        },
        None,
    )
    .await
    .unwrap();
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
            _notaryContract: notary_contract,
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
legacy_addresses = true

[aws]
region = "eu-central-1"
kms_deployer = "alias/never-used-in-tests"

[accounts]
notary = "0x1111111111111111111111111111111111111111"
backend = "0x2222222222222222222222222222222222222222"

[contracts]
notary = "{notary_contract:#x}"
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

    // A legacy file plans, but apply refuses it outright.
    let signer = SignerSource::from_spec(ANVIL_KEY).unwrap();
    let err = apply::run(&path, &cfg, &signer, &apply::Options::default())
        .await
        .unwrap_err();
    assert!(format!("{err}").contains("LEGACY"), "got: {err}");

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
    assert_eq!(status_of("contracts.notary"), Status::Ok);
    // The stored signer matches accounts.notary: no rotation planned.
    assert_eq!(status_of("contracts.notary.signer"), Status::Ok);
    assert_eq!(status_of("contracts.registry"), Status::Ok);
    // The Registry's notaryContract() points at the recorded proxy.
    assert_eq!(status_of("contracts.registry.notary_wiring"), Status::Ok);
    assert_eq!(status_of("contracts.wallet_factory"), Status::Ok);
    assert_eq!(status_of("contracts.bank"), Status::Deploy);
    // x_client_id is set and nothing is wired: a deploy is pending.
    assert_eq!(status_of("contracts.x_zk_verifier"), Status::Deploy);
    // No Google client id: skipped, not deployed.
    assert_eq!(status_of("contracts.google_oidc_verifier"), Status::Skipped);
    // Identity section absent: skipped.
    assert_eq!(status_of("identity"), Status::Skipped);
}
