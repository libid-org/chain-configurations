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
    primitives::{
        Address,
        U256,
    },
    providers::{
        Provider,
        ProviderBuilder,
    },
};
use libid_contracts::{
    bindings::{
        ceremony::{
            CeremonyProofVerifier,
            GoogleJwtRoots,
            NotaryService,
        },
        factory::LibidFactory,
        identity::IdentityNames,
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
    platforms,
    signer::SignerSource,
};

// The canonical anvil account #0 key. Public test material, not a secret.
const ANVIL_KEY: &str =
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
// The address of anvil account #0 — the declared operational owner in the
// local dev config, exactly as networks/local-dev.toml describes it.
const ANVIL_OWNER: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
// Anvil account #1, the notary signer in the local dev config.
const ANVIL_NOTARY: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
// A Notary Fee that is not zero, so the fee path is exercised rather than
// passing by default.
const NOTARY_FEE_WEI: u64 = 1_000_000_000_000_000;

/// Anvil WITHOUT its predeployed CREATE2 deployer, so apply's install path
/// is what puts it there. The stack itself fits under EIP-170 — only the
/// ceremony circuits' Honk verifiers do not, and those are deployed
/// elsewhere.
fn spawn_anvil() -> AnvilInstance {
    alloy::node_bindings::Anvil::new()
        .arg("--disable-default-create2-deployer")
        .try_spawn()
        .expect("anvil spawns (is foundry on PATH?)")
}

/// A network file PRE-FILLED with the full canonical address table —
/// written before the chain has anything on it, because every address is a
/// pure function of its name. Owner: the anvil #0 wallet, explicitly.
fn prefilled_network_file(dir: &std::path::Path, rpc: &str) -> PathBuf {
    let artifacts = Artifacts::embedded();
    let factory = predict_factory_address(&artifacts).unwrap();
    let addr = |name: &str| format!("{:#x}", predict_address(factory, name));
    let path = dir.join("anvil-local.toml");
    let body = format!(
        r#"[network]
name = "anvil-local"
chain_id = 31337
rpc_url = "{rpc}"

[aws]
region = "eu-central-1"
kms_deployer = "alias/unused-in-tests"

[accounts]
notary = "{ANVIL_NOTARY}"
owner = "{ANVIL_OWNER}"

[notary_service]
fee_wei = "{NOTARY_FEE_WEI}"

[contracts]
factory = "{factory:#x}"
notary_service = "{notary_service}"
ceremony_proof_verifier = "{pv}"
identity_names = "{identity_names}"
google_jwt_roots = "{roots}"
"#,
        notary_service = addr(names::NOTARY_SERVICE),
        pv = addr(names::CEREMONY_PROOF_VERIFIER),
        identity_names = addr(names::IDENTITY_NAMES),
        roots = addr(names::GOOGLE_JWT_ROOTS),
    );
    std::fs::write(&path, body).expect("write network file");
    path
}

/// Apply `path` against its chain with the anvil #0 key.
async fn apply_with(path: &std::path::Path, opts: apply::Options) -> apply::Summary {
    let cfg = NetworkConfig::load(path).expect("config loads");
    let signer = SignerSource::from_spec(ANVIL_KEY).expect("local signer");
    apply::run(path, &cfg, &signer, &opts)
        .await
        .expect("apply converges")
}

/// Assert every declared canonical address equals
/// `predict_address(factory, name)` — the CREATE3 name-determinism proof —
/// and that the chain has CODE at each of them.
async fn assert_declared_and_present<P: Provider>(provider: &P, cfg: &NetworkConfig) {
    let artifacts = Artifacts::embedded();
    let factory = predict_factory_address(&artifacts).unwrap();
    for c in names::CANONICAL_CONTRACTS {
        let declared: Address = cfg
            .contracts
            .raw(c.key)
            .unwrap_or_else(|| panic!("{} declared", c.key))
            .parse()
            .unwrap_or_else(|e| panic!("{} parses: {e}", c.key));
        assert_eq!(
            declared,
            predict_address(factory, c.name),
            "{} is not at its CREATE3 address",
            c.key
        );
        assert!(
            !provider.get_code_at(declared).await.unwrap().is_empty(),
            "{} has no code at {declared:#x}",
            c.key
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
    let dir = tempfile::tempdir().expect("tempdir");
    let path = prefilled_network_file(dir.path(), &anvil.endpoint());
    let before = std::fs::read(&path).expect("read config");
    let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());
    let cfg = NetworkConfig::load(&path).expect("config loads");

    // Virgin chain: the plan wants everything, including the onboarding gate.
    let virgin = plan::build(&cfg).await.expect("plan on a virgin chain");
    assert_eq!(virgin.status_of("create2_deployer"), Some(Status::Deploy));
    assert_eq!(virgin.status_of("contracts.factory"), Some(Status::Deploy));
    assert_eq!(
        virgin.status_of("contracts.notary_service"),
        Some(Status::Deploy)
    );
    assert!(virgin.has_deploys());

    // A fresh deploy without the flag is refused: the guard reads chain
    // state, and a virgin chain means this apply publishes the whole stack.
    let signer = SignerSource::from_spec(ANVIL_KEY).expect("local signer");
    let refused = apply::run(&path, &cfg, &signer, &apply::Options::default()).await;
    assert!(
        refused
            .expect_err("a virgin chain needs the flag")
            .to_string()
            .contains("--confirm-fresh-deploy"),
        "the refusal must name the flag that lifts it"
    );

    // The fresh deploy itself.
    let summary = apply_with(
        &path,
        apply::Options {
            confirm_fresh_deploy: true,
            dev: true,
            ..Default::default()
        },
    )
    .await;
    assert!(
        summary
            .deployed
            .iter()
            .any(|(c, _)| c == "contracts.notary_service"),
        "the Notary Service is deployed first: {:?}",
        summary.deployed
    );
    assert_declared_and_present(&provider, &cfg).await;

    // The wiring the stack is useless without.
    let notary_service: Address = cfg.contracts.notary_service.parse().unwrap();
    let proof_verifier: Address = cfg.contracts.ceremony_proof_verifier.parse().unwrap();
    let identity_names: Address = cfg.contracts.identity_names.parse().unwrap();
    let jwt_roots: Address = cfg.contracts.google_jwt_roots.parse().unwrap();

    let service = NotaryService::new(notary_service, &provider);
    assert!(service
        .isTrustedNotary(ANVIL_NOTARY.parse().unwrap())
        .call()
        .await
        .unwrap());
    assert_eq!(
        service.fee().call().await.unwrap(),
        U256::from(NOTARY_FEE_WEI)
    );

    let names_contract = IdentityNames::new(identity_names, &provider);
    assert_eq!(
        names_contract.proofVerifier().call().await.unwrap(),
        proof_verifier
    );

    let roots = GoogleJwtRoots::new(jwt_roots, &provider);
    assert_eq!(roots.notaryService().call().await.unwrap(), notary_service);
    assert_eq!(
        roots.quoteRotation().call().await.unwrap(),
        U256::from(NOTARY_FEE_WEI)
    );
    // The trust list starts empty, so it wants a rotation before any Google
    // name can bind. That is a keeper's job, not apply's.
    assert!(roots.needsRotation().call().await.unwrap());

    // Every launch platform owns its keyspace, and none can verify anything
    // yet: no Platform Verifier is registered, so the Proof Verifier says so
    // rather than answering for a platform it cannot check.
    let verifier = CeremonyProofVerifier::new(proof_verifier, &provider);
    for platform in platforms::LAUNCH {
        let platform_id = platforms::platform_id(platform.domain);
        assert!(
            !verifier.verifiesPlatform(platform_id).call().await.unwrap(),
            "{} has a verifier registered already",
            platform.label
        );
        assert!(
            names_contract
                .resolveId(platform_id, "12345".into())
                .call()
                .await
                .is_err(),
            "{} answered instead of reverting UnknownPlatform",
            platform.label
        );
    }

    // Factory ownership ended at the declared operational owner.
    let factory: Address = cfg.contracts.factory.parse().unwrap();
    assert_eq!(
        LibidFactory::new(factory, &provider)
            .owner()
            .call()
            .await
            .unwrap(),
        ANVIL_OWNER.parse::<Address>().unwrap()
    );

    // A second apply needs no flag and deploys nothing.
    let again = apply_with(&path, apply::Options::default()).await;
    assert!(
        again.deployed.is_empty(),
        "the second apply deployed {:?}",
        again.deployed
    );
    let settled = plan::build(&cfg).await.expect("plan after apply");
    assert!(
        !settled.has_deploys(),
        "the settled plan still wants deploys:\n{}",
        settled.render()
    );

    // Every explicit upgrade runs, and the state behind each proxy survives.
    let upgrades: Vec<apply::Upgrade> = apply::Upgrade::VALUES
        .iter()
        .map(|v| v.parse().expect("value parses"))
        .collect();
    let upgraded = apply_with(
        &path,
        apply::Options {
            upgrades,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(upgraded.upgraded.len(), apply::Upgrade::VALUES.len());
    assert_eq!(
        service.fee().call().await.unwrap(),
        U256::from(NOTARY_FEE_WEI)
    );
    assert_eq!(
        names_contract.proofVerifier().call().await.unwrap(),
        proof_verifier
    );
    assert_eq!(roots.notaryService().call().await.unwrap(), notary_service);
    assert_declared_and_present(&provider, &cfg).await;

    // The whole point: the file is byte-identical through all of it.
    assert_eq!(
        before,
        std::fs::read(&path).expect("re-read config"),
        "apply rewrote the network file"
    );
}

/// Declarative convergence: a stack that lost its wiring is repaired by the
/// next apply, without redeploying anything. The rotation path is the same
/// one an operator uses by editing `accounts.notary`.
#[tokio::test]
async fn apply_converges_drifted_wiring_without_redeploying() {
    let anvil = spawn_anvil();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = prefilled_network_file(dir.path(), &anvil.endpoint());
    apply_with(
        &path,
        apply::Options {
            confirm_fresh_deploy: true,
            dev: true,
            ..Default::default()
        },
    )
    .await;

    let cfg = NetworkConfig::load(&path).expect("config loads");
    let notary_service: Address = cfg.contracts.notary_service.parse().unwrap();
    let proof_verifier: Address = cfg.contracts.ceremony_proof_verifier.parse().unwrap();
    let identity_names: Address = cfg.contracts.identity_names.parse().unwrap();

    // Drift: the owner (the anvil #0 key, which is also the apply signer)
    // points the naming system somewhere else and changes the fee.
    let key: alloy::signers::local::PrivateKeySigner = ANVIL_KEY.parse().unwrap();
    let owned = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(key))
        .connect_http(anvil.endpoint_url());
    IdentityNames::new(identity_names, &owned)
        .setProofVerifier(Address::repeat_byte(0x99))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    NotaryService::new(notary_service, &owned)
        .setFee(U256::from(7))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    let drifted = plan::build(&cfg).await.expect("plan sees the drift");
    assert_eq!(
        drifted.status_of("identity_names.proof_verifier"),
        Some(Status::Configure)
    );
    assert_eq!(
        drifted.status_of("notary_service.fee"),
        Some(Status::Configure)
    );
    assert!(!drifted.has_deploys(), "drift is not a redeploy");

    let repaired = apply_with(&path, apply::Options::default()).await;
    assert!(repaired.deployed.is_empty());
    let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());
    assert_eq!(
        IdentityNames::new(identity_names, &provider)
            .proofVerifier()
            .call()
            .await
            .unwrap(),
        proof_verifier
    );
    assert_eq!(
        NotaryService::new(notary_service, &provider)
            .fee()
            .call()
            .await
            .unwrap(),
        U256::from(NOTARY_FEE_WEI)
    );
}

/// The network-invariance proof: run the SAME pre-filled declarative apply
/// against two completely separate bare anvils (both without even the
/// CREATE2 deployer) and assert both chains end up with code at the SAME
/// declared canonical addresses. Integration tests can therefore use
/// identical config data regardless of which chain they run on.
#[tokio::test]
async fn fresh_apply_addresses_are_network_invariant() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut instances = Vec::new();
    for index in 0..2u8 {
        let anvil = spawn_anvil();
        let sub = dir.path().join(format!("chain{index}"));
        std::fs::create_dir_all(&sub).expect("subdir");
        let path = prefilled_network_file(&sub, &anvil.endpoint());
        apply_with(
            &path,
            apply::Options {
                confirm_fresh_deploy: true,
                dev: true,
                ..Default::default()
            },
        )
        .await;
        instances.push((anvil, path));
    }

    for (anvil, path) in &instances {
        let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());
        let cfg = NetworkConfig::load(path).expect("config loads");
        assert_declared_and_present(&provider, &cfg).await;
    }

    // Same declarations, so the same addresses — the whole cross-network
    // guarantee, checked rather than asserted in a comment.
    let first = NetworkConfig::load(&instances[0].1).unwrap();
    let second = NetworkConfig::load(&instances[1].1).unwrap();
    for c in names::CANONICAL_CONTRACTS {
        assert_eq!(
            first.contracts.raw(c.key),
            second.contracts.raw(c.key),
            "{} diverged between chains",
            c.key
        );
    }
}
