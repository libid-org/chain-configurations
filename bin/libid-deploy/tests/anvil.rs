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
        keccak256,
        Address,
        Bytes,
        U256,
    },
    providers::{
        Provider,
        ProviderBuilder,
    },
    sol_types::SolError,
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
    deploy::deploy_contract_from,
    factory::{
        predict_address,
        predict_factory_address,
    },
    Artifacts,
};
use libid_deploy::{
    apply,
    ceremony,
    config::NetworkConfig,
    names,
    plan::{
        self,
        Status,
    },
    platforms::{
        self,
        VerifierKind,
        LAUNCH_VERIFIER_VERSION,
    },
    rpc::RpcEndpoint,
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
/// is what puts it there. Default code-size limit on purpose: everything
/// apply deploys, the ceremony circuits' ~18 KiB Honk verifiers included,
/// fits under EIP-170, and a test that raised the limit would stop
/// proving it.
fn spawn_anvil() -> AnvilInstance {
    anvil_builder()
        .try_spawn()
        .expect("anvil spawns (is foundry on PATH?)")
}

fn anvil_builder() -> alloy::node_bindings::Anvil {
    alloy::node_bindings::Anvil::new().arg("--disable-default-create2-deployer")
}

/// An `http://127.0.0.1:<port>` nothing listens on: the port is taken from
/// the kernel and released again, so a connection is refused at once.
fn closed_endpoint() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    format!("http://127.0.0.1:{port}")
}

/// The committed `networks/local-dev.toml`, read from the repository.
fn committed_local_dev() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../networks/local-dev.toml")
}

/// `--rpc-url <endpoint>` over `cfg`.
fn override_rpc(cfg: &NetworkConfig, endpoint: &str) -> RpcEndpoint {
    RpcEndpoint::resolve(cfg, Some(endpoint)).expect("the override resolves")
}

/// A network file PRE-FILLED with the full canonical address table —
/// written before the chain has anything on it, because every address is a
/// pure function of its name. Owner: the anvil #0 wallet, explicitly.
fn prefilled_network_file(dir: &std::path::Path, rpc: &str) -> PathBuf {
    write_network_file(dir, rpc)
}

fn write_network_file(dir: &std::path::Path, rpc: &str) -> PathBuf {
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
x_platform_verifier = "{x}"
github_platform_verifier = "{github}"
google_platform_verifier = "{google}"
"#,
        notary_service = addr(names::NOTARY_SERVICE),
        pv = addr(names::CEREMONY_PROOF_VERIFIER),
        identity_names = addr(names::IDENTITY_NAMES),
        roots = addr(names::GOOGLE_JWT_ROOTS),
        x = addr(names::X_PLATFORM_VERIFIER),
        github = addr(names::GITHUB_PLATFORM_VERIFIER),
        google = addr(names::GOOGLE_PLATFORM_VERIFIER),
    );
    std::fs::write(&path, body).expect("write network file");
    path
}

/// Some other contract with code, to drift a trust root onto. What
/// `setTrustRoots` requires of an address is that its code hash matches the
/// one named, so any deployed contract drifts the pin exactly — and could
/// never accept a proof, which is why apply must pull it back.
async fn deploy_stand_in(rpc: &str, key: &str) -> Address {
    let signer: alloy::signers::local::PrivateKeySigner = key.parse().unwrap();
    let provider = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer))
        .connect_http(rpc.parse().unwrap());
    let artifacts = Artifacts::embedded();
    deploy_contract_from(
        &provider,
        artifacts.bytecode("WTIA9").unwrap(),
        "circuit verifier stand-in",
        None,
    )
    .await
    .expect("stand-in deploys")
}

/// The endpoint the file itself names — no `--rpc-url`.
fn file_rpc(cfg: &NetworkConfig) -> RpcEndpoint {
    RpcEndpoint::resolve(cfg, None).expect("the file's endpoint resolves")
}

/// Apply `path` against the chain it names with the anvil #0 key.
async fn apply_with(path: &std::path::Path, opts: apply::Options) -> apply::Summary {
    let cfg = NetworkConfig::load(path).expect("config loads");
    let signer = SignerSource::from_spec(ANVIL_KEY).expect("local signer");
    apply::run(path, &cfg, &file_rpc(&cfg), &signer, &opts)
        .await
        .expect("apply converges")
}

/// Assert every declared canonical address equals
/// `predict_address(factory, name)` — the CREATE3 name-determinism proof —
/// and that the chain has CODE at every one of them.
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

/// The `logN` a deployed bb verifier reports for its own circuit, read by
/// handing it a proof of the wrong length. The error is
/// `ProofLengthWrongWithLogN`, which only a Honk verifier raises.
async fn honk_log_n<P: Provider>(provider: &P, verifier: Address) -> u64 {
    let err = ceremony::HonkVerifier::new(verifier, provider)
        .verify(Bytes::new(), Vec::new())
        .call()
        .await
        .expect_err("an empty proof is the wrong length");
    let data = err
        .as_revert_data()
        .expect("the verifier reverted with data");
    let decoded = ceremony::HonkVerifier::ProofLengthWrongWithLogN::abi_decode(&data)
        .expect("only a Honk verifier raises ProofLengthWrongWithLogN");
    decoded.logN.to::<u64>()
}

/// The address apply deploys a circuit's Honk verifier to: CREATE3 under a
/// name carrying the pinned circuits version, so it is known before the
/// chain has anything on it.
fn circuit_verifier_address(circuit: &ceremony::Circuit) -> Address {
    let factory = predict_factory_address(&Artifacts::embedded()).unwrap();
    predict_address(factory, &circuit.factory_name().unwrap())
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
    let virgin = plan::build(&cfg, &file_rpc(&cfg))
        .await
        .expect("plan on a virgin chain");
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
    let refused = apply::run(
        &path,
        &cfg,
        &file_rpc(&cfg),
        &signer,
        &apply::Options::default(),
    )
    .await;
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

    // Every launch platform owns its keyspace AND can verify: one apply
    // builds the circuit verifiers, deploys a Platform Verifier on each and
    // registers it, so the naming system resolves instead of reverting
    // UnknownPlatform.
    let verifier = CeremonyProofVerifier::new(proof_verifier, &provider);
    for platform in platforms::LAUNCH {
        let platform_id = platforms::platform_id(platform.domain);
        assert!(
            verifier.verifiesPlatform(platform_id).call().await.unwrap(),
            "{} has no verifier registered",
            platform.label
        );
        assert_eq!(
            names_contract
                .resolveId(platform_id, "12345".into())
                .call()
                .await
                .expect("a wired platform resolves"),
            Address::ZERO
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
    let settled = plan::build(&cfg, &file_rpc(&cfg))
        .await
        .expect("plan after apply");
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

    let drifted = plan::build(&cfg, &file_rpc(&cfg))
        .await
        .expect("plan sees the drift");
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

/// The Platform Verifiers, end to end on a virgin chain: one apply builds
/// the two ceremony circuits' Honk verifiers from the vendored artifacts,
/// deploys a Platform Verifier per platform pinned to the right one — by
/// address AND by the code hash the chain reports — registers each into the
/// Supported Version Set, and leaves the naming system resolving and
/// quoting for all three.
#[tokio::test]
async fn platform_verifiers_deploy_wire_and_register() {
    let anvil = spawn_anvil();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = prefilled_network_file(dir.path(), &anvil.endpoint());
    let before = std::fs::read(&path).expect("read config");
    let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());

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
    assert_declared_and_present(&provider, &cfg).await;

    // Both circuit verifiers are real Honk verifiers at their CREATE3
    // addresses, over DIFFERENT circuits. A bb verifier has no getter for
    // its verification key; the one thing it says about itself is the logN
    // a wrong-length proof comes back with, so that is what separates a
    // real verifier from a contract that merely has code.
    let mut log_n = Vec::new();
    for circuit in ceremony::CIRCUITS {
        let address = circuit_verifier_address(circuit);
        let code = provider.get_code_at(address).await.unwrap();
        assert!(
            !code.is_empty(),
            "the {} circuit verifier has no code at {address:#x}",
            circuit.name
        );
        // EIP-170: anvil runs the default limit, so a verifier over it
        // could not have been deployed — this passing IS the size proof.
        assert!(
            code.len() <= 24_576,
            "the {} circuit verifier is {} bytes, over EIP-170",
            circuit.name,
            code.len()
        );
        let reported = honk_log_n(&provider, address).await;
        assert!(reported > 0, "{} reports no circuit size", circuit.name);
        log_n.push(reported);
    }
    assert_ne!(
        log_n[0], log_n[1],
        "both platforms would verify under one circuit"
    );

    let notary_service: Address = cfg.contracts.notary_service.parse().unwrap();
    let proof_verifier: Address = cfg.contracts.ceremony_proof_verifier.parse().unwrap();
    let identity_names: Address = cfg.contracts.identity_names.parse().unwrap();
    let jwt_roots: Address = cfg.contracts.google_jwt_roots.parse().unwrap();

    let registry = CeremonyProofVerifier::new(proof_verifier, &provider);
    let names_contract = IdentityNames::new(identity_names, &provider);

    for platform in platforms::LAUNCH {
        let platform_id = platforms::platform_id(platform.domain);
        let proxy: Address = cfg
            .contracts
            .raw(platform.contracts_key)
            .unwrap()
            .parse()
            .unwrap();
        let verifier = ceremony::TlsPlatformVerifier::new(proxy, &provider);

        // It answers for its own platform, and pins the verifier of the
        // circuit its proofs are made under — nonzero, at the address the
        // circuits pin derives, with the code hash the CHAIN reports.
        assert_eq!(
            verifier.platformId().call().await.unwrap(),
            platform_id,
            "{} serves the wrong platform",
            platform.label
        );
        let circuit = circuit_verifier_address(&platform.circuit);
        let wired = verifier.honkVerifier().call().await.unwrap();
        assert_ne!(wired, Address::ZERO, "{} pins nothing", platform.label);
        assert_eq!(wired, circuit, "{} pins the wrong circuit", platform.label);
        assert_eq!(
            verifier.honkVerifierCodehash().call().await.unwrap(),
            keccak256(provider.get_code_at(wired).await.unwrap()),
            "{} recorded a hash the chain does not hold",
            platform.label
        );

        // The parameters come from the generated tables, not from here.
        let params = verifier.protocolParameters().call().await.unwrap();
        assert_eq!(
            params.futureObservationAllowance,
            platform.future_observation_allowance
        );
        match platform.kind {
            VerifierKind::TlsNotary {
                proof_lifetime,
                max_future_attestation_skew,
            } => {
                assert_eq!(params.proofLifetime, proof_lifetime);
                assert_eq!(params.maxFutureAttestationSkew, max_future_attestation_skew);
                assert_eq!(
                    verifier.notaryService().call().await.unwrap(),
                    notary_service
                );
            }
            VerifierKind::GoogleJwt => {
                // A profile that notarizes nothing holds no Notary Service
                // and no attestation window.
                assert_eq!(params.proofLifetime, 0);
                assert_eq!(params.maxFutureAttestationSkew, 0);
                assert_eq!(
                    verifier.notaryService().call().await.unwrap(),
                    Address::ZERO
                );
                assert_eq!(
                    ceremony::GooglePlatformVerifier::new(proxy, &provider)
                        .jwtRoots()
                        .call()
                        .await
                        .unwrap(),
                    jwt_roots
                );
            }
        }

        // Registered, so the platform can verify and the resolvers answer.
        assert_eq!(
            registry
                .verifierOf(platform_id, LAUNCH_VERIFIER_VERSION)
                .call()
                .await
                .unwrap(),
            proxy
        );
        assert!(registry.verifiesPlatform(platform_id).call().await.unwrap());
        assert_eq!(
            names_contract
                .resolveId(platform_id, "12345".into())
                .call()
                .await
                .expect("a wired platform resolves"),
            Address::ZERO
        );

        // One Notary Fee per attestation the profile requires, quoted end
        // to end through the naming system.
        let expected_quote = match platform.kind {
            VerifierKind::TlsNotary { .. } => U256::from(NOTARY_FEE_WEI) * U256::from(2),
            VerifierKind::GoogleJwt => U256::ZERO,
        };
        assert_eq!(
            names_contract
                .quoteClaim(platform_id, LAUNCH_VERIFIER_VERSION)
                .call()
                .await
                .unwrap(),
            expected_quote,
            "{} quotes the wrong price",
            platform.label
        );
    }

    // X and GitHub prove the same statement, so they share one deployed
    // verifier rather than paying for two copies of it.
    let x_proxy: Address = cfg.contracts.x_platform_verifier.parse().unwrap();
    let github_proxy: Address = cfg.contracts.github_platform_verifier.parse().unwrap();
    let google_proxy: Address = cfg.contracts.google_platform_verifier.parse().unwrap();
    let mut pinned = Vec::new();
    for proxy in [x_proxy, github_proxy, google_proxy] {
        pinned.push(
            ceremony::TlsPlatformVerifier::new(proxy, &provider)
                .honkVerifier()
                .call()
                .await
                .unwrap(),
        );
    }
    assert_eq!(pinned[0], pinned[1], "X and GitHub pin different copies");
    assert_ne!(pinned[0], pinned[2], "Google shares X's circuit");

    // A second apply deploys and configures nothing more: the circuit
    // verifiers are CREATE3-named, so a converged chain is recognised.
    let again = apply_with(&path, apply::Options::default()).await;
    assert!(again.deployed.is_empty(), "{:?}", again.deployed);
    assert!(again.configured.is_empty(), "{:?}", again.configured);
    let settled = plan::build(&cfg, &file_rpc(&cfg))
        .await
        .expect("plan after apply");
    assert!(
        !settled.has_deploys(),
        "the settled plan still wants deploys:\n{}",
        settled.render()
    );
    for circuit in ceremony::CIRCUITS {
        assert_eq!(
            settled.status_of(&format!("circuits.{}", circuit.name)),
            Some(Status::Ok)
        );
    }
    for platform in platforms::LAUNCH {
        assert_eq!(
            settled.status_of(&format!("ceremony.{}.registration", platform.domain)),
            Some(Status::Ok)
        );
        assert_eq!(
            settled
                .status_of(&format!("contracts.{}.trust_roots", platform.contracts_key)),
            Some(Status::Ok)
        );
    }

    // Every verifier upgrades, and its trust roots survive.
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
    for platform in platforms::LAUNCH {
        let proxy: Address = cfg
            .contracts
            .raw(platform.contracts_key)
            .unwrap()
            .parse()
            .unwrap();
        let circuit = circuit_verifier_address(&platform.circuit);
        assert_eq!(
            ceremony::TlsPlatformVerifier::new(proxy, &provider)
                .honkVerifierCodehash()
                .call()
                .await
                .unwrap(),
            keccak256(provider.get_code_at(circuit).await.unwrap())
        );
    }

    assert_eq!(
        before,
        std::fs::read(&path).expect("re-read config"),
        "apply rewrote the network file"
    );
}

/// A trust root that drifted off the pinned artifact is pulled back by the
/// next apply, without redeploying anything. Moving the circuits pin is the
/// same path: a release is a new CREATE3 name, so the verifier changes
/// while the proxy — and therefore the registration — does not.
#[tokio::test]
async fn apply_pulls_a_drifted_trust_root_back_onto_the_pinned_verifier() {
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
    let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());
    let notary_service: Address = cfg.contracts.notary_service.parse().unwrap();
    let x_proxy: Address = cfg.contracts.x_platform_verifier.parse().unwrap();
    let pinned = circuit_verifier_address(&platforms::X.circuit);

    // Drift: the owner points X at some other contract with code. It would
    // never accept a proof, which is why apply must pull the pin back.
    let elsewhere = deploy_stand_in(&anvil.endpoint(), ANVIL_KEY).await;
    assert_ne!(elsewhere, pinned);
    let key: alloy::signers::local::PrivateKeySigner = ANVIL_KEY.parse().unwrap();
    let owned = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(key))
        .connect_http(anvil.endpoint_url());
    ceremony::TlsPlatformVerifier::new(x_proxy, &owned)
        .setTrustRoots(
            notary_service,
            elsewhere,
            keccak256(provider.get_code_at(elsewhere).await.unwrap()),
        )
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    let drifted = plan::build(&cfg, &file_rpc(&cfg))
        .await
        .expect("plan sees the pin drift");
    assert_eq!(
        drifted.status_of("contracts.x_platform_verifier.trust_roots"),
        Some(Status::Configure)
    );
    assert!(!drifted.has_deploys(), "a rotation is not a redeploy");

    let repaired = apply_with(&path, apply::Options::default()).await;
    assert!(repaired.deployed.is_empty(), "{:?}", repaired.deployed);
    let x = ceremony::TlsPlatformVerifier::new(x_proxy, &provider);
    assert_eq!(x.honkVerifier().call().await.unwrap(), pinned);
    assert_eq!(
        x.honkVerifierCodehash().call().await.unwrap(),
        keccak256(provider.get_code_at(pinned).await.unwrap())
    );
    // The proxy did not move: the registration still points at it.
    assert_eq!(
        CeremonyProofVerifier::new(
            cfg.contracts.ceremony_proof_verifier.parse().unwrap(),
            &provider
        )
        .verifierOf(
            platforms::platform_id(platforms::X.domain),
            LAUNCH_VERIFIER_VERSION
        )
        .call()
        .await
        .unwrap(),
        x_proxy
    );
}

/// The committed local-dev file is not just parseable: UNMODIFIED, it
/// converges a real anvil the file does not name, signing with the
/// deployer spec it carries. Its `rpc_url` is the compose service name,
/// which does not resolve here; `--rpc-url` is the way in from outside that
/// network, and the file stays byte-identical through the apply.
#[tokio::test]
async fn the_committed_local_dev_file_converges_an_anvil_through_rpc_url() {
    let anvil = spawn_anvil();
    let path = committed_local_dev();
    let before = std::fs::read(&path).expect("networks/local-dev.toml readable");

    let cfg = NetworkConfig::load(&path).expect("local-dev loads");
    assert_eq!(
        cfg.network.rpc_url, "http://anvil:8545",
        "the committed file names the compose service, not this anvil"
    );
    let rpc = override_rpc(&cfg, &anvil.endpoint());
    assert!(rpc.is_override());

    // The signer spec in the file is what apply uses by default — no
    // --signer, no AWS.
    let signer = SignerSource::from_spec(&cfg.aws.kms_deployer).expect("signer spec");
    assert_eq!(signer.describe(), "local private key");
    apply::run(
        &path,
        &cfg,
        &rpc,
        &signer,
        &apply::Options {
            confirm_fresh_deploy: true,
            dev: true,
            ..Default::default()
        },
    )
    .await
    .expect("local-dev converges");

    assert_eq!(
        std::fs::read(&path).expect("readable after apply"),
        before,
        "apply rewrote the committed file"
    );

    let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());
    assert_declared_and_present(&provider, &cfg).await;

    // The roles the file separates stay separate on chain: the notary
    // signer is anvil #1, the owner is anvil #0.
    let notary_service: Address = cfg.contracts.notary_service.parse().unwrap();
    let service = NotaryService::new(notary_service, &provider);
    assert!(service
        .isTrustedNotary(ANVIL_NOTARY.parse().unwrap())
        .call()
        .await
        .unwrap());
    assert!(!service
        .isTrustedNotary(ANVIL_OWNER.parse().unwrap())
        .call()
        .await
        .unwrap());
    assert_eq!(
        service.fee().call().await.unwrap(),
        U256::from(NOTARY_FEE_WEI),
        "the local fee must stay non-zero so a wrong-value client fails here"
    );
    assert_eq!(
        LibidFactory::new(cfg.contracts.factory.parse().unwrap(), &provider)
            .owner()
            .call()
            .await
            .unwrap(),
        ANVIL_OWNER.parse::<Address>().unwrap()
    );
}

/// `--rpc-url` moves the transport and nothing else. The file names an
/// endpoint nothing listens on; through the override everything lands at
/// the addresses the file declares — `predict_address(factory, name)`, the
/// same CREATE3 salts as any other network — the file still names its dead
/// endpoint afterwards, and a second apply through the override is a
/// no-op.
#[tokio::test]
async fn rpc_override_moves_only_the_transport() {
    let anvil = spawn_anvil();
    let dir = tempfile::tempdir().expect("tempdir");
    let dead = closed_endpoint();
    let path = prefilled_network_file(dir.path(), &dead);
    let before = std::fs::read(&path).unwrap();
    let cfg = NetworkConfig::load(&path).expect("config loads");

    // The file's own endpoint really is unusable, or this proves nothing.
    plan::build(&cfg, &file_rpc(&cfg))
        .await
        .expect_err("nothing listens where the file points");

    let rpc = override_rpc(&cfg, &anvil.endpoint());
    let signer = SignerSource::from_spec(ANVIL_KEY).unwrap();
    let opts = apply::Options {
        confirm_fresh_deploy: true,
        dev: true,
        ..Default::default()
    };
    let summary = apply::run(&path, &cfg, &rpc, &signer, &opts)
        .await
        .expect("apply converges through the override");

    // Every canonical component deployed, at exactly the file's address.
    let factory = predict_factory_address(&Artifacts::embedded()).unwrap();
    for c in names::CANONICAL_CONTRACTS {
        let declared: Address = cfg.contracts.raw(c.key).unwrap().parse().unwrap();
        let landed = summary
            .deployed
            .iter()
            .find(|(component, _)| component == &format!("contracts.{}", c.key))
            .unwrap_or_else(|| panic!("{} was not deployed", c.key))
            .1;
        assert_eq!(landed, declared, "{} moved off its declared address", c.key);
        assert_eq!(landed, predict_address(factory, c.name));
    }
    let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());
    assert_declared_and_present(&provider, &cfg).await;
    for circuit in ceremony::CIRCUITS {
        let addr = circuit_verifier_address(circuit);
        assert!(
            !provider.get_code_at(addr).await.unwrap().is_empty(),
            "{} has no code at its CREATE3 address {addr:#x}",
            circuit.name
        );
    }

    // The file is untouched and still names the dead endpoint; the
    // override lived only in the invocation.
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(NetworkConfig::load(&path).unwrap().network.rpc_url, dead);

    let settled = plan::build(&cfg, &rpc)
        .await
        .expect("plan through the override");
    assert_eq!(settled.rpc_url, rpc.url().to_string());
    assert!(!settled.has_deploys(), "{}", settled.render());
    let again = apply::run(&path, &cfg, &rpc, &signer, &apply::Options::default())
        .await
        .expect("second apply through the override");
    assert!(again.deployed.is_empty(), "{:?}", again.deployed);
}

/// A set-but-unusable override is an error, never a fallback: the file
/// names a LIVE anvil, the flag names a dead port, and both plan and apply
/// must fail without touching the live chain.
#[tokio::test]
async fn rpc_override_never_falls_back_to_the_file() {
    let anvil = spawn_anvil();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = prefilled_network_file(dir.path(), &anvil.endpoint());
    let cfg = NetworkConfig::load(&path).expect("config loads");
    let dead = closed_endpoint();
    let rpc = override_rpc(&cfg, &dead);

    let err = plan::build(&cfg, &rpc)
        .await
        .expect_err("plan must not fall back to the file's endpoint")
        .to_string();
    assert!(err.contains(&dead), "{err}");
    assert!(err.contains("--rpc-url"), "{err}");

    let signer = SignerSource::from_spec(ANVIL_KEY).unwrap();
    let opts = apply::Options {
        confirm_fresh_deploy: true,
        dev: true,
        ..Default::default()
    };
    let err = apply::run(&path, &cfg, &rpc, &signer, &opts)
        .await
        .expect_err("apply must not fall back to the file's endpoint")
        .to_string();
    assert!(err.contains(&dead), "{err}");

    let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());
    assert_eq!(
        provider.get_block_number().await.unwrap(),
        0,
        "something reached the chain the file names"
    );
}

/// The override changes where the calls go, not which chain the file
/// describes: an anvil on another chain id is refused with the file's
/// number, and nothing is sent.
#[tokio::test]
async fn rpc_override_still_enforces_the_declared_chain_id() {
    let other = anvil_builder()
        .args(["--chain-id", "31338"])
        .try_spawn()
        .expect("anvil spawns");
    let dir = tempfile::tempdir().expect("tempdir");
    let path = prefilled_network_file(dir.path(), &closed_endpoint());
    let cfg = NetworkConfig::load(&path).expect("config loads");
    assert_eq!(cfg.network.chain_id, 31337);
    let rpc = override_rpc(&cfg, &other.endpoint());

    let plan = plan::build(&cfg, &rpc).await.expect("plan is read-only");
    assert_eq!(plan.chain_id_actual, 31338);
    assert_eq!(plan.status_of("network.chain_id"), Some(Status::Warn));

    let signer = SignerSource::from_spec(ANVIL_KEY).unwrap();
    let opts = apply::Options {
        confirm_fresh_deploy: true,
        dev: true,
        ..Default::default()
    };
    let err = apply::run(&path, &cfg, &rpc, &signer, &opts)
        .await
        .expect_err("apply refuses the wrong chain")
        .to_string();
    assert!(err.contains("chain id mismatch"), "{err}");
    assert!(err.contains("31337") && err.contains("31338"), "{err}");

    let provider = ProviderBuilder::new().connect_http(other.endpoint_url());
    assert_eq!(provider.get_block_number().await.unwrap(), 0);
}

/// The command line a consumer with a bare anvil runs — keeper's CI, a
/// developer on the host — against the committed file, unmodified. Pins the
/// flag name downstream depends on.
#[test]
fn the_cli_applies_the_committed_file_through_rpc_url() {
    let anvil = spawn_anvil();
    let path = committed_local_dev();
    let before = std::fs::read(&path).unwrap();
    let bin = env!("CARGO_BIN_EXE_libid-deploy");

    let apply = std::process::Command::new(bin)
        .arg("apply")
        .arg("--network")
        .arg(&path)
        .arg("--rpc-url")
        .arg(anvil.endpoint())
        .args(["--yes", "--confirm-fresh-deploy", "--dev"])
        .output()
        .expect("libid-deploy runs");
    let stdout = String::from_utf8_lossy(&apply.stdout);
    let stderr = String::from_utf8_lossy(&apply.stderr);
    assert!(apply.status.success(), "apply failed\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("Deployed (all at their declared canonical addresses):"),
        "{stdout}"
    );
    for c in names::CANONICAL_CONTRACTS {
        let addr = plan::predicted(c.key).unwrap();
        assert!(
            stdout.contains(&format!("contracts.{} = {addr:#x}", c.key)),
            "{} missing from the summary:\n{stdout}",
            c.key
        );
    }
    assert_eq!(std::fs::read(&path).unwrap(), before);

    let plan = std::process::Command::new(bin)
        .arg("plan")
        .arg("--network")
        .arg(&path)
        .arg("--rpc-url")
        .arg(anvil.endpoint())
        .output()
        .expect("libid-deploy runs");
    let stdout = String::from_utf8_lossy(&plan.stdout);
    assert!(plan.status.success(), "{stdout}");
    assert!(
        stdout.starts_with(&format!("Plan for local-dev via {}/", anvil.endpoint())),
        "{stdout}"
    );
    assert!(!stdout.contains("DEPLOY"), "{stdout}");
}
