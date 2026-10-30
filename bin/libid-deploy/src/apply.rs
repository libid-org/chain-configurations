//! Converge a chain onto the network file: deploy whatever the CHAIN lacks
//! (in dependency order), re-send the idempotent configuration ops, and
//! perform any explicitly requested upgrades.
//!
//! The file pre-declares every canonical address (validated to equal
//! `predict_address(factory, name)` at load), so apply reads presence from
//! chain state (`eth_getCode` at the declared address / the factory's
//! `deployedAt` record) and NEVER rewrites the file — after an apply the
//! config is byte-identical to before it.
//!
//! The flow is FACTORY-FIRST: step 0 makes sure the keyless CREATE2
//! deployer and the deterministic `LibidFactory` exist (installing them
//! where missing), verifies the factory sits at exactly its predicted
//! canonical address (the CANARY — a mismatch means the chain derives
//! CREATE2 addresses differently and the run aborts), and then every entry
//! contract deploys THROUGH the factory via CREATE3 under its canonical
//! name from [`crate::names`], so its address is a pure function of the
//! name — identical on every network. Implementations stay plain CREATE
//! deploys: their addresses are referenced by a proxy slot, not canonical,
//! and upgrades replace them without moving any entry address.
//!
//! The stack order is `script/Deploy.s.sol`'s: the Notary Service every
//! notarized session is authenticated through, the Proof Verifier the
//! identity registry dispatches bindings through, the identity registry
//! itself, and the Google JWT root list that pays the Notary Service for
//! each rotation. Two steps that script does not have: the handle escrow,
//! right after the identity registry it resolves through, and at the end
//! the ceremony circuits' Honk verifiers and a Platform Verifier per
//! platform pinned to one of them and registered into the Supported Version
//! Set, without which the registry accepts no binding for the platform.
//! The declared Safes come last ([`crate::safes`]).

mod safes;

use std::{
    collections::BTreeMap,
    fmt,
    path::Path,
    str::FromStr,
};

use alloy::{
    network::TransactionBuilder,
    primitives::{
        utils::Unit,
        Address,
        Bytes,
        U256,
    },
    providers::{
        ext::AnvilApi,
        DynProvider,
        Provider,
        ProviderBuilder,
    },
    rpc::types::TransactionRequest,
    sol_types::{
        SolCall,
        SolValue,
    },
};
use anyhow::{
    anyhow,
    bail,
    Context,
    Result,
};
use libid_contracts::{
    bindings::{
        ceremony::{
            CeremonyProofVerifier,
            GoogleJwtRoots,
            GooglePlatformVerifier,
            NotaryService,
            PlatformVerifierBase,
        },
        escrow::HandleEscrow,
        factory::LibidFactory,
        identity::IdentityRegistry,
        proxy::IUUPSUpgradeable,
    },
    deploy::deploy_contract_from,
    factory::{
        ensure_create2_deployer,
        predict_address,
        FactoryGenesis,
    },
    platform_verifier::PlatformVerifier,
    send_with_nonce_retry,
    Artifacts,
};

use crate::{
    circuits::{
        Circuit,
        Site,
        Verifiers,
    },
    config::{
        NetworkConfig,
        Stack,
    },
    names,
    platforms::{
        self,
        Platform,
        LAUNCH_VERIFIER_VERSION,
    },
    rpc::RpcEndpoint,
    signer::SignerSource,
};

/// A component an operator can explicitly upgrade. Every one is a UUPS
/// proxy: the implementation is replaced and the entry address, its
/// storage and its owner all survive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upgrade {
    /// The Notary Service — the trusted key set and the fee survive.
    NotaryService,
    /// The Proof Verifier — the Supported Version Set survives.
    ProofVerifier,
    /// The identity registry — every binding survives.
    IdentityRegistry,
    /// The handle escrow — every deposit, and the identity registry it
    /// resolves through, survive.
    HandleEscrow,
    /// The Google JWT root list — both key generations survive.
    GoogleJwtRoots,
    /// The `x/v1` Platform Verifier — its trust roots survive.
    /// Registration is not touched: the Proof Verifier points at the
    /// proxy, which does not move.
    XPlatformVerifier,
    /// The `github/v1` Platform Verifier.
    GitHubPlatformVerifier,
    /// The `google/v1` Platform Verifier.
    GooglePlatformVerifier,
}

impl Upgrade {
    /// The proxy's `[contracts]` key.
    fn contracts_key(self) -> &'static str {
        match self {
            Self::NotaryService => "notary_service",
            Self::ProofVerifier => "ceremony_proof_verifier",
            Self::IdentityRegistry => "identity_registry",
            Self::HandleEscrow => "handle_escrow",
            Self::GoogleJwtRoots => "google_jwt_roots",
            Self::XPlatformVerifier => platforms::X.contracts_key,
            Self::GitHubPlatformVerifier => platforms::GITHUB.contracts_key,
            Self::GooglePlatformVerifier => platforms::GOOGLE.contracts_key,
        }
    }

    /// The compiled contract whose implementation is redeployed.
    fn contract(self) -> &'static str {
        match self {
            Self::NotaryService => "NotaryService",
            Self::ProofVerifier => "CeremonyProofVerifier",
            Self::IdentityRegistry => "IdentityRegistry",
            Self::HandleEscrow => "HandleEscrow",
            Self::GoogleJwtRoots => "GoogleJwtRoots",
            Self::XPlatformVerifier => platforms::X.contract(),
            Self::GitHubPlatformVerifier => platforms::GITHUB.contract(),
            Self::GooglePlatformVerifier => platforms::GOOGLE.contract(),
        }
    }

    /// The implementation creation code, from the bytecode
    /// `libid-contracts` embeds.
    fn implementation_code(self, artifacts: &Artifacts) -> Result<Bytes> {
        Ok(artifacts.bytecode(self.contract())?)
    }

    /// Every value `--upgrade` accepts, for the CLI help and the error.
    pub const VALUES: &'static [&'static str] = &[
        "notary-service",
        "proof-verifier",
        "identity-registry",
        "handle-escrow",
        "google-jwt-roots",
        "x-platform-verifier",
        "github-platform-verifier",
        "google-platform-verifier",
    ];
}

impl From<PlatformVerifier> for Upgrade {
    fn from(verifier: PlatformVerifier) -> Self {
        match verifier {
            PlatformVerifier::X => Self::XPlatformVerifier,
            PlatformVerifier::GitHub => Self::GitHubPlatformVerifier,
            PlatformVerifier::Google => Self::GooglePlatformVerifier,
        }
    }
}

impl fmt::Display for Upgrade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotaryService => "notary-service",
            Self::ProofVerifier => "proof-verifier",
            Self::IdentityRegistry => "identity-registry",
            Self::HandleEscrow => "handle-escrow",
            Self::GoogleJwtRoots => "google-jwt-roots",
            Self::XPlatformVerifier => "x-platform-verifier",
            Self::GitHubPlatformVerifier => "github-platform-verifier",
            Self::GooglePlatformVerifier => "google-platform-verifier",
        })
    }
}

impl FromStr for Upgrade {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim() {
            "notary-service" => Ok(Self::NotaryService),
            "proof-verifier" => Ok(Self::ProofVerifier),
            "identity-registry" => Ok(Self::IdentityRegistry),
            "handle-escrow" => Ok(Self::HandleEscrow),
            "google-jwt-roots" => Ok(Self::GoogleJwtRoots),
            "x-platform-verifier" => Ok(Self::XPlatformVerifier),
            "github-platform-verifier" => Ok(Self::GitHubPlatformVerifier),
            "google-platform-verifier" => Ok(Self::GooglePlatformVerifier),
            other => bail!(
                "unknown upgrade component '{other}' (expected {})",
                Self::VALUES.join(", ")
            ),
        }
    }
}

/// Options for [`Applier::run`].
#[derive(Debug, Default)]
pub struct Options {
    /// Components to explicitly upgrade.
    pub upgrades: Vec<Upgrade>,
    /// Required when the FACTORY has no code on-chain (a virgin network):
    /// that first apply publishes the entire declared stack. With the
    /// factory present, apply converges incrementally without the flag.
    pub confirm_fresh_deploy: bool,
}

/// What an apply run did. The network file is declarative and NEVER
/// rewritten, so there is nothing to report about it: every deployed
/// component landed at exactly the address the file already declares.
#[derive(Debug, Default)]
pub struct Summary {
    /// Freshly deployed components, as `(component, address)`.
    pub deployed: Vec<(String, Address)>,
    /// Explicitly upgraded components.
    pub upgraded: Vec<String>,
    /// On-chain configuration changes beyond the always-resent idempotent
    /// ops — signer and fee convergence, wiring, ownership handovers.
    pub configured: Vec<String>,
}

impl Summary {
    /// Render for humans / the CI step summary.
    pub fn render(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        if self.deployed.is_empty() {
            let _ = writeln!(out, "Deployed: none");
        } else {
            let _ =
                writeln!(out, "Deployed (all at their declared canonical addresses):");
            for (component, addr) in &self.deployed {
                let _ = writeln!(out, "  {component} = {addr:#x}");
            }
        }
        if self.upgraded.is_empty() {
            let _ = writeln!(out, "Upgraded: none");
        } else {
            let _ = writeln!(out, "Upgraded: {}", self.upgraded.join(", "));
        }
        if !self.configured.is_empty() {
            let _ = writeln!(out, "Configured: {}", self.configured.join(", "));
        }
        let _ = writeln!(out, "Config: declarative — never rewritten");
        out
    }
}

/// Converges the chain behind one endpoint onto one network file, signing
/// as its deployer. The file is never rewritten, and the endpoint decides
/// nothing about what is deployed: the file's chain id is enforced against
/// whatever answers.
pub struct Applier<'a> {
    provider: DynProvider,
    artifacts: Artifacts,
    cfg: &'a NetworkConfig,
    /// The deployer's canonical factory.
    factory: Address,
    sender: Address,
    stack: Stack,
    opts: Options,
    summary: Summary,
    /// Circuit -> where its verifier is, located once before anything is
    /// sent, so a Platform Verifier this run deploys or rotates does not
    /// move the answer for the platform after it.
    circuits: BTreeMap<Circuit, Site>,
}

impl<'a> Applier<'a> {
    /// Sign with `signer` against `rpc`, once it reports the chain id `cfg`
    /// declares.
    pub async fn connect(
        cfg: &'a NetworkConfig,
        rpc: &RpcEndpoint,
        signer: &SignerSource,
        opts: Options,
    ) -> Result<Self> {
        let (wallet, sender) = signer.build_wallet(None).await?;
        tracing::info!(
            %sender,
            signer = %signer.describe(),
            rpc = %rpc.describe(),
            "applying"
        );
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(rpc.url().clone())
            .erased();

        let chain_id = provider.get_chain_id().await.map_err(|e| {
            anyhow!("failed to read the chain id from {}: {e}", rpc.describe())
        })?;
        if chain_id != cfg.network.chain_id {
            bail!(
                "chain id mismatch: {} expects {}, {} reports {chain_id} — refusing to \
                 send anything",
                cfg.network.name,
                cfg.network.chain_id,
                rpc.describe()
            );
        }

        let artifacts = Artifacts::embedded();
        let factory = cfg.accounts.factory_genesis()?.address(&artifacts)?;
        Ok(Self {
            provider,
            artifacts,
            cfg,
            factory,
            sender,
            stack: cfg.contracts.stack()?,
            opts,
            summary: Summary::default(),
            circuits: BTreeMap::new(),
        })
    }

    /// Converge the chain onto the file at `path`, which errors name.
    pub async fn run(mut self, path: &Path) -> Result<Summary> {
        // The signer must be the declared deployer: it is the factory's
        // genesis admin, the only key `factory.deploy` accepts, and what
        // every canonical address in the file was predicted from.
        let genesis = self.cfg.accounts.factory_genesis()?;
        if self.sender != genesis.admin {
            bail!(
                "apply signs as {:#x} but accounts.deployer of '{}' is {:#x} — the \
                 signer must be the deployer key: its factory, and every address \
                 declared in {}, follow from that key",
                self.sender,
                self.cfg.network.name,
                genesis.admin,
                path.display()
            );
        }

        let notary_signer = self.cfg.accounts.notary_address()?;
        let notary_fee = self.cfg.notary_service.fee()?;
        // The operational owner the factory should END up with; defaults
        // to the deployer.
        let operational_owner = self.cfg.accounts.owner_address().unwrap_or(self.sender);

        self.install_factory(genesis, path).await?;

        // ── Presence: what does the CHAIN have, of what the file declares? ─
        // Deployed-vs-not is read from chain state at the declared
        // (canonical, validated) addresses — config emptiness no longer
        // means anything.
        let stack = self.stack;
        let notary_service_present = self.code_present(stack.notary_service).await?;
        let proof_verifier_present = self.code_present(stack.proof_verifier).await?;
        let identity_registry_present =
            self.code_present(stack.identity_registry).await?;
        let handle_escrow_present = self.code_present(stack.handle_escrow).await?;
        let jwt_roots_present = self.code_present(stack.jwt_roots).await?;

        // Does anything need `factory.deploy` (owner-gated)? Only then must
        // the apply signer own the factory: it does from genesis, unless an
        // earlier apply handed the factory to a different operational owner.
        let mut needs_factory_deploy = !(notary_service_present
            && proof_verifier_present
            && identity_registry_present
            && handle_escrow_present
            && jwt_roots_present);
        for platform in platforms::LAUNCH {
            let declared = self.cfg.contracts.address(platform.contracts_key)?;
            needs_factory_deploy |= !self.code_present(declared).await?;
        }
        // A circuit verifier no Platform Verifier uses yet deploys through
        // the factory too, under a name carrying the pinned circuits release.
        for circuit in Circuit::ALL {
            let site = self.verifiers().site(circuit).await?;
            if let Site::Named { address, .. } = site {
                needs_factory_deploy |= !self.code_present(address).await?;
            }
            self.circuits.insert(circuit, site);
        }
        if needs_factory_deploy {
            self.ensure_factory_ownership().await?;
        }

        self.notary_service(notary_service_present, notary_signer, notary_fee)
            .await?;
        self.proof_verifier(proof_verifier_present).await?;
        self.identity_registry(identity_registry_present).await?;
        self.handle_escrow(handle_escrow_present).await?;
        self.jwt_roots(jwt_roots_present).await?;

        // ── 6. A Platform Verifier per platform, on its circuit's verifier ─
        for platform in platforms::LAUNCH {
            self.platform_verifier(platform).await?;
        }
        self.check_accepts_bindings().await?;

        // Every requested upgrade ran inside its component's section above;
        // a component none of them owns would have been silently dropped.
        if self.summary.upgraded.len() != self.opts.upgrades.len() {
            bail!(
                "{} upgrade(s) requested, {} applied — a requested component has \
                 no section in apply",
                self.opts.upgrades.len(),
                self.summary.upgraded.len()
            );
        }

        // ── Factory ownership converges to the declared operational owner ─
        self.converge_factory_owner(operational_owner).await?;

        self.safes().await?;

        // Nothing is recorded back: the file already declares every
        // canonical address and the chain records the rest.
        Ok(self.summary)
    }

    /// Step 0, the deterministic-deployment substrate. The keyless CREATE2
    /// deployer and the LibidFactory are the hard onboarding gate: a chain
    /// that cannot host them cannot host the stack.
    async fn install_factory(
        &mut self,
        genesis: FactoryGenesis,
        path: &Path,
    ) -> Result<()> {
        let predicted_factory = self.factory;
        let factory_was_present = self.code_present(predicted_factory).await?;

        // The fresh-deploy guard keys on CHAIN STATE, not config emptiness:
        // a factory with no code means a virgin network, and this apply
        // would publish the entire declared stack.
        if !factory_was_present && !self.opts.confirm_fresh_deploy {
            bail!(
                "the LibidFactory has no code at its canonical address \
                 {predicted_factory:#x} on '{}' — this chain is VIRGIN, so this apply \
                 would be a FRESH DEPLOY of the whole stack declared in {}. Re-run \
                 with --confirm-fresh-deploy if the network is genuinely new; once \
                 the factory exists, apply converges incrementally without the flag.",
                self.cfg.network.name,
                path.display()
            );
        }

        ensure_create2_deployer(&self.provider)
            .await
            .context("the canonical CREATE2 deployer is the onboarding gate")?;
        let libid_factory = genesis.ensure(&self.provider, &self.artifacts).await?;

        // CANARY: after any install the factory must sit at exactly the
        // predicted address. A mismatch (or missing code) means the chain
        // does not derive CREATE2 addresses the standard way — every
        // "deterministic" address downstream would be wrong, so abort before
        // sending anything.
        if libid_factory != predicted_factory
            || !self.code_present(predicted_factory).await?
        {
            bail!(
                "FACTORY CANARY FAILED: the LibidFactory is not at its canonical \
                 predicted address {predicted_factory:#x} (got {libid_factory:#x}). \
                 This chain does not derive CREATE2 addresses the standard way \
                 (zkSync-Era-style derivation?), so cross-network address parity is \
                 impossible here — refusing to proceed."
            );
        }
        if !factory_was_present {
            tracing::info!(%libid_factory, "LibidFactory installed at its canonical address");
            self.summary
                .deployed
                .push(("contracts.factory".into(), libid_factory));
        }
        Ok(())
    }

    /// Step 1, the Notary Service: everything else takes its proxy address.
    async fn notary_service(
        &mut self,
        present: bool,
        notary_signer: Address,
        notary_fee: U256,
    ) -> Result<()> {
        let notary_service = self.stack.notary_service;
        if !present {
            let addr = self
                .deploy_named_proxy(
                    names::NOTARY_SERVICE,
                    "NotaryService",
                    NotaryService::initializeCall {
                        owner_: self.sender,
                        notary_: notary_signer,
                        fee_: notary_fee,
                    }
                    .abi_encode()
                    .into(),
                )
                .await?;
            tracing::info!(
                %addr,
                name = names::NOTARY_SERVICE,
                "NotaryService proxy deployed"
            );
            debug_assert_eq!(addr, notary_service);
            self.summary
                .deployed
                .push(("contracts.notary_service".into(), addr));
        }

        self.upgrade_if_requested("notary_service", notary_service)
            .await?;

        // Declarative key trust: the file says which signer the stack
        // accepts. Only the ADDITION is inferable — the service holds a SET
        // so a rotation can overlap, and which outgoing key to stop trusting
        // is a decision the file does not carry.
        let service = NotaryService::new(notary_service, &self.provider);
        let trusted = service
            .isTrustedNotary(notary_signer)
            .call()
            .await
            .map_err(|e| anyhow!("NotaryService.isTrustedNotary read failed: {e}"))?;
        if !trusted {
            send_with_nonce_retry!(
                service.setNotary(notary_signer, true),
                "NotaryService.setNotary",
                &self.provider,
                self.sender
            )?;
            tracing::info!(%notary_signer, "notary key trusted");
            self.summary
                .configured
                .push(format!("notary key {notary_signer:#x} trusted"));
        }

        let on_chain_fee = service
            .fee()
            .call()
            .await
            .map_err(|e| anyhow!("NotaryService.fee read failed: {e}"))?;
        if on_chain_fee != notary_fee {
            send_with_nonce_retry!(
                service.setFee(notary_fee),
                "NotaryService.setFee",
                &self.provider,
                self.sender
            )?;
            tracing::info!(from_wei = %on_chain_fee, to_wei = %notary_fee, "notary fee set");
            self.summary
                .configured
                .push(format!("notary fee {on_chain_fee} -> {notary_fee} wei"));
        }

        if let Some(recipient) = self.cfg.notary_service.fee_recipient.get() {
            let on_chain_recipient =
                service.feeRecipient().call().await.map_err(|e| {
                    anyhow!("NotaryService.feeRecipient read failed: {e}")
                })?;
            if on_chain_recipient != recipient {
                send_with_nonce_retry!(
                    service.setFeeRecipient(recipient),
                    "NotaryService.setFeeRecipient",
                    &self.provider,
                    self.sender
                )?;
                tracing::info!(
                    from = %on_chain_recipient,
                    to = %recipient,
                    "notary fee recipient set"
                );
                self.summary.configured.push(format!(
                    "notary fee recipient {on_chain_recipient:#x} -> {recipient:#x}"
                ));
            }
        }
        Ok(())
    }

    /// Step 2, the Proof Verifier the identity registry dispatches through.
    async fn proof_verifier(&mut self, present: bool) -> Result<()> {
        let proof_verifier = self.stack.proof_verifier;
        if !present {
            let addr = self
                .deploy_named_proxy(
                    names::CEREMONY_PROOF_VERIFIER,
                    "CeremonyProofVerifier",
                    CeremonyProofVerifier::initializeCall {
                        owner_: self.sender,
                    }
                    .abi_encode()
                    .into(),
                )
                .await?;
            tracing::info!(
                %addr,
                name = names::CEREMONY_PROOF_VERIFIER,
                "CeremonyProofVerifier proxy deployed"
            );
            debug_assert_eq!(addr, proof_verifier);
            self.summary
                .deployed
                .push(("contracts.ceremony_proof_verifier".into(), addr));
        }

        self.upgrade_if_requested("ceremony_proof_verifier", proof_verifier)
            .await
    }

    /// Step 3, the identity registry, dispatching through the Proof Verifier.
    async fn identity_registry(&mut self, present: bool) -> Result<()> {
        let Stack {
            identity_registry,
            proof_verifier,
            ..
        } = self.stack;
        if !present {
            let addr = self
                .deploy_named_proxy(
                    names::IDENTITY_REGISTRY,
                    "IdentityRegistry",
                    IdentityRegistry::initializeCall {
                        owner_: self.sender,
                    }
                    .abi_encode()
                    .into(),
                )
                .await?;
            tracing::info!(
                %addr,
                name = names::IDENTITY_REGISTRY,
                "IdentityRegistry proxy deployed"
            );
            debug_assert_eq!(addr, identity_registry);
            self.summary
                .deployed
                .push(("contracts.identity_registry".into(), addr));
        }

        self.upgrade_if_requested("identity_registry", identity_registry)
            .await?;

        let registry = IdentityRegistry::new(identity_registry, &self.provider);
        let wired =
            registry.proofVerifier().call().await.map_err(|e| {
                anyhow!("IdentityRegistry.proofVerifier read failed: {e}")
            })?;
        if wired != proof_verifier {
            send_with_nonce_retry!(
                registry.setProofVerifier(proof_verifier),
                "IdentityRegistry.setProofVerifier",
                &self.provider,
                self.sender
            )?;
            tracing::info!(%proof_verifier, "IdentityRegistry dispatches through the proof verifier");
            self.summary.configured.push(format!(
                "identity registry -> proof verifier {proof_verifier:#x}"
            ));
        }
        Ok(())
    }

    /// Step 4, the handle escrow, bound to the identity registry. `initialize`
    /// refuses a registry whose `nodeKeyed()` is not true, so the registry
    /// and any upgrade of it land first.
    async fn handle_escrow(&mut self, present: bool) -> Result<()> {
        let Stack {
            handle_escrow,
            identity_registry,
            ..
        } = self.stack;
        if !present {
            let addr = self
                .deploy_named_proxy(
                    names::HANDLE_ESCROW,
                    "HandleEscrow",
                    HandleEscrow::initializeCall {
                        owner_: self.sender,
                        registry_: identity_registry,
                    }
                    .abi_encode()
                    .into(),
                )
                .await?;
            tracing::info!(
                %addr,
                name = names::HANDLE_ESCROW,
                %identity_registry,
                "HandleEscrow proxy deployed"
            );
            debug_assert_eq!(addr, handle_escrow);
            self.summary
                .deployed
                .push(("contracts.handle_escrow".into(), addr));
        }

        self.upgrade_if_requested("handle_escrow", handle_escrow)
            .await?;

        // The escrow has no setter for its registry, so apply can only check
        // it. One bound elsewhere pays out to whoever THAT contract says
        // holds a handle.
        let resolves_through = HandleEscrow::new(handle_escrow, &self.provider)
            .registry()
            .call()
            .await
            .map_err(|e| anyhow!("HandleEscrow.registry read failed: {e}"))?;
        if resolves_through != identity_registry {
            bail!(
                "the HandleEscrow at {handle_escrow:#x} resolves through \
                 {resolves_through:#x}, not the declared IdentityRegistry \
                 {identity_registry:#x}. apply cannot rebind it: that takes an escrow \
                 implementation that moves it, or a new canonical escrow name"
            );
        }
        Ok(())
    }

    /// Step 5, the Google JWT root list, beside the verifier it serves.
    async fn jwt_roots(&mut self, present: bool) -> Result<()> {
        let Stack {
            jwt_roots,
            notary_service,
            ..
        } = self.stack;
        if !present {
            let addr = self
                .deploy_named_proxy(
                    names::GOOGLE_JWT_ROOTS,
                    "GoogleJwtRoots",
                    GoogleJwtRoots::initializeCall {
                        owner_: self.sender,
                        notary_: notary_service,
                    }
                    .abi_encode()
                    .into(),
                )
                .await?;
            tracing::info!(
                %addr,
                name = names::GOOGLE_JWT_ROOTS,
                "GoogleJwtRoots proxy deployed; the trust list starts EMPTY: point a \
                 keeper at it, or every Google binding reverts"
            );
            debug_assert_eq!(addr, jwt_roots);
            self.summary
                .deployed
                .push(("contracts.google_jwt_roots".into(), addr));
        }

        self.upgrade_if_requested("google_jwt_roots", jwt_roots)
            .await?;

        let roots = GoogleJwtRoots::new(jwt_roots, &self.provider);
        let roots_notary = roots
            .notaryService()
            .call()
            .await
            .map_err(|e| anyhow!("GoogleJwtRoots.notaryService read failed: {e}"))?;
        if roots_notary != notary_service {
            send_with_nonce_retry!(
                roots.setNotaryService(notary_service),
                "GoogleJwtRoots.setNotaryService",
                &self.provider,
                self.sender
            )?;
            tracing::info!(%notary_service, "GoogleJwtRoots verifies through the notary service");
            self.summary
                .configured
                .push(format!("jwt roots -> notary service {notary_service:#x}"));
        }
        Ok(())
    }

    /// The registry accepts a platform's bindings once its Proof Verifier
    /// routes the platform to a registered verifier.
    async fn check_accepts_bindings(&self) -> Result<()> {
        let identity_registry = self.stack.identity_registry;
        let registry = IdentityRegistry::new(identity_registry, &self.provider);
        for platform in platforms::LAUNCH {
            let accepts = registry
                .acceptsBindings(platform.id())
                .call()
                .await
                .map_err(|e| {
                    anyhow!("IdentityRegistry.acceptsBindings read failed: {e}")
                })?;
            if !accepts {
                bail!(
                    "IdentityRegistry {identity_registry:#x} accepts no {} binding after \
                     apply registered its verifier",
                    platform.label
                );
            }
        }
        Ok(())
    }

    /// Reads which circuit verifiers this chain's Platform Verifiers use.
    fn verifiers(&self) -> Verifiers<'_> {
        Verifiers {
            provider: &self.provider,
            artifacts: &self.artifacts,
            contracts: &self.cfg.contracts,
            factory: self.factory,
        }
    }

    /// Whether `addr` has code on-chain — the declarative presence check.
    async fn code_present(&self, addr: Address) -> Result<bool> {
        Ok(!self
            .provider
            .get_code_at(addr)
            .await
            .map_err(|e| anyhow!("get_code({addr:#x}) failed: {e}"))?
            .is_empty())
    }

    /// Hand the factory over to `desired`, the declared `[accounts].owner`
    /// (default: the deployer). Ownable2Step: from the sender this
    /// INITIATES the handover; on a dev chain (anvil/hardhat) the
    /// acceptance is completed by impersonating the new owner, so local
    /// stacks end fully converged.
    async fn converge_factory_owner(&mut self, desired: Address) -> Result<()> {
        let sender = self.sender;
        let factory = self.factory;
        let contract = LibidFactory::new(factory, &self.provider);
        let current = contract
            .owner()
            .call()
            .await
            .map_err(|e| anyhow!("LibidFactory.owner read failed: {e}"))?;
        if current == desired {
            return Ok(());
        }
        if current != sender {
            // Nothing this signer can do; say so instead of failing the whole
            // apply after the chain already converged.
            tracing::warn!(
                owner = %current,
                signer = %sender,
                wanted = %desired,
                "factory owner is not the apply signer: cannot hand ownership to \
                 accounts.owner"
            );
            self.summary.configured.push(format!(
                "factory ownership NOT converged: owned by {current:#x}, wanted \
                 {desired:#x}"
            ));
            return Ok(());
        }

        let pending = contract
            .pendingOwner()
            .call()
            .await
            .map_err(|e| anyhow!("LibidFactory.pendingOwner read failed: {e}"))?;
        if pending != desired {
            send_with_nonce_retry!(
                contract.transferOwnership(desired),
                "LibidFactory.transferOwnership",
                &self.provider,
                sender
            )?;
            tracing::info!(from = %sender, to = %desired, "factory ownership handover initiated");
        }

        if self.is_dev_chain().await? {
            // Complete the two-step locally: impersonate the operational
            // owner (e.g. the anvil #0 wallet) and accept.
            self.provider
                .anvil_set_balance(desired, Unit::ETHER.wei())
                .await
                .map_err(|e| anyhow!("anvil_setBalance failed: {e}"))?;
            self.provider
                .anvil_impersonate_account(desired)
                .await
                .map_err(|e| anyhow!("anvil_impersonateAccount failed: {e}"))?;
            let accept = TransactionRequest::default()
                .with_from(desired)
                .with_to(factory)
                .with_input(LibidFactory::acceptOwnershipCall {}.abi_encode());
            self.provider
                .eth_send_unsigned_transaction(accept)
                .await
                .map_err(|e| anyhow!("impersonated acceptOwnership failed: {e}"))?;
            self.provider
                .anvil_stop_impersonating_account(desired)
                .await
                .map_err(|e| anyhow!("anvil_stopImpersonatingAccount failed: {e}"))?;
            tracing::info!(from = %sender, to = %desired, "factory ownership converged (dev)");
            self.summary.configured.push(format!(
                "factory ownership transferred to accounts.owner {desired:#x} (dev)"
            ));
        } else {
            self.summary.configured.push(format!(
                "factory ownership handover to accounts.owner {desired:#x} initiated — \
                 pending acceptOwnership by that key"
            ));
        }
        Ok(())
    }

    /// Whether the RPC's `web3_clientVersion` reports a dev chain (anvil or
    /// hardhat).
    async fn is_dev_chain(&self) -> Result<bool> {
        let version = self
            .provider
            .get_client_version()
            .await
            .map_err(|e| anyhow!("web3_clientVersion failed: {e}"))?
            .to_lowercase();
        Ok(version.contains("anvil") || version.contains("hardhat"))
    }

    /// Make sure the apply signer owns the factory (its `deploy` is
    /// owner-gated).
    ///
    /// - Signer already the owner: nothing to do.
    /// - Signer is the pending owner (an interrupted Ownable2Step handover):
    ///   `acceptOwnership`.
    /// - Otherwise a hard error: the signer is the deployer, the factory's
    ///   genesis admin, so another owner means an earlier apply handed the
    ///   factory to a different `accounts.owner`, and that key has to hand it
    ///   back before anything new can deploy.
    async fn ensure_factory_ownership(&self) -> Result<()> {
        let (factory, sender) = (self.factory, self.sender);
        let contract = LibidFactory::new(factory, &self.provider);
        let owner = contract
            .owner()
            .call()
            .await
            .map_err(|e| anyhow!("LibidFactory.owner read failed: {e}"))?;
        if owner == sender {
            return Ok(());
        }
        let pending = contract
            .pendingOwner()
            .call()
            .await
            .map_err(|e| anyhow!("LibidFactory.pendingOwner read failed: {e}"))?;
        if pending == sender {
            send_with_nonce_retry!(
                contract.acceptOwnership(),
                "LibidFactory.acceptOwnership",
                &self.provider,
                sender
            )?;
            tracing::info!(from = %owner, to = %sender, "factory ownership accepted");
            return Ok(());
        }
        bail!(
            "the factory at {factory:#x} is owned by {owner:#x} but apply signs as \
             {sender:#x}. factory.deploy is owner-gated and the deployer is its genesis \
             admin, so that owner must transferOwnership back to the deployer first"
        )
    }

    /// CREATE3-deploy `creation_code` under `name` through the factory, with
    /// an explicit chain-fetched nonce (the rest of the apply flow manages
    /// nonces explicitly, so the provider's cached filler cannot be trusted
    /// here). Idempotent: a name the factory already deployed returns its
    /// recorded address without sending anything — that is how a
    /// partially-failed apply converges instead of tripping on the
    /// single-use name.
    ///
    /// The returned address is verified to equal `predict_address(factory,
    /// name)` — the whole point of the exercise.
    async fn factory_deploy_named(
        &self,
        name: &str,
        creation_code: Bytes,
    ) -> Result<Address> {
        let (factory, sender) = (self.factory, self.sender);
        let contract = LibidFactory::new(factory, &self.provider);
        let predicted = predict_address(factory, name);

        let existing = contract
            .deployedAt(name.to_string())
            .call()
            .await
            .map_err(|e| anyhow!("factory deployedAt({name}) read failed: {e}"))?;
        if existing != Address::ZERO {
            tracing::info!(name, %existing, "already deployed by the factory; reusing");
            if existing != predicted {
                bail!(
                    "factory record for {name} is {existing:#x} but predict says \
                     {predicted:#x} — the deterministic invariant is broken"
                );
            }
            return Ok(existing);
        }

        // `deploy` is sent as raw calldata: alloy's `sol!` reserves the
        // `deploy` method name on generated contract instances.
        let call = LibidFactory::deployCall {
            name: name.to_string(),
            creationCode: creation_code,
        };
        let nonce = self
            .provider
            .get_transaction_count(sender)
            .await
            .map_err(|e| {
                anyhow!("factory deploy of {name} failed to fetch nonce: {e}")
            })?;
        let tx = TransactionRequest::default()
            .with_to(factory)
            .with_input(Bytes::from(call.abi_encode()))
            .with_nonce(nonce);
        let pending = self
            .provider
            .send_transaction(tx)
            .await
            .map_err(|e| anyhow!("factory deploy of {name} send failed: {e}"))?;
        pending
            .get_receipt()
            .await
            .map_err(|e| anyhow!("factory deploy of {name} confirmation failed: {e}"))?;

        let deployed = contract
            .deployedAt(name.to_string())
            .call()
            .await
            .map_err(|e| anyhow!("factory deployedAt({name}) re-read failed: {e}"))?;
        if deployed != predicted {
            bail!(
                "factory deployed {name} at {deployed:#x} but predict says \
                 {predicted:#x} — the deterministic invariant is broken"
            );
        }
        Ok(deployed)
    }

    /// Deploy `contract`'s implementation via plain CREATE (its address is
    /// referenced, not canonical), then CREATE3-deploy an ERC1967 proxy for
    /// it under `name` through the factory, initialized with the ABI-encoded
    /// `init_data`. The named-proxy shape of every UUPS entry contract.
    async fn deploy_named_proxy(
        &self,
        name: &str,
        contract: &str,
        init_data: Bytes,
    ) -> Result<Address> {
        let implementation_code = self.artifacts.bytecode(contract)?;
        // Reuse before paying for an implementation nobody will point at.
        let record = LibidFactory::new(self.factory, &self.provider)
            .deployedAt(name.to_string())
            .call()
            .await
            .map_err(|e| anyhow!("factory deployedAt({name}) read failed: {e}"))?;
        if record != Address::ZERO {
            return self.factory_deploy_named(name, Bytes::new()).await;
        }

        let implementation = deploy_contract_from(
            &self.provider,
            implementation_code,
            &format!("{contract} (impl)"),
            Some(self.sender),
        )
        .await?;
        let creation_code = self.proxy_creation_code(implementation, init_data)?;
        self.factory_deploy_named(name, creation_code).await
    }

    /// The circuit verifier for `circuit`: the one its Platform Verifiers
    /// already use, or the copy under [`crate::circuits::factory_name`],
    /// deployed if the chain lacks it. A second apply finds code at the same
    /// address and sends nothing.
    async fn circuit_verifier(&mut self, circuit: Circuit) -> Result<Address> {
        let (name, address) = match self.circuits.get(&circuit) {
            Some(Site::InUse(address)) => return Ok(*address),
            Some(Site::Named { name, address }) => (name.clone(), *address),
            None => bail!("{} verifier was not located", circuit.name()),
        };
        if !self.code_present(address).await? {
            let creation_code = self.artifacts.bytecode(circuit.contract())?;
            let deployed = self.factory_deploy_named(&name, creation_code).await?;
            tracing::info!(
                circuit = circuit.name(),
                %deployed,
                %name,
                "circuit verifier deployed"
            );
            debug_assert_eq!(deployed, address);
            self.summary
                .deployed
                .push((format!("circuits.{}", circuit.name()), deployed));
        }
        Ok(address)
    }

    /// Deploy, wire and register one platform's Platform Verifier, on the
    /// verifier for the ceremony circuit its proofs are made under.
    async fn platform_verifier(&mut self, platform: &Platform) -> Result<()> {
        let proxy = self.cfg.contracts.address(platform.contracts_key)?;
        let circuit = self.circuit_verifier(platform.circuit()).await?;

        if !self.code_present(proxy).await? {
            // The initializer knows the contract's rules — a Notary Service
            // exactly where the profile notarizes — and the code at `circuit`
            // must be the verifier the implementation compiles in, so a
            // mis-wiring fails here rather than at the proxy's constructor.
            platform
                .verifier
                .circuit_codehash_at(&self.provider, &self.artifacts, circuit)
                .await?;
            let init = platform
                .initializer(
                    self.sender,
                    self.stack.notary_service,
                    circuit,
                    self.stack.jwt_roots,
                )
                .call()?;
            let deployed = self
                .deploy_named_proxy(
                    platform.canonical_name,
                    platform.contract(),
                    init.abi_encode().into(),
                )
                .await?;
            tracing::info!(
                platform = platform.label,
                %deployed,
                name = platform.canonical_name,
                "Platform Verifier deployed"
            );
            debug_assert_eq!(deployed, proxy);
            self.summary.deployed.push((platform.component(), deployed));
        }

        self.upgrade_if_requested(platform.contracts_key, proxy)
            .await?;
        self.converge_trust_roots(platform, proxy, circuit).await?;
        if platform.reads_jwt_roots() {
            self.converge_jwt_roots(proxy).await?;
        }
        self.register_verifier(platform, proxy).await
    }

    /// Point a Platform Verifier at its circuit's verifier when the one it
    /// uses lacks the vendored code; one that holds it stays, whatever its
    /// address. A circuits release with new code lands under a new factory
    /// name, and the proxy's implementation compiles in the code hash it
    /// accepts, so the rotation needs `--upgrade` of that Platform Verifier
    /// in the same run; without it apply stops before sending
    /// `setTrustRoots`.
    ///
    /// The surface is `PlatformVerifierBase`'s, identical in every Platform
    /// Verifier. The Notary Service the proxy holds is kept: zero for
    /// Google, whose profile notarizes nothing.
    async fn converge_trust_roots(
        &mut self,
        platform: &Platform,
        proxy: Address,
        circuit: Address,
    ) -> Result<()> {
        let verifier = PlatformVerifierBase::new(proxy, &self.provider);
        let wired =
            verifier.honkVerifier().call().await.map_err(|e| {
                anyhow!("{}.honkVerifier read failed: {e}", platform.label)
            })?;
        if wired == circuit || self.verifiers().in_use(platform).await?.is_some() {
            return Ok(());
        }
        platform
            .verifier
            .rotation_codehash_at(&self.provider, &self.artifacts, proxy, circuit)
            .await
            .with_context(|| {
                format!(
                    "{} pins {wired:#x}; rotating it onto {circuit:#x} takes \
                     --upgrade {} in the same apply",
                    platform.label,
                    Upgrade::from(platform.verifier)
                )
            })?;
        let notary =
            verifier.notaryService().call().await.map_err(|e| {
                anyhow!("{}.notaryService read failed: {e}", platform.label)
            })?;
        send_with_nonce_retry!(
            verifier.setTrustRoots(notary, circuit),
            format!("{}.setTrustRoots", platform.label),
            &self.provider,
            self.sender
        )?;
        tracing::info!(
            platform = platform.label,
            from = %wired,
            to = %circuit,
            "circuit verifier rotated"
        );
        self.summary.configured.push(format!(
            "{} circuit verifier {wired:#x} -> {circuit:#x}",
            platform.label
        ));
        Ok(())
    }

    /// The Google verifier reads its trusted moduli through the root list; a
    /// drifted pointer is a verifier trusting a list nobody rotates.
    async fn converge_jwt_roots(&mut self, proxy: Address) -> Result<()> {
        let jwt_roots = self.stack.jwt_roots;
        let verifier = GooglePlatformVerifier::new(proxy, &self.provider);
        let wired =
            verifier.jwtRoots().call().await.map_err(|e| {
                anyhow!("GooglePlatformVerifier.jwtRoots read failed: {e}")
            })?;
        if wired == jwt_roots {
            return Ok(());
        }
        send_with_nonce_retry!(
            verifier.setJwtRoots(jwt_roots),
            "GooglePlatformVerifier.setJwtRoots",
            &self.provider,
            self.sender
        )?;
        tracing::info!(%jwt_roots, "Google verifier reads roots from GoogleJwtRoots");
        self.summary
            .configured
            .push(format!("google verifier -> jwt roots {jwt_roots:#x}"));
        Ok(())
    }

    /// Register the verifier in the Supported Version Set. Until this lands,
    /// `IdentityRegistry.bind` reverts `UnknownVersion` and every resolver
    /// for the platform reverts `UnknownPlatform`.
    async fn register_verifier(
        &mut self,
        platform: &Platform,
        proxy: Address,
    ) -> Result<()> {
        let platform_id = platform.id();
        let version_set =
            CeremonyProofVerifier::new(self.stack.proof_verifier, &self.provider);
        let registered = version_set
            .verifierOf(platform_id, LAUNCH_VERIFIER_VERSION)
            .call()
            .await
            .map_err(|e| anyhow!("CeremonyProofVerifier.verifierOf read failed: {e}"))?;
        if registered == proxy {
            return Ok(());
        }
        send_with_nonce_retry!(
            version_set.setVerifier(platform_id, LAUNCH_VERIFIER_VERSION, proxy),
            format!("CeremonyProofVerifier.setVerifier({})", platform.label),
            &self.provider,
            self.sender
        )?;
        tracing::info!(
            platform = platform.label,
            version = LAUNCH_VERIFIER_VERSION,
            %proxy,
            "Platform Verifier registered"
        );
        self.summary.configured.push(format!(
            "{} verifier v{LAUNCH_VERIFIER_VERSION} -> {proxy:#x}",
            platform.label
        ));
        Ok(())
    }

    /// Replace a UUPS proxy's implementation with a freshly deployed one of
    /// `upgrade`'s contract. The entry address, its storage and its owner
    /// all survive.
    async fn upgrade_proxy(&self, upgrade: Upgrade, proxy: Address) -> Result<Address> {
        let label = upgrade.contract();
        let new_impl = deploy_contract_from(
            &self.provider,
            upgrade.implementation_code(&self.artifacts)?,
            &format!("{label} (new impl)"),
            Some(self.sender),
        )
        .await?;
        let proxied = IUUPSUpgradeable::new(proxy, &self.provider);
        send_with_nonce_retry!(
            proxied.upgradeToAndCall(new_impl, Bytes::new()),
            format!("{label}.upgradeToAndCall"),
            &self.provider,
            self.sender
        )?;
        Ok(new_impl)
    }

    /// Run the `--upgrade`s that name the proxy under `[contracts].<key>`.
    /// Called from the component's own section, once its proxy has code
    /// and BEFORE anything reads or writes through it: the implementation
    /// running today may predate a getter the wiring reads (a HandleEscrow
    /// from before libid-contracts 0.15 has no `registry()`), and the
    /// upgrade is what makes that read answer. Nothing to do when no
    /// upgrade names the component.
    async fn upgrade_if_requested(&mut self, key: &str, proxy: Address) -> Result<()> {
        let requested: Vec<Upgrade> = self
            .opts
            .upgrades
            .iter()
            .copied()
            .filter(|u| u.contracts_key() == key)
            .collect();
        for upgrade in requested {
            let new_impl = self.upgrade_proxy(upgrade, proxy).await?;
            tracing::info!(
                contract = upgrade.contract(),
                %proxy,
                %new_impl,
                "proxy upgraded"
            );
            self.summary
                .upgraded
                .push(format!("{} -> {new_impl:#x}", upgrade.contract()));
        }
        Ok(())
    }

    /// ERC1967Proxy creation code ++ `abi.encode(implementation, initData)`
    /// — the bytes a CREATE3 name is deployed from.
    fn proxy_creation_code(
        &self,
        implementation: Address,
        init_data: Bytes,
    ) -> Result<Bytes> {
        let mut code = self.artifacts.bytecode("ERC1967Proxy")?.to_vec();
        code.extend_from_slice(&(implementation, init_data).abi_encode_params());
        Ok(code.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `--upgrade` value round-trips, and each names a canonical
    /// contract the config actually declares.
    #[test]
    fn every_upgrade_value_parses_and_names_a_canonical_proxy() {
        for value in Upgrade::VALUES {
            let upgrade: Upgrade = value.parse().expect("value parses");
            assert_eq!(upgrade.to_string(), *value);
            assert!(
                names::canonical_name(upgrade.contracts_key()).is_some(),
                "{value} names no canonical contract"
            );
        }
    }

    /// An unknown component lists the ones that exist rather than failing
    /// bare. `notary` and `identity-names` are what the Notary Service and
    /// the identity registry used to answer to, so a stale runbook fails
    /// loudly instead of upgrading nothing.
    #[test]
    fn an_unknown_upgrade_value_lists_the_known_ones() {
        for stale in ["notary", "identity-names"] {
            let err = stale.parse::<Upgrade>().unwrap_err().to_string();
            assert!(err.contains("notary-service"), "got: {err}");
            assert!(err.contains("identity-registry"), "got: {err}");
        }
    }
}
