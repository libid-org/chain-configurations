//! Read-only comparison of desired state (the network file) against the
//! chain. No signer, no transactions — safe to run from anywhere.
//!
//! A file pre-declares EVERY address, so presence is read from CHAIN STATE.
//! A component is either "declared + present" (ok) or "declared + missing"
//! (DEPLOY — apply would put it at exactly the declared address). Declared
//! at a WRONG address never reaches the plan: `NetworkConfig::load` rejects
//! a canonical key that does not equal `predict_address(factory, name)`.
//! Once the factory exists the plan also diffs its on-chain `deployedAt`
//! records against the config to surface drift.

mod checks;

use std::collections::BTreeMap;

use alloy::{
    primitives::{
        keccak256,
        Address,
    },
    providers::{
        DynProvider,
        Provider,
        ProviderBuilder,
    },
};
use anyhow::{
    anyhow,
    Result,
};
use checks::{
    AcceptsBindings,
    CircuitVerifier,
    Code,
    Create2Deployer,
    EscrowRegistry,
    FactoryOwner,
    FactoryRecord,
    NotaryFee,
    NotarySigner,
    Registration,
    RegistryProofVerifier,
    RootsNotaryService,
    RootsRotation,
    TrustRoots,
};
use libid_contracts::{
    bindings::{
        ceremony::{
            CeremonyProofVerifier,
            GoogleJwtRoots,
            NotaryService,
            PlatformVerifierBase,
        },
        escrow::HandleEscrow,
        factory::LibidFactory,
        identity::IdentityRegistry,
    },
    factory::{
        predict_address,
        FactoryGenesis,
        CREATE2_DEPLOYER,
    },
    Artifacts,
};
use serde::Serialize;

use crate::{
    circuits::{
        self,
        Circuit,
    },
    config::NetworkConfig,
    names,
    platforms::{
        self,
        Platform,
        LAUNCH_VERIFIER_VERSION,
    },
    rpc::RpcEndpoint,
};

/// What a plan concluded about one component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Desired and present; nothing to do.
    Ok,
    /// Missing; `apply` would deploy it.
    Deploy,
    /// Present but configuration would be (re-)sent or recorded.
    Configure,
    /// Not requested by the config; skipped.
    Skipped,
    /// Something looks wrong; `apply` will not fix it silently.
    Warn,
}

/// One line of the plan.
#[derive(Debug, Clone, Serialize)]
pub struct Item {
    /// Component name, e.g. `contracts.identity_registry`.
    pub component: String,
    /// What apply would do.
    pub status: Status,
    /// Human-readable detail.
    pub detail: String,
}

impl Item {
    /// One plan line.
    pub(crate) fn new(
        component: impl Into<String>,
        status: Status,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            component: component.into(),
            status,
            detail: detail.into(),
        }
    }
}

/// The whole plan.
#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    /// Network name from the file.
    pub network: String,
    /// The endpoint that answered, by origin — `--rpc-url`'s, or the file's
    /// `network.rpc_url` when the file names one and no flag was given.
    /// Scheme, host and port: a private endpoint's key stays out of every
    /// plan and every summary of one.
    pub rpc_origin: String,
    /// Chain id the file expects.
    pub chain_id_expected: u64,
    /// Chain id the RPC reported.
    pub chain_id_actual: u64,
    /// Per-component findings.
    pub items: Vec<Item>,
}

impl Plan {
    /// Whether `apply` would send any transaction beyond the always-resent
    /// idempotent configuration ops.
    pub fn has_deploys(&self) -> bool {
        self.items.iter().any(|i| i.status == Status::Deploy)
    }

    /// The status recorded for one component, if the plan covers it.
    pub fn status_of(&self, component: &str) -> Option<Status> {
        self.items
            .iter()
            .find(|i| i.component == component)
            .map(|i| i.status)
    }

    /// Render for humans.
    pub fn render(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let _ = writeln!(
            out,
            "Plan for {} via {} (chain {} — RPC reports {})",
            self.network, self.rpc_origin, self.chain_id_expected, self.chain_id_actual
        );
        for item in &self.items {
            let tag = match item.status {
                Status::Ok => "ok       ",
                Status::Deploy => "DEPLOY   ",
                Status::Configure => "configure",
                Status::Skipped => "skipped  ",
                Status::Warn => "WARN     ",
            };
            let _ = writeln!(out, "  [{tag}] {:<38} {}", item.component, item.detail);
        }
        out
    }
}

impl Plan {
    /// Compare the desired state with the chain behind `rpc`.
    pub async fn build(cfg: &NetworkConfig, rpc: &RpcEndpoint) -> Result<Self> {
        let provider = ProviderBuilder::new()
            .connect_http(rpc.url().clone())
            .erased();
        let chain_id_actual = provider.get_chain_id().await.map_err(|e| {
            anyhow!("failed to read the chain id from {}: {e}", rpc.describe())
        })?;

        let mut planner = Planner {
            provider,
            artifacts: Artifacts::embedded(),
            cfg,
            items: Vec::new(),
        };
        if chain_id_actual != cfg.network.chain_id {
            planner.push(Item::new(
                "network.chain_id",
                Status::Warn,
                format!(
                    "file says {} but the RPC reports {chain_id_actual} — apply would \
                     refuse to send anything",
                    cfg.network.chain_id
                ),
            ));
        }
        planner.stack().await?;

        Ok(Plan {
            network: cfg.network.name.clone(),
            rpc_origin: rpc.origin(),
            chain_id_expected: cfg.network.chain_id,
            chain_id_actual,
            items: planner.items,
        })
    }
}

/// Reads the chain for one plan, one component at a time, and collects
/// what each read means.
struct Planner<'a> {
    provider: DynProvider,
    artifacts: Artifacts,
    cfg: &'a NetworkConfig,
    items: Vec<Item>,
}

impl Planner<'_> {
    fn push(&mut self, item: impl Into<Item>) {
        self.items.push(item.into());
    }

    /// Whether `address` has code, recorded as `component`'s line.
    async fn code(&mut self, component: &str, address: Address) -> Result<bool> {
        let present = !self
            .provider
            .get_code_at(address)
            .await
            .map_err(|e| anyhow!("get_code({component}) failed: {e}"))?
            .is_empty();
        self.push(Code {
            component: component.into(),
            address,
            present,
        });
        Ok(present)
    }

    /// Every component, in deploy order.
    async fn stack(&mut self) -> Result<()> {
        // ── The onboarding gate ──────────────────────────────────────────
        let predicted_factory = self
            .cfg
            .accounts
            .factory_genesis()?
            .address(&self.artifacts)?;
        let present = !self
            .provider
            .get_code_at(CREATE2_DEPLOYER)
            .await
            .map_err(|e| anyhow!("get_code(create2_deployer) failed: {e}"))?
            .is_empty();
        self.push(Create2Deployer { present });

        let factory = self.cfg.contracts.address("factory")?;
        let factory_present = self.code("contracts.factory", factory).await?;
        if factory != predicted_factory {
            // Unreachable through `load`, which validates the equality; kept
            // so a caller building a config by hand still gets told.
            self.push(Item::new(
                "contracts.factory",
                Status::Warn,
                format!("declared {factory:#x} but predicted {predicted_factory:#x}"),
            ));
        }

        // ── The stack, in deploy order ───────────────────────────────────
        let stack = self.cfg.contracts.stack()?;
        if self
            .code("contracts.notary_service", stack.notary_service)
            .await?
        {
            self.notary_service(stack.notary_service).await;
        }
        let proof_verifier = self
            .code("contracts.ceremony_proof_verifier", stack.proof_verifier)
            .await?
            .then_some(stack.proof_verifier);
        let identity_registry_present = self
            .code("contracts.identity_registry", stack.identity_registry)
            .await?;
        if identity_registry_present {
            self.identity_registry(stack.identity_registry, stack.proof_verifier)
                .await;
        }
        if self
            .code("contracts.handle_escrow", stack.handle_escrow)
            .await?
        {
            self.handle_escrow(stack.handle_escrow, stack.identity_registry)
                .await;
        }
        if self
            .code("contracts.google_jwt_roots", stack.jwt_roots)
            .await?
        {
            self.jwt_roots(stack.jwt_roots, stack.notary_service).await;
        }

        // ── The ceremony circuit verifiers ───────────────────────────────
        // apply deploys these through the factory under a name carrying the
        // pinned circuits release, so the address is a pure function of
        // which artifact it is — known here before the chain has anything
        // on it.
        let mut verifiers: BTreeMap<Circuit, Address> = BTreeMap::new();
        for circuit in Circuit::ALL {
            verifiers.insert(circuit, self.circuit(factory, circuit).await?);
        }

        // ── The Platform Verifiers ───────────────────────────────────────
        for platform in platforms::LAUNCH {
            let circuit = *verifiers
                .get(&platform.circuit())
                .ok_or_else(|| anyhow!("{} has no circuit plan", platform.label))?;
            self.platform_verifier(platform, circuit, proof_verifier)
                .await?;
            if identity_registry_present {
                self.accepts_bindings(platform, stack.identity_registry)
                    .await;
            }
        }

        // ── Factory bookkeeping ──────────────────────────────────────────
        if factory_present {
            self.factory_records(factory).await;
        }
        Ok(())
    }

    /// The declared notary signer must be trusted, and the declared fee
    /// must be the one the service charges.
    async fn notary_service(&mut self, address: Address) {
        let service = NotaryService::new(address, &self.provider);
        let signer = match self.cfg.accounts.notary_address() {
            Ok(addr) => addr,
            Err(e) => {
                self.items.push(Item::new(
                    "notary_service.signer",
                    Status::Warn,
                    e.to_string(),
                ));
                return;
            }
        };
        let trusted = service
            .isTrustedNotary(signer)
            .call()
            .await
            .map_err(|e| e.to_string());
        self.items.push(NotarySigner { signer, trusted }.into());

        let declared = match self.cfg.notary_service.fee() {
            Ok(fee) => fee,
            Err(e) => {
                self.items.push(Item::new(
                    "notary_service.fee",
                    Status::Warn,
                    e.to_string(),
                ));
                return;
            }
        };
        let on_chain = service.fee().call().await.map_err(|e| e.to_string());
        self.items.push(NotaryFee { declared, on_chain }.into());
    }

    /// The identity registry dispatches every binding through the Proof
    /// Verifier.
    async fn identity_registry(&mut self, address: Address, proof_verifier: Address) {
        let wired = IdentityRegistry::new(address, &self.provider)
            .proofVerifier()
            .call()
            .await
            .map_err(|e| e.to_string());
        self.push(RegistryProofVerifier {
            declared: proof_verifier,
            wired,
        });
    }

    /// Whether the registry accepts the platform's bindings.
    async fn accepts_bindings(
        &mut self,
        platform: &'static Platform,
        identity_registry: Address,
    ) {
        let accepts = IdentityRegistry::new(identity_registry, &self.provider)
            .acceptsBindings(platform.id())
            .call()
            .await
            .map_err(|e| e.to_string());
        self.push(AcceptsBindings { platform, accepts });
    }

    /// The identity registry the escrow resolves through.
    async fn handle_escrow(&mut self, address: Address, identity_registry: Address) {
        let on_chain = HandleEscrow::new(address, &self.provider)
            .registry()
            .call()
            .await
            .map_err(|e| e.to_string());
        self.push(EscrowRegistry {
            declared: identity_registry,
            on_chain,
        });
    }

    /// The Notary Service the root list pays, and whether it holds fresh
    /// keys.
    async fn jwt_roots(&mut self, address: Address, notary_service: Address) {
        let roots = GoogleJwtRoots::new(address, &self.provider);
        let on_chain = roots
            .notaryService()
            .call()
            .await
            .map_err(|e| e.to_string());
        let needed = roots
            .needsRotation()
            .call()
            .await
            .map_err(|e| e.to_string());
        self.push(RootsNotaryService {
            declared: notary_service,
            on_chain,
        });
        self.push(RootsRotation { needed });
    }

    /// A ceremony circuit's verifier under `factory`; returns where it is,
    /// or would be, deployed.
    async fn circuit(&mut self, factory: Address, circuit: Circuit) -> Result<Address> {
        let name = circuits::factory_name(circuit)?;
        let address = predict_address(factory, &name);
        let code = self
            .provider
            .get_code_at(address)
            .await
            .map_err(|e| anyhow!("get_code({name}) failed: {e}"))?;
        let vendored = circuit.runtime_codehash(&self.artifacts)?;
        self.push(CircuitVerifier {
            circuit,
            name,
            address,
            codehash: (!code.is_empty()).then(|| keccak256(&code)),
            vendored,
        });
        Ok(address)
    }

    /// One platform's Platform Verifier: whether it exists, whether its
    /// implementation pins the vendored circuit verifier and its trust
    /// roots point at the deployed one at `circuit_address`, and whether it
    /// is registered in the Supported Version Set of `proof_verifier`, when
    /// that has code.
    async fn platform_verifier(
        &mut self,
        platform: &'static Platform,
        circuit_address: Address,
        proof_verifier: Option<Address>,
    ) -> Result<()> {
        let vendored = platform.circuit().runtime_codehash(&self.artifacts)?;
        let proxy = self.cfg.contracts.address(platform.contracts_key)?;

        if self.code(&platform.component(), proxy).await? {
            let verifier = PlatformVerifierBase::new(proxy, &self.provider);
            let wired = verifier
                .honkVerifier()
                .call()
                .await
                .map_err(|e| e.to_string());
            let pinned = verifier
                .circuitCodehash()
                .call()
                .await
                .map_err(|e| e.to_string());
            self.push(TrustRoots {
                platform,
                circuit_address,
                vendored,
                wired,
                pinned,
            });
        }

        let registered = match proof_verifier {
            Some(proof_verifier) => Some(
                CeremonyProofVerifier::new(proof_verifier, &self.provider)
                    .verifierOf(platform.id(), LAUNCH_VERIFIER_VERSION)
                    .call()
                    .await
                    .map_err(|e| e.to_string()),
            ),
            None => None,
        };
        self.push(Registration {
            platform,
            proxy,
            registered,
        });
        Ok(())
    }

    /// Diff the factory's own `deployedAt` records against the declared
    /// table, and its owner against `accounts.owner`.
    async fn factory_records(&mut self, factory: Address) {
        let contract = LibidFactory::new(factory, &self.provider);
        for &c in names::CANONICAL_CONTRACTS {
            let Some(declared) = self.cfg.contracts.declared(c.key).and_then(|d| d.get())
            else {
                continue;
            };
            let recorded = contract
                .deployedAt(c.name.to_string())
                .call()
                .await
                .map_err(|e| e.to_string());
            self.items.push(
                FactoryRecord {
                    contract: c,
                    declared,
                    recorded,
                }
                .into(),
            );
        }
        let owner = contract.owner().call().await.map_err(|e| e.to_string());
        self.push(FactoryOwner {
            declared: self.cfg.accounts.owner_address(),
            owner,
        });
    }
}

/// The canonical address a component would land at under `genesis`'s
/// factory — the prediction the declarative table is built from.
pub fn predicted(genesis: FactoryGenesis, key: &str) -> Result<Address> {
    let artifacts = Artifacts::embedded();
    let factory = genesis.address(&artifacts)?;
    let name = names::canonical_name(key)
        .ok_or_else(|| anyhow!("{key} is not a canonical contract"))?;
    Ok(predict_address(factory, name))
}
