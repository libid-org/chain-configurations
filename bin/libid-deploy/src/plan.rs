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

use alloy::{
    primitives::Address,
    providers::{
        Provider,
        ProviderBuilder,
    },
};
use anyhow::{
    anyhow,
    Result,
};
use libid_contracts::{
    bindings::{
        ceremony::{
            GoogleJwtRoots,
            NotaryService,
        },
        factory::LibidFactory,
        identity::IdentityNames,
    },
    factory::{
        predict_address,
        predict_factory_address,
        CREATE2_DEPLOYER,
    },
    Artifacts,
};
use serde::Serialize;

use crate::{
    config::{
        required_address,
        NetworkConfig,
    },
    names,
    platforms,
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
    /// Component name, e.g. `contracts.identity_names`.
    pub component: String,
    /// What apply would do.
    pub status: Status,
    /// Human-readable detail.
    pub detail: String,
}

/// The whole plan.
#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    /// Network name from the file.
    pub network: String,
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
            "Plan for {} (chain {} — RPC reports {})",
            self.network, self.chain_id_expected, self.chain_id_actual
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

struct Builder {
    items: Vec<Item>,
}

impl Builder {
    fn push(
        &mut self,
        component: impl Into<String>,
        status: Status,
        detail: impl Into<String>,
    ) {
        self.items.push(Item {
            component: component.into(),
            status,
            detail: detail.into(),
        });
    }
}

/// Check whether a declared address actually has code, and report. A
/// code-less declared address is a planned DEPLOY: the address is
/// deterministic, so apply lands exactly there.
async fn check_code<P: Provider>(
    b: &mut Builder,
    provider: &P,
    component: &str,
    addr: Address,
) -> Result<bool> {
    let code = provider
        .get_code_at(addr)
        .await
        .map_err(|e| anyhow!("get_code({component}) failed: {e}"))?;
    if code.is_empty() {
        b.push(
            component,
            Status::Deploy,
            format!(
                "declared at {addr:#x} — no code on-chain; apply would deploy it there"
            ),
        );
        Ok(false)
    } else {
        b.push(component, Status::Ok, format!("{addr:#x}"));
        Ok(true)
    }
}

/// Compare the desired state with the chain.
pub async fn build(cfg: &NetworkConfig) -> Result<Plan> {
    let rpc_url: url::Url = cfg
        .network
        .rpc_url
        .parse()
        .map_err(|e| anyhow!("invalid RPC URL: {e}"))?;
    let provider = ProviderBuilder::new().connect_http(rpc_url);
    let chain_id_actual = provider
        .get_chain_id()
        .await
        .map_err(|e| anyhow!("failed to read the chain id: {e}"))?;

    let mut b = Builder { items: Vec::new() };
    if chain_id_actual != cfg.network.chain_id {
        b.push(
            "network.chain_id",
            Status::Warn,
            format!(
                "file says {} but the RPC reports {chain_id_actual} — apply would \
                 refuse to send anything",
                cfg.network.chain_id
            ),
        );
    }

    // ── The onboarding gate ──────────────────────────────────────────────
    let artifacts = Artifacts::embedded();
    let predicted_factory = predict_factory_address(&artifacts)?;
    let deployer_present = !provider
        .get_code_at(CREATE2_DEPLOYER)
        .await
        .map_err(|e| anyhow!("get_code(create2_deployer) failed: {e}"))?
        .is_empty();
    b.push(
        "create2_deployer",
        if deployer_present {
            Status::Ok
        } else {
            Status::Deploy
        },
        if deployer_present {
            format!("{CREATE2_DEPLOYER:#x}")
        } else {
            format!(
                "{CREATE2_DEPLOYER:#x} has no code — apply would install it via the \
                 keyless presigned transaction"
            )
        },
    );

    let declared_factory = required_address(&cfg.contracts.factory, "contracts.factory")?;
    let factory_present =
        check_code(&mut b, &provider, "contracts.factory", declared_factory).await?;
    if declared_factory != predicted_factory {
        // Unreachable through `load`, which validates the equality; kept so
        // a caller building a config by hand still gets told.
        b.push(
            "contracts.factory",
            Status::Warn,
            format!(
                "declared {declared_factory:#x} but predicted {predicted_factory:#x}"
            ),
        );
    }

    // ── The stack, in deploy order ───────────────────────────────────────
    let notary_service =
        required_address(&cfg.contracts.notary_service, "contracts.notary_service")?;
    let notary_service_present = check_code(
        &mut b,
        &provider,
        "contracts.notary_service",
        notary_service,
    )
    .await?;
    if notary_service_present {
        plan_notary_service(&mut b, &provider, cfg, notary_service).await;
    }

    let proof_verifier = required_address(
        &cfg.contracts.ceremony_proof_verifier,
        "contracts.ceremony_proof_verifier",
    )?;
    check_code(
        &mut b,
        &provider,
        "contracts.ceremony_proof_verifier",
        proof_verifier,
    )
    .await?;

    let identity_names =
        required_address(&cfg.contracts.identity_names, "contracts.identity_names")?;
    let identity_names_present = check_code(
        &mut b,
        &provider,
        "contracts.identity_names",
        identity_names,
    )
    .await?;
    if identity_names_present {
        plan_identity_names(&mut b, &provider, identity_names, proof_verifier).await;
    }
    // The keyspaces are written, not read: IdentityNames exposes no getter
    // for a platform's rules, so apply converges them by re-sending
    // `setPlatform`, which is owner-only and idempotent.
    for platform in platforms::LAUNCH {
        b.push(
            format!("identity_names.platform.{}", platform.domain),
            if identity_names_present {
                Status::Configure
            } else {
                Status::Deploy
            },
            format!(
                "setPlatform({:#x}) re-sent — the contract exposes no rules getter",
                platforms::platform_id(platform.domain)
            ),
        );
    }

    let jwt_roots = required_address(
        &cfg.contracts.google_jwt_roots,
        "contracts.google_jwt_roots",
    )?;
    let jwt_roots_present =
        check_code(&mut b, &provider, "contracts.google_jwt_roots", jwt_roots).await?;
    if jwt_roots_present {
        plan_jwt_roots(&mut b, &provider, jwt_roots, notary_service).await;
    }

    // ── Factory bookkeeping ──────────────────────────────────────────────
    if factory_present {
        plan_factory_records(&mut b, &provider, cfg, declared_factory).await;
    }

    Ok(Plan {
        network: cfg.network.name.clone(),
        chain_id_expected: cfg.network.chain_id,
        chain_id_actual,
        items: b.items,
    })
}

/// The declared notary signer must be trusted, and the declared fee must be
/// the one the service charges.
async fn plan_notary_service<P: Provider>(
    b: &mut Builder,
    provider: &P,
    cfg: &NetworkConfig,
    notary_service: Address,
) {
    let service = NotaryService::new(notary_service, provider);
    let declared_signer = match required_address(&cfg.accounts.notary, "accounts.notary")
    {
        Ok(addr) => addr,
        Err(e) => {
            b.push("notary_service.signer", Status::Warn, e.to_string());
            return;
        }
    };
    match service.isTrustedNotary(declared_signer).call().await {
        Ok(true) => b.push(
            "notary_service.signer",
            Status::Ok,
            format!("{declared_signer:#x} is trusted"),
        ),
        Ok(false) => b.push(
            "notary_service.signer",
            Status::Configure,
            format!(
                "{declared_signer:#x} is NOT trusted — apply would setNotary it. \
                 Untrusting the outgoing key is a separate governance call, so a \
                 rotation can overlap"
            ),
        ),
        Err(e) => b.push(
            "notary_service.signer",
            Status::Warn,
            format!("isTrustedNotary read failed: {e}"),
        ),
    }

    let declared_fee = match cfg.notary_service.fee() {
        Ok(fee) => fee,
        Err(e) => {
            b.push("notary_service.fee", Status::Warn, e.to_string());
            return;
        }
    };
    match service.fee().call().await {
        Ok(on_chain) if on_chain == declared_fee => b.push(
            "notary_service.fee",
            Status::Ok,
            format!("{declared_fee} wei"),
        ),
        Ok(on_chain) => b.push(
            "notary_service.fee",
            Status::Configure,
            format!(
                "{on_chain} wei on-chain, file says {declared_fee} — apply sends setFee"
            ),
        ),
        Err(e) => b.push(
            "notary_service.fee",
            Status::Warn,
            format!("fee read failed: {e}"),
        ),
    }
}

/// The naming system dispatches every claim through the Proof Verifier;
/// without that pointer `quoteClaim` calls the zero address.
async fn plan_identity_names<P: Provider>(
    b: &mut Builder,
    provider: &P,
    identity_names: Address,
    proof_verifier: Address,
) {
    match IdentityNames::new(identity_names, provider)
        .proofVerifier()
        .call()
        .await
    {
        Ok(addr) if addr == proof_verifier => b.push(
            "identity_names.proof_verifier",
            Status::Ok,
            format!("{addr:#x}"),
        ),
        Ok(addr) => b.push(
            "identity_names.proof_verifier",
            Status::Configure,
            format!("points at {addr:#x}, file declares {proof_verifier:#x}"),
        ),
        Err(e) => b.push(
            "identity_names.proof_verifier",
            Status::Warn,
            format!("proofVerifier read failed: {e}"),
        ),
    }
}

/// The root list pays the Notary Service for each rotation, and holds
/// nothing until a keeper has landed one.
async fn plan_jwt_roots<P: Provider>(
    b: &mut Builder,
    provider: &P,
    jwt_roots: Address,
    notary_service: Address,
) {
    let roots = GoogleJwtRoots::new(jwt_roots, provider);
    match roots.notaryService().call().await {
        Ok(addr) if addr == notary_service => b.push(
            "google_jwt_roots.notary_service",
            Status::Ok,
            format!("{addr:#x}"),
        ),
        Ok(addr) => b.push(
            "google_jwt_roots.notary_service",
            Status::Configure,
            format!("points at {addr:#x}, file declares {notary_service:#x}"),
        ),
        Err(e) => b.push(
            "google_jwt_roots.notary_service",
            Status::Warn,
            format!("notaryService read failed: {e}"),
        ),
    }
    match roots.needsRotation().call().await {
        Ok(true) => b.push(
            "google_jwt_roots.rotation",
            Status::Warn,
            "the trust list wants a rotation — every Google claim reverts \
             UntrustedModulus until a keeper lands one. Not apply's job",
        ),
        Ok(false) => b.push("google_jwt_roots.rotation", Status::Ok, "trusted and fresh"),
        Err(e) => b.push(
            "google_jwt_roots.rotation",
            Status::Warn,
            format!("needsRotation read failed: {e}"),
        ),
    }
}

/// Diff the factory's own `deployedAt` records against the declared table.
/// A record that disagrees with the declaration means the chain and the
/// file describe different deployments.
async fn plan_factory_records<P: Provider>(
    b: &mut Builder,
    provider: &P,
    cfg: &NetworkConfig,
    factory: Address,
) {
    let contract = LibidFactory::new(factory, provider);
    for c in names::CANONICAL_CONTRACTS {
        let component = format!("factory.record.{}", c.key);
        let Some(raw) = cfg.contracts.raw(c.key) else {
            continue;
        };
        let Ok(declared) = required_address(raw, &component) else {
            continue;
        };
        match contract.deployedAt(c.name.to_string()).call().await {
            Ok(addr) if addr == Address::ZERO => b.push(
                &component,
                Status::Skipped,
                format!("'{}' not yet deployed by the factory", c.name),
            ),
            Ok(addr) if addr == declared => {
                b.push(&component, Status::Ok, format!("'{}' -> {addr:#x}", c.name))
            }
            Ok(addr) => b.push(
                &component,
                Status::Warn,
                format!(
                    "factory recorded '{}' at {addr:#x} but the file declares \
                     {declared:#x} — the deterministic invariant is broken",
                    c.name
                ),
            ),
            Err(e) => b.push(
                &component,
                Status::Warn,
                format!("deployedAt('{}') read failed: {e}", c.name),
            ),
        }
    }
    match contract.owner().call().await {
        Ok(owner) => {
            let desired = cfg.accounts.owner_address().ok().flatten();
            match desired {
                Some(want) if want != owner => b.push(
                    "factory.owner",
                    Status::Configure,
                    format!("{owner:#x} on-chain, accounts.owner declares {want:#x}"),
                ),
                _ => b.push("factory.owner", Status::Ok, format!("{owner:#x}")),
            }
        }
        Err(e) => b.push(
            "factory.owner",
            Status::Warn,
            format!("owner read failed: {e}"),
        ),
    }
}

/// The canonical address a component would land at — the prediction the
/// declarative table is built from.
pub fn predicted(key: &str) -> Result<Address> {
    let artifacts = Artifacts::embedded();
    let factory = predict_factory_address(&artifacts)?;
    let name = names::canonical_name(key)
        .ok_or_else(|| anyhow!("{key} is not a canonical contract"))?;
    Ok(predict_address(factory, name))
}
