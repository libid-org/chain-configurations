//! Read-only comparison of desired state (the network file) against the
//! chain. No signer, no transactions — safe to run from anywhere.
//!
//! Declarative model (0.4.0): a canonical file pre-declares EVERY address,
//! so presence is read from CHAIN STATE. A component is either
//! "declared + present" (ok), "declared + missing" (DEPLOY — apply would
//! put it at exactly the declared address), or declared at a WRONG address
//! — which never reaches the plan, because `NetworkConfig::load` rejects a
//! canonical key that does not equal `predict_address(factory, name)`.
//! Legacy files (`network.legacy_addresses`) keep the old reading: an
//! empty key plans a deploy and a populated key with no code is a WARN.
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
        factory::LibidFactory,
        identity::IdentityNames,
        login::Registry,
        notary::Notary,
        transfer::Bank,
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
        opt_address,
        NetworkConfig,
    },
    names,
    platforms::{
        identity_platform_id,
        GOOGLE_DOMAIN,
        IDENTITY_GITHUB,
        IDENTITY_GOOGLE,
        IDENTITY_X,
        INITIAL_VERSION,
        PLATFORM_CONFIGS,
        WEB_PREFIXES,
        X_DOMAIN,
    },
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
    /// Component name, e.g. `contracts.bank`.
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

/// Check whether a declared address actually has code, and report. On a
/// canonical file a code-less declared address is a planned DEPLOY (the
/// address is deterministic, apply lands there); on a legacy file it is a
/// WARN (the record claims something the chain does not have).
async fn check_code<P: Provider>(
    b: &mut Builder,
    provider: &P,
    component: &str,
    addr: Address,
    legacy: bool,
) -> Result<bool> {
    let code = provider
        .get_code_at(addr)
        .await
        .map_err(|e| anyhow!("get_code({component}) failed: {e}"))?;
    if code.is_empty() {
        if legacy {
            b.push(
                component,
                Status::Warn,
                format!("{addr:#x} is recorded but has NO CODE on-chain"),
            );
        } else {
            b.push(
                component,
                Status::Deploy,
                format!("declared at {addr:#x} — no code on-chain; apply would deploy it there"),
            );
        }
        Ok(false)
    } else {
        b.push(component, Status::Ok, format!("{addr:#x}"));
        Ok(true)
    }
}

/// Cheap consumer check: does `contract`'s `notaryContract()` point at the
/// recorded Notary proxy? The selector is shared by every 0.2.0 consumer
/// (read here through the Registry binding). Unreadable usually means a
/// pre-Notary (0.1.x) deployment; a mismatch is not something apply fixes
/// silently — both warn.
async fn check_notary_wiring<P: Provider>(
    b: &mut Builder,
    provider: &P,
    component: &str,
    contract: Address,
    notary: Address,
) {
    let component = format!("{component}.notary_wiring");
    match Registry::new(contract, provider)
        .notaryContract()
        .call()
        .await
    {
        Ok(wired) if wired == notary => b.push(
            component,
            Status::Ok,
            format!("notaryContract() = {wired:#x}"),
        ),
        Ok(wired) => b.push(
            component,
            Status::Warn,
            format!(
                "notaryContract() = {wired:#x} but contracts.notary is {notary:#x} — \
                 apply will not fix this silently"
            ),
        ),
        Err(e) => b.push(
            component,
            Status::Warn,
            format!(
                "notaryContract() unreadable ({e}) — a pre-Notary (0.1.x) deployment? \
                 The planned fresh redeploy is the fix"
            ),
        ),
    }
}

/// Build the plan. Connects read-only; sends nothing.
pub async fn build(cfg: &NetworkConfig) -> Result<Plan> {
    let rpc_url: url::Url = cfg
        .network
        .rpc_url
        .parse()
        .map_err(|e| anyhow!("invalid RPC URL: {e}"))?;
    let provider = ProviderBuilder::new().connect_http(rpc_url);
    let chain_id = provider.get_chain_id().await.map_err(|e| {
        anyhow!(
            "failed to read the chain id from {}: {e}",
            cfg.network.rpc_url
        )
    })?;

    let legacy = cfg.network.legacy_addresses;
    let mut b = Builder { items: Vec::new() };
    if chain_id != cfg.network.chain_id {
        b.push(
            "network.chain_id",
            Status::Warn,
            format!(
                "config says {} but the RPC reports {chain_id} — apply will refuse",
                cfg.network.chain_id
            ),
        );
    }

    // ── The onboarding gate: CREATE2 deployer + deterministic factory ────
    // These come FIRST: a chain that cannot host them cannot host the
    // stack, and every expected address below hangs off the factory.
    let artifacts = Artifacts::embedded();
    let predicted_factory = predict_factory_address(&artifacts)
        .map_err(|e| anyhow!("predict_factory_address failed: {e}"))?;
    let deployer_code = provider
        .get_code_at(CREATE2_DEPLOYER)
        .await
        .map_err(|e| anyhow!("get_code(create2 deployer) failed: {e}"))?;
    if deployer_code.is_empty() {
        b.push(
            "contracts.create2_deployer",
            Status::Deploy,
            format!(
                "missing — apply installs the keyless deployer at \
                 {CREATE2_DEPLOYER:#x} via its presigned transaction; a chain \
                 that rejects it (EIP-155-only) CANNOT host the stack"
            ),
        );
    } else {
        b.push(
            "contracts.create2_deployer",
            Status::Ok,
            format!("{CREATE2_DEPLOYER:#x}"),
        );
    }
    let factory_code = provider
        .get_code_at(predicted_factory)
        .await
        .map_err(|e| anyhow!("get_code(factory) failed: {e}"))?;
    let factory_present = !factory_code.is_empty();
    if factory_present {
        b.push(
            "contracts.factory",
            Status::Ok,
            format!("{predicted_factory:#x} (canonical)"),
        );
    } else {
        b.push(
            "contracts.factory",
            Status::Deploy,
            format!(
                "missing — apply deploys it at its canonical address \
                 {predicted_factory:#x} (CANARY: any other address aborts)"
            ),
        );
    }
    if let Some(recorded) = opt_address(&cfg.contracts.factory, "contracts.factory")? {
        if recorded != predicted_factory {
            b.push(
                "contracts.factory.record",
                Status::Warn,
                format!(
                    "config records {recorded:#x} but the canonical factory \
                     address is {predicted_factory:#x}"
                ),
            );
        }
    }
    // Every canonical contract's expected address is a pure function of
    // (factory, name) — quotable before anything is deployed.
    let expected = |name: &str| predict_address(predicted_factory, name);

    // ── Notary (deploys first; everything verifies through it) ───────────
    let cfg_signer = opt_address(&cfg.accounts.notary, "accounts.notary")?;
    let mut notary_addr = None;
    match opt_address(&cfg.contracts.notary, "contracts.notary")? {
        None => b.push(
            "contracts.notary",
            Status::Deploy,
            format!(
                "not deployed — apply would deploy it FIRST at {:#x} \
                 (CREATE3 '{}') and wire every other contract through it",
                expected(names::NOTARY),
                names::NOTARY
            ),
        ),
        Some(addr) => {
            if check_code(&mut b, &provider, "contracts.notary", addr, legacy).await? {
                notary_addr = Some(addr);
                // The signer DIFF: the file says who the notary signer is;
                // an on-chain mismatch is a planned setNotary rotation.
                let on_chain = Notary::new(addr, &provider)
                    .notary()
                    .call()
                    .await
                    .map_err(|e| anyhow!("Notary.notary read failed: {e}"))?;
                match cfg_signer {
                    Some(signer) if signer == on_chain => b.push(
                        "contracts.notary.signer",
                        Status::Ok,
                        format!("{on_chain:#x}"),
                    ),
                    Some(signer) => b.push(
                        "contracts.notary.signer",
                        Status::Configure,
                        format!(
                            "on-chain {on_chain:#x} but accounts.notary says \
                             {signer:#x} — apply would setNotary (rotation)"
                        ),
                    ),
                    // validate() rejects an empty accounts.notary, so this
                    // arm is unreachable through NetworkConfig::load.
                    None => b.push(
                        "contracts.notary.signer",
                        Status::Warn,
                        "accounts.notary is empty — nothing to diff against",
                    ),
                }
            }
        }
    }

    // ── Core contracts ───────────────────────────────────────────────────
    let core = [
        (
            "contracts.wallet_factory",
            &cfg.contracts.wallet_factory,
            names::WALLET_FACTORY,
        ),
        (
            "contracts.registry",
            &cfg.contracts.registry,
            names::REGISTRY,
        ),
        ("contracts.bank", &cfg.contracts.bank, names::BANK),
    ];
    let mut registry_addr = None;
    let mut bank_addr = None;
    for (component, value, name) in core {
        match opt_address(value, component)? {
            Some(addr) => {
                let present =
                    check_code(&mut b, &provider, component, addr, legacy).await?;
                if present {
                    if component == "contracts.registry" {
                        registry_addr = Some(addr);
                    }
                    if component == "contracts.bank" {
                        bank_addr = Some(addr);
                    }
                }
            }
            None => b.push(
                component,
                Status::Deploy,
                format!(
                    "not deployed — apply would deploy at {:#x} (CREATE3 '{name}')",
                    expected(name)
                ),
            ),
        }
    }

    // ── Verifier wiring (read from the Registry, the source of truth) ────
    let cfg_x_verifier =
        opt_address(&cfg.contracts.x_zk_verifier, "contracts.x_zk_verifier")?;
    let cfg_oidc_verifier = opt_address(
        &cfg.contracts.google_oidc_verifier,
        "contracts.google_oidc_verifier",
    )?;
    if let Some(registry_addr) = registry_addr {
        let registry = Registry::new(registry_addr, &provider);

        if let Some(notary) = notary_addr {
            check_notary_wiring(
                &mut b,
                &provider,
                "contracts.registry",
                registry_addr,
                notary,
            )
            .await;
        }

        let on_chain_x = registry
            .zkVerifierOf(X_DOMAIN.into())
            .call()
            .await
            .map_err(|e| anyhow!("Registry.zkVerifierOf({X_DOMAIN}) read failed: {e}"))?;
        verifier_item(
            &mut b,
            "contracts.x_zk_verifier",
            on_chain_x,
            cfg_x_verifier,
            !cfg.platforms.x_client_id.trim().is_empty(),
            "platforms.x_client_id is empty",
            expected(names::X_ZK_VERIFIER),
            names::X_ZK_VERIFIER,
            legacy,
        );
        if let (Some(notary), false) = (notary_addr, on_chain_x == Address::ZERO) {
            check_notary_wiring(
                &mut b,
                &provider,
                "contracts.x_zk_verifier",
                on_chain_x,
                notary,
            )
            .await;
        }

        let on_chain_oidc = registry
            .oidcVerifierOf(GOOGLE_DOMAIN.into())
            .call()
            .await
            .map_err(|e| {
                anyhow!("Registry.oidcVerifierOf({GOOGLE_DOMAIN}) read failed: {e}")
            })?;
        let oidc_wanted = !cfg.platforms.google_client_id.trim().is_empty();
        verifier_item(
            &mut b,
            "contracts.google_oidc_verifier",
            on_chain_oidc,
            cfg_oidc_verifier,
            oidc_wanted,
            "platforms.google_client_id is empty",
            expected(names::GOOGLE_OIDC_VERIFIER),
            names::GOOGLE_OIDC_VERIFIER,
            legacy,
        );
        if let (Some(notary), false) = (notary_addr, on_chain_oidc == Address::ZERO) {
            check_notary_wiring(
                &mut b,
                &provider,
                "contracts.google_oidc_verifier",
                on_chain_oidc,
                notary,
            )
            .await;
        }

        // Platform resolve configs: getPlatform exposes only endpoint +
        // handlePrefix, so apply always re-sends (owner-only, idempotent).
        for &(domain, endpoint, ..) in PLATFORM_CONFIGS {
            let current = registry.getPlatform(domain.into()).call().await;
            let detail = match current {
                Ok(p) if p.endpoint == endpoint => {
                    "present; re-sent on every apply (idempotent)".to_owned()
                }
                Ok(p) if p.endpoint.is_empty() => {
                    "unset — apply would configure".to_owned()
                }
                Ok(p) => {
                    format!("endpoint differs ({} on-chain) — apply resets", p.endpoint)
                }
                Err(e) => format!("unreadable ({e}) — apply would configure"),
            };
            b.push(
                format!("registry.platform.{domain}"),
                Status::Configure,
                detail,
            );
        }
    } else {
        b.push(
            "registry.wiring",
            Status::Skipped,
            "registry not deployed; verifier and platform checks deferred",
        );
    }

    // ── Bank configuration ───────────────────────────────────────────────
    if let Some(bank_addr) = bank_addr {
        let bank = Bank::new(bank_addr, &provider);
        for (platform, prefix) in WEB_PREFIXES {
            let on_chain = bank
                .getPlatformWebPrefix(platform.to_string())
                .call()
                .await
                .unwrap_or_default();
            if on_chain == *prefix {
                b.push(
                    format!("bank.web_prefix.{platform}"),
                    Status::Ok,
                    prefix.to_string(),
                );
            } else {
                b.push(
                    format!("bank.web_prefix.{platform}"),
                    Status::Configure,
                    format!("on-chain {on_chain:?} → {prefix:?}"),
                );
            }
        }
        for token in &cfg.tokens {
            let resolved = bank.resolveToken(token.symbol.clone()).call().await;
            let desired: Address = token.address.parse().map_err(|e| {
                anyhow!("invalid token address for {}: {e}", token.symbol)
            })?;
            match resolved {
                Ok(addr) if addr == desired => {
                    b.push(
                        format!("bank.token.{}", token.symbol),
                        Status::Ok,
                        format!("{addr:#x}"),
                    );
                }
                Ok(addr) => b.push(
                    format!("bank.token.{}", token.symbol),
                    Status::Warn,
                    format!("registered as {addr:#x}, config says {desired:#x}"),
                ),
                Err(_) => b.push(
                    format!("bank.token.{}", token.symbol),
                    Status::Configure,
                    "not registered — apply would register",
                ),
            }
        }
        for (platform, templates) in &cfg.templates {
            let desired = templates.as_vec().len();
            let count = bank
                .platformTemplateCount(platform.clone())
                .call()
                .await
                .map(|c| c.to::<u64>())
                .unwrap_or(0);
            b.push(
                format!("bank.templates.{platform}"),
                Status::Configure,
                format!(
                    "{count} on-chain, {desired} desired — cleared and re-seeded on \
                     every apply"
                ),
            );
        }
    } else {
        b.push(
            "bank.configuration",
            Status::Skipped,
            "bank not deployed; token/template/prefix checks deferred",
        );
    }

    // ── Identity-names stack ─────────────────────────────────────────────
    if let Some(identity) = &cfg.identity {
        let names = opt_address(&identity.identity_names, "identity.identity_names")?;
        // Wiring reads below must only hit a LIVE IdentityNames: a declared
        // address with no code (virgin chain) cannot answer eth_call.
        let mut names_live = None;
        match names {
            Some(addr) => {
                if check_code(&mut b, &provider, "identity.identity_names", addr, legacy)
                    .await?
                {
                    names_live = Some(addr);
                }
            }
            None => b.push(
                "identity.identity_names",
                Status::Deploy,
                format!(
                    "not deployed — apply would deploy at {:#x} (CREATE3 '{}')",
                    expected(names::IDENTITY_NAMES),
                    names::IDENTITY_NAMES
                ),
            ),
        }
        let wanted: Vec<(
            &str,
            Option<Address>,
            bool,
            &crate::platforms::IdentityPlatform,
        )> = vec![
            (
                "identity.github_identity_verifier",
                opt_address(
                    &identity.github_identity_verifier,
                    "identity.github_identity_verifier",
                )?,
                true,
                &IDENTITY_GITHUB,
            ),
            (
                "identity.x_identity_verifier",
                identity
                    .x_identity_verifier
                    .as_deref()
                    .map(|v| opt_address(v, "identity.x_identity_verifier"))
                    .transpose()?
                    .flatten(),
                identity.x_identity_verifier.is_some(),
                &IDENTITY_X,
            ),
            (
                "identity.google_identity_verifier",
                identity
                    .google_identity_verifier
                    .as_deref()
                    .map(|v| opt_address(v, "identity.google_identity_verifier"))
                    .transpose()?
                    .flatten(),
                identity.google_identity_verifier.is_some(),
                &IDENTITY_GOOGLE,
            ),
        ];
        for (component, configured, requested, platform) in wanted {
            if !requested {
                b.push(component, Status::Skipped, "key absent — not requested");
                continue;
            }
            match configured {
                Some(addr) => {
                    let present =
                        check_code(&mut b, &provider, component, addr, legacy).await?;
                    // GitHub and X verify through the Notary contract;
                    // Google trusts the JWKS roots instead and has no
                    // notaryContract() getter.
                    if present && component != "identity.google_identity_verifier" {
                        if let Some(notary) = notary_addr {
                            check_notary_wiring(
                                &mut b, &provider, component, addr, notary,
                            )
                            .await;
                        }
                    }
                    if let Some(names_addr) = names_live {
                        let names_contract = IdentityNames::new(names_addr, &provider);
                        let wired = names_contract
                            .verifierOf(
                                identity_platform_id(platform.domain),
                                INITIAL_VERSION,
                            )
                            .call()
                            .await
                            .map_err(|e| {
                                anyhow!("verifierOf({}) failed: {e}", platform.label)
                            })?;
                        if wired != addr {
                            b.push(
                                format!("{component}.wiring"),
                                Status::Configure,
                                format!(
                                    "IdentityNames points at {wired:#x} — apply re-wires \
                                     to {addr:#x}"
                                ),
                            );
                        }
                    }
                }
                None => {
                    let key = component
                        .strip_prefix("identity.")
                        .expect("identity components are identity.*");
                    let detail = match names::canonical_name("identity", key) {
                        Some(name) => format!(
                            "not deployed — apply would deploy at {:#x} \
                             (CREATE3 '{name}')",
                            expected(name)
                        ),
                        None => "not deployed — apply would deploy".into(),
                    };
                    b.push(component, Status::Deploy, detail);
                }
            }
        }
    } else {
        b.push(
            "identity",
            Status::Skipped,
            "section absent — the identity-names stack is not requested",
        );
    }

    // ── Factory records vs config (drift) ────────────────────────────────
    // The factory's `deployedAt` mapping is the on-chain truth about what
    // was deployed under each canonical name; a populated config key must
    // agree with it.
    if factory_present {
        let factory = LibidFactory::new(predicted_factory, &provider);
        for c in names::CANONICAL_CONTRACTS {
            let recorded = factory
                .deployedAt(c.name.to_string())
                .call()
                .await
                .map_err(|e| anyhow!("factory deployedAt({}) failed: {e}", c.name))?;
            if recorded == Address::ZERO {
                // Never deployed under this name; the per-component items
                // above already cover it.
                continue;
            }
            let component = format!("factory.record.{}.{}", c.section, c.key);
            match config_canonical_value(cfg, c.section, c.key)? {
                Some(addr) if addr == recorded => b.push(
                    component,
                    Status::Ok,
                    format!("'{}' = {recorded:#x}", c.name),
                ),
                Some(addr) if c.name == names::GOOGLE_OIDC_VERIFIER => b.push(
                    component,
                    Status::Ok,
                    format!(
                        "config {addr:#x} diverges from the factory record \
                         {recorded:#x} — expected after an `--upgrade \
                         oidc-verifier` REPLACE (the canonical name is \
                         single-use; the record keeps the first deploy)"
                    ),
                ),
                Some(addr) => b.push(
                    component,
                    Status::Warn,
                    format!(
                        "config records {addr:#x} but the factory deployed \
                         '{}' at {recorded:#x}",
                        c.name
                    ),
                ),
                None => b.push(
                    component,
                    Status::Configure,
                    format!(
                        "factory deployed '{}' at {recorded:#x} but this file \
                         does not declare it — apply would reuse it (the factory \
                         record is the on-chain truth)",
                        c.name
                    ),
                ),
            }
        }
    }

    Ok(Plan {
        network: cfg.network.name.clone(),
        chain_id_expected: cfg.network.chain_id,
        chain_id_actual: chain_id,
        items: b.items,
    })
}

/// The config's declared address for a canonical `(section, key)` pair,
/// treating an absent `[identity]` section or absent optional key as
/// undeclared.
fn config_canonical_value(
    cfg: &NetworkConfig,
    section: &str,
    key: &str,
) -> Result<Option<Address>> {
    match cfg.canonical_raw(section, key) {
        Some(value) => opt_address(value, key),
        None => Ok(None),
    }
}

/// Classify a Registry-wired verifier slot. The Registry pointer is the
/// on-chain truth; on a canonical file the declared address always equals
/// the CREATE3 prediction, so a zero slot on a wanted verifier is simply a
/// planned deploy-and-wire.
#[allow(clippy::too_many_arguments)]
fn verifier_item(
    b: &mut Builder,
    component: &str,
    on_chain: Address,
    configured: Option<Address>,
    wanted: bool,
    unwanted_reason: &str,
    expected: Address,
    name: &str,
    legacy: bool,
) {
    // `--upgrade oidc-verifier` REPLACES the GoogleOidcVerifier with a
    // plain-CREATE deploy; the Registry then legitimately points away from
    // the canonical declared address, and the chain is the only record.
    let replaceable = name == names::GOOGLE_OIDC_VERIFIER;
    match (on_chain == Address::ZERO, configured) {
        (true, Some(cfg_addr)) if !legacy && wanted => b.push(
            component,
            Status::Deploy,
            format!(
                "declared at {cfg_addr:#x} but the Registry points at nothing — \
                 apply would deploy (CREATE3 '{name}') and wire"
            ),
        ),
        (true, Some(_)) if !legacy => b.push(
            component,
            Status::Skipped,
            format!("declared but not requested ({unwanted_reason})"),
        ),
        (true, None) if wanted => b.push(
            component,
            Status::Deploy,
            format!(
                "not deployed — apply would deploy at {expected:#x} \
                 (CREATE3 '{name}') and wire"
            ),
        ),
        (true, None) => b.push(
            component,
            Status::Skipped,
            format!("not requested ({unwanted_reason})"),
        ),
        (true, Some(cfg_addr)) => b.push(
            component,
            Status::Warn,
            format!("config records {cfg_addr:#x} but the Registry points at nothing"),
        ),
        (false, None) => b.push(
            component,
            Status::Configure,
            format!(
                "on-chain {on_chain:#x} — a legacy file does not record it; the \
                 Registry is the record"
            ),
        ),
        (false, Some(cfg_addr)) if cfg_addr == on_chain => {
            b.push(component, Status::Ok, format!("{on_chain:#x}"))
        }
        (false, Some(cfg_addr)) if !legacy && replaceable => b.push(
            component,
            Status::Ok,
            format!(
                "live verifier {on_chain:#x} diverges from the canonical declaration \
                 {cfg_addr:#x} — expected after an `--upgrade oidc-verifier` REPLACE; \
                 the Registry pointer is the record"
            ),
        ),
        (false, Some(cfg_addr)) => b.push(
            component,
            Status::Warn,
            format!(
                "config records {cfg_addr:#x} but the Registry points at {on_chain:#x}"
            ),
        ),
    }
}
