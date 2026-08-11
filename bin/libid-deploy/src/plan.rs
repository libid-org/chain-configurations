//! Read-only comparison of desired state (the network file) against the
//! chain. No signer, no transactions — safe to run from anywhere.

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
use libid_contracts::bindings::{
    identity::IdentityNames,
    login::Registry,
    transfer::Bank,
};
use serde::Serialize;

use crate::{
    config::{
        opt_address,
        NetworkConfig,
    },
    platforms::{
        identity_platform_id,
        GOOGLE_DOMAIN,
        IDENTITY_GITHUB,
        IDENTITY_GOOGLE,
        IDENTITY_X,
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

/// Check whether a configured address actually has code, and report.
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
            Status::Warn,
            format!("{addr:#x} is recorded but has NO CODE on-chain"),
        );
        Ok(false)
    } else {
        b.push(component, Status::Ok, format!("{addr:#x}"));
        Ok(true)
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

    // ── Core contracts ───────────────────────────────────────────────────
    let core = [
        ("contracts.wallet_factory", &cfg.contracts.wallet_factory),
        ("contracts.registry", &cfg.contracts.registry),
        ("contracts.notary_registry", &cfg.contracts.notary_registry),
        ("contracts.bank", &cfg.contracts.bank),
    ];
    let mut registry_addr = None;
    let mut bank_addr = None;
    for (component, value) in core {
        match opt_address(value, component)? {
            Some(addr) => {
                let present = check_code(&mut b, &provider, component, addr).await?;
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
                "not deployed — apply would deploy",
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
        );

        let on_chain_oidc = registry
            .oidcVerifierOf(GOOGLE_DOMAIN.into())
            .call()
            .await
            .map_err(|e| {
                anyhow!("Registry.oidcVerifierOf({GOOGLE_DOMAIN}) read failed: {e}")
            })?;
        let oidc_wanted = !cfg.accounts.oidc_notary.trim().is_empty()
            && !cfg.platforms.google_client_id.trim().is_empty();
        verifier_item(
            &mut b,
            "contracts.google_oidc_verifier",
            on_chain_oidc,
            cfg_oidc_verifier,
            oidc_wanted,
            "accounts.oidc_notary or platforms.google_client_id is empty",
        );

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
        match names {
            Some(addr) => {
                check_code(&mut b, &provider, "identity.identity_names", addr).await?;
            }
            None => b.push(
                "identity.identity_names",
                Status::Deploy,
                "not deployed — apply would deploy",
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
                    check_code(&mut b, &provider, component, addr).await?;
                    if let Some(names_addr) = names {
                        let names_contract = IdentityNames::new(names_addr, &provider);
                        let wired = names_contract
                            .verifierOf(identity_platform_id(platform.domain))
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
                None => b.push(
                    component,
                    Status::Deploy,
                    "not deployed — apply would deploy",
                ),
            }
        }
    } else {
        b.push(
            "identity",
            Status::Skipped,
            "section absent — the identity-names stack is not requested",
        );
    }

    Ok(Plan {
        network: cfg.network.name.clone(),
        chain_id_expected: cfg.network.chain_id,
        chain_id_actual: chain_id,
        items: b.items,
    })
}

/// Classify a Registry-wired verifier slot.
fn verifier_item(
    b: &mut Builder,
    component: &str,
    on_chain: Address,
    configured: Option<Address>,
    wanted: bool,
    unwanted_reason: &str,
) {
    match (on_chain == Address::ZERO, configured) {
        (true, None) if wanted => b.push(
            component,
            Status::Deploy,
            "not deployed — apply would deploy and wire",
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
            format!("on-chain {on_chain:#x} — apply records it into the config"),
        ),
        (false, Some(cfg_addr)) if cfg_addr == on_chain => {
            b.push(component, Status::Ok, format!("{on_chain:#x}"))
        }
        (false, Some(cfg_addr)) => b.push(
            component,
            Status::Warn,
            format!(
                "config records {cfg_addr:#x} but the Registry points at {on_chain:#x}"
            ),
        ),
    }
}
