//! Converge a chain onto the network file: deploy whatever is missing (in
//! dependency order), re-send the idempotent configuration ops, perform any
//! explicitly requested upgrades, and record the deployed addresses back
//! into the file.
//!
//! The orchestration order is ported from dyaka's deployers:
//! `dyaka-auth::deploy::run` (login stack), `dyaka-transfer::deploy`
//! (Bank diamond + reconcile), and `dyaka-identity::deploy::run` (the
//! identity-names stack, only when `[identity]` is present).

use std::path::Path;

use alloy::{
    primitives::{
        Address,
        Bytes,
    },
    providers::{
        Provider,
        ProviderBuilder,
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
        identity::{
            GitHubIdentityVerifier,
            GoogleIdentityVerifier,
            IdentityJwksRoots,
            IdentityNames,
            XIdentityVerifier,
        },
        login::{
            IRegistryAdmin,
            NotaryRegistry,
            Registry,
            WalletFactory,
            XZkVerifier,
        },
        oidc::GoogleOidcVerifier,
        transfer::Bank,
    },
    deploy::{
        deploy_behind_proxy,
        deploy_contract_from,
        upgrade_uups,
    },
    diamond::{
        deploy_bank_diamond,
        replace_bank_facets,
    },
    send_with_nonce_retry,
    Artifacts,
};
use tracing::{
    info,
    warn,
};

use crate::{
    config::{
        opt_address,
        record_addresses,
        required_address,
        AddressUpdate,
        NetworkConfig,
    },
    platforms::{
        identity_platform_id,
        IdentityPlatform,
        GITHUB_SHAPE,
        GOOGLE_DOMAIN,
        IDENTITY_GITHUB,
        IDENTITY_GOOGLE,
        IDENTITY_X,
        PLATFORM_CONFIGS,
        WEB_PREFIXES,
        X_DOMAIN,
        X_ENDPOINT,
        X_HANDLE_PREFIX,
    },
    signer::SignerSource,
};

/// A component an operator can explicitly upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upgrade {
    /// UUPS `upgradeToAndCall` on the Registry proxy.
    Registry,
    /// UUPS `upgradeToAndCall` on the WalletFactory proxy.
    WalletFactory,
    /// UUPS `upgradeToAndCall` on the NotaryRegistry proxy.
    NotaryRegistry,
    /// Diamond facet REPLACE on the Bank — there is no implementation slot;
    /// the diamond is the storage, the facets are the code.
    Bank,
    /// Redeploy + re-point: the GoogleOidcVerifier is replaced and its
    /// ADDRESS CHANGES (the config records the new one).
    OidcVerifier,
}

impl std::str::FromStr for Upgrade {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim() {
            "registry" => Ok(Self::Registry),
            "wallet-factory" => Ok(Self::WalletFactory),
            "notary-registry" => Ok(Self::NotaryRegistry),
            "bank" => Ok(Self::Bank),
            "oidc-verifier" => Ok(Self::OidcVerifier),
            other => bail!(
                "unknown upgrade component '{other}' (expected registry, \
                 wallet-factory, notary-registry, bank, oidc-verifier)"
            ),
        }
    }
}

/// Options for [`run`].
#[derive(Debug, Default)]
pub struct Options {
    /// Components to explicitly upgrade.
    pub upgrades: Vec<Upgrade>,
    /// Required when the whole `[contracts]` section is empty: a fresh
    /// deploy orphans anything already on the chain.
    pub confirm_fresh_deploy: bool,
}

/// What an apply run did.
#[derive(Debug, Default)]
pub struct Summary {
    /// Freshly deployed components, as `(component, address)`.
    pub deployed: Vec<(String, Address)>,
    /// Explicitly upgraded components.
    pub upgraded: Vec<String>,
    /// Config keys the rewrite changed (`section.key`).
    pub recorded: Vec<String>,
}

impl Summary {
    /// Render for humans / the CI step summary.
    pub fn render(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        if self.deployed.is_empty() {
            let _ = writeln!(out, "Deployed: none");
        } else {
            let _ = writeln!(out, "Deployed:");
            for (component, addr) in &self.deployed {
                let _ = writeln!(out, "  {component} = {addr:#x}");
            }
        }
        if self.upgraded.is_empty() {
            let _ = writeln!(out, "Upgraded: none");
        } else {
            let _ = writeln!(out, "Upgraded: {}", self.upgraded.join(", "));
        }
        if self.recorded.is_empty() {
            let _ = writeln!(out, "Config: unchanged");
        } else {
            let _ = writeln!(out, "Config updated: {}", self.recorded.join(", "));
        }
        out
    }
}

/// Run the apply: converge the chain, then rewrite the network file.
pub async fn run(
    path: &Path,
    cfg: &NetworkConfig,
    signer: &SignerSource,
    opts: &Options,
) -> Result<Summary> {
    let rpc_url: url::Url = cfg
        .network
        .rpc_url
        .parse()
        .map_err(|e| anyhow!("invalid RPC URL: {e}"))?;

    if cfg.contracts_all_empty()? && !opts.confirm_fresh_deploy {
        bail!(
            "[contracts] in {} is entirely empty, so this would be a FRESH DEPLOY. \
             That publishes a new set of contracts and abandons anything already \
             deployed for '{}', including every balance held in it. Re-run with \
             --confirm-fresh-deploy if the network is genuinely empty; if you meant \
             to update an existing deployment, restore the addresses instead.",
            path.display(),
            cfg.network.name
        );
    }

    let (wallet, sender) = signer.build_wallet(None).await?;
    info!("applying as {sender:#x} via {}", signer.describe());
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url);

    let chain_id = provider
        .get_chain_id()
        .await
        .map_err(|e| anyhow!("failed to read the chain id: {e}"))?;
    if chain_id != cfg.network.chain_id {
        bail!(
            "chain id mismatch: {} expects {}, the RPC reports {chain_id} — refusing \
             to send anything",
            cfg.network.name,
            cfg.network.chain_id
        );
    }

    let artifacts = Artifacts::embedded();
    let notary = required_address(&cfg.accounts.notary, "accounts.notary")?;
    let backend = required_address(&cfg.accounts.backend, "accounts.backend")?;

    let mut summary = Summary::default();
    let mut updates: Vec<AddressUpdate> = Vec::new();
    let record = |summary: &mut Summary,
                  updates: &mut Vec<AddressUpdate>,
                  key: &str,
                  addr: Address,
                  force: bool| {
        summary.deployed.push((format!("contracts.{key}"), addr));
        updates.push(AddressUpdate {
            section: "contracts",
            key: key.to_owned(),
            address: addr,
            force,
        });
    };

    // ── Login stack ──────────────────────────────────────────────────────
    let factory_existing =
        opt_address(&cfg.contracts.wallet_factory, "contracts.wallet_factory")?;
    let registry_existing = opt_address(&cfg.contracts.registry, "contracts.registry")?;

    let factory = match factory_existing {
        Some(addr) => addr,
        None => {
            let wallet_impl = deploy_contract_from(
                &provider,
                artifacts.bytecode("WebWallet")?,
                "WebWallet (impl)",
                Some(sender),
            )
            .await?;
            info!("WebWallet impl deployed at {wallet_impl:#x}");
            let addr = deploy_behind_proxy(
                &provider,
                &artifacts,
                "WalletFactory",
                &WalletFactory::initializeCall {
                    owner_: sender,
                    walletImpl_: wallet_impl,
                    // The registry proxy may not exist yet; it is pointed in
                    // below once it does.
                    registry_: registry_existing.unwrap_or(Address::ZERO),
                },
                Some(sender),
            )
            .await?;
            info!("WalletFactory proxy deployed at {addr:#x}");
            record(&mut summary, &mut updates, "wallet_factory", addr, false);
            addr
        }
    };

    let registry = match registry_existing {
        Some(addr) => addr,
        None => {
            let addr = deploy_behind_proxy(
                &provider,
                &artifacts,
                "Registry",
                &IRegistryAdmin::initializeCall {
                    _notary: notary,
                    _backend: backend,
                    _walletFactory: factory,
                    _owner: sender,
                },
                Some(sender),
            )
            .await?;
            info!("Registry proxy deployed at {addr:#x}");
            let factory_contract = WalletFactory::new(factory, &provider);
            send_with_nonce_retry!(
                factory_contract.setRegistry(addr),
                "WalletFactory.setRegistry",
                &provider,
                sender
            )?;
            record(&mut summary, &mut updates, "registry", addr, false);
            addr
        }
    };

    let notary_registry =
        match opt_address(&cfg.contracts.notary_registry, "contracts.notary_registry")? {
            Some(addr) => addr,
            None => {
                let addr = deploy_behind_proxy(
                    &provider,
                    &artifacts,
                    "NotaryRegistry",
                    &NotaryRegistry::initializeCall {
                        owner_: sender,
                        initialNotary: notary,
                    },
                    Some(sender),
                )
                .await?;
                info!("NotaryRegistry proxy deployed at {addr:#x}");
                record(&mut summary, &mut updates, "notary_registry", addr, false);
                addr
            }
        };

    // ── Bank diamond ─────────────────────────────────────────────────────
    let bank = match opt_address(&cfg.contracts.bank, "contracts.bank")? {
        Some(addr) => addr,
        None => {
            let addr = deploy_bank_diamond(
                &provider,
                &artifacts,
                sender,
                notary_registry,
                backend,
                registry,
            )
            .await?;
            info!("Bank diamond deployed at {addr:#x}");
            record(&mut summary, &mut updates, "bank", addr, false);
            addr
        }
    };

    // ── Verifiers (guarded: deploy only when the Registry slot is zero) ──
    let registry_views = Registry::new(registry, &provider);
    let admin = IRegistryAdmin::new(registry, &provider);

    let x_client_id = cfg.platforms.x_client_id.trim();
    if !x_client_id.is_empty() {
        let on_chain = registry_views
            .zkVerifierOf(X_DOMAIN.into())
            .call()
            .await
            .map_err(|e| anyhow!("Registry.zkVerifierOf({X_DOMAIN}) read failed: {e}"))?;
        if on_chain == Address::ZERO {
            // The XZkVerifier's notary must match the Registry's notary.
            let registry_notary = registry_views
                .notary()
                .call()
                .await
                .map_err(|e| anyhow!("Registry.notary read failed: {e}"))?;
            let addr = deploy_x_zk_verifier(
                &provider,
                &artifacts,
                sender,
                registry_notary,
                x_client_id,
            )
            .await?;
            send_with_nonce_retry!(
                admin.setZkVerifier(X_DOMAIN.into(), addr),
                "Registry.setZkVerifier(api.x.com)",
                &provider,
                sender
            )?;
            info!("Registry.setZkVerifier({X_DOMAIN}, {addr:#x}) done");
            record(&mut summary, &mut updates, "x_zk_verifier", addr, false);
        } else {
            // Idempotency guard: a nonzero verifier is never redeployed. A
            // CHANGED x_client_id is NOT applied — the deployed verifier
            // keeps the client id baked in at first deploy.
            updates.push(AddressUpdate {
                section: "contracts",
                key: "x_zk_verifier".into(),
                address: on_chain,
                force: false,
            });
        }
    } else {
        warn!("platforms.x_client_id is empty — skipping the XZkVerifier");
    }

    let oidc_notary = opt_address(&cfg.accounts.oidc_notary, "accounts.oidc_notary")?;
    let google_client_id = cfg.platforms.google_client_id.trim();
    let upgrade_oidc = opts.upgrades.contains(&Upgrade::OidcVerifier);
    if upgrade_oidc && (oidc_notary.is_none() || google_client_id.is_empty()) {
        // An explicit upgrade request that cannot be honoured must not fall
        // through to a silent no-op — that is the exact failure the flag
        // exists to fix.
        bail!(
            "--upgrade oidc-verifier needs accounts.oidc_notary and \
             platforms.google_client_id set: the verifier is constructed with the \
             notary it trusts and the JWT audience it enforces"
        );
    }
    if let (Some(oidc_notary), false) = (oidc_notary, google_client_id.is_empty()) {
        let on_chain = registry_views
            .oidcVerifierOf(GOOGLE_DOMAIN.into())
            .call()
            .await
            .map_err(|e| {
                anyhow!("Registry.oidcVerifierOf({GOOGLE_DOMAIN}) read failed: {e}")
            })?;
        if on_chain == Address::ZERO || upgrade_oidc {
            if on_chain != Address::ZERO {
                info!(
                    "replacing GoogleOidcVerifier {on_chain:#x} — the new deployment \
                     gets a NEW address; the old verifier stays on-chain but nothing \
                     points at it"
                );
            }
            let addr = deploy_oidc_verifier(
                &provider,
                &artifacts,
                sender,
                oidc_notary,
                google_client_id,
            )
            .await?;
            send_with_nonce_retry!(
                admin.setOidcVerifier(GOOGLE_DOMAIN.into(), addr),
                "Registry.setOidcVerifier(www.googleapis.com)",
                &provider,
                sender
            )?;
            info!("Registry.setOidcVerifier({GOOGLE_DOMAIN}, {addr:#x}) done");
            if on_chain != Address::ZERO {
                summary
                    .upgraded
                    .push("google_oidc_verifier (replaced)".into());
            }
            record(
                &mut summary,
                &mut updates,
                "google_oidc_verifier",
                addr,
                upgrade_oidc,
            );
        } else {
            updates.push(AddressUpdate {
                section: "contracts",
                key: "google_oidc_verifier".into(),
                address: on_chain,
                force: false,
            });
        }
    } else {
        warn!(
            "accounts.oidc_notary or platforms.google_client_id is empty — skipping \
             the GoogleOidcVerifier"
        );
    }

    // ── Explicit upgrades ────────────────────────────────────────────────
    for upgrade in &opts.upgrades {
        match upgrade {
            Upgrade::Registry => {
                upgrade_uups(
                    &provider,
                    &artifacts,
                    registry,
                    "Registry",
                    Bytes::new(),
                    Some(sender),
                )
                .await?;
                summary.upgraded.push("registry".into());
            }
            Upgrade::WalletFactory => {
                upgrade_uups(
                    &provider,
                    &artifacts,
                    factory,
                    "WalletFactory",
                    Bytes::new(),
                    Some(sender),
                )
                .await?;
                summary.upgraded.push("wallet-factory".into());
            }
            Upgrade::NotaryRegistry => {
                upgrade_uups(
                    &provider,
                    &artifacts,
                    notary_registry,
                    "NotaryRegistry",
                    Bytes::new(),
                    Some(sender),
                )
                .await?;
                summary.upgraded.push("notary-registry".into());
            }
            Upgrade::Bank => {
                replace_bank_facets(&provider, &artifacts, bank, Some(sender)).await?;
                summary.upgraded.push("bank".into());
            }
            // Handled above, where the deploy inputs live.
            Upgrade::OidcVerifier => {}
        }
    }

    // ── Idempotent configuration (always re-sent, mirroring reconcile) ───
    // getPlatform exposes only endpoint+handlePrefix, so a skip keyed on
    // those would miss idPrefix/idSuffix drift. setPlatform is owner-only
    // and idempotent on-chain, so re-sending is safe.
    for &(domain, endpoint, handle_prefix, id_prefix, id_suffix) in PLATFORM_CONFIGS {
        send_with_nonce_retry!(
            admin.setPlatform(
                domain.into(),
                endpoint.into(),
                handle_prefix.into(),
                id_prefix.into(),
                id_suffix.into(),
            ),
            format!("Registry.setPlatform({domain})"),
            &provider,
            sender
        )?;
        info!("Registry.setPlatform({domain}) done");
    }

    let bank_contract = Bank::new(bank, &provider);

    // Token registration tolerates "already registered" reverts: the call
    // dry-runs first, so a duplicate fails at send without costing gas.
    for token in &cfg.tokens {
        let token_addr: Address = token
            .address
            .parse()
            .map_err(|e| anyhow!("invalid token address for {}: {e}", token.symbol))?;
        match bank_contract
            .registerToken(token.symbol.clone(), token_addr)
            .send()
            .await
        {
            Ok(pending) => match pending.get_receipt().await {
                Ok(_) => info!("Bank.registerToken({}) done", token.symbol),
                Err(e) => info!(
                    "Bank.registerToken({}) confirmation failed (may already exist): {e}",
                    token.symbol
                ),
            },
            Err(e) => info!(
                "Bank.registerToken({}) send failed (may already exist): {e}",
                token.symbol
            ),
        }
    }

    // Templates: setPlatformTemplate is append-only on-chain, so replacing
    // needs a clear first. Clear + re-seed each platform back-to-back so a
    // transient failure mid-run leaves at most one platform bare, and a
    // re-run fully repairs it.
    for (platform, templates) in &cfg.templates {
        send_with_nonce_retry!(
            bank_contract.clearPlatformTemplates(platform.clone()),
            format!("Bank.clearPlatformTemplates({platform})"),
            &provider,
            sender
        )?;
        for template in templates.as_vec() {
            send_with_nonce_retry!(
                bank_contract.setPlatformTemplate(platform.clone(), template.clone()),
                format!("Bank.setPlatformTemplate({platform})"),
                &provider,
                sender
            )?;
        }
        info!("Bank templates re-seeded for {platform}");
    }

    // Web prefixes: cheap to diff, so only drift is sent.
    for (platform, prefix) in WEB_PREFIXES {
        let on_chain = bank_contract
            .getPlatformWebPrefix(platform.to_string())
            .call()
            .await
            .unwrap_or_default();
        if on_chain == *prefix {
            continue;
        }
        send_with_nonce_retry!(
            bank_contract.setPlatformWebPrefix(platform.to_string(), prefix.to_string()),
            format!("Bank.setPlatformWebPrefix({platform})"),
            &provider,
            sender
        )?;
        info!("Bank.setPlatformWebPrefix({platform}, {prefix}) done");
    }

    // ── Identity-names stack (only when the section is present) ──────────
    if let Some(identity) = &cfg.identity {
        apply_identity(
            &provider,
            &artifacts,
            sender,
            notary,
            backend,
            identity,
            &mut summary,
            &mut updates,
        )
        .await?;
    }

    // ── Record what happened back into the file ──────────────────────────
    summary.recorded = record_addresses(path, &updates)
        .with_context(|| format!("failed to record addresses into {}", path.display()))?;

    Ok(summary)
}

/// Deploy the X ZK login verifier stack (XHonkVerifier + XZkVerifier UUPS
/// proxy). Does NOT register it on the Registry.
async fn deploy_x_zk_verifier<P: Provider>(
    provider: &P,
    artifacts: &Artifacts,
    sender: Address,
    notary: Address,
    client_id: &str,
) -> Result<Address> {
    // The generated UltraHonk verifiers exceed EIP-170; the target chain
    // must allow big code (Eden does).
    info!("deploying XHonkVerifier (exceeds EIP-170; the chain must allow big code)");
    let honk_bytecode = artifacts
        .linked_bytecode(provider, "XHonkVerifier", "XHonkVerifier", Some(sender))
        .await?;
    let honk =
        deploy_contract_from(provider, honk_bytecode, "XHonkVerifier", Some(sender))
            .await?;
    info!("XHonkVerifier deployed at {honk:#x}");

    let addr = deploy_behind_proxy(
        provider,
        artifacts,
        "XZkVerifier",
        &XZkVerifier::initializeCall {
            _owner: sender,
            _notary: notary,
            _honkVerifier: honk,
            _xClientId: Bytes::from(client_id.as_bytes().to_vec()),
            _endpoint: X_ENDPOINT.into(),
            _handlePrefix: X_HANDLE_PREFIX.into(),
            _platformName: X_DOMAIN.into(),
        },
        Some(sender),
    )
    .await?;
    info!("XZkVerifier proxy deployed at {addr:#x}");
    Ok(addr)
}

/// Deploy the Google OIDC verifier stack (HonkVerifier + GoogleOidcVerifier
/// behind an ERC1967 proxy). Does NOT register it on the Registry.
///
/// The proxy is not optional: GoogleOidcVerifier's constructor calls
/// `_disableInitializers()`, so the bare implementation can never be
/// initialized.
async fn deploy_oidc_verifier<P: Provider>(
    provider: &P,
    artifacts: &Artifacts,
    sender: Address,
    oidc_notary: Address,
    initial_aud: &str,
) -> Result<Address> {
    // The circuit binds the JWT `aud` and the contract enforces it, so an
    // empty client id yields a verifier that rejects every real proof.
    if initial_aud.trim().is_empty() {
        bail!(
            "platforms.google_client_id is required to deploy the OIDC verifier: it \
             becomes the expected JWT audience, and a verifier deployed without it \
             rejects every proof"
        );
    }
    info!("deploying OIDC HonkVerifier (exceeds EIP-170; the chain must allow big code)");
    let honk_bytecode = artifacts
        .linked_bytecode(provider, "Verifier", "HonkVerifier", Some(sender))
        .await?;
    let honk =
        deploy_contract_from(provider, honk_bytecode, "OIDC HonkVerifier", Some(sender))
            .await?;
    info!("OIDC HonkVerifier deployed at {honk:#x}");

    let addr = deploy_behind_proxy(
        provider,
        artifacts,
        "GoogleOidcVerifier",
        &GoogleOidcVerifier::initializeCall {
            _verifier: honk,
            _owner: sender,
            initialNotary: oidc_notary,
            initialAud: initial_aud.into(),
        },
        Some(sender),
    )
    .await?;
    info!("GoogleOidcVerifier proxy deployed at {addr:#x}");
    Ok(addr)
}

/// Converge the identity-names stack. GitHub needs only the two keys and is
/// always wired; X and Google each need a large Honk circuit verifier and
/// are requested by their key being PRESENT in the section.
#[allow(clippy::too_many_arguments)]
async fn apply_identity<P: Provider>(
    provider: &P,
    artifacts: &Artifacts,
    sender: Address,
    notary: Address,
    backend: Address,
    identity: &crate::config::Identity,
    summary: &mut Summary,
    updates: &mut Vec<AddressUpdate>,
) -> Result<()> {
    let record = |summary: &mut Summary,
                  updates: &mut Vec<AddressUpdate>,
                  key: &str,
                  addr: Address| {
        summary.deployed.push((format!("identity.{key}"), addr));
        updates.push(AddressUpdate {
            section: "identity",
            key: key.to_owned(),
            address: addr,
            force: false,
        });
    };

    // The naming contract first: every setPlatform below is a call to it.
    let names = match opt_address(&identity.identity_names, "identity.identity_names")? {
        Some(addr) => addr,
        None => {
            let addr = deploy_behind_proxy(
                provider,
                artifacts,
                "IdentityNames",
                &IdentityNames::initializeCall { owner_: sender },
                Some(sender),
            )
            .await?;
            info!("IdentityNames deployed at {addr:#x}");
            record(summary, updates, "identity_names", addr);
            addr
        }
    };

    let mut wired: Vec<(&IdentityPlatform, Address)> = Vec::new();

    // GitHub: always wired once the section exists.
    let github = match opt_address(
        &identity.github_identity_verifier,
        "identity.github_identity_verifier",
    )? {
        Some(addr) => addr,
        None => {
            let (endpoint, handle_prefix, id_prefix, id_suffix) = GITHUB_SHAPE;
            let addr = deploy_behind_proxy(
                provider,
                artifacts,
                "GitHubIdentityVerifier",
                &GitHubIdentityVerifier::initializeCall {
                    owner_: sender,
                    notary_: notary,
                    backend_: backend,
                    shape_: GitHubIdentityVerifier::ResponseShape {
                        endpoint: endpoint.into(),
                        handlePrefix: handle_prefix.into(),
                        idPrefix: id_prefix.into(),
                        idSuffix: id_suffix.into(),
                    },
                },
                Some(sender),
            )
            .await?;
            info!("GitHubIdentityVerifier deployed at {addr:#x}");
            record(summary, updates, "github_identity_verifier", addr);
            addr
        }
    };
    wired.push((&IDENTITY_GITHUB, github));

    // X: requested by the key being present.
    if let Some(value) = &identity.x_identity_verifier {
        let addr = match opt_address(value, "identity.x_identity_verifier")? {
            Some(addr) => addr,
            None => {
                info!(
                    "deploying XHonkVerifier for identity (exceeds EIP-170; the chain \
                     must allow big code)"
                );
                let honk_bytecode = artifacts
                    .linked_bytecode(
                        provider,
                        "XHonkVerifier",
                        "XHonkVerifier",
                        Some(sender),
                    )
                    .await?;
                let honk = deploy_contract_from(
                    provider,
                    honk_bytecode,
                    "XHonkVerifier (identity)",
                    Some(sender),
                )
                .await?;
                let addr = deploy_behind_proxy(
                    provider,
                    artifacts,
                    "XIdentityVerifier",
                    &XIdentityVerifier::initializeCall {
                        owner_: sender,
                        notary_: notary,
                        honkVerifier_: honk,
                        shape_: XIdentityVerifier::ResponseShape {
                            platformName: X_DOMAIN.into(),
                            endpoint: X_ENDPOINT.into(),
                            handlePrefix: X_HANDLE_PREFIX.into(),
                            idPrefix: crate::platforms::X_ID_PREFIX.into(),
                            idSuffix: crate::platforms::X_ID_SUFFIX.into(),
                        },
                    },
                    Some(sender),
                )
                .await?;
                info!("XIdentityVerifier deployed at {addr:#x}");
                record(summary, updates, "x_identity_verifier", addr);
                addr
            }
        };
        wired.push((&IDENTITY_X, addr));
    }

    // Google: requested by the key being present. Also needs the JWKS
    // trust list, deployed alongside.
    if let Some(value) = &identity.google_identity_verifier {
        let addr = match opt_address(value, "identity.google_identity_verifier")? {
            Some(addr) => addr,
            None => {
                let roots = match identity
                    .identity_jwks_roots
                    .as_deref()
                    .map(|v| opt_address(v, "identity.identity_jwks_roots"))
                    .transpose()?
                    .flatten()
                {
                    Some(addr) => addr,
                    None => {
                        let roots = deploy_behind_proxy(
                            provider,
                            artifacts,
                            "IdentityJwksRoots",
                            &IdentityJwksRoots::initializeCall {
                                owner_: sender,
                                initialNotary: notary,
                            },
                            Some(sender),
                        )
                        .await?;
                        info!("IdentityJwksRoots deployed at {roots:#x}");
                        record(summary, updates, "identity_jwks_roots", roots);
                        roots
                    }
                };
                info!(
                    "deploying Google HonkVerifier for identity (exceeds EIP-170; the \
                     chain must allow big code)"
                );
                let honk_bytecode = artifacts
                    .linked_bytecode(provider, "Verifier", "HonkVerifier", Some(sender))
                    .await?;
                let honk = deploy_contract_from(
                    provider,
                    honk_bytecode,
                    "HonkVerifier (Google identity)",
                    Some(sender),
                )
                .await?;
                let addr = deploy_behind_proxy(
                    provider,
                    artifacts,
                    "GoogleIdentityVerifier",
                    &GoogleIdentityVerifier::initializeCall {
                        owner_: sender,
                        honkVerifier_: honk,
                        jwksRoots_: roots,
                    },
                    Some(sender),
                )
                .await?;
                info!("GoogleIdentityVerifier deployed at {addr:#x}");
                warn!(
                    "IdentityJwksRoots at {roots:#x} starts EMPTY. Point a JWKS \
                     rotation listener at it before Google names work."
                );
                record(summary, updates, "google_identity_verifier", addr);
                addr
            }
        };
        wired.push((&IDENTITY_GOOGLE, addr));
    }

    // Wire every known platform. Owner-only and idempotent, so re-sending
    // converges wiring drift too.
    let names_contract = IdentityNames::new(names, provider);
    for (platform, verifier) in wired {
        send_with_nonce_retry!(
            names_contract.setPlatform(
                identity_platform_id(platform.domain),
                verifier,
                platform.allowance,
                platform.rules.clone(),
            ),
            format!("IdentityNames.setPlatform({})", platform.label),
            provider,
            sender
        )?;
        info!("IdentityNames.setPlatform({}) done", platform.label);
    }

    Ok(())
}
