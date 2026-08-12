//! The network file: schema, parsing, and validation.
//!
//! The model is DECLARATIVE (libid-deploy 0.4.0): every canonical contract
//! lives at a CREATE3-deterministic address, so the `[contracts]` and
//! `[identity]` address keys are ALWAYS present and pre-filled with the
//! canonical table — `validate` rejects a canonical key whose value is not
//! exactly `predict_address(factory, name)`. Whether a declared contract is
//! deployed is determined from CHAIN STATE (`eth_getCode`) at plan/apply
//! time, never from config emptiness, and `apply` NEVER rewrites the file.
//!
//! Legacy files (`network.legacy_addresses = true`) record a pre-factory
//! deployment verbatim: the old empty-means-not-deployed convention still
//! parses and plans there, but `apply` refuses them — the planned fresh
//! redeploy replaces such stacks with canonical ones.

use std::{
    collections::BTreeMap,
    path::Path,
};

use alloy::primitives::Address;
use anyhow::{
    anyhow,
    bail,
    Context,
    Result,
};
use libid_contracts::factory::{
    predict_address,
    predict_factory_address,
};
use serde::Deserialize;

use crate::names;

/// One parsed network file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// The chain this file describes.
    pub network: Network,
    /// Where the deployer key lives.
    pub aws: Aws,
    /// Addresses of keys (not contracts) the contracts trust.
    pub accounts: Accounts,
    /// The core contract addresses — DECLARED, pre-filled with the
    /// canonical table.
    #[serde(default)]
    pub contracts: Contracts,
    /// The identity-names stack. Absent section = not wanted.
    #[serde(default)]
    pub identity: Option<Identity>,
    /// INPUT: OAuth client ids and bot handles.
    #[serde(default)]
    pub platforms: Platforms,
    /// INPUT: tokens registered on the Bank.
    #[serde(default)]
    pub tokens: Vec<Token>,
    /// INPUT: per-platform comment templates, keyed by platform domain.
    #[serde(default)]
    pub templates: BTreeMap<String, Templates>,
}

/// `[network]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// Network name; also the GitHub environment the apply workflow uses.
    pub name: String,
    /// Chain id `apply` refuses to run without matching on-chain.
    pub chain_id: u64,
    /// JSON-RPC endpoint.
    pub rpc_url: String,
    /// LEGACY marker: the file records a pre-factory (plain-CREATE)
    /// deployment verbatim. Canonical-address validation is skipped,
    /// `plan` keeps the old empty-means-not-deployed reading, and `apply`
    /// refuses to run — the fresh redeploy replaces such stacks.
    #[serde(default)]
    pub legacy_addresses: bool,
}

/// `[aws]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Aws {
    /// Region the KMS key lives in.
    pub region: String,
    /// KMS key id, `alias/...` name, or full ARN of the deployer key.
    pub kms_deployer: String,
}

/// `[accounts]` — addresses of KEYS, not contracts.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Accounts {
    /// The notary SIGNER — the EOA/KMS identity whose signatures the stack
    /// accepts. The Notary CONTRACT (`contracts.notary`) stores this
    /// address; apply initializes it with this value and `setNotary`s when
    /// they drift. Distinct on purpose: this is a key, not a contract.
    pub notary: String,
    /// LEGACY (pre-Notary deployments only): the JWKS-rotation notary that
    /// was wired directly into the old GoogleOidcVerifier. Since
    /// libid-contracts 0.2.0 every consumer verifies through the shared
    /// Notary contract, so this key is no longer wired anywhere. Kept so
    /// legacy network files still validate.
    #[serde(default)]
    pub oidc_notary: String,
    /// The backend signing identity; the Bank grants it the backend role.
    pub backend: String,
    /// The OPERATIONAL OWNER the factory should end up with. Empty =
    /// the deployer (the apply signer). On real networks this is the KMS
    /// genesis admin — the same identity as the deployer key — so the
    /// default is exact; on local dev chains it names the anvil #0 wallet
    /// and the anvil auto-impersonation hands factory ownership to IT.
    #[serde(default)]
    pub owner: String,
}

impl Accounts {
    /// The declared operational owner, if any (`None` = default to the
    /// deployer).
    pub fn owner_address(&self) -> Result<Option<Address>> {
        opt_address(&self.owner, "accounts.owner")
    }
}

/// `[contracts]` — declared canonical addresses.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contracts {
    /// The deterministic LibidFactory proxy — one canonical CREATE2 address
    /// on every EVM network.
    #[serde(default)]
    pub factory: String,
    /// The Bank diamond.
    #[serde(default)]
    pub bank: String,
    /// The Registry UUPS proxy.
    #[serde(default)]
    pub registry: String,
    /// The WalletFactory UUPS proxy.
    #[serde(default)]
    pub wallet_factory: String,
    /// The Notary UUPS proxy — the ONE contract everything else verifies
    /// notary attestations through. It stores the notary SIGNER address
    /// from `accounts.notary`; do not confuse the two. Deployed FIRST on a
    /// fresh deploy, then wired into every consumer at initialize.
    #[serde(default)]
    pub notary: String,
    /// The XZkVerifier proxy (deployed only when `x_client_id` is set).
    #[serde(default)]
    pub x_zk_verifier: String,
    /// The GoogleOidcVerifier proxy. Declared at its canonical address
    /// even after an `--upgrade oidc-verifier` REPLACE: the replacement is
    /// a plain-CREATE deploy recorded ONLY on-chain, in
    /// `Registry.oidcVerifierOf` — the chain, not this file, is the record.
    #[serde(default)]
    pub google_oidc_verifier: String,
}

/// `[identity]` — declared canonical addresses. The optional keys signal
/// wanted-ness by PRESENCE (an absent `x_identity_verifier` means "not
/// wanted"); a present key must carry the canonical address.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// The IdentityNames contract — the address consumers resolve against.
    #[serde(default)]
    pub identity_names: String,
    /// The GitHub verifier (needs only the notary+backend keys).
    #[serde(default)]
    pub github_identity_verifier: String,
    /// The X verifier (needs a Honk circuit verifier). Absent = not wanted.
    #[serde(default)]
    pub x_identity_verifier: Option<String>,
    /// The Google verifier (needs a Honk circuit verifier and the JWKS
    /// trust list). Absent = not wanted.
    #[serde(default)]
    pub google_identity_verifier: Option<String>,
    /// The Google JWKS trust list, deployed alongside the Google verifier.
    /// Starts EMPTY on-chain: point a JWKS rotation listener at it before
    /// Google names work.
    #[serde(default)]
    pub identity_jwks_roots: Option<String>,
}

/// `[platforms]` — INPUT keys.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Platforms {
    /// X OAuth app client id, embedded in the XZkVerifier. Empty skips the
    /// X ZK verifier deploy.
    #[serde(default)]
    pub x_client_id: String,
    /// Google OAuth client id — the JWT audience the OIDC verifier
    /// enforces on-chain. Required to deploy that verifier.
    #[serde(default)]
    pub google_client_id: String,
    /// The GitHub bot handle the templates mention. Informational for
    /// off-chain parsers; the on-chain truth is `[templates]`.
    #[serde(default)]
    pub github_bot_handle: String,
    /// The X bot handle the templates mention.
    #[serde(default)]
    pub x_bot_handle: String,
}

/// One `[[tokens]]` entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Token {
    /// Bank-registered token name, e.g. `$TIA`.
    pub symbol: String,
    /// Token contract address; the zero address means native.
    pub address: String,
}

/// A `[templates]` value: one template or several.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Templates {
    /// A single template string.
    One(String),
    /// Several templates for the same platform.
    Many(Vec<String>),
}

impl Templates {
    /// The templates as a slice-like vec.
    pub fn as_vec(&self) -> Vec<String> {
        match self {
            Self::One(t) => vec![t.clone()],
            Self::Many(ts) => ts.clone(),
        }
    }
}

/// Parse an address field that may be empty (legacy files; optional keys).
pub fn opt_address(value: &str, label: &str) -> Result<Option<Address>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let addr: Address = value
        .parse()
        .map_err(|e| anyhow!("invalid address for {label}: {e}"))?;
    if addr == Address::ZERO {
        // A recorded zero address carries no information — nothing
        // legitimate deploys to the zero address.
        return Ok(None);
    }
    Ok(Some(addr))
}

/// Parse a required address field.
pub fn required_address(value: &str, label: &str) -> Result<Address> {
    opt_address(value, label)?
        .ok_or_else(|| anyhow!("{label} must be set to a nonzero address"))
}

impl NetworkConfig {
    /// Load and validate a network file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let cfg: Self = toml::from_str(&text)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Structural sanity checks — everything that can fail before touching
    /// the network. Canonical files additionally get the address-equality
    /// check: every declared canonical key must EQUAL
    /// `predict_address(factory, name)`.
    pub fn validate(&self) -> Result<()> {
        if self.network.name.trim().is_empty() {
            bail!("network.name must not be empty");
        }
        if self.network.chain_id == 0 {
            bail!("network.chain_id must be nonzero");
        }
        let _: url::Url = self
            .network
            .rpc_url
            .parse()
            .map_err(|e| anyhow!("invalid network.rpc_url: {e}"))?;
        required_address(&self.accounts.notary, "accounts.notary")?;
        required_address(&self.accounts.backend, "accounts.backend")?;
        if !self.accounts.oidc_notary.trim().is_empty() {
            required_address(&self.accounts.oidc_notary, "accounts.oidc_notary")?;
        }
        self.accounts.owner_address()?;
        for token in &self.tokens {
            if token.symbol.trim().is_empty() {
                bail!("a [[tokens]] entry has an empty symbol");
            }
            // The zero address is legitimate here: it names the native token.
            let _: Address = token.address.parse().map_err(|e| {
                anyhow!("invalid address for token {}: {e}", token.symbol)
            })?;
        }
        if self.aws.region.trim().is_empty() {
            bail!("aws.region must not be empty");
        }
        if self.aws.kms_deployer.trim().is_empty() {
            bail!("aws.kms_deployer must not be empty");
        }

        if self.network.legacy_addresses {
            self.validate_legacy_addresses()
        } else {
            self.validate_canonical_addresses()
        }
    }

    /// Legacy files: addresses are free-form records of a pre-factory
    /// deployment; only well-formedness is checked.
    fn validate_legacy_addresses(&self) -> Result<()> {
        for (label, value) in [
            ("contracts.factory", &self.contracts.factory),
            ("contracts.bank", &self.contracts.bank),
            ("contracts.registry", &self.contracts.registry),
            ("contracts.wallet_factory", &self.contracts.wallet_factory),
            ("contracts.notary", &self.contracts.notary),
            ("contracts.x_zk_verifier", &self.contracts.x_zk_verifier),
            (
                "contracts.google_oidc_verifier",
                &self.contracts.google_oidc_verifier,
            ),
        ] {
            opt_address(value, label)?;
        }
        if let Some(identity) = &self.identity {
            opt_address(&identity.identity_names, "identity.identity_names")?;
            opt_address(
                &identity.github_identity_verifier,
                "identity.github_identity_verifier",
            )?;
            for (label, value) in [
                (
                    "identity.x_identity_verifier",
                    &identity.x_identity_verifier,
                ),
                (
                    "identity.google_identity_verifier",
                    &identity.google_identity_verifier,
                ),
                (
                    "identity.identity_jwks_roots",
                    &identity.identity_jwks_roots,
                ),
            ] {
                if let Some(value) = value {
                    opt_address(value, label)?;
                }
            }
        }
        Ok(())
    }

    /// Canonical files: every declared canonical key must EQUAL the
    /// predicted CREATE3 address for its frozen name; the factory key must
    /// equal the canonical factory address. Non-canonical addresses
    /// (tokens, account keys) stay free-form.
    fn validate_canonical_addresses(&self) -> Result<()> {
        let artifacts = libid_contracts::Artifacts::embedded();
        let factory = predict_factory_address(&artifacts)
            .map_err(|e| anyhow!("predict_factory_address failed: {e}"))?;

        let declared_factory = required_address(
            &self.contracts.factory,
            "contracts.factory",
        )
        .map_err(|e| {
            anyhow!("{e} — pre-fill it with the canonical factory address {factory:#x}")
        })?;
        if declared_factory != factory {
            bail!(
                "contracts.factory declares {declared_factory:#x} but the canonical \
                 LibidFactory address is {factory:#x} — declared canonical addresses \
                 must equal their prediction"
            );
        }

        for c in names::CANONICAL_CONTRACTS {
            let label = format!("{}.{}", c.section, c.key);
            let Some(raw) = self.canonical_raw(c.section, c.key) else {
                // Absent [identity] section or absent optional key = the
                // component is not wanted; nothing to check.
                continue;
            };
            let expected = predict_address(factory, c.name);
            let declared = required_address(raw, &label).map_err(|e| {
                anyhow!(
                    "{e} — the declarative schema pre-fills every canonical address; \
                     set it to {expected:#x} (CREATE3 '{}')",
                    c.name
                )
            })?;
            if declared != expected {
                bail!(
                    "{label} declares {declared:#x} but the canonical address of \
                     CREATE3 '{}' is {expected:#x} — declared canonical addresses \
                     must equal predict_address(factory, name)",
                    c.name
                );
            }
        }

        if let Some(identity) = &self.identity {
            if identity.google_identity_verifier.is_some()
                && identity.identity_jwks_roots.is_none()
            {
                bail!(
                    "identity.google_identity_verifier is declared but \
                     identity.identity_jwks_roots is absent — the Google verifier \
                     trusts the JWKS roots contract, so declare both"
                );
            }
        }
        Ok(())
    }

    /// The raw config value for a canonical `(section, key)` pair, treating
    /// an absent `[identity]` section or absent optional key as "not
    /// wanted" (`None`).
    pub fn canonical_raw(&self, section: &str, key: &str) -> Option<&str> {
        let identity = self.identity.as_ref();
        match (section, key) {
            ("contracts", "notary") => Some(self.contracts.notary.as_str()),
            ("contracts", "wallet_factory") => {
                Some(self.contracts.wallet_factory.as_str())
            }
            ("contracts", "registry") => Some(self.contracts.registry.as_str()),
            ("contracts", "bank") => Some(self.contracts.bank.as_str()),
            ("contracts", "x_zk_verifier") => Some(self.contracts.x_zk_verifier.as_str()),
            ("contracts", "google_oidc_verifier") => {
                Some(self.contracts.google_oidc_verifier.as_str())
            }
            ("identity", "identity_names") => identity.map(|i| i.identity_names.as_str()),
            ("identity", "github_identity_verifier") => {
                identity.map(|i| i.github_identity_verifier.as_str())
            }
            ("identity", "x_identity_verifier") => {
                identity.and_then(|i| i.x_identity_verifier.as_deref())
            }
            ("identity", "google_identity_verifier") => {
                identity.and_then(|i| i.google_identity_verifier.as_deref())
            }
            ("identity", "identity_jwks_roots") => {
                identity.and_then(|i| i.identity_jwks_roots.as_deref())
            }
            _ => None,
        }
    }

    /// The templates flattened to `(platform, template)` pairs, in file
    /// order per platform.
    pub fn template_pairs(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for (platform, templates) in &self.templates {
            for template in templates.as_vec() {
                out.push((platform.clone(), template));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn networks_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../networks")
    }

    /// A minimal CANONICAL file with every address pre-filled from the
    /// prediction, as a TOML string.
    fn canonical_toml() -> String {
        let artifacts = libid_contracts::Artifacts::embedded();
        let factory = predict_factory_address(&artifacts).unwrap();
        let addr = |name: &str| format!("{:#x}", predict_address(factory, name));
        format!(
            r#"[network]
name = "canonical-test"
chain_id = 31337
rpc_url = "http://localhost:8545"

[aws]
region = "eu-central-1"
kms_deployer = "alias/test"

[accounts]
notary = "0x1111111111111111111111111111111111111111"
backend = "0x2222222222222222222222222222222222222222"
owner = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

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
        )
    }

    /// The committed Eden file is a CANONICAL declarative config now, not the
    /// legacy record it used to be. `load` runs the full canonical-equality
    /// check, so if this fails with a named expected address, the committed
    /// table has drifted from `predict_address` — regenerate it with
    /// `plan --print-addresses` instead of editing either side by hand.
    #[test]
    fn the_seeded_eden_file_is_canonical_and_requests_identity() {
        let cfg = NetworkConfig::load(&networks_dir().join("eden-testnet.toml"))
            .expect("eden-testnet.toml loads");
        assert_eq!(cfg.network.chain_id, 3735928814);
        // Not legacy: the file no longer takes the exemption from canonical
        // address equality, which is also what makes `apply` willing to run it.
        assert!(!cfg.network.legacy_addresses);

        // The identity stack is requested in full. `identity_jwks_roots` matters
        // most: it is the on-chain trust list a keeper rotates, and without it
        // Google names can never be verified.
        let identity = cfg.identity.as_ref().expect("identity section requested");
        assert!(identity.x_identity_verifier.is_some());
        assert!(identity.google_identity_verifier.is_some());
        assert!(identity.identity_jwks_roots.is_some());

        assert_eq!(cfg.tokens.len(), 4);
        // Both platforms carry templates and each template names the bot.
        let pairs = cfg.template_pairs();
        assert_eq!(pairs.len(), 6);
        assert!(pairs.iter().all(|(_, t)| t.contains("@testyakly")));
    }

    /// The committed mainnet template is FULLY pre-filled and passes the
    /// canonical-equality validation once its placeholder inputs are set.
    #[test]
    fn the_mainnet_example_is_fully_prefilled_and_canonical() {
        let text = std::fs::read_to_string(networks_dir().join("mainnet.toml.example"))
            .expect("mainnet.toml.example readable");
        // The template ships placeholder INPUTs; substitute the minimum an
        // operator must fill so validation reaches the address checks.
        let text = text
            .replace("chain_id = 0", "chain_id = 1")
            .replace("rpc_url = \"\"", "rpc_url = \"https://example.invalid\"")
            .replace("region = \"\"", "region = \"eu-central-1\"")
            .replace("kms_deployer = \"\"", "kms_deployer = \"alias/x\"")
            .replace(
                "notary = \"\"",
                "notary = \"0x1111111111111111111111111111111111111111\"",
            )
            .replace(
                "backend = \"\"",
                "backend = \"0x2222222222222222222222222222222222222222\"",
            );
        let cfg: NetworkConfig = toml::from_str(&text).expect("template parses");
        assert!(!cfg.network.legacy_addresses);
        cfg.validate().expect("template validates canonically");
        // FULLY pre-filled: identity included, every canonical key present.
        let identity = cfg.identity.as_ref().expect("identity declared");
        assert!(identity.x_identity_verifier.is_some());
        assert!(identity.google_identity_verifier.is_some());
        assert!(identity.identity_jwks_roots.is_some());
    }

    /// A fully pre-filled canonical config validates.
    #[test]
    fn canonical_config_validates() {
        let cfg: NetworkConfig = toml::from_str(&canonical_toml()).unwrap();
        cfg.validate().expect("canonical config validates");
        assert_eq!(
            cfg.accounts.owner_address().unwrap(),
            Some(
                "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
                    .parse()
                    .unwrap()
            )
        );
    }

    /// A canonical key whose value differs from the prediction is a
    /// validation ERROR that names the expected address.
    #[test]
    fn canonical_mismatch_is_an_error_naming_the_expected_address() {
        let artifacts = libid_contracts::Artifacts::embedded();
        let factory = predict_factory_address(&artifacts).unwrap();
        let expected = predict_address(factory, names::BANK);
        let wrong = "0x00000000000000000000000000000000deadbeef";
        let text = canonical_toml().replace(&format!("{expected:#x}"), wrong);
        let cfg: NetworkConfig = toml::from_str(&text).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("contracts.bank"), "got: {err}");
        assert!(err.contains(&format!("{expected:#x}")), "got: {err}");
    }

    /// The old empty-means-not-deployed convention is DEAD on canonical
    /// files: an empty canonical key is an error naming the fill-in value.
    #[test]
    fn canonical_empty_key_is_an_error() {
        let artifacts = libid_contracts::Artifacts::embedded();
        let factory = predict_factory_address(&artifacts).unwrap();
        let expected = predict_address(factory, names::REGISTRY);
        let text = canonical_toml().replace(&format!("{expected:#x}"), "");
        let cfg: NetworkConfig = toml::from_str(&text).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("contracts.registry"), "got: {err}");
        assert!(err.contains(&format!("{expected:#x}")), "got: {err}");
    }

    /// Declaring the Google identity verifier without the JWKS roots is
    /// rejected: the pair deploys and verifies together.
    #[test]
    fn google_identity_without_jwks_roots_is_an_error() {
        let text = canonical_toml()
            .lines()
            .filter(|l| !l.starts_with("identity_jwks_roots"))
            .collect::<Vec<_>>()
            .join("\n");
        let cfg: NetworkConfig = toml::from_str(&text).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("identity_jwks_roots"), "got: {err}");
    }
}
