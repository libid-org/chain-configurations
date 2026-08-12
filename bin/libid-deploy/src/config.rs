//! The network file: schema, parsing, validation, and the comment-preserving
//! rewrite that records deployed addresses.
//!
//! Convention: keys under `[contracts]` and `[identity]` are OUTPUTS. An
//! empty string or an absent key means "not deployed yet"; `apply` fills
//! only those and never overwrites a non-empty value (the one exception is
//! an explicit `--upgrade oidc-verifier`, which REPLACES the verifier and
//! must record its new address). Everything else is an INPUT an operator
//! edits.

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
use serde::Deserialize;

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
    /// OUTPUT: the core contract addresses.
    #[serde(default)]
    pub contracts: Contracts,
    /// OUTPUT: the identity-names stack. Absent section = not wanted.
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
}

/// `[contracts]` — OUTPUT keys.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contracts {
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
    /// The GoogleOidcVerifier proxy (deployed only when `google_client_id`
    /// is set).
    #[serde(default)]
    pub google_oidc_verifier: String,
}

/// `[identity]` — OUTPUT keys. A key PRESENT but empty is a deploy request;
/// an ABSENT key is "not wanted". `identity_names` and
/// `github_identity_verifier` are always wanted once the section exists.
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

/// Parse an OUTPUT-style address field: empty = not deployed.
pub fn opt_address(value: &str, label: &str) -> Result<Option<Address>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let addr: Address = value
        .parse()
        .map_err(|e| anyhow!("invalid address for {label}: {e}"))?;
    if addr == Address::ZERO {
        // A recorded zero address is "not deployed", the same as empty —
        // nothing legitimate deploys to the zero address.
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
    /// the network.
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
        for (label, value) in [
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
        Ok(())
    }

    /// Whether the whole core `[contracts]` section is empty — the state
    /// that makes `apply` a FRESH DEPLOY and requires
    /// `--confirm-fresh-deploy`.
    pub fn contracts_all_empty(&self) -> Result<bool> {
        Ok([
            opt_address(&self.contracts.bank, "contracts.bank")?,
            opt_address(&self.contracts.registry, "contracts.registry")?,
            opt_address(&self.contracts.wallet_factory, "contracts.wallet_factory")?,
            opt_address(&self.contracts.notary, "contracts.notary")?,
            opt_address(&self.contracts.x_zk_verifier, "contracts.x_zk_verifier")?,
            opt_address(
                &self.contracts.google_oidc_verifier,
                "contracts.google_oidc_verifier",
            )?,
        ]
        .iter()
        .all(Option::is_none))
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

/// One address to record in the network file.
#[derive(Debug, Clone)]
pub struct AddressUpdate {
    /// Table name: `contracts` or `identity`.
    pub section: &'static str,
    /// Key inside the table.
    pub key: String,
    /// The deployed address.
    pub address: Address,
    /// Overwrite even a non-empty value. Only the OIDC verifier REPLACE
    /// upgrade sets this — its address genuinely changes.
    pub force: bool,
}

/// Record deployed addresses into the network file, preserving comments and
/// formatting. Only empty/absent keys are filled unless `force` is set.
/// Returns the keys that changed, as `section.key` strings.
pub fn record_addresses(path: &Path, updates: &[AddressUpdate]) -> Result<Vec<String>> {
    if updates.is_empty() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .with_context(|| format!("failed to parse {}", path.display()))?;

    let mut changed = Vec::new();
    for update in updates {
        if doc.get(update.section).is_none() {
            doc[update.section] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        let table = doc[update.section]
            .as_table_mut()
            .ok_or_else(|| anyhow!("[{}] is not a table", update.section))?;
        let current = table
            .get(&update.key)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_owned();
        let occupied = opt_address(&current, &update.key)?.is_some();
        if occupied && !update.force {
            continue;
        }
        let new_value = format!("{:#x}", update.address);
        if current == new_value {
            continue;
        }
        table[&update.key] = toml_edit::value(new_value);
        changed.push(format!("{}.{}", update.section, update.key));
    }

    if !changed.is_empty() {
        std::fs::write(path, doc.to_string())
            .with_context(|| format!("failed to write {}", path.display()))?;
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../networks/eden-testnet.toml")
    }

    /// The committed Eden file parses, validates, and carries the real
    /// deployment: every core contract populated, identity absent.
    #[test]
    fn the_seeded_eden_file_parses() {
        let cfg = NetworkConfig::load(&seeded_path()).expect("eden-testnet.toml loads");
        assert_eq!(cfg.network.chain_id, 3735928814);
        assert!(cfg.identity.is_none());
        assert!(!cfg.contracts_all_empty().unwrap());
        assert_eq!(cfg.tokens.len(), 4);
        // Both platforms carry templates and each template names the bot.
        let pairs = cfg.template_pairs();
        assert_eq!(pairs.len(), 6);
        assert!(pairs.iter().all(|(_, t)| t.contains("@testyakly")));
    }

    /// Recording fills only empty keys, preserves every comment, and leaves
    /// populated keys alone without `force`.
    #[test]
    fn record_addresses_preserves_comments_and_never_clobbers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net.toml");
        let original = "\
# A load-bearing comment.
[network]
name = \"test\" # trailing comment
chain_id = 1
rpc_url = \"http://localhost:8545\"

[contracts]
bank = \"\" # filled by apply
registry = \"0xd764dbc5e51a042c004c52833f7e2f32b0cc651e\"
";
        std::fs::write(&path, original).unwrap();

        let new_addr = Address::repeat_byte(0xab);
        let changed = record_addresses(
            &path,
            &[
                AddressUpdate {
                    section: "contracts",
                    key: "bank".into(),
                    address: new_addr,
                    force: false,
                },
                AddressUpdate {
                    section: "contracts",
                    key: "registry".into(),
                    address: new_addr,
                    force: false,
                },
                AddressUpdate {
                    section: "identity",
                    key: "identity_names".into(),
                    address: new_addr,
                    force: false,
                },
            ],
        )
        .unwrap();
        assert_eq!(changed, vec!["contracts.bank", "identity.identity_names"]);

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# A load-bearing comment."));
        assert!(text.contains("# trailing comment"));
        assert!(text.contains(&format!("bank = \"{new_addr:#x}\"")));
        // The populated registry survived untouched.
        assert!(
            text.contains("registry = \"0xd764dbc5e51a042c004c52833f7e2f32b0cc651e\"")
        );
        // The identity section was created for the new key.
        assert!(text.contains("[identity]"));
    }

    /// `force` is the explicit escape hatch for the OIDC verifier REPLACE.
    #[test]
    fn record_addresses_force_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net.toml");
        std::fs::write(
            &path,
            "[contracts]\ngoogle_oidc_verifier = \"0x69cc7c69b39ada71ce908d432868d5ef9a6a6d0e\"\n",
        )
        .unwrap();
        let new_addr = Address::repeat_byte(0xcd);
        let changed = record_addresses(
            &path,
            &[AddressUpdate {
                section: "contracts",
                key: "google_oidc_verifier".into(),
                address: new_addr,
                force: true,
            }],
        )
        .unwrap();
        assert_eq!(changed, vec!["contracts.google_oidc_verifier"]);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(&format!("{new_addr:#x}")));
    }

    /// A rewrite with nothing to change leaves the file byte-identical.
    #[test]
    fn record_addresses_is_a_noop_when_populated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net.toml");
        let original =
            std::fs::read_to_string(seeded_path()).expect("seeded file readable");
        std::fs::write(&path, &original).unwrap();
        let changed = record_addresses(
            &path,
            &[AddressUpdate {
                section: "contracts",
                key: "bank".into(),
                address: Address::repeat_byte(0xef),
                force: false,
            }],
        )
        .unwrap();
        assert!(changed.is_empty());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }
}
