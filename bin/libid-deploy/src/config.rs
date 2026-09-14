//! The network file: schema, parsing, and validation.
//!
//! The model is DECLARATIVE: every canonical contract lives at a
//! CREATE3-deterministic address, so the `[contracts]` address keys are
//! ALWAYS present and pre-filled with the canonical table — `validate`
//! rejects a key whose value is not exactly
//! `predict_address(factory, name)`. Whether a declared contract is
//! deployed is determined from CHAIN STATE (`eth_getCode`) at plan/apply
//! time, never from config emptiness, and `apply` NEVER rewrites the file.

use std::path::Path;

use alloy::primitives::{
    Address,
    U256,
};
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
    /// What one attestation verification costs.
    pub notary_service: NotaryService,
    /// The canonical contract addresses — DECLARED, pre-filled with the
    /// canonical table.
    pub contracts: Contracts,
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
    /// The notary SIGNER — the EOA/KMS identity whose attestations the
    /// stack accepts. The NotaryService CONTRACT
    /// (`contracts.notary_service`) holds the trusted key set; apply
    /// initializes it with this key and adds it when it is missing.
    /// Distinct on purpose: this is a key, not a contract.
    pub notary: String,
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

/// `[notary_service]` — the one governance parameter of the service.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotaryService {
    /// What one attestation verification costs, in wei, as a decimal
    /// string (TOML integers do not reach `uint256`). May be zero: a
    /// deployment may meter at no charge, and the exact-value rule still
    /// applies. Editing it makes apply send `setFee`.
    pub fee_wei: String,
}

impl NotaryService {
    /// The declared fee.
    pub fn fee(&self) -> Result<U256> {
        self.fee_wei
            .trim()
            .parse()
            .map_err(|e| anyhow!("invalid notary_service.fee_wei: {e}"))
    }
}

/// `[contracts]` — declared canonical addresses. Every key is always
/// present and equals `predict_address(factory, name)`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contracts {
    /// The deterministic LibidFactory proxy — one canonical CREATE2
    /// address on every EVM network.
    pub factory: String,
    /// The NotaryService proxy — the ONE place a notary attestation is
    /// authenticated. Deployed FIRST; every consumer takes its address.
    pub notary_service: String,
    /// The CeremonyProofVerifier proxy: the Supported Version Set.
    pub ceremony_proof_verifier: String,
    /// The IdentityNames proxy — the contract consumers resolve against.
    pub identity_names: String,
    /// The GoogleJwtRoots proxy. Starts EMPTY on-chain: point a keeper at
    /// it before Google names work.
    pub google_jwt_roots: String,
    /// The `x/v1` Platform Verifier proxy.
    pub x_platform_verifier: String,
    /// The `github/v1` Platform Verifier proxy.
    pub github_platform_verifier: String,
    /// The `google/v1` Platform Verifier proxy.
    pub google_platform_verifier: String,
}

impl Contracts {
    /// The raw value declared for a canonical `[contracts]` key.
    pub fn raw(&self, key: &str) -> Option<&str> {
        Some(match key {
            "factory" => self.factory.as_str(),
            "notary_service" => self.notary_service.as_str(),
            "ceremony_proof_verifier" => self.ceremony_proof_verifier.as_str(),
            "identity_names" => self.identity_names.as_str(),
            "google_jwt_roots" => self.google_jwt_roots.as_str(),
            "x_platform_verifier" => self.x_platform_verifier.as_str(),
            "github_platform_verifier" => self.github_platform_verifier.as_str(),
            "google_platform_verifier" => self.google_platform_verifier.as_str(),
            _ => return None,
        })
    }
}

/// Parse an address field that may be empty (optional keys).
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
    /// the network, including the address-equality check: every declared
    /// canonical key must EQUAL `predict_address(factory, name)`.
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
        self.accounts.owner_address()?;
        self.notary_service.fee()?;
        if self.aws.region.trim().is_empty() {
            bail!("aws.region must not be empty");
        }
        if self.aws.kms_deployer.trim().is_empty() {
            bail!("aws.kms_deployer must not be empty");
        }
        self.validate_canonical_addresses()
    }

    /// Every declared canonical key must EQUAL the predicted CREATE3
    /// address for its frozen name; the factory key must equal the
    /// canonical factory address.
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
            let label = format!("contracts.{}", c.key);
            let raw = self
                .contracts
                .raw(c.key)
                .ok_or_else(|| anyhow!("{label} is not a known canonical key"))?;
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn networks_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../networks")
    }

    /// A minimal file with every address pre-filled from the prediction.
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
owner = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

[notary_service]
fee_wei = "1000"

[contracts]
factory = "{factory:#x}"
notary_service = "{notary_service}"
ceremony_proof_verifier = "{pv}"
identity_names = "{names}"
google_jwt_roots = "{roots}"
x_platform_verifier = "{x}"
github_platform_verifier = "{github}"
google_platform_verifier = "{google}"
"#,
            notary_service = addr(names::NOTARY_SERVICE),
            pv = addr(names::CEREMONY_PROOF_VERIFIER),
            names = addr(names::IDENTITY_NAMES),
            roots = addr(names::GOOGLE_JWT_ROOTS),
            x = addr(names::X_PLATFORM_VERIFIER),
            github = addr(names::GITHUB_PLATFORM_VERIFIER),
            google = addr(names::GOOGLE_PLATFORM_VERIFIER),
        )
    }

    /// Every committed network file loads under the full canonical-equality
    /// check. If this fails with a named expected address, the committed
    /// table has drifted from `predict_address` — regenerate it with
    /// `plan --print-addresses` instead of editing either side by hand.
    #[test]
    fn every_committed_network_file_is_canonical() {
        let mut seen = 0;
        for entry in std::fs::read_dir(networks_dir()).expect("networks/ readable") {
            let path = entry.expect("dir entry").path();
            if path.extension().is_some_and(|e| e == "toml") {
                NetworkConfig::load(&path).unwrap_or_else(|e| {
                    panic!("{} does not load: {e:?}", path.display())
                });
                seen += 1;
            }
        }
        assert!(seen > 0, "no network files found");
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
            );
        let cfg: NetworkConfig = toml::from_str(&text).expect("template parses");
        cfg.validate().expect("template validates canonically");
    }

    /// A fully pre-filled config validates.
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
        assert_eq!(cfg.notary_service.fee().unwrap(), U256::from(1000));
    }

    /// A canonical key whose value differs from the prediction is a
    /// validation ERROR that names the expected address.
    #[test]
    fn canonical_mismatch_is_an_error_naming_the_expected_address() {
        let artifacts = libid_contracts::Artifacts::embedded();
        let factory = predict_factory_address(&artifacts).unwrap();
        let expected = predict_address(factory, names::IDENTITY_NAMES);
        let wrong = "0x00000000000000000000000000000000deadbeef";
        let text = canonical_toml().replace(&format!("{expected:#x}"), wrong);
        let cfg: NetworkConfig = toml::from_str(&text).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("contracts.identity_names"), "got: {err}");
        assert!(err.contains(&format!("{expected:#x}")), "got: {err}");
    }

    /// An empty canonical key is an error naming the fill-in value.
    #[test]
    fn canonical_empty_key_is_an_error() {
        let artifacts = libid_contracts::Artifacts::embedded();
        let factory = predict_factory_address(&artifacts).unwrap();
        let expected = predict_address(factory, names::GOOGLE_JWT_ROOTS);
        let text = canonical_toml().replace(&format!("{expected:#x}"), "");
        let cfg: NetworkConfig = toml::from_str(&text).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("contracts.google_jwt_roots"), "got: {err}");
        assert!(err.contains(&format!("{expected:#x}")), "got: {err}");
    }
}
