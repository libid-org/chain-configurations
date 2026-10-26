//! The network file: schema, parsing, and validation.
//!
//! The model is DECLARATIVE: every canonical contract lives at a
//! CREATE3-deterministic address, so the `[contracts]` address keys are
//! ALWAYS present and pre-filled with the canonical table — `validate`
//! rejects a key whose value is not exactly
//! `predict_address(factory, name)`. Whether a declared contract is
//! deployed is determined from CHAIN STATE (`eth_getCode`) at plan/apply
//! time, never from config emptiness, and `apply` NEVER rewrites the file.

use std::{
    collections::BTreeMap,
    fmt,
    path::Path,
    str::FromStr,
};

use alloy::{
    hex::FromHexError,
    primitives::{
        Address,
        U256,
    },
};
use anyhow::{
    anyhow,
    bail,
    Context,
    Result,
};
use libid_contracts::factory::{
    predict_address,
    FactoryGenesis,
};
use serde::Deserialize;

use crate::{
    names,
    safes::{
        OwnerSet,
        Safe,
        SENTINEL_OWNERS,
    },
};

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
    /// The Safe multisigs, by name: `[safes.<name>]`.
    #[serde(default)]
    pub safes: BTreeMap<String, SafeConfig>,
}

/// `[network]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// Network name; also the GitHub environment the apply workflow uses.
    pub name: String,
    /// Chain id `apply` refuses to run without matching on-chain — against
    /// whichever endpoint answers, `--rpc-url` included.
    pub chain_id: u64,
    /// The JSON-RPC endpoint this file's own environment reaches, when the
    /// file names one at all. A real network's endpoint is a secret of the
    /// environment that runs the command — the `RPC_URL` secret of its
    /// GitHub environment, `--rpc-url` on a host — so its file carries
    /// none. `local-dev` names its compose service, which is no secret.
    /// See [`crate::rpc`].
    #[serde(default)]
    pub rpc_url: Option<String>,
}

impl Network {
    /// The endpoint the file names, if it names one: an absent or empty
    /// `rpc_url` is none.
    pub fn rpc_url(&self) -> Option<&str> {
        self.rpc_url
            .as_deref()
            .map(str::trim)
            .filter(|url| !url.is_empty())
    }
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
    /// The DEPLOYER — the address of `aws.kms_deployer`. It is the genesis
    /// admin baked into the factory's init code, so the factory address
    /// and every canonical address below follow from it; one deployer per
    /// environment gives testnet and mainnet their own tables. `apply`
    /// refuses a signer that is not this address: `factory.deploy` is
    /// owner-gated, and this is the owner.
    pub deployer: DeclaredAddress,
    /// The notary SIGNER — the EOA/KMS identity whose attestations the
    /// stack accepts. The NotaryService CONTRACT
    /// (`contracts.notary_service`) holds the trusted key set; apply
    /// initializes it with this key and adds it when it is missing.
    /// Distinct on purpose: this is a key, not a contract.
    pub notary: DeclaredAddress,
    /// The OPERATIONAL OWNER the factory should end up with. Empty =
    /// the deployer, which owns it from genesis, so the default is exact. A
    /// different key makes apply start the Ownable2Step handover; on a dev
    /// chain apply completes it by impersonation.
    #[serde(default)]
    pub owner: DeclaredAddress,
}

impl Accounts {
    /// The deployer key's address.
    pub fn deployer_address(&self) -> Result<Address> {
        self.deployer.required("accounts.deployer")
    }

    /// The notary signer's address.
    pub fn notary_address(&self) -> Result<Address> {
        self.notary.required("accounts.notary")
    }

    /// The factory this network's deployer owns from genesis: what every
    /// canonical address is predicted from.
    pub fn factory_genesis(&self) -> Result<FactoryGenesis> {
        Ok(FactoryGenesis {
            admin: self.deployer_address()?,
        })
    }

    /// The declared operational owner, if any (`None` = default to the
    /// deployer).
    pub fn owner_address(&self) -> Option<Address> {
        self.owner.get()
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
    pub factory: DeclaredAddress,
    /// The NotaryService proxy — the ONE place a notary attestation is
    /// authenticated. Deployed FIRST; every consumer takes its address.
    pub notary_service: DeclaredAddress,
    /// The CeremonyProofVerifier proxy: the Supported Version Set.
    pub ceremony_proof_verifier: DeclaredAddress,
    /// The IdentityRegistry proxy — the contract consumers resolve against.
    pub identity_registry: DeclaredAddress,
    /// The HandleEscrow proxy, initialized with `identity_registry`, which it
    /// keeps for life.
    pub handle_escrow: DeclaredAddress,
    /// The GoogleJwtRoots proxy. Starts EMPTY on-chain: point a keeper at
    /// it, or every Google binding reverts.
    pub google_jwt_roots: DeclaredAddress,
    /// The `x/v1` Platform Verifier proxy.
    pub x_platform_verifier: DeclaredAddress,
    /// The `github/v1` Platform Verifier proxy.
    pub github_platform_verifier: DeclaredAddress,
    /// The `google/v1` Platform Verifier proxy.
    pub google_platform_verifier: DeclaredAddress,
}

impl Contracts {
    /// The value declared for a canonical `[contracts]` key.
    pub fn declared(&self, key: &str) -> Option<DeclaredAddress> {
        Some(match key {
            "factory" => self.factory,
            "notary_service" => self.notary_service,
            "ceremony_proof_verifier" => self.ceremony_proof_verifier,
            "identity_registry" => self.identity_registry,
            "handle_escrow" => self.handle_escrow,
            "google_jwt_roots" => self.google_jwt_roots,
            "x_platform_verifier" => self.x_platform_verifier,
            "github_platform_verifier" => self.github_platform_verifier,
            "google_platform_verifier" => self.google_platform_verifier,
            _ => return None,
        })
    }

    /// The address declared for a canonical `[contracts]` key.
    pub fn address(&self, key: &str) -> Result<Address> {
        self.declared(key)
            .ok_or_else(|| anyhow!("{key} is not a canonical contract"))?
            .required(&format!("contracts.{key}"))
    }

    /// The entry contracts the stack wires together.
    pub fn stack(&self) -> Result<Stack> {
        Ok(Stack {
            notary_service: self.address("notary_service")?,
            proof_verifier: self.address("ceremony_proof_verifier")?,
            identity_registry: self.address("identity_registry")?,
            handle_escrow: self.address("handle_escrow")?,
            jwt_roots: self.address("google_jwt_roots")?,
        })
    }
}

/// `[safes.<name>]` — one Safe multisig. Its address follows from the name
/// and `accounts.deployer` alone (see [`crate::safes`]); the owners and
/// threshold are what apply hands it to.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeConfig {
    /// The Safe's address — DECLARED, validated to equal its prediction.
    pub address: DeclaredAddress,
    /// The owners it ends up with.
    pub owners: Vec<Address>,
    /// How many of them must sign.
    pub threshold: u64,
}

impl SafeConfig {
    /// The declared owners and threshold.
    pub fn owner_set(&self) -> OwnerSet {
        OwnerSet {
            owners: self.owners.clone(),
            threshold: self.threshold,
        }
    }
}

/// The declared addresses of the entry contracts every Platform Verifier
/// and every wiring check refers to.
#[derive(Debug, Clone, Copy)]
pub struct Stack {
    /// The Notary Service proxy.
    pub notary_service: Address,
    /// The Proof Verifier proxy: the Supported Version Set.
    pub proof_verifier: Address,
    /// The identity registry proxy.
    pub identity_registry: Address,
    /// The handle escrow proxy.
    pub handle_escrow: Address,
    /// The Google JWT root list proxy.
    pub jwt_roots: Address,
}

/// An address field of the network file. Blank declares none, and so does
/// the zero address: nothing legitimate deploys there.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct DeclaredAddress(Option<Address>);

impl DeclaredAddress {
    /// The declared address, if any.
    pub fn get(self) -> Option<Address> {
        self.0
    }

    /// The declared address, or an error naming the field `label`.
    pub fn required(self, label: &str) -> Result<Address> {
        self.0
            .ok_or_else(|| anyhow!("{label} must be set to a nonzero address"))
    }
}

impl FromStr for DeclaredAddress {
    type Err = FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = s.trim();
        if value.is_empty() {
            return Ok(Self(None));
        }
        let addr: Address = value.parse()?;
        Ok(Self((addr != Address::ZERO).then_some(addr)))
    }
}

impl TryFrom<String> for DeclaredAddress {
    type Error = FromHexError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl fmt::Display for DeclaredAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(addr) => write!(f, "{addr}"),
            None => Ok(()),
        }
    }
}

impl NetworkConfig {
    /// Load and validate a network file.
    pub fn load(path: &Path) -> Result<Self> {
        let cfg = Self::read(path)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// The file as written, before validation: what `plan --print-addresses`
    /// reads, so that a file whose `[contracts]` table is still to be filled
    /// in can print the table it needs.
    pub fn read(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        toml::from_str(&text)
            .with_context(|| format!("failed to parse {}", path.display()))
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
        if let Some(url) = self.network.rpc_url() {
            crate::rpc::parse_rpc_url(url, "network.rpc_url")?;
        }
        self.accounts.notary_address()?;
        self.notary_service.fee()?;
        if self.aws.region.trim().is_empty() {
            bail!("aws.region must not be empty");
        }
        if self.aws.kms_deployer.trim().is_empty() {
            bail!("aws.kms_deployer must not be empty");
        }
        self.validate_canonical_addresses()?;
        self.validate_safes()
    }

    /// Every declared Safe: a name of `[a-z0-9_]`, distinct nonzero owners,
    /// a threshold they can meet, and the address its name predicts.
    fn validate_safes(&self) -> Result<()> {
        let deployer = self.accounts.deployer_address()?;
        for (name, declared) in &self.safes {
            let label = format!("safes.{name}");
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            {
                bail!("{label}: a Safe name is lowercase letters, digits and '_'");
            }
            let expected = Safe { name, deployer }.address();
            let address = declared
                .address
                .required(&format!("{label}.address"))
                .map_err(|e| {
                    anyhow!(
                        "{e} — set it to {expected:#x}, the address its name predicts"
                    )
                })?;
            if address != expected {
                bail!(
                    "{label}.address declares {address:#x} but the Safe '{name}' of \
                     deployer {deployer:#x} is at {expected:#x}"
                );
            }
            let owners = &declared.owners;
            if owners.is_empty() {
                bail!("{label}.owners must name at least one owner");
            }
            for (i, owner) in owners.iter().enumerate() {
                if [Address::ZERO, SENTINEL_OWNERS, address].contains(owner) {
                    bail!("{label}.owners: {owner:#x} cannot own a Safe");
                }
                if owners[..i].contains(owner) {
                    bail!("{label}.owners lists {owner:#x} twice");
                }
            }
            if declared.threshold == 0 || declared.threshold > owners.len() as u64 {
                bail!(
                    "{label}.threshold is {} but must be 1 to {} (its owner count)",
                    declared.threshold,
                    owners.len()
                );
            }
        }
        Ok(())
    }

    /// Every declared canonical key must EQUAL the predicted CREATE3
    /// address for its frozen name; the factory key must equal the
    /// deployer's factory address.
    fn validate_canonical_addresses(&self) -> Result<()> {
        let artifacts = libid_contracts::Artifacts::embedded();
        let factory = self
            .accounts
            .factory_genesis()?
            .address(&artifacts)
            .map_err(|e| anyhow!("predicting the factory address failed: {e}"))?;

        let declared_factory = self.contracts.address("factory").map_err(|e| {
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
                .declared(c.key)
                .ok_or_else(|| anyhow!("{label} is not a known canonical key"))?;
            let expected = predict_address(factory, c.name);
            let declared = raw.required(&label).map_err(|e| {
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
pub(crate) mod tests {
    use std::path::PathBuf;

    use super::*;

    fn networks_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../networks")
    }

    /// Anvil account #0: the deployer of the test configurations.
    pub(crate) const TEST_DEPLOYER: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    /// The factory the test deployer owns from genesis.
    pub(crate) fn test_factory() -> Address {
        let genesis = FactoryGenesis {
            admin: TEST_DEPLOYER.parse().unwrap(),
        };
        genesis
            .address(&libid_contracts::Artifacts::embedded())
            .unwrap()
    }

    /// A minimal file with every address pre-filled from the prediction.
    pub(crate) fn canonical_toml() -> String {
        let factory = test_factory();
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
deployer = "{TEST_DEPLOYER}"
notary = "0x1111111111111111111111111111111111111111"
owner = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

[notary_service]
fee_wei = "1000"

[contracts]
factory = "{factory:#x}"
notary_service = "{notary_service}"
ceremony_proof_verifier = "{pv}"
identity_registry = "{registry}"
handle_escrow = "{escrow}"
google_jwt_roots = "{roots}"
x_platform_verifier = "{x}"
github_platform_verifier = "{github}"
google_platform_verifier = "{google}"
"#,
            notary_service = addr(names::NOTARY_SERVICE),
            pv = addr(names::CEREMONY_PROOF_VERIFIER),
            registry = addr(names::IDENTITY_REGISTRY),
            escrow = addr(names::HANDLE_ESCROW),
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
            .replace("region = \"\"", "region = \"eu-central-1\"")
            .replace("kms_deployer = \"\"", "kms_deployer = \"alias/x\"")
            .replace(
                "notary = \"\"",
                "notary = \"0x1111111111111111111111111111111111111111\"",
            );
        let cfg: NetworkConfig = toml::from_str(&text).expect("template parses");
        cfg.validate().expect("template validates canonically");
    }

    /// A real network's file names no endpoint — the environment supplies
    /// it — and validates like one that does. An empty `rpc_url` is none.
    #[test]
    fn a_file_without_an_endpoint_validates() {
        let text = canonical_toml().replace("rpc_url = \"http://localhost:8545\"\n", "");
        let cfg: NetworkConfig = toml::from_str(&text).unwrap();
        cfg.validate().expect("validates without an endpoint");
        assert_eq!(cfg.network.rpc_url(), None);

        let text = canonical_toml().replace("http://localhost:8545", "");
        let cfg: NetworkConfig = toml::from_str(&text).unwrap();
        cfg.validate().expect("an empty endpoint is none");
        assert_eq!(cfg.network.rpc_url(), None);
    }

    /// Blank and the zero address declare none; anything else must be an
    /// address.
    #[test]
    fn a_declared_address_parses_blank_and_zero_as_none() {
        let none: DeclaredAddress = "  ".parse().unwrap();
        assert_eq!(none.get(), None);
        let zero: DeclaredAddress = format!("{:#x}", Address::ZERO).parse().unwrap();
        assert_eq!(zero.get(), None);
        let some: DeclaredAddress = TEST_DEPLOYER.parse().unwrap();
        assert_eq!(some.get(), Some(TEST_DEPLOYER.parse().unwrap()));
        assert_eq!(some.to_string(), TEST_DEPLOYER);
        assert!("0xnot-an-address".parse::<DeclaredAddress>().is_err());
    }

    /// A fully pre-filled config validates.
    #[test]
    fn canonical_config_validates() {
        let cfg: NetworkConfig = toml::from_str(&canonical_toml()).unwrap();
        cfg.validate().expect("canonical config validates");
        assert_eq!(
            cfg.accounts.owner_address(),
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
        let expected = predict_address(test_factory(), names::IDENTITY_REGISTRY);
        let wrong = "0x00000000000000000000000000000000deadbeef";
        let text = canonical_toml().replace(&format!("{expected:#x}"), wrong);
        let cfg: NetworkConfig = toml::from_str(&text).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("contracts.identity_registry"), "got: {err}");
        assert!(err.contains(&format!("{expected:#x}")), "got: {err}");
    }

    /// A `[safes.<name>]` table for the test deployer.
    fn with_safe(
        name: &str,
        address: Address,
        owners: &[&str],
        threshold: u64,
    ) -> String {
        let owners = owners
            .iter()
            .map(|o| format!("\"{o}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "{}\n[safes.{name}]\naddress = \"{address:#x}\"\nowners = [{owners}]\n\
             threshold = {threshold}\n",
            canonical_toml()
        )
    }

    fn test_safe(name: &str) -> Address {
        Safe {
            name,
            deployer: TEST_DEPLOYER.parse().unwrap(),
        }
        .address()
    }

    /// A Safe at the address its name predicts validates.
    #[test]
    fn a_declared_safe_validates_at_its_predicted_address() {
        let text = with_safe(
            "notary_fees",
            test_safe("notary_fees"),
            &[TEST_DEPLOYER, "0x1111111111111111111111111111111111111111"],
            2,
        );
        let cfg: NetworkConfig = toml::from_str(&text).unwrap();
        cfg.validate().expect("the predicted address validates");
        assert_eq!(cfg.safes.get("notary_fees").map(|s| s.threshold), Some(2));
    }

    /// A Safe declared at another name's address is an error naming the
    /// predicted one.
    #[test]
    fn a_safe_at_another_address_is_an_error_naming_the_prediction() {
        let expected = test_safe("notary_fees");
        let text = with_safe(
            "notary_fees",
            test_safe("registry_fees"),
            &[TEST_DEPLOYER],
            1,
        );
        let cfg: NetworkConfig = toml::from_str(&text).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("safes.notary_fees.address"), "got: {err}");
        assert!(err.contains(&format!("{expected:#x}")), "got: {err}");
    }

    /// Owners and threshold a Safe would refuse are refused at load.
    #[test]
    fn a_safe_with_unusable_owners_is_an_error() {
        let address = test_safe("notary_fees");
        for (owners, threshold, needle) in [
            (vec![], 1, "at least one owner"),
            (vec![TEST_DEPLOYER, TEST_DEPLOYER], 1, "twice"),
            (vec![TEST_DEPLOYER], 2, "threshold"),
            (vec![TEST_DEPLOYER], 0, "threshold"),
            (
                vec!["0x0000000000000000000000000000000000000001"],
                1,
                "cannot own",
            ),
        ] {
            let text = with_safe("notary_fees", address, &owners, threshold);
            let cfg: NetworkConfig = toml::from_str(&text).unwrap();
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains(needle), "{owners:?}/{threshold}: {err}");
        }
    }

    /// An empty canonical key is an error naming the fill-in value.
    #[test]
    fn canonical_empty_key_is_an_error() {
        let expected = predict_address(test_factory(), names::GOOGLE_JWT_ROOTS);
        let text = canonical_toml().replace(&format!("{expected:#x}"), "");
        let cfg: NetworkConfig = toml::from_str(&text).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("contracts.google_jwt_roots"), "got: {err}");
        assert!(err.contains(&format!("{expected:#x}")), "got: {err}");
    }
}
