//! The deployer's signing backend: a raw hex private key (anvil, local
//! rehearsal) or an AWS KMS secp256k1 key (production; the private material
//! never leaves the HSM).
//!
//! The spec is classified by SHAPE — no prefixes, no configuration —
//! porting the original monorepo's wallet-pool `SignerSource::from_spec`
//! exactly: a secp256k1 private key is 64 hex chars (optionally
//! `0x`-prefixed), every real KMS identifier contains a non-hex character
//! (UUID dashes, `alias/`, ARN colons), and an ALL-HEX value of the wrong
//! length is a mangled private key rejected here by name rather than
//! shipped to AWS as a bogus key id.

use alloy::{
    network::EthereumWallet,
    primitives::{
        Address,
        FixedBytes,
    },
    signers::{
        aws::AwsSigner,
        local::PrivateKeySigner,
        // Brings `address()` into scope; it is not an inherent method.
        Signer,
    },
};
use anyhow::{
    anyhow,
    bail,
    Result,
};

/// Where the deployer's signing key lives.
#[derive(Debug, Clone)]
pub enum SignerSource {
    /// Hex-encoded secp256k1 private key, with or without a `0x` prefix.
    PrivateKey(String),
    /// An AWS KMS key id, alias (`alias/...`) or full ARN. Region and
    /// credentials come from the ambient AWS config chain (AWS_REGION,
    /// profile, OIDC role) — there is nothing to configure here.
    Kms(String),
}

impl SignerSource {
    /// Classify a `--signer` spec by shape. See the module docs for why the
    /// two forms are structurally disjoint.
    pub fn from_spec(spec: &str) -> Result<Self> {
        let entry = spec.trim();
        if entry.is_empty() {
            bail!("empty signer spec");
        }
        let hexish = entry.strip_prefix("0x").unwrap_or(entry);
        if hexish.chars().all(|c| c.is_ascii_hexdigit()) {
            if hexish.len() == 64 {
                return Ok(Self::PrivateKey(entry.to_owned()));
            }
            bail!(
                "'{}…' looks like a hex private key but has {} hex chars, expected \
                 64 — refusing to treat it as a KMS key id",
                &entry[..entry.len().min(8)],
                hexish.len()
            );
        }
        Ok(Self::Kms(entry.to_owned()))
    }

    /// A description safe to log. Never contains key material.
    pub fn describe(&self) -> String {
        match self {
            Self::PrivateKey(_) => "local private key".into(),
            Self::Kms(key_id) => format!("AWS KMS {key_id}"),
        }
    }

    /// Build a wallet and report the address it signs as. `chain_id` is
    /// stamped into the signer for EIP-155 replay protection.
    pub async fn build_wallet(
        &self,
        chain_id: Option<u64>,
    ) -> Result<(EthereumWallet, Address)> {
        match self {
            Self::PrivateKey(hex_key) => {
                let raw = hex_key.strip_prefix("0x").unwrap_or(hex_key);
                let bytes = alloy::hex::decode(raw)
                    .map_err(|e| anyhow!("failed to decode signing key: {e}"))?;
                if bytes.len() != 32 {
                    bail!("signing key must be 32 bytes, got {}", bytes.len());
                }
                let sk: FixedBytes<32> = FixedBytes::from_slice(&bytes);
                let mut signer = PrivateKeySigner::from_bytes(&sk)
                    .map_err(|e| anyhow!("failed to create signer: {e}"))?;
                if let Some(id) = chain_id {
                    signer.set_chain_id(Some(id));
                }
                let address = signer.address();
                Ok((EthereumWallet::from(signer), address))
            }
            Self::Kms(key_id) => {
                // `defaults()` requires an explicit behaviour version so an
                // SDK upgrade cannot silently change retry/timeout semantics
                // underneath a deploy.
                let cfg = aws_config::defaults(aws_config::BehaviorVersion::latest())
                    .load()
                    .await;
                let client = aws_sdk_kms::Client::new(&cfg);
                // Performs its own GetPublicKey to derive the address; a
                // missing kms:Sign/GetPublicKey grant surfaces here, at
                // startup, rather than on the first transaction. AwsSigner
                // also handles the DER decode and the EIP-2 low-s flip AWS
                // does not do server-side.
                let signer = AwsSigner::new(client, key_id.clone(), chain_id)
                    .await
                    .map_err(|e| {
                        anyhow!("failed to create KMS signer for {key_id}: {e}")
                    })?;
                let address = signer.address();
                Ok((EthereumWallet::from(signer), address))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The canonical anvil account #0 key. Public test material, not a secret.
    const ANVIL_KEY: &str =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const ANVIL_ADDR: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    /// The classification table: shape decides everything.
    #[test]
    fn spec_classifies_by_shape() {
        assert!(matches!(
            SignerSource::from_spec(ANVIL_KEY).unwrap(),
            SignerSource::PrivateKey(k) if k == ANVIL_KEY
        ));
        assert!(matches!(
            SignerSource::from_spec(&format!("0x{ANVIL_KEY}")).unwrap(),
            SignerSource::PrivateKey(_)
        ));
        for id in [
            "alias/dyaka-testnet-deployer",
            "bfa1bb3b-53a5-491b-a825-32998fd43a3d",
            "arn:aws:kms:eu-central-1:123456789012:key/abc",
        ] {
            assert!(
                matches!(
                    SignerSource::from_spec(id).unwrap(),
                    SignerSource::Kms(k) if k == id
                ),
                "{id}"
            );
        }
    }

    /// A truncated key paste fails here with a message naming the problem,
    /// not at AWS as a NotFoundException.
    #[test]
    fn wrong_length_hex_is_rejected_not_sent_to_kms() {
        let err = SignerSource::from_spec("0xdeadbeef").unwrap_err();
        assert!(format!("{err}").contains("expected 64"), "got: {err}");
        assert!(SignerSource::from_spec("").is_err());
        assert!(SignerSource::from_spec("   ").is_err());
    }

    #[tokio::test]
    async fn private_key_derives_the_expected_address() {
        for spec in [ANVIL_KEY.to_owned(), format!("0x{ANVIL_KEY}")] {
            let src = SignerSource::from_spec(&spec).unwrap();
            let (_, addr) = src.build_wallet(Some(31337)).await.unwrap();
            assert_eq!(addr.to_string().to_lowercase(), ANVIL_ADDR.to_lowercase());
        }
    }

    #[test]
    fn describe_never_leaks_key_material() {
        let src = SignerSource::PrivateKey(ANVIL_KEY.into());
        assert!(!src.describe().contains(ANVIL_KEY));
    }
}
