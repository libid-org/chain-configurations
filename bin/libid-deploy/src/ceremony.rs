//! The Platform Verifiers: the contracts that decode one platform's
//! ceremony payload, verify its proof and authenticate its attestations.
//!
//! # Why the artifacts live here
//!
//! `libid-contracts` embeds compiled bytecode only for the contracts its
//! `COVERED` list names, and the Platform Verifiers are not among them —
//! its own `script/Deploy.s.sol` registers none either. This repository
//! deploys them, so it compiles them from the same tag its `libid-contracts`
//! dependency comes from and embeds the result:
//! `scripts/vendor-platform-verifiers.sh` writes `artifacts/`, and the tag
//! it builds is derived from `Cargo.toml` rather than restated, so vendored
//! bytecode and typed bindings cannot come from different releases.
//!
//! # The circuit verifier
//!
//! `PlatformVerifierBase._setTrustRoots` pins the bb-generated UltraHonk
//! verifier the platform's proofs are checked under, BY ADDRESS AND BY CODE
//! HASH: it reads `address(honkVerifier_).codehash` and refuses a value
//! that does not match the hash the caller named, and refuses the empty and
//! zero hashes outright. A bb verifier embeds its verification key as code
//! constants and exposes no getter, so the code hash is the only handle on
//! which circuit a deployed verifier answers for.
//!
//! Consequently this tool cannot invent one. The operator declares the
//! address in `[ceremony.<platform>].circuit_verifier`, apply reads the
//! code there and hashes it, and a platform with no declaration gets no
//! Platform Verifier — it owns its keyspace and verifies nothing, which is
//! exactly what the chain reports.

use std::collections::BTreeMap;

use alloy::{
    hex,
    primitives::Bytes,
};
use anyhow::{
    anyhow,
    bail,
    Result,
};

/// Bindings for the TLSNotary Platform Verifiers — `XPlatformVerifier` and
/// `GitHubPlatformVerifier`. One interface for both: the platforms differ
/// in the layout they accept, not in the surface a deployment touches, and
/// each contract answers for itself through `platformId()`.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod tls_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface TlsPlatformVerifier {
            /// `notary_` is the Notary Service this profile's attestations
            /// are authenticated through — required here, because a
            /// TLSNotary profile carries two of them.
            ///
            /// `honkVerifierCodehash_` is checked against the code at
            /// `honkVerifier_`: naming the artifact is what makes a
            /// mis-wiring fail at deploy instead of at the first user's
            /// proof.
            function initialize(
                address owner_,
                address notary_,
                address honkVerifier_,
                bytes32 honkVerifierCodehash_,
                uint64 proofLifetime_,
                uint64 maxFutureAttestationSkew_,
                uint64 futureObservationAllowance_
            ) external;

            /// The identity platform this verifier serves. The Proof
            /// Verifier refuses to register one under another platform.
            function platformId() external view returns (bytes32);
            /// One Notary Fee per attestation the profile requires.
            function quote() external view returns (uint256);
            function notaryService() external view returns (address);
            function honkVerifier() external view returns (address);
            function honkVerifierCodehash() external view returns (bytes32);
            function protocolParameters()
                external
                view
                returns (
                    uint64 proofLifetime,
                    uint64 maxFutureAttestationSkew,
                    uint64 futureObservationAllowance
                );
            function setTrustRoots(
                address notary_,
                address honkVerifier_,
                bytes32 honkVerifierCodehash_
            ) external;
            function setProtocolParameters(
                uint64 proofLifetime_,
                uint64 maxFutureAttestationSkew_,
                uint64 futureObservationAllowance_
            ) external;

            function owner() external view returns (address);
            function pendingOwner() external view returns (address);
            function transferOwnership(address newOwner) external;
            function acceptOwnership() external;
        }
    }
}

pub use tls_inner::TlsPlatformVerifier;

/// Bindings for `ceremony/GooglePlatformVerifier.sol`.
///
/// Its profile notarizes nothing — the evidence is a signed JWT checked
/// against Google's published keys — so it holds NO Notary Service (a
/// nonzero one is rejected), no proof lifetime and no attestation skew,
/// and reads the JWT root list instead.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod google_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface GooglePlatformVerifier {
            /// `notary_` must be the zero address here. The signed `exp`
            /// is the whole validity ceiling, so only the observation
            /// allowance remains — Google's `exp` runs about an hour ahead
            /// of the moment it describes.
            function initialize(
                address owner_,
                address notary_,
                address honkVerifier_,
                bytes32 honkVerifierCodehash_,
                uint64 futureObservationAllowance_,
                address jwtRoots_
            ) external;

            function platformId() external view returns (bytes32);
            function quote() external view returns (uint256);
            function notaryService() external view returns (address);
            function honkVerifier() external view returns (address);
            function honkVerifierCodehash() external view returns (bytes32);
            /// The root list this verifier trusts moduli through.
            function jwtRoots() external view returns (address);
            function setJwtRoots(address roots) external;
            function protocolParameters()
                external
                view
                returns (
                    uint64 proofLifetime,
                    uint64 maxFutureAttestationSkew,
                    uint64 futureObservationAllowance
                );
            function setTrustRoots(
                address notary_,
                address honkVerifier_,
                bytes32 honkVerifierCodehash_
            ) external;

            function owner() external view returns (address);
            function pendingOwner() external view returns (address);
            function transferOwnership(address newOwner) external;
            function acceptOwnership() external;
        }
    }
}

pub use google_inner::GooglePlatformVerifier;

/// The vendored artifacts, embedded at compile time. Named individually
/// rather than pulled from a directory: a missing one must be a compile
/// error, not a runtime surprise on a chain that has already been half
/// converged.
const ARTIFACTS: &[(&str, &str)] = &[
    (
        "XPlatformVerifier",
        include_str!("../artifacts/XPlatformVerifier.sol/XPlatformVerifier.json"),
    ),
    (
        "GitHubPlatformVerifier",
        include_str!(
            "../artifacts/GitHubPlatformVerifier.sol/GitHubPlatformVerifier.json"
        ),
    ),
    (
        "GooglePlatformVerifier",
        include_str!(
            "../artifacts/GooglePlatformVerifier.sol/GooglePlatformVerifier.json"
        ),
    ),
];

fn artifact(contract: &str) -> Result<serde_json::Value> {
    let raw = ARTIFACTS
        .iter()
        .find(|(name, _)| *name == contract)
        .map(|(_, raw)| *raw)
        .ok_or_else(|| anyhow!("no vendored artifact for {contract}"))?;
    serde_json::from_str(raw)
        .map_err(|e| anyhow!("vendored artifact for {contract} is not valid JSON: {e}"))
}

/// The creation bytecode of a Platform Verifier implementation.
pub fn creation_code(contract: &str) -> Result<Bytes> {
    let json = artifact(contract)?;
    let raw = json["bytecode"]["object"]
        .as_str()
        .ok_or_else(|| anyhow!("no bytecode.object in the {contract} artifact"))?;
    let raw = raw.strip_prefix("0x").unwrap_or(raw);
    if raw.contains("__$") {
        // Nothing here links a library today. If one ever does, it must be
        // deployed and substituted before this bytecode means anything —
        // silently deploying the placeholder would produce a verifier that
        // reverts on every call.
        bail!("{contract} has unresolved link references; the vendor script must follow them");
    }
    let bytes = hex::decode(raw)
        .map_err(|e| anyhow!("invalid bytecode hex for {contract}: {e}"))?;
    if bytes.is_empty() {
        bail!("the vendored {contract} artifact has empty bytecode");
    }
    Ok(Bytes::from(bytes))
}

/// The artifact's `methodIdentifiers`: `"sig(args)" -> 4-byte selector`
/// (8 hex chars, no `0x`).
pub fn method_identifiers(contract: &str) -> Result<BTreeMap<String, String>> {
    let json = artifact(contract)?;
    let methods = json["methodIdentifiers"]
        .as_object()
        .ok_or_else(|| anyhow!("no methodIdentifiers in the {contract} artifact"))?;
    methods
        .iter()
        .map(|(sig, value)| {
            let selector = value
                .as_str()
                .ok_or_else(|| anyhow!("non-string selector for {sig} in {contract}"))?;
            Ok((sig.clone(), selector.to_owned()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use alloy::sol_types::SolCall;

    use super::*;

    /// Every vendored artifact decodes to real creation code.
    #[test]
    fn every_vendored_artifact_carries_bytecode() {
        for (contract, _) in ARTIFACTS {
            let code =
                creation_code(contract).unwrap_or_else(|e| panic!("{contract}: {e}"));
            assert!(code.len() > 1_000, "{contract} bytecode looks truncated");
        }
    }

    /// The bindings and the bytecode must come from one release. A binding
    /// whose selector the artifact does not carry would encode a call the
    /// deployed contract has no function for — and `initialize` reaching
    /// the fallback of a fresh proxy is a contract left uninitialized, open
    /// for anyone to claim.
    #[test]
    fn every_bound_selector_exists_in_the_artifact() {
        let check = |contract: &str, sig: &str, selector: [u8; 4]| {
            let methods = method_identifiers(contract).expect("methodIdentifiers");
            let found = methods
                .get(sig)
                .unwrap_or_else(|| panic!("{contract} has no {sig}"));
            assert_eq!(*found, hex::encode(selector), "{contract}.{sig} selector");
        };

        for contract in ["XPlatformVerifier", "GitHubPlatformVerifier"] {
            check(
                contract,
                TlsPlatformVerifier::initializeCall::SIGNATURE,
                TlsPlatformVerifier::initializeCall::SELECTOR,
            );
            check(
                contract,
                TlsPlatformVerifier::platformIdCall::SIGNATURE,
                TlsPlatformVerifier::platformIdCall::SELECTOR,
            );
            check(
                contract,
                TlsPlatformVerifier::honkVerifierCodehashCall::SIGNATURE,
                TlsPlatformVerifier::honkVerifierCodehashCall::SELECTOR,
            );
            check(
                contract,
                TlsPlatformVerifier::protocolParametersCall::SIGNATURE,
                TlsPlatformVerifier::protocolParametersCall::SELECTOR,
            );
        }

        check(
            "GooglePlatformVerifier",
            GooglePlatformVerifier::initializeCall::SIGNATURE,
            GooglePlatformVerifier::initializeCall::SELECTOR,
        );
        check(
            "GooglePlatformVerifier",
            GooglePlatformVerifier::jwtRootsCall::SIGNATURE,
            GooglePlatformVerifier::jwtRootsCall::SELECTOR,
        );
    }

    /// Google's initializer takes the root list and no attestation window;
    /// the TLSNotary one takes the window and no root list. Mixing them up
    /// would encode arguments the contract reads as other arguments.
    #[test]
    fn the_two_initializers_are_distinct() {
        assert_ne!(
            TlsPlatformVerifier::initializeCall::SELECTOR,
            GooglePlatformVerifier::initializeCall::SELECTOR
        );
        let methods = method_identifiers("GooglePlatformVerifier").unwrap();
        assert!(!methods.contains_key(TlsPlatformVerifier::initializeCall::SIGNATURE));
    }
}
