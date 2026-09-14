//! The ceremony contracts this repository compiles itself: the Platform
//! Verifiers that decode one platform's ceremony payload and authenticate
//! its attestations, and the bb-generated UltraHonk verifiers their proofs
//! are checked under.
//!
//! # Why the artifacts live here
//!
//! `libid-contracts` embeds compiled bytecode only for the contracts its
//! `COVERED` list names, and the Platform Verifiers are not among them —
//! its own `script/Deploy.s.sol` registers none either. Nor does anything
//! upstream ship a Honk verifier: one derives from a circuit's
//! verification key, which `libid-circuits` publishes as a release asset.
//! `scripts/vendor-artifacts.sh` builds all of them — the Platform
//! Verifiers from the `libid-contracts` tag `Cargo.toml` pins, the Honk
//! verifiers from the `libid-circuits` release `circuits-manifest.json`
//! pins — and writes `artifacts/`. Both tags are derived from their pin
//! rather than restated, so vendored bytecode and typed bindings cannot
//! come from different releases.
//!
//! # The circuit verifier
//!
//! `PlatformVerifierBase._setTrustRoots` pins the verifier a platform's
//! proofs are checked under BY ADDRESS AND BY CODE HASH: it reads
//! `address(honkVerifier_).codehash` and refuses a value that does not
//! match the hash the caller named, and refuses the empty and zero hashes
//! outright. A bb verifier embeds its verification key as code constants
//! and exposes no getter, so the code hash is the only handle on which
//! circuit a deployed verifier answers for.
//!
//! Apply therefore deploys the verifier itself and reads the hash back off
//! the chain. The verifier goes through the factory under
//! [`Circuit::factory_name`] — a CREATE3 name carrying the circuit and the
//! pinned circuits version — so its address is a pure function of which
//! artifact it is: a converged chain is recognised without a redeploy, and
//! a circuits release is a new name, a new address and a `setTrustRoots`.

use std::{
    collections::BTreeMap,
    sync::OnceLock,
};

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

/// Bindings for a bb-generated UltraHonk verifier: the one call a Platform
/// Verifier makes of it, and the error a wrong-length proof raises.
///
/// That error carries the circuit's `logN`, which is the only thing a
/// deployed verifier says about itself — it has no getter for its
/// verification key — so it is how a test tells a real verifier from a
/// contract that merely has code.
#[allow(unused_attributes)]
mod honk_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface HonkVerifier {
            error ProofLengthWrongWithLogN(
                uint256 logN,
                uint256 actualLength,
                uint256 expectedLength
            );

            function verify(bytes calldata proof, bytes32[] calldata publicInputs)
                external
                view
                returns (bool);
        }
    }
}

pub use honk_inner::HonkVerifier;

/// The `libid-circuits` release manifest, committed verbatim as the pin.
/// It carries the version, the toolchain the assets were built by and a
/// sha256 per file, so the version the factory names are derived from is
/// the same document the vendor script verifies its downloads against.
const CIRCUITS_MANIFEST: &str = include_str!("../circuits-manifest.json");

/// One ceremony circuit's bb-generated UltraHonk verifier.
///
/// There are two, not three: `oidc-google` proves the Google JWT, and
/// `bearer-link` ties a token exchange to an identity for X and GitHub
/// alike, because their statements are byte-identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Circuit {
    /// The circuit's directory in the `libid-circuits` release — also the
    /// tarball's name and the middle of the factory name below.
    pub name: &'static str,
    /// The vendored contract, and the `.sol` file holding it. bb always
    /// emits `HonkVerifier`; the vendor script renames it so two verifiers
    /// can live in one project and one artifact path names one circuit.
    pub contract: &'static str,
}

impl Circuit {
    /// The CREATE3 name this circuit's verifier deploys under.
    ///
    /// Deliberately NOT in [`crate::names`]: the canonical table is the
    /// set of entry contracts a network file declares, and these are
    /// referenced by the Platform Verifier that pins them instead. The
    /// version is part of the name because a Honk verifier IS its
    /// verification key — a new circuits release is a different contract,
    /// so it must be a different address rather than a silent replacement.
    pub fn factory_name(&self) -> Result<String> {
        Ok(format!(
            "libid.circuits.{}.{}",
            self.name,
            circuits_version()?
        ))
    }
}

/// The token-exchange circuit, shared by X and GitHub.
pub const BEARER_LINK: Circuit = Circuit {
    name: "bearer-link",
    contract: "BearerLinkHonkVerifier",
};

/// Google's OIDC circuit.
pub const OIDC_GOOGLE: Circuit = Circuit {
    name: "oidc-google",
    contract: "OidcGoogleHonkVerifier",
};

/// Every circuit the launch platforms verify under.
pub const CIRCUITS: &[Circuit] = &[BEARER_LINK, OIDC_GOOGLE];

fn manifest() -> Result<&'static serde_json::Value> {
    static PARSED: OnceLock<Option<serde_json::Value>> = OnceLock::new();
    PARSED
        .get_or_init(|| serde_json::from_str(CIRCUITS_MANIFEST).ok())
        .as_ref()
        .ok_or_else(|| anyhow!("circuits-manifest.json is not valid JSON"))
}

/// The pinned `libid-circuits` release the vendored Honk verifiers were
/// generated from.
pub fn circuits_version() -> Result<&'static str> {
    manifest()?["version"]
        .as_str()
        .ok_or_else(|| anyhow!("circuits-manifest.json has no version"))
}

/// The vendored artifacts, embedded at compile time as
/// `(<file>, <contract>, json)`. Named individually rather than pulled
/// from a directory: a missing one must be a compile error, not a runtime
/// surprise on a chain that has already been half converged.
const ARTIFACTS: &[(&str, &str, &str)] = &[
    (
        "XPlatformVerifier",
        "XPlatformVerifier",
        include_str!("../artifacts/XPlatformVerifier.sol/XPlatformVerifier.json"),
    ),
    (
        "GitHubPlatformVerifier",
        "GitHubPlatformVerifier",
        include_str!(
            "../artifacts/GitHubPlatformVerifier.sol/GitHubPlatformVerifier.json"
        ),
    ),
    (
        "GooglePlatformVerifier",
        "GooglePlatformVerifier",
        include_str!(
            "../artifacts/GooglePlatformVerifier.sol/GooglePlatformVerifier.json"
        ),
    ),
    (
        "BearerLinkHonkVerifier",
        "BearerLinkHonkVerifier",
        include_str!(
            "../artifacts/BearerLinkHonkVerifier.sol/BearerLinkHonkVerifier.json"
        ),
    ),
    (
        "BearerLinkHonkVerifier",
        "RelationsLib",
        include_str!("../artifacts/BearerLinkHonkVerifier.sol/RelationsLib.json"),
    ),
    (
        "BearerLinkHonkVerifier",
        "ZKTranscriptLib",
        include_str!("../artifacts/BearerLinkHonkVerifier.sol/ZKTranscriptLib.json"),
    ),
    (
        "OidcGoogleHonkVerifier",
        "OidcGoogleHonkVerifier",
        include_str!(
            "../artifacts/OidcGoogleHonkVerifier.sol/OidcGoogleHonkVerifier.json"
        ),
    ),
    (
        "OidcGoogleHonkVerifier",
        "RelationsLib",
        include_str!("../artifacts/OidcGoogleHonkVerifier.sol/RelationsLib.json"),
    ),
    (
        "OidcGoogleHonkVerifier",
        "ZKTranscriptLib",
        include_str!("../artifacts/OidcGoogleHonkVerifier.sol/ZKTranscriptLib.json"),
    ),
];

fn artifact(file: &str, contract: &str) -> Result<serde_json::Value> {
    let raw = ARTIFACTS
        .iter()
        .find(|(f, c, _)| *f == file && *c == contract)
        .map(|(_, _, raw)| *raw)
        .ok_or_else(|| anyhow!("no vendored artifact for {file}.sol:{contract}"))?;
    serde_json::from_str(raw).map_err(|e| {
        anyhow!("the vendored artifact for {file}.sol:{contract} is not valid JSON: {e}")
    })
}

/// The raw `bytecode.object` hex (no `0x`), link placeholders intact.
pub fn creation_code_hex(contract: &str) -> Result<String> {
    bytecode_hex(contract, contract)
}

fn bytecode_hex(file: &str, contract: &str) -> Result<String> {
    let json = artifact(file, contract)?;
    let raw = json["bytecode"]["object"]
        .as_str()
        .ok_or_else(|| anyhow!("no bytecode.object in {file}.sol:{contract}"))?;
    let raw = raw.strip_prefix("0x").unwrap_or(raw);
    if raw.is_empty() {
        bail!("the vendored {file}.sol:{contract} artifact has empty bytecode");
    }
    Ok(raw.to_owned())
}

/// The artifact's `bytecode.linkReferences`: `"<path>.sol" -> { "<Lib>":
/// [{start, length}] }`, empty when the contract links nothing.
pub fn link_references(
    contract: &str,
) -> Result<serde_json::Map<String, serde_json::Value>> {
    let json = artifact(contract, contract)?;
    Ok(json["bytecode"]["linkReferences"]
        .as_object()
        .cloned()
        .unwrap_or_default())
}

fn decode(file: &str, contract: &str) -> Result<Bytes> {
    let raw = bytecode_hex(file, contract)?;
    if raw.contains("__$") {
        // Deploying the placeholder would produce a contract that reverts
        // on every call that reaches the library.
        bail!(
            "{file}.sol:{contract} has unresolved link references; deploy it through \
             the linking path"
        );
    }
    let bytes = hex::decode(&raw)
        .map_err(|e| anyhow!("invalid bytecode hex for {contract}: {e}"))?;
    Ok(Bytes::from(bytes))
}

/// The creation bytecode of a contract whose `.sol` file shares its name
/// and which links no library.
pub fn creation_code(contract: &str) -> Result<Bytes> {
    decode(contract, contract)
}

/// The creation bytecode of a library vendored beside `file` — the shape
/// `bytecode.linkReferences` names them in.
pub fn library_creation_code(file: &str, library: &str) -> Result<Bytes> {
    decode(file, library)
}

/// The artifact's `methodIdentifiers`: `"sig(args)" -> 4-byte selector`
/// (8 hex chars, no `0x`).
pub fn method_identifiers(contract: &str) -> Result<BTreeMap<String, String>> {
    let json = artifact(contract, contract)?;
    let methods = json["methodIdentifiers"]
        .as_object()
        .ok_or_else(|| anyhow!("no methodIdentifiers in {contract}.sol:{contract}"))?;
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
        for (file, contract, _) in ARTIFACTS {
            let code = bytecode_hex(file, contract)
                .unwrap_or_else(|e| panic!("{file}.sol:{contract}: {e}"));
            assert!(
                code.len() > 2_000,
                "{file}.sol:{contract} bytecode looks truncated"
            );
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

    /// The only thing a Platform Verifier asks of its circuit verifier is
    /// `IHonkVerifier.verify`. An artifact without that selector would be
    /// wired in and revert at the first user's proof.
    #[test]
    fn every_circuit_verifier_answers_the_interface_it_is_wired_into() {
        for circuit in CIRCUITS {
            let methods = method_identifiers(circuit.contract)
                .unwrap_or_else(|e| panic!("{}: {e}", circuit.name));
            assert!(
                methods.contains_key("verify(bytes,bytes32[])"),
                "{} exposes no verify(bytes,bytes32[])",
                circuit.name
            );
        }
    }

    /// A bb verifier links two libraries, and every library it names is
    /// vendored beside it — an artifact missing one could only deploy with
    /// its placeholder left in, which reverts on every proof.
    #[test]
    fn every_linked_library_is_vendored_beside_its_verifier() {
        for circuit in CIRCUITS {
            let refs = link_references(circuit.contract)
                .unwrap_or_else(|e| panic!("{}: {e}", circuit.name));
            let mut seen = 0;
            for (path, libs) in &refs {
                let stem = std::path::Path::new(path)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or_else(|| {
                        panic!("{}: bad library path {path}", circuit.name)
                    });
                assert_eq!(stem, circuit.contract);
                for lib in libs.as_object().into_iter().flatten().map(|(name, _)| name) {
                    library_creation_code(stem, lib)
                        .unwrap_or_else(|e| panic!("{}.{lib}: {e}", circuit.name));
                    seen += 1;
                }
            }
            assert!(
                seen > 0,
                "{} links nothing — did the build inline?",
                circuit.name
            );
        }
    }

    /// The two circuits are distinct artifacts under distinct names; a
    /// shared one would wire both platforms to one verification key.
    #[test]
    fn each_circuit_has_its_own_artifact_and_factory_name() {
        assert_ne!(BEARER_LINK.contract, OIDC_GOOGLE.contract);
        assert_ne!(
            creation_code_hex(BEARER_LINK.contract).unwrap(),
            creation_code_hex(OIDC_GOOGLE.contract).unwrap()
        );
        let version = circuits_version().expect("the pin parses");
        for circuit in CIRCUITS {
            let name = circuit.factory_name().unwrap();
            assert!(
                name.starts_with("libid.circuits."),
                "{name} is not namespaced"
            );
            assert!(
                name.ends_with(version),
                "{name} does not carry the pinned version"
            );
        }
        assert_ne!(
            BEARER_LINK.factory_name().unwrap(),
            OIDC_GOOGLE.factory_name().unwrap()
        );
    }
}
