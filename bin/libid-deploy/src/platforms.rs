//! The launch platform table: what each platform's Platform Verifier is
//! initialized with and registered under.
//!
//! Nothing here is retyped. The platform keys come from `libid-identity`'s
//! generated table — the same one Solidity and TypeScript read — the
//! profile shape from `libid-profiles`, generated from `CeremonyProfile.sol`'s
//! source, and which contract serves a platform and which circuit it proves
//! under from `libid-contracts`. A key restated here would name a platform
//! no deployed verifier serves.

use alloy::primitives::{
    keccak256,
    Address,
    FixedBytes,
};
use libid_contracts::{
    circuits::Circuit,
    platform_verifier::{
        GoogleRoots,
        Initializer,
        PlatformVerifier,
        TlsNotaryRoots,
    },
};
use libid_identity::platforms;
use libid_profiles as profiles;

use crate::names;

/// The verifier version the launch profile is registered under.
///
/// This is the Proof Verifier's routing slot for a platform — this chain's
/// slot number, NOT the ceremony version baked into the verifier's code.
/// The launch profiles are `x/v1`, `github/v1` and `google/v1`, so the
/// launch deployment takes slot one; a later profile is registered into a
/// new slot by governance, which is a `setVerifier` call and not a deploy.
pub const LAUNCH_VERIFIER_VERSION: u16 = 1;

/// One launch platform.
#[derive(Debug, Clone)]
pub struct Platform {
    /// Human label for logs and plan lines.
    pub label: &'static str,
    /// The platform key, a bare name: libID namespaces only its own
    /// strings, and keccak256 of the key is the on-chain platform id.
    pub key: &'static str,
    /// The `[contracts]` key holding its Platform Verifier proxy address.
    pub contracts_key: &'static str,
    /// The canonical CREATE3 name of that proxy.
    pub canonical_name: &'static str,
    /// Which launch Platform Verifier serves it: the contract the proxy
    /// points at, the ceremony circuit its proofs are checked under and
    /// whether it holds a Notary Service all follow from this.
    pub verifier: PlatformVerifier,
}

impl Platform {
    /// The compiled contract the Platform Verifier proxy points at.
    pub const fn contract(&self) -> &'static str {
        self.verifier.contract()
    }

    /// The ceremony circuit whose Honk verifier this platform's proofs are
    /// checked under. X and GitHub share one: their statements are
    /// byte-identical, so one circuit proves both.
    pub const fn circuit(&self) -> Circuit {
        self.verifier.circuit()
    }

    /// What the Platform Verifier initializes with, shaped by what the
    /// profile notarizes: a TLSNotary profile pins the Notary Service, and
    /// Google reads the JWT root list instead. `Initializer::check` refuses
    /// what the contract would refuse — a zero owner, Honk verifier, Notary
    /// Service or root list — before anything is sent.
    pub fn initializer(
        &self,
        owner: Address,
        notary_service: Address,
        honk_verifier: Address,
        jwt_roots: Address,
    ) -> Initializer {
        let tls_notary = TlsNotaryRoots {
            owner,
            notary_service,
            honk_verifier,
        };
        match self.verifier {
            PlatformVerifier::X => Initializer::X(tls_notary),
            PlatformVerifier::GitHub => Initializer::GitHub(tls_notary),
            PlatformVerifier::Google => Initializer::Google(GoogleRoots {
                owner,
                honk_verifier,
                jwt_roots,
            }),
        }
    }
}

/// X.
pub const X: Platform = Platform {
    label: "X",
    key: platforms::PLATFORM_X_KEY,
    contracts_key: "x_platform_verifier",
    canonical_name: names::X_PLATFORM_VERIFIER,
    verifier: PlatformVerifier::X,
};

/// GitHub.
pub const GITHUB: Platform = Platform {
    label: "GitHub",
    key: platforms::PLATFORM_GITHUB_KEY,
    contracts_key: "github_platform_verifier",
    canonical_name: names::GITHUB_PLATFORM_VERIFIER,
    verifier: PlatformVerifier::GitHub,
};

/// Google.
pub const GOOGLE: Platform = Platform {
    label: "Google",
    key: platforms::PLATFORM_GOOGLE_KEY,
    contracts_key: "google_platform_verifier",
    canonical_name: names::GOOGLE_PLATFORM_VERIFIER,
    verifier: PlatformVerifier::Google,
};

/// The closed launch list, in deploy order. A platform outside it has no
/// profile, and the ceremony contracts revert on one.
pub const LAUNCH: &[Platform] = &[X, GITHUB, GOOGLE];

/// The launch platform with this key, or nothing.
pub fn by_key(key: &str) -> Option<&'static Platform> {
    LAUNCH.iter().find(|p| p.key == key)
}

/// The on-chain platform id for a platform key.
pub fn platform_id(key: &str) -> FixedBytes<32> {
    keccak256(key.as_bytes())
}

// The verifier shape is a property of the profile, not a choice made here:
// `PlatformVerifierBase._setTrustRoots` rejects a Notary Service on a
// profile that notarizes nothing, and rejects its absence on one that does.
// The contract table (`PlatformVerifier::notarizes`) must agree with the
// profile table. Checked where a mistake cannot run.
const _: () = {
    assert!(profiles::LAUNCH.len() == LAUNCH.len());
    assert!(PlatformVerifier::ALL.len() == LAUNCH.len());
    assert!(X.verifier.notarizes());
    assert!(profiles::X.attestation_count() == 2);
    assert!(GITHUB.verifier.notarizes());
    assert!(profiles::GITHUB.attestation_count() == 2);
    assert!(!GOOGLE.verifier.notarizes());
    assert!(profiles::GOOGLE.attestation_count() == 0);
    // Each platform pairs with the contract written for it, which answers
    // `platformId()` for that platform alone.
    assert!(matches!(X.verifier, PlatformVerifier::X));
    assert!(matches!(GITHUB.verifier, PlatformVerifier::GitHub));
    assert!(matches!(GOOGLE.verifier, PlatformVerifier::Google));
    // The launch slot is the launch profile's own version. They are
    // different numbers for different jobs and happen to agree at launch;
    // a profile bump that left this behind would register a `v2` verifier
    // in the `v1` slot.
    assert!(profiles::X.ceremony_version == LAUNCH_VERIFIER_VERSION);
    assert!(profiles::GITHUB.ceremony_version == LAUNCH_VERIFIER_VERSION);
    assert!(profiles::GOOGLE.ceremony_version == LAUNCH_VERIFIER_VERSION);
    assert!(platforms::PLATFORMS.len() == LAUNCH.len());
};

#[cfg(test)]
mod tests {
    use libid_contracts::Artifacts;

    use super::*;

    /// The platform ids come from the generated keys — a mistyped key would
    /// hash every handle to nodes no deployed reader looks up — and the
    /// contract table spells each platform the same way.
    #[test]
    fn platform_ids_come_from_the_generated_keys() {
        assert_eq!(platform_id(X.key), keccak256(b"x"));
        assert_eq!(platform_id(GITHUB.key), keccak256(b"github"));
        assert_eq!(platform_id(GOOGLE.key), keccak256(b"google"));
        assert_ne!(platform_id(X.key), platform_id(GITHUB.key));
        for platform in LAUNCH {
            assert_eq!(platform.key, platform.verifier.platform());
            assert_eq!(platform_id(platform.key), platform.verifier.platform_id());
        }
    }

    /// Every platform the profile and identity tables know is a launch
    /// platform here.
    #[test]
    fn the_launch_list_matches_the_generated_tables() {
        for profile in profiles::LAUNCH {
            assert!(
                by_key(profile.platform).is_some(),
                "{} has a profile but no launch entry",
                profile.platform
            );
        }
        for platform in &platforms::PLATFORMS {
            assert!(
                by_key(platform.key).is_some(),
                "{} is in the identity table but not launched",
                platform.key
            );
        }
        assert!(by_key("discord").is_none());
    }

    /// One circuit for both TLSNotary platforms, a separate one for
    /// Google: the statement, not the platform, decides.
    #[test]
    fn the_circuits_follow_the_statements() {
        assert_eq!(X.circuit(), GITHUB.circuit());
        assert_ne!(X.circuit(), GOOGLE.circuit());
        for platform in LAUNCH {
            assert!(Circuit::ALL.contains(&platform.circuit()));
        }
    }

    /// Every platform's Platform Verifier is a canonical contract with its
    /// own name and its own `[contracts]` key, and its implementation is
    /// one the contracts crate embeds.
    #[test]
    fn every_platform_verifier_is_canonical_and_embedded() {
        let artifacts = Artifacts::embedded();
        for platform in LAUNCH {
            assert_eq!(
                names::canonical_name(platform.contracts_key),
                Some(platform.canonical_name),
                "{} is not in the canonical table",
                platform.label
            );
            assert!(artifacts.bytecode(platform.contract()).is_ok());
        }
    }

    /// The initializer each platform builds passes the contract's own
    /// rules and initializes that platform's contract.
    #[test]
    fn every_initializer_passes_the_contracts_checks() {
        let some = Address::repeat_byte(0x11);
        for platform in LAUNCH {
            let init = platform.initializer(some, some, some, some);
            init.check()
                .unwrap_or_else(|e| panic!("{}: {e}", platform.label));
            assert_eq!(init.verifier(), platform.verifier);
        }
    }
}
