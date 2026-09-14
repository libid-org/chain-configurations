//! The launch platform table: what `IdentityNames.setPlatform` writes for
//! each keyspace, and what each platform's Platform Verifier is
//! initialized with.
//!
//! Nothing here is retyped. The platform domains and normalization rules
//! come from `libid-identity`'s generated table — the same one Solidity and
//! TypeScript read — the profile shape from `libid-profiles`, generated
//! from `CeremonyProfile.sol`'s source, and which contract serves a
//! platform and which circuit it proves under from `libid-contracts`. A
//! value restated here would key handles differently from every deployed
//! reader.

use alloy::primitives::{
    keccak256,
    Address,
    FixedBytes,
};
use anyhow::{
    bail,
    Result,
};
use libid_contracts::{
    bindings::identity::IdentityNames,
    circuits::Circuit,
    platform_verifier::{
        GoogleRoots,
        Initializer,
        PlatformVerifier,
        TlsNotaryRoots,
    },
};
use libid_identity::{
    handle_vectors as vectors,
    Rules,
};
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

/// How a platform's Platform Verifier is initialized — the shape differs
/// with what the profile notarizes.
#[derive(Debug, Clone, Copy)]
pub enum VerifierKind {
    /// A TLSNotary profile: two notarized sessions, so the verifier holds
    /// the Notary Service, a proof lifetime and an attestation skew.
    TlsNotary {
        /// Maximum age of this platform's token attestation, in seconds.
        proof_lifetime: u64,
        /// Maximum lead over block time an attestation may carry.
        max_future_attestation_skew: u64,
    },
    /// Google's: a signed JWT checked against Google's published keys. It
    /// notarizes nothing, so the verifier must hold NO Notary Service —
    /// `PlatformVerifierBase` rejects one for a profile whose attestation
    /// count is zero — and no attestation window; the signed `exp` is the
    /// whole validity ceiling. It reads the JWT root list instead.
    GoogleJwt,
}

/// One launch platform.
#[derive(Debug, Clone)]
pub struct Platform {
    /// Human label for logs and plan lines.
    pub label: &'static str,
    /// The platform's own bare name: libID namespaces only its own
    /// strings, and keccak256 of this is the on-chain platform id.
    pub domain: &'static str,
    /// The normalization rules `setPlatform` stores.
    pub rules: IdentityNames::Rules,
    /// How far ahead of block time this profile's evidence time may run.
    pub future_observation_allowance: u64,
    /// How its Platform Verifier initializes.
    pub kind: VerifierKind,
    /// The `[contracts]` key holding its Platform Verifier proxy address.
    pub contracts_key: &'static str,
    /// The canonical CREATE3 name of that proxy.
    pub canonical_name: &'static str,
    /// Which launch Platform Verifier serves it: the contract the proxy
    /// points at and the ceremony circuit its proofs are checked under
    /// both follow from this.
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
    /// profile notarizes. `Initializer::check` refuses what the contract
    /// would refuse — a Notary Service on Google, none on a TLSNotary
    /// profile, a parameter over its ceiling — before anything is sent.
    pub fn initializer(
        &self,
        owner: Address,
        notary_service: Address,
        honk_verifier: Address,
        jwt_roots: Address,
    ) -> Result<Initializer> {
        Ok(match (self.verifier, self.kind) {
            (
                verifier @ (PlatformVerifier::X | PlatformVerifier::GitHub),
                VerifierKind::TlsNotary {
                    proof_lifetime,
                    max_future_attestation_skew,
                },
            ) => {
                let roots = TlsNotaryRoots {
                    owner,
                    notary_service,
                    honk_verifier,
                    proof_lifetime,
                    max_future_attestation_skew,
                    future_observation_allowance: self.future_observation_allowance,
                };
                if verifier == PlatformVerifier::X {
                    Initializer::X(roots)
                } else {
                    Initializer::GitHub(roots)
                }
            }
            (PlatformVerifier::Google, VerifierKind::GoogleJwt) => {
                Initializer::Google(GoogleRoots {
                    owner,
                    honk_verifier,
                    future_observation_allowance: self.future_observation_allowance,
                    jwt_roots,
                })
            }
            // Pinned apart at compile time below; kept as an error rather
            // than a panic because the wrong initializer on a contract
            // encodes arguments it reads as other arguments.
            (verifier, kind) => bail!(
                "{} pairs the {verifier:?} contract with the {kind:?} shape",
                self.label
            ),
        })
    }
}

/// Widen a generated rule table into the contract's struct. `const` so a
/// value that does not fit the on-chain width fails the build below rather
/// than silently truncating into a keyspace nobody can resolve.
const fn on_chain_rules(rules: Rules) -> IdentityNames::Rules {
    IdentityNames::Rules {
        maxLength: rules.max_length as u16,
        stripLeadingAt: rules.strip_leading_at,
        isEmail: rules.is_email,
        allowUnderscore: rules.allow_underscore,
        allowHyphen: rules.allow_hyphen,
    }
}

/// X: letters, digits and underscore.
pub const X: Platform = Platform {
    label: "X",
    domain: vectors::PLATFORM_X_DOMAIN,
    rules: on_chain_rules(Rules::X),
    future_observation_allowance: vectors::FUTURE_ALLOWANCE_X,
    kind: VerifierKind::TlsNotary {
        proof_lifetime: profiles::PROOF_LIFETIME_SECONDS_X,
        max_future_attestation_skew: profiles::MAX_FUTURE_ATTESTATION_SKEW_SECONDS,
    },
    contracts_key: "x_platform_verifier",
    canonical_name: names::X_PLATFORM_VERIFIER,
    verifier: PlatformVerifier::X,
};

/// GitHub: letters, digits and hyphen.
pub const GITHUB: Platform = Platform {
    label: "GitHub",
    domain: vectors::PLATFORM_GITHUB_DOMAIN,
    rules: on_chain_rules(Rules::GITHUB),
    future_observation_allowance: vectors::FUTURE_ALLOWANCE_GITHUB,
    kind: VerifierKind::TlsNotary {
        proof_lifetime: profiles::PROOF_LIFETIME_SECONDS_GITHUB,
        max_future_attestation_skew: profiles::MAX_FUTURE_ATTESTATION_SKEW_SECONDS,
    },
    contracts_key: "github_platform_verifier",
    canonical_name: names::GITHUB_PLATFORM_VERIFIER,
    verifier: PlatformVerifier::GitHub,
};

/// Google: an email address, used exactly as proved. The OIDC circuit
/// exposes no `iat`, so the evidence time is the token's `exp` — about an
/// hour ahead of the moment it describes, hence the larger allowance.
pub const GOOGLE: Platform = Platform {
    label: "Google",
    domain: vectors::PLATFORM_GOOGLE_DOMAIN,
    rules: on_chain_rules(Rules::GOOGLE),
    future_observation_allowance: vectors::FUTURE_ALLOWANCE_GOOGLE,
    kind: VerifierKind::GoogleJwt,
    contracts_key: "google_platform_verifier",
    canonical_name: names::GOOGLE_PLATFORM_VERIFIER,
    verifier: PlatformVerifier::Google,
};

/// The closed launch list, in deploy order. A platform outside it has no
/// profile, and the ceremony contracts revert on one.
pub const LAUNCH: &[Platform] = &[X, GITHUB, GOOGLE];

/// The launch platform with this domain, or nothing.
pub fn by_domain(domain: &str) -> Option<&'static Platform> {
    LAUNCH.iter().find(|p| p.domain == domain)
}

/// The on-chain platform id for a platform domain.
pub fn platform_id(domain: &str) -> FixedBytes<32> {
    keccak256(domain.as_bytes())
}

// The verifier shape is a property of the profile, not a choice made here:
// `PlatformVerifierBase._setTrustRoots` rejects a Notary Service on a
// profile that notarizes nothing, and rejects its absence on one that does.
// The contract table agrees (`PlatformVerifier::notarizes`), and the kind
// here must agree with both. Checked where a mistake cannot run.
const _: () = {
    assert!(profiles::LAUNCH.len() == LAUNCH.len());
    assert!(PlatformVerifier::ALL.len() == LAUNCH.len());
    assert!(matches!(X.kind, VerifierKind::TlsNotary { .. }));
    assert!(X.verifier.notarizes());
    assert!(profiles::X.attestation_count() == 2);
    assert!(matches!(GITHUB.kind, VerifierKind::TlsNotary { .. }));
    assert!(GITHUB.verifier.notarizes());
    assert!(profiles::GITHUB.attestation_count() == 2);
    assert!(matches!(GOOGLE.kind, VerifierKind::GoogleJwt));
    assert!(!GOOGLE.verifier.notarizes());
    assert!(profiles::GOOGLE.attestation_count() == 0);
    // Each platform pairs with the contract written for it: the TLSNotary
    // initializer on the Google contract would encode arguments the
    // contract reads as other arguments.
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
    assert!(Rules::X.max_length <= u16::MAX as usize);
    assert!(Rules::GITHUB.max_length <= u16::MAX as usize);
    assert!(Rules::GOOGLE.max_length <= u16::MAX as usize);
};

#[cfg(test)]
mod tests {
    use libid_contracts::Artifacts;

    use super::*;

    /// The platform ids come from the generated domains — a mistyped
    /// domain would key every handle differently from every deployed
    /// reader — and the contract table spells each platform the same way.
    #[test]
    fn platform_ids_come_from_the_generated_domains() {
        assert_eq!(platform_id(X.domain), keccak256(b"x"));
        assert_eq!(platform_id(GITHUB.domain), keccak256(b"github"));
        assert_eq!(platform_id(GOOGLE.domain), keccak256(b"google"));
        assert_ne!(platform_id(X.domain), platform_id(GITHUB.domain));
        for platform in LAUNCH {
            assert_eq!(platform.domain, platform.verifier.platform());
            assert_eq!(
                platform_id(platform.domain),
                platform.verifier.platform_id()
            );
        }
    }

    /// The rules written on chain are the generated ones, field for field.
    #[test]
    fn on_chain_rules_mirror_the_generated_table() {
        for (platform, rules) in [
            (X, Rules::X),
            (GITHUB, Rules::GITHUB),
            (GOOGLE, Rules::GOOGLE),
        ] {
            assert_eq!(platform.rules.maxLength as usize, rules.max_length);
            assert_eq!(platform.rules.stripLeadingAt, rules.strip_leading_at);
            assert_eq!(platform.rules.isEmail, rules.is_email);
            assert_eq!(platform.rules.allowUnderscore, rules.allow_underscore);
            assert_eq!(platform.rules.allowHyphen, rules.allow_hyphen);
        }
    }

    /// Every launch platform the profile table knows has a keyspace here.
    #[test]
    fn the_launch_list_matches_the_profile_table() {
        for profile in profiles::LAUNCH {
            assert!(
                by_domain(profile.platform).is_some(),
                "{} has a profile but no keyspace",
                profile.platform
            );
        }
        assert!(by_domain("discord").is_none());
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
    /// rules with the generated parameters, and takes the shape its
    /// profile demands.
    #[test]
    fn every_initializer_passes_the_contracts_checks() {
        let some = Address::repeat_byte(0x11);
        for platform in LAUNCH {
            let init = platform
                .initializer(some, some, some, some)
                .unwrap_or_else(|e| panic!("{}: {e}", platform.label));
            init.check()
                .unwrap_or_else(|e| panic!("{}: {e}", platform.label));
            assert_eq!(init.verifier(), platform.verifier);
            match (platform.kind, init) {
                (
                    VerifierKind::TlsNotary { .. },
                    Initializer::X(_) | Initializer::GitHub(_),
                ) => {}
                (VerifierKind::GoogleJwt, Initializer::Google(_)) => {}
                (kind, init) => panic!("{}: {kind:?} built {init:?}", platform.label),
            }
        }
    }
}
