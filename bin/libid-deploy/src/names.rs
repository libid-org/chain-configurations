//! The authoritative canonical-name table.
//!
//! Every top-level (entry) contract is deployed through the deterministic
//! `LibidFactory` via CREATE3 with `salt = keccak256(name)`, so its address
//! is a pure function of the name: the same on every EVM network,
//! computable before anything is deployed.
//!
//! CRITICAL: renaming an entry here = a NEW address, forever, on every
//! network. Names are append-only; a name already deployed on any real
//! network must never change.
//!
//! Two kinds of contract are deliberately NOT in this table. Proxy
//! implementations deploy via plain CREATE: their addresses are referenced
//! by a proxy slot, and an upgrade replaces one without moving any entry
//! address. The ceremony circuits' Honk verifiers do go through the
//! factory — see [`crate::ceremony::Circuit::factory_name`] — but under a
//! name carrying the circuits version rather than a frozen one, because a
//! Honk verifier IS its verification key: a new circuits release must be a
//! new address, not a silent replacement. Neither kind is declared in a
//! network file.

use libid_contracts::factory::predict_address;

/// One canonical (factory-deployed) contract.
#[derive(Debug, Clone, Copy)]
pub struct CanonicalContract {
    /// Key inside the network file's `[contracts]` table.
    pub key: &'static str,
    /// The factory name — the ONLY input to the address.
    pub name: &'static str,
}

/// The Notary Service proxy — deploys first; every notarized session is
/// authenticated through it.
pub const NOTARY_SERVICE: &str = "libid.NotaryService";
/// The Proof Verifier proxy: the Supported Version Set the naming system
/// dispatches claims through.
pub const CEREMONY_PROOF_VERIFIER: &str = "libid.CeremonyProofVerifier";
/// The IdentityNames proxy — the contract consumers resolve against.
pub const IDENTITY_NAMES: &str = "libid.IdentityNames";
/// The Google JWT root list proxy, read by the Google Platform Verifier.
pub const GOOGLE_JWT_ROOTS: &str = "libid.GoogleJwtRoots";
/// The `x/v1` Platform Verifier proxy.
pub const X_PLATFORM_VERIFIER: &str = "libid.XPlatformVerifier";
/// The `github/v1` Platform Verifier proxy.
pub const GITHUB_PLATFORM_VERIFIER: &str = "libid.GitHubPlatformVerifier";
/// The `google/v1` Platform Verifier proxy.
pub const GOOGLE_PLATFORM_VERIFIER: &str = "libid.GooglePlatformVerifier";

/// Every canonical contract, in deploy order.
pub const CANONICAL_CONTRACTS: &[CanonicalContract] = &[
    CanonicalContract {
        key: "notary_service",
        name: NOTARY_SERVICE,
    },
    CanonicalContract {
        key: "ceremony_proof_verifier",
        name: CEREMONY_PROOF_VERIFIER,
    },
    CanonicalContract {
        key: "identity_names",
        name: IDENTITY_NAMES,
    },
    CanonicalContract {
        key: "google_jwt_roots",
        name: GOOGLE_JWT_ROOTS,
    },
    CanonicalContract {
        key: "x_platform_verifier",
        name: X_PLATFORM_VERIFIER,
    },
    CanonicalContract {
        key: "github_platform_verifier",
        name: GITHUB_PLATFORM_VERIFIER,
    },
    CanonicalContract {
        key: "google_platform_verifier",
        name: GOOGLE_PLATFORM_VERIFIER,
    },
];

/// The canonical name for a `[contracts]` key, if the component is
/// factory-deployed.
pub fn canonical_name(key: &str) -> Option<&'static str> {
    CANONICAL_CONTRACTS
        .iter()
        .find(|c| c.key == key)
        .map(|c| c.name)
}

/// Render the full network-invariant address table: the CREATE2 deployer,
/// the factory, and every canonical contract. Pure computation — no RPC.
pub fn render_address_table() -> anyhow::Result<String> {
    use std::fmt::Write;

    use libid_contracts::factory::{
        predict_factory_address,
        CREATE2_DEPLOYER,
    };

    let artifacts = libid_contracts::Artifacts::embedded();
    let factory = predict_factory_address(&artifacts)?;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Canonical addresses (network-invariant — the same on every EVM chain):"
    );
    let _ = writeln!(
        out,
        "  {:<34} {:<34} {CREATE2_DEPLOYER:#x}",
        "create2_deployer", "(keyless, Arachnid)"
    );
    let _ = writeln!(
        out,
        "  {:<34} {:<34} {factory:#x}",
        "contracts.factory", "(CREATE2, frozen init code)"
    );
    for c in CANONICAL_CONTRACTS {
        let addr = predict_address(factory, c.name);
        let _ = writeln!(
            out,
            "  {:<34} {:<34} {addr:#x}",
            format!("contracts.{}", c.key),
            c.name
        );
    }
    // Not declared in any network file, but deployed through the same
    // factory and just as network-invariant: an operator reading this table
    // is reading every address apply will land on.
    for circuit in crate::ceremony::CIRCUITS {
        let name = circuit.factory_name()?;
        let addr = predict_address(factory, &name);
        let _ = writeln!(
            out,
            "  {:<34} {:<34} {addr:#x}",
            format!("circuits.{}", circuit.name),
            name
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Names are the sole input to an address, so a duplicate key or a
    /// duplicate name would silently point two components at one contract.
    #[test]
    fn the_table_has_no_duplicate_keys_or_names() {
        for (i, a) in CANONICAL_CONTRACTS.iter().enumerate() {
            for b in &CANONICAL_CONTRACTS[i + 1..] {
                assert_ne!(a.key, b.key, "duplicate key {}", a.key);
                assert_ne!(a.name, b.name, "duplicate name {}", a.name);
            }
        }
    }

    /// Every canonical name carries the `libid.` prefix every deployed
    /// reader keys on.
    #[test]
    fn every_canonical_name_is_namespaced() {
        for c in CANONICAL_CONTRACTS {
            assert!(c.name.starts_with("libid."), "{} is not namespaced", c.name);
        }
    }
}
