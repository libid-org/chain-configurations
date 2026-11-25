//! The authoritative canonical-name table.
//!
//! Every top-level (entry) contract is deployed through the deterministic
//! `LibidFactory` via CREATE3 with `salt = keccak256(name)`, so its address
//! is a pure function of the factory's deployer and the name: the same on
//! every EVM network that deployer deploys to, computable before anything
//! is deployed.
//!
//! CRITICAL: renaming an entry here = a NEW address, forever, on every
//! network. Names are append-only; a name already deployed on any real
//! network must never change.
//!
//! A name is unique per factory: a new factory gives every name a new
//! address, so a stack under a new factory keeps the plain names.
//!
//! The `.2` names are the stack of libid-contracts 0.19: an Authorization
//! Digest without a chain id and one primary handle per wallet. The Notary
//! Service and the Google JWT root list serve both stacks under their plain
//! names. `libid.HandleEscrow.4` is the escrow of libid-contracts 0.21, whose
//! refunds open `REFUND_GRACE` after the sender's last deposit;
//! `libid.HandleEscrow.3` is the 0.19 escrow, and `libid.HandleEscrow.2`
//! belongs to the factory before this one.
//!
//! Two kinds of contract are NOT in this table and in no network file:
//! proxy implementations, which a proxy slot references and an upgrade
//! replaces without moving any entry address, and the ceremony circuits'
//! Honk verifiers, which a Platform Verifier references. Both deploy at the
//! CREATE2 address of their code ([`crate::code`]): a release with new code
//! is a new address, not a silent replacement.

use libid_contracts::factory::{
    predict_address,
    FactoryGenesis,
};

use crate::{
    apply::Upgrade,
    code::Code,
    platforms,
};

/// One canonical (factory-deployed) contract.
#[derive(Debug, Clone, Copy)]
pub struct CanonicalContract {
    /// Key inside the network file's `[contracts]` table.
    pub key: &'static str,
    /// The factory name — the ONLY input to the address.
    pub name: &'static str,
    /// Whether every network file declares it. An optional contract is on
    /// the networks whose file declares it, and only there.
    pub required: bool,
}

/// The Notary Service proxy — deploys first; every notarized session is
/// authenticated through it.
pub const NOTARY_SERVICE: &str = "libid.NotaryService";
/// The Proof Verifier proxy: the Supported Version Set the identity
/// registry dispatches bindings through.
pub const CEREMONY_PROOF_VERIFIER: &str = "libid.CeremonyProofVerifier.2";
/// The IdentityRegistry proxy — the contract consumers resolve against.
/// It keys identities by the SHA-256 nodes the circuits prove and holds one
/// primary handle per wallet.
pub const IDENTITY_REGISTRY: &str = "libid.IdentityRegistry.2";
/// The HandleEscrow proxy: value sent to a handle node before anyone holds
/// it, claimed through the IdentityRegistry it was initialized with. No
/// setter moves it off that registry. A sender refunds its own deposits,
/// from `REFUND_GRACE` after its last one.
pub const HANDLE_ESCROW: &str = "libid.HandleEscrow.4";
/// The Google JWT root list proxy, read by the Google Platform Verifier.
pub const GOOGLE_JWT_ROOTS: &str = "libid.GoogleJwtRoots";
/// The `x/v1` Platform Verifier proxy.
pub const X_PLATFORM_VERIFIER: &str = "libid.XPlatformVerifier.2";
/// The `github/v1` Platform Verifier proxy.
pub const GITHUB_PLATFORM_VERIFIER: &str = "libid.GitHubPlatformVerifier.2";
/// The `google/v1` Platform Verifier proxy.
pub const GOOGLE_PLATFORM_VERIFIER: &str = "libid.GooglePlatformVerifier.2";
/// The referral splitter: the fee receiver of a bind, which pays a
/// referrer's handle its share through the handle escrow. Not a proxy:
/// its registry and escrow are constructor arguments, so a new version is a
/// new name.
pub const REFERRAL_SPLITTER: &str = "libid.ReferralSplitter";

/// Every canonical contract, in deploy order.
pub const CANONICAL_CONTRACTS: &[CanonicalContract] = &[
    CanonicalContract {
        key: "notary_service",
        name: NOTARY_SERVICE,
        required: true,
    },
    CanonicalContract {
        key: "ceremony_proof_verifier",
        name: CEREMONY_PROOF_VERIFIER,
        required: true,
    },
    CanonicalContract {
        key: "identity_registry",
        name: IDENTITY_REGISTRY,
        required: true,
    },
    CanonicalContract {
        key: "handle_escrow",
        name: HANDLE_ESCROW,
        required: true,
    },
    CanonicalContract {
        key: "google_jwt_roots",
        name: GOOGLE_JWT_ROOTS,
        required: true,
    },
    CanonicalContract {
        key: "x_platform_verifier",
        name: X_PLATFORM_VERIFIER,
        required: true,
    },
    CanonicalContract {
        key: "github_platform_verifier",
        name: GITHUB_PLATFORM_VERIFIER,
        required: true,
    },
    CanonicalContract {
        key: "google_platform_verifier",
        name: GOOGLE_PLATFORM_VERIFIER,
        required: true,
    },
    CanonicalContract {
        key: "referral_splitter",
        name: REFERRAL_SPLITTER,
        required: false,
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

/// Render the full address table of one deployer: the CREATE2 deployer, the
/// factory, every canonical contract, and where this release's
/// implementations and circuit verifiers deploy. The same on every EVM chain
/// that deployer deploys to. Pure computation — no RPC.
pub fn render_address_table(genesis: FactoryGenesis) -> anyhow::Result<String> {
    use std::fmt::Write;

    use libid_contracts::factory::CREATE2_DEPLOYER;

    let artifacts = libid_contracts::Artifacts::embedded();
    let factory = genesis.address(&artifacts)?;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Canonical addresses of deployer {:#x} (the same on every EVM chain it deploys to):",
        genesis.admin
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
    // Not declared in any network file, but just as deterministic: the
    // implementation an upgrade moves its proxy to, and a circuit verifier
    // no Platform Verifier uses yet.
    let implementations = Upgrade::VALUES.iter().map(|value| {
        let upgrade: Upgrade = value.parse()?;
        anyhow::Ok((
            format!("implementations.{}", upgrade.contracts_key()),
            upgrade.contract(),
        ))
    });
    let verifiers = platforms::circuits()
        .into_iter()
        .map(|circuit| Ok((format!("circuits.{}", circuit.name()), circuit.contract())));
    for row in implementations.chain(verifiers) {
        let (component, contract) = row?;
        let addr = Code::of(&artifacts, contract)?.address();
        let _ = writeln!(out, "  {component:<34} {contract:<34} {addr:#x}");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use alloy::primitives::Address;

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

    /// The printed table holds every implementation and circuit verifier of
    /// the release at the address of its code, each its own.
    #[test]
    fn the_printed_table_holds_the_release_code_addresses() {
        let artifacts = libid_contracts::Artifacts::embedded();
        let genesis = FactoryGenesis {
            admin: Address::repeat_byte(0x11),
        };
        let table = render_address_table(genesis).unwrap();
        let mut printed = BTreeSet::new();
        for contract in Upgrade::VALUES
            .iter()
            .map(|value| value.parse::<Upgrade>().unwrap().contract())
            .chain(platforms::circuits().into_iter().map(|c| c.contract()))
        {
            let address = Code::of(&artifacts, contract).unwrap().address();
            let row = format!(" {contract:<34} {address:#x}\n");
            assert!(table.contains(&row), "{contract} is missing:\n{table}");
            assert!(printed.insert(address), "{contract} shares an address");
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
