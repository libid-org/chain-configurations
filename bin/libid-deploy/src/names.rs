//! The authoritative canonical-name table.
//!
//! Since libid-contracts 0.3.0 every top-level (entry) contract is deployed
//! through the deterministic `LibidFactory` via CREATE3 with
//! `salt = keccak256(name)`, so its address is a pure function of the name:
//! the same on every EVM network, computable before anything is deployed.
//!
//! CRITICAL: renaming an entry here = a NEW address, forever, on every
//! network. Names are append-only; a name already deployed on any real
//! network must never change. Implementations, facets, and the Honk circuit
//! verifiers are NOT in this table on purpose — they deploy via plain
//! CREATE, their addresses are referenced (by a proxy slot or the Registry)
//! rather than canonical, and upgrades replace them without moving any
//! entry address.

use libid_contracts::factory::predict_address;

/// One canonical (factory-deployed) contract.
#[derive(Debug, Clone, Copy)]
pub struct CanonicalContract {
    /// Network-file table the address is recorded in: `contracts` or
    /// `identity`.
    pub section: &'static str,
    /// Key inside that table.
    pub key: &'static str,
    /// The factory name — the ONLY input to the address.
    pub name: &'static str,
}

/// The Notary proxy — deploys first; everything verifies through it.
pub const NOTARY: &str = "libid.Notary";
/// The Registry UUPS proxy.
pub const REGISTRY: &str = "libid.Registry";
/// The WalletFactory UUPS proxy.
pub const WALLET_FACTORY: &str = "libid.WalletFactory";
/// The XZkVerifier UUPS proxy.
pub const X_ZK_VERIFIER: &str = "libid.XZkVerifier";
/// The GoogleOidcVerifier proxy. NOTE: `--upgrade oidc-verifier` REPLACES
/// this contract with a plain-CREATE deployment (the name is single-use),
/// so after a replace the live address legitimately diverges from the
/// canonical one; the factory's record keeps pointing at the first deploy.
pub const GOOGLE_OIDC_VERIFIER: &str = "libid.GoogleOidcVerifier";
/// The Bank diamond. CREATE3 makes its constructor args (owner, cut facet)
/// irrelevant to the address.
pub const BANK: &str = "libid.Bank";
/// The IdentityNames proxy.
pub const IDENTITY_NAMES: &str = "libid.IdentityNames";
/// The GitHubIdentityVerifier proxy.
pub const GITHUB_IDENTITY_VERIFIER: &str = "libid.GitHubIdentityVerifier";
/// The XIdentityVerifier proxy.
pub const X_IDENTITY_VERIFIER: &str = "libid.XIdentityVerifier";
/// The GoogleIdentityVerifier proxy.
pub const GOOGLE_IDENTITY_VERIFIER: &str = "libid.GoogleIdentityVerifier";
/// The IdentityJwksRoots proxy.
pub const IDENTITY_JWKS_ROOTS: &str = "libid.IdentityJwksRoots";

/// Every canonical contract, in deploy order.
pub const CANONICAL_CONTRACTS: &[CanonicalContract] = &[
    CanonicalContract {
        section: "contracts",
        key: "notary",
        name: NOTARY,
    },
    CanonicalContract {
        section: "contracts",
        key: "wallet_factory",
        name: WALLET_FACTORY,
    },
    CanonicalContract {
        section: "contracts",
        key: "registry",
        name: REGISTRY,
    },
    CanonicalContract {
        section: "contracts",
        key: "bank",
        name: BANK,
    },
    CanonicalContract {
        section: "contracts",
        key: "x_zk_verifier",
        name: X_ZK_VERIFIER,
    },
    CanonicalContract {
        section: "contracts",
        key: "google_oidc_verifier",
        name: GOOGLE_OIDC_VERIFIER,
    },
    CanonicalContract {
        section: "identity",
        key: "identity_names",
        name: IDENTITY_NAMES,
    },
    CanonicalContract {
        section: "identity",
        key: "github_identity_verifier",
        name: GITHUB_IDENTITY_VERIFIER,
    },
    CanonicalContract {
        section: "identity",
        key: "x_identity_verifier",
        name: X_IDENTITY_VERIFIER,
    },
    CanonicalContract {
        section: "identity",
        key: "google_identity_verifier",
        name: GOOGLE_IDENTITY_VERIFIER,
    },
    CanonicalContract {
        section: "identity",
        key: "identity_jwks_roots",
        name: IDENTITY_JWKS_ROOTS,
    },
];

/// The canonical name for a `section`/`key` pair, if the component is
/// factory-deployed.
pub fn canonical_name(section: &str, key: &str) -> Option<&'static str> {
    CANONICAL_CONTRACTS
        .iter()
        .find(|c| c.section == section && c.key == key)
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
        "  {:<34} {:<30} {CREATE2_DEPLOYER:#x}",
        "create2_deployer", "(keyless, Arachnid)"
    );
    let _ = writeln!(
        out,
        "  {:<34} {:<30} {factory:#x}",
        "contracts.factory", "(CREATE2, frozen init code)"
    );
    for c in CANONICAL_CONTRACTS {
        let addr = predict_address(factory, c.name);
        let _ = writeln!(
            out,
            "  {:<34} {:<30} {addr:#x}",
            format!("{}.{}", c.section, c.key),
            c.name
        );
    }
    Ok(out)
}
