//! Where the ceremony circuits' Honk verifiers land.
//!
//! The verifiers themselves are `libid-contracts`' business: it vendors
//! each circuit's bb-generated UltraHonk verifier from the `libid-circuits`
//! release it pins and embeds the compiled artifact beside the rest of the
//! stack, so nothing here generates, compiles or stores bytecode. What is
//! decided here is the address each one deploys to, and that is what makes
//! apply idempotent for them.
//!
//! # The verifier: CREATE3, under a name carrying the circuits release
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
//! the chain. The verifier goes through the factory under [`factory_name`]
//! — a CREATE3 name carrying the circuit and the circuits release the
//! crate vendors — so its address is a pure function of which artifact it
//! is: a converged chain is recognised without a redeploy, and a circuits
//! release is a new name, a new address and a `setTrustRoots`. The verifier
//! is one self-contained contract, so its code hash, the one the Platform
//! Verifiers pin, is the same on every chain.

use anyhow::Result;
pub use libid_contracts::circuits::Circuit;
use libid_contracts::{
    circuits,
    Artifacts,
};

/// The `libid-circuits` release the embedded verifiers came from, read
/// from the pin `libid-contracts` vendors beside its artifacts.
pub fn version() -> Result<String> {
    Ok(circuits::version(&Artifacts::embedded())?)
}

/// The CREATE3 name `circuit`'s verifier deploys under.
///
/// Deliberately NOT in [`crate::names`]' canonical table: that is the set of
/// entry contracts a network file declares, and these are referenced by the
/// Platform Verifier that pins them instead. The version is part of the
/// name because a Honk verifier IS its verification key — a new circuits
/// release is a different contract, so it must be a different address
/// rather than a silent replacement.
pub fn factory_name(circuit: Circuit) -> Result<String> {
    Ok(format!("libid.circuits.{}.{}", circuit.name(), version()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two circuits are distinct artifacts under distinct names; a
    /// shared one would wire both platforms to one verification key.
    #[test]
    fn each_circuit_has_its_own_factory_name() {
        let version = version().expect("the pin the crate vendors parses");
        let mut names = Vec::new();
        for circuit in Circuit::ALL {
            let name = factory_name(circuit).unwrap();
            assert!(
                name.starts_with("libid.circuits."),
                "{name} is not namespaced"
            );
            assert!(
                name.ends_with(&version),
                "{name} does not carry the pinned circuits release"
            );
            names.push(name);
        }
        names.dedup();
        assert_eq!(names.len(), Circuit::ALL.len());
    }
}
