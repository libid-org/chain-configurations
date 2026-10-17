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
//! Each Platform Verifier implementation compiles in the runtime code hash
//! of its circuit's verifier (`circuitCodehash()`), and `initialize`,
//! `setTrustRoots` and `verify` revert `WrongCircuit` for any other code.
//! A bb verifier embeds its verification key as code constants, so the
//! code hash is the only handle on which circuit a deployed verifier
//! answers for.
//!
//! The verifier goes through the factory under [`factory_name`] — a CREATE3
//! name carrying the circuit and the circuits release the crate vendors —
//! so its address is a pure function of which artifact it is: a converged
//! chain is recognised without a redeploy. A circuits release is a new
//! name, a new address, and a Platform Verifier upgrade onto an
//! implementation that pins the new hash, followed by `setTrustRoots`.

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
/// Not in [`crate::names`]' canonical table, which holds the entry
/// contracts a network file declares: the Platform Verifier that pins a
/// circuit verifier references it. The version is part of the name because
/// a Honk verifier IS its verification key, so a new circuits release lands
/// at a new address.
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
