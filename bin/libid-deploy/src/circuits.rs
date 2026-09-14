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
//! release is a new name, a new address and a `setTrustRoots`.
//!
//! # The libraries: CREATE2, at an address derived from their bytecode
//!
//! A bb verifier links `RelationsLib` and `ZKTranscriptLib`: their
//! functions are `external`, so they are deployed contracts rather than
//! inlined code, and the verifier's creation code carries a placeholder
//! per call site until each one's address is substituted in. bb writes a
//! copy of both into every verifier it generates, and the copies compile
//! to the same bytecode. [`Libraries`](libid_contracts::deploy::Libraries)
//! deploys each distinct bytecode ONCE, through the canonical CREATE2
//! deployer under an empty salt, so the
//! address is a function of the code ([`library_address`]): the same on
//! every chain, found rather than deployed again on a re-run, and shared by
//! every verifier that links it. The verifier's runtime code carries those
//! addresses, so its code hash — the one the Platform Verifiers pin — is
//! network-invariant too.

use std::collections::BTreeMap;

use alloy::primitives::Address;
use anyhow::Result;
pub use libid_contracts::circuits::Circuit;
use libid_contracts::{
    circuits::{
        self,
        LIBRARIES,
    },
    deploy::library_address,
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

/// The shared libraries the embedded verifiers link, each at the address
/// its creation code derives — `address -> library`, one entry per distinct
/// bytecode. Pure computation, no RPC: known before the chain has anything
/// on it, like the canonical table.
///
/// Two entries for the launch circuits: both verifiers carry the same two
/// libraries, so their copies collapse onto one address each. A copy that
/// ever compiled differently would appear as its own entry under the same
/// name, which is exactly the deployment it would get.
pub fn library_addresses() -> Result<BTreeMap<Address, &'static str>> {
    let artifacts = Artifacts::embedded();
    let mut addresses = BTreeMap::new();
    for circuit in Circuit::ALL {
        for library in LIBRARIES {
            // A library links nothing itself, so its creation code is final
            // as embedded — the bytes `Libraries::deploy` hashes.
            let code = artifacts.bytecode_named(circuit.contract(), library)?;
            addresses.insert(library_address(&code), library);
        }
    }
    Ok(addresses)
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

    /// The premise of sharing, checked offline: both verifiers' copies of
    /// each library compile to identical bytecode, so a fresh chain gets
    /// exactly one deployment per library, however many circuits link it.
    #[test]
    fn every_library_is_one_deployment_across_all_circuits() {
        let addresses = library_addresses().unwrap();
        assert_eq!(addresses.len(), LIBRARIES.len(), "{addresses:?}");
        for library in LIBRARIES {
            assert!(
                addresses.values().any(|l| *l == library),
                "{library} has no address"
            );
        }
    }
}
