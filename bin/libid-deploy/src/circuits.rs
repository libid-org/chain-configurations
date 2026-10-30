//! Where the ceremony circuits' Honk verifiers land.
//!
//! The verifiers themselves are `libid-contracts`' business: it vendors
//! each circuit's bb-generated UltraHonk verifier from the `libid-circuits`
//! release it pins and embeds the compiled artifact beside the rest of the
//! stack, so nothing here generates, compiles or stores bytecode. What is
//! decided here is which deployed verifier a chain uses and where a new one
//! deploys, and that is what makes apply idempotent for them.
//!
//! # The verifier: the code hash, then CREATE3 under the circuits release
//!
//! Each Platform Verifier implementation compiles in the runtime code hash
//! of its circuit's verifier (`circuitCodehash()`), and `initialize`,
//! `setTrustRoots` and `verify` revert `WrongCircuit` for any other code.
//! A bb verifier embeds its verification key as code constants, so the
//! code hash is the only handle on which circuit a deployed verifier
//! answers for.
//!
//! A Platform Verifier whose verifier holds the vendored code keeps it,
//! whatever name it was deployed under, so a circuits release that rebuilds
//! the same verifier deploys and rotates nothing. Otherwise the verifier
//! goes through the factory under [`factory_name`] — a CREATE3 name carrying
//! the circuit and the circuits release the crate vendors — so a second
//! apply finds it and sends nothing. A release with new code is a new name,
//! a new address, and a Platform Verifier upgrade onto an implementation
//! that pins the new hash, followed by `setTrustRoots`.

use alloy::{
    primitives::{
        keccak256,
        Address,
        B256,
    },
    providers::{
        DynProvider,
        Provider,
    },
};
use anyhow::{
    anyhow,
    Result,
};
pub use libid_contracts::circuits::Circuit;
use libid_contracts::{
    bindings::ceremony::PlatformVerifierBase,
    circuits,
    factory::predict_address,
    Artifacts,
};

use crate::{
    config::Contracts,
    platforms::{
        self,
        Platform,
    },
};

/// The `libid-circuits` release the embedded verifiers came from, read
/// from the pin `libid-contracts` vendors beside its artifacts.
pub fn version() -> Result<String> {
    Ok(circuits::version(&Artifacts::embedded())?)
}

/// The CREATE3 name `circuit`'s verifier deploys under when no Platform
/// Verifier uses one with the vendored code.
///
/// Not in [`crate::names`]' canonical table, which holds the entry
/// contracts a network file declares: the Platform Verifier that pins a
/// circuit verifier references it. The version is part of the name because
/// a Honk verifier IS its verification key, so a release with new code
/// lands at a new address.
pub fn factory_name(circuit: Circuit) -> Result<String> {
    Ok(format!("libid.circuits.{}.{}", circuit.name(), version()?))
}

/// Where a circuit's verifier is on one chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Site {
    /// A verifier holding the vendored code that a Platform Verifier already
    /// uses, under whatever name it was deployed.
    InUse(Address),
    /// Where [`factory_name`] lands under the factory.
    Named {
        /// The CREATE3 name.
        name: String,
        /// Its address.
        address: Address,
    },
}

impl Site {
    /// The verifier's address.
    pub fn address(&self) -> Address {
        match self {
            Self::InUse(address) | Self::Named { address, .. } => *address,
        }
    }
}

/// The verifier a Platform Verifier uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wired {
    /// `honkVerifier()`.
    pub address: Address,
    /// Whether the code there is the vendored verifier of the platform's
    /// circuit.
    pub vendored: bool,
}

/// Reads which circuit verifiers the Platform Verifiers of one chain use.
pub struct Verifiers<'a> {
    /// The chain.
    pub provider: &'a DynProvider,
    /// The vendored verifiers.
    pub artifacts: &'a Artifacts,
    /// The declared Platform Verifier proxies.
    pub contracts: &'a Contracts,
    /// The deployer's canonical factory.
    pub factory: Address,
}

impl Verifiers<'_> {
    /// The verifier `platform`'s Platform Verifier uses. Its proxy must
    /// have code.
    pub async fn wired(&self, platform: &Platform) -> Result<Wired> {
        let proxy = self.contracts.address(platform.contracts_key)?;
        let address = PlatformVerifierBase::new(proxy, self.provider)
            .honkVerifier()
            .call()
            .await
            .map_err(|e| anyhow!("{}.honkVerifier read failed: {e}", platform.label))?;
        let vendored = platform.circuit().runtime_codehash(self.artifacts)?;
        Ok(Wired {
            address,
            vendored: self.code_hash(address).await? == Some(vendored),
        })
    }

    /// Where `circuit`'s verifier is: one a Platform Verifier of the circuit
    /// already uses with the vendored code, else [`factory_name`]'s address.
    /// A Platform Verifier whose verifier cannot be read offers none; the
    /// read that converges it reports the failure.
    pub async fn site(&self, circuit: Circuit) -> Result<Site> {
        for platform in platforms::LAUNCH.iter().filter(|p| p.circuit() == circuit) {
            let proxy = self.contracts.address(platform.contracts_key)?;
            if self.code_hash(proxy).await?.is_none() {
                continue;
            }
            match self.wired(platform).await {
                Ok(wired) if wired.vendored => return Ok(Site::InUse(wired.address)),
                Ok(_) => {}
                Err(error) => tracing::warn!(
                    platform = platform.label,
                    %error,
                    "skipped while locating the circuit verifier"
                ),
            }
        }
        let name = factory_name(circuit)?;
        Ok(Site::Named {
            address: predict_address(self.factory, &name),
            name,
        })
    }

    /// The code hash at `address`, `None` when it holds no code.
    pub async fn code_hash(&self, address: Address) -> Result<Option<B256>> {
        let code = self
            .provider
            .get_code_at(address)
            .await
            .map_err(|e| anyhow!("get_code({address:#x}) failed: {e}"))?;
        Ok((!code.is_empty()).then(|| keccak256(&code)))
    }
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
