//! Code that deploys through the keyless CREATE2 deployer: the
//! implementations behind the proxies and the ceremony circuits' Honk
//! verifiers.
//!
//! Its address is a function of its creation code and nothing else: the same
//! on every network, known from the release without an RPC, and whatever
//! code is there came from that creation code. An implementation is compared
//! by this address and never by its code hash: a UUPS implementation holds
//! its own address as an immutable, so its runtime code is not the
//! artifact's.

use alloy::primitives::{
    keccak256,
    Address,
    Bytes,
    B256,
};
use anyhow::Result;
use libid_contracts::{
    factory::CREATE2_DEPLOYER,
    Artifacts,
};

/// The salt of every deploy. Constant, since the address commits to the
/// creation code already; another salt is another address on every network.
const SALT: B256 = B256::ZERO;

/// The creation code of a contract that takes no constructor arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Code {
    creation: Bytes,
}

impl Code {
    /// The code of `contract` in `artifacts`.
    pub fn of(artifacts: &Artifacts, contract: &str) -> Result<Self> {
        Ok(Self {
            creation: artifacts.bytecode(contract)?,
        })
    }

    /// Where it deploys, on every network.
    pub fn address(&self) -> Address {
        CREATE2_DEPLOYER.create2(SALT, keccak256(&self.creation))
    }

    /// What [`CREATE2_DEPLOYER`] takes to deploy it: the salt, then the
    /// creation code.
    pub(crate) fn calldata(&self) -> Bytes {
        [SALT.as_slice(), &self.creation].concat().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Anybody computes the address with `cast create2` from the release's
    /// creation code and a zero salt.
    #[test]
    fn the_address_is_create2_of_the_creation_code_under_a_zero_salt() {
        let artifacts = Artifacts::embedded();
        let creation = artifacts.bytecode("HandleEscrow").unwrap();
        assert_eq!(
            Code::of(&artifacts, "HandleEscrow").unwrap().address(),
            CREATE2_DEPLOYER.create2([0; 32], keccak256(creation))
        );
    }

    /// One byte of another creation code is another address.
    #[test]
    fn the_address_commits_to_every_byte_of_the_code() {
        let code = Code::of(&Artifacts::embedded(), "HandleEscrow").unwrap();
        let last = code.creation.len() - 1;
        for at in [0, last / 2, last] {
            let mut creation = code.creation.to_vec();
            creation[at] ^= 1;
            let changed = Code {
                creation: creation.into(),
            };
            assert_ne!(changed.address(), code.address(), "byte {at}");
        }
    }
}
