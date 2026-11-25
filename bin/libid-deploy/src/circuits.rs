//! Where the ceremony circuits' Honk verifiers land.
//!
//! The verifiers themselves are `libid-contracts`' business: it vendors
//! each circuit's bb-generated UltraHonk verifier from the `libid-circuits`
//! release it pins and embeds the compiled artifact beside the rest of the
//! stack, so nothing here generates, compiles or stores bytecode. What is
//! decided here is which deployed verifier a chain uses and where a new one
//! deploys, and that is what makes apply idempotent for them.
//!
//! # The verifier: the code hash, then CREATE2 of its code
//!
//! Each Platform Verifier implementation compiles in the runtime code hash
//! of its circuit's verifier (`circuitCodehash()`), and `initialize`,
//! `setTrustRoots` and `verify` revert `WrongCircuit` for any other code.
//! A bb verifier embeds its verification key as code constants, so the
//! code hash is the only handle on which circuit a deployed verifier
//! answers for.
//!
//! A Platform Verifier whose verifier holds the vendored code keeps it,
//! wherever it was deployed, so a circuits release that rebuilds the same
//! verifier deploys and rotates nothing. Otherwise the verifier goes to the
//! CREATE2 address of its creation code ([`Code`]), so a second apply finds
//! it and sends nothing. A release with new code is a new address, and a
//! Platform Verifier upgrade onto an implementation that pins the new hash,
//! followed by `setTrustRoots`.

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
    Artifacts,
};

use crate::{
    code::Code,
    config::Contracts,
    platforms::{
        self,
        Platform,
    },
};

/// Where a circuit's verifier is on one chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Site {
    /// A verifier holding the vendored code that a Platform Verifier already
    /// uses, wherever it was deployed.
    InUse(Address),
    /// Where the vendored verifier deploys: [`Code::address`].
    Vendored(Address),
}

impl Site {
    /// The verifier's address.
    pub fn address(&self) -> Address {
        match self {
            Self::InUse(address) | Self::Vendored(address) => *address,
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
    /// already uses with the vendored code, else its code's own address.
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
        let code = Code::of(self.artifacts, circuit.contract())?;
        Ok(Site::Vendored(code.address()))
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
