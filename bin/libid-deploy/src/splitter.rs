//! The referral splitter: the fee receiver of a bind, which takes exactly
//! its fee. With a referral it pays the referrer's handle its share of the
//! fee through the handle escrow, and the treasury the rest. The identity
//! registry and the escrow are constructor arguments, fixed for life; its
//! owner, the identity registry's owner when apply deploys it, keeps the
//! settings below.

use std::fmt;

use alloy::{
    contract::Error as ContractError,
    primitives::{
        Address,
        Bytes,
        B256,
        U256,
    },
    providers::Provider,
    sol_types::SolConstructor,
};
use anyhow::{
    anyhow,
    Result,
};
use libid_contracts::{
    bindings::{
        identity::IdentityRegistry,
        referral::ReferralSplitter,
    },
    Artifacts,
};

use crate::config::Stack;

/// The settings a splitter's owner changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// Where every part of a fee that is not a delivered share goes.
    pub treasury: Address,
    /// The referrer's part of a referred fee, in basis points.
    pub share_bps: u16,
    /// What a bind through the splitter pays, in wei; the splitter reverts
    /// any other amount.
    pub fee: U256,
}

impl Settings {
    /// The owner calls that move these settings onto `declared`.
    pub fn changes_to(&self, declared: &Settings) -> Vec<Change> {
        [
            (self.treasury != declared.treasury)
                .then_some(Change::Treasury(declared.treasury)),
            (self.share_bps != declared.share_bps)
                .then_some(Change::Share(declared.share_bps)),
            (self.fee != declared.fee).then_some(Change::Fee(declared.fee)),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

impl fmt::Display for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "treasury {:#x}, share {} bps, fee {} wei",
            self.treasury, self.share_bps, self.fee
        )
    }
}

/// One owner call and the value it sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// `setTreasury`.
    Treasury(Address),
    /// `setShare`.
    Share(u16),
    /// `setFee`.
    Fee(U256),
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Treasury(treasury) => write!(f, "setTreasury({treasury:#x})"),
            Self::Share(share_bps) => write!(f, "setShare({share_bps})"),
            Self::Fee(fee) => write!(f, "setFee({fee})"),
        }
    }
}

/// A splitter the network file declares.
#[derive(Debug, Clone, Copy)]
pub struct Splitter {
    /// Its canonical address.
    pub address: Address,
    /// The settings it holds.
    pub settings: Settings,
}

impl Splitter {
    /// The creation code of the splitter paid by `stack`'s identity registry
    /// and paying through its escrow, owned by `owner`.
    pub fn creation_code(
        &self,
        artifacts: &Artifacts,
        stack: &Stack,
        owner: Address,
    ) -> Result<Bytes> {
        let mut code = artifacts.bytecode("ReferralSplitter")?.to_vec();
        code.extend(
            ReferralSplitter::constructorCall {
                registry: stack.identity_registry,
                escrow: stack.handle_escrow,
                owner_: owner,
                treasury_: self.settings.treasury,
                shareBps_: self.settings.share_bps,
                fee_: self.settings.fee,
            }
            .abi_encode(),
        );
        Ok(code.into())
    }

    /// What the chain holds at its address.
    pub async fn on_chain<P: Provider>(&self, provider: &P) -> Result<OnChain> {
        let contract = ReferralSplitter::new(self.address, provider);
        let (registry, escrow, owner, treasury, share_bps, fee) = (
            contract.REGISTRY(),
            contract.ESCROW(),
            contract.owner(),
            contract.treasury(),
            contract.shareBps(),
            contract.fee(),
        );
        let (registry, escrow, owner, treasury, share_bps, fee) = tokio::try_join!(
            registry.call(),
            escrow.call(),
            owner.call(),
            treasury.call(),
            share_bps.call(),
            fee.call(),
        )
        .map_err(|e| {
            anyhow!("ReferralSplitter read at {:#x} failed: {e}", self.address)
        })?;
        Ok(OnChain {
            registry,
            escrow,
            owner,
            settings: Settings {
                treasury,
                share_bps,
                fee,
            },
        })
    }
}

/// What a deployed splitter holds.
#[derive(Debug, Clone, Copy)]
pub struct OnChain {
    /// The identity registry it takes fees from.
    pub registry: Address,
    /// The escrow it delivers shares through.
    pub escrow: Address,
    /// Its owner.
    pub owner: Address,
    /// Its settings.
    pub settings: Settings,
}

impl OnChain {
    /// Whether it takes fees from `stack`'s identity registry and delivers
    /// through its escrow.
    pub fn wired_to(&self, stack: &Stack) -> bool {
        self.registry == stack.identity_registry && self.escrow == stack.handle_escrow
    }
}

/// Whether an identity registry pays a fee receiver through `onBindFee`.
pub(crate) trait FeeCall {
    /// `bindWithFeeCall` naming no fee reverts `NoFee` on an implementation
    /// that has it, and reverts otherwise on one that predates it.
    async fn calls_fee_receiver(&self) -> Result<bool>;
}

impl<P: Provider> FeeCall for IdentityRegistry::IdentityRegistryInstance<P> {
    async fn calls_fee_receiver(&self) -> Result<bool> {
        let probe = self.bindWithFeeCall(
            B256::ZERO,
            0,
            Bytes::new(),
            String::new(),
            false,
            U256::ZERO,
            Address::ZERO,
            Bytes::new(),
        );
        match probe.call().await {
            Ok(_) => Ok(false),
            Err(e) if e.as_decoded_error::<IdentityRegistry::NoFee>().is_some() => {
                Ok(true)
            }
            Err(ContractError::TransportError(e))
                if e.as_error_resp()
                    .is_some_and(|r| r.message.to_lowercase().contains("revert")) =>
            {
                Ok(false)
            }
            Err(e) => Err(anyhow!(
                "IdentityRegistry.bindWithFeeCall probe at {:#x} failed: {e}",
                self.address()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TREASURY: Address = Address::repeat_byte(0x7e);

    fn settings() -> Settings {
        Settings {
            treasury: TREASURY,
            share_bps: 3_000,
            fee: U256::from(3_700_000_000_000_000u64),
        }
    }

    /// Equal settings need no call.
    #[test]
    fn equal_settings_change_nothing() {
        assert!(settings().changes_to(&settings()).is_empty());
    }

    /// Each differing setting is one call carrying the declared value.
    #[test]
    fn each_differing_setting_is_one_call() {
        let declared = Settings {
            share_bps: 2_500,
            fee: U256::from(1u64),
            ..settings()
        };
        let changes = settings().changes_to(&declared);
        assert_eq!(
            changes,
            [Change::Share(2_500), Change::Fee(U256::from(1u64))]
        );
        assert_eq!(changes[1].to_string(), "setFee(1)");
    }
}
