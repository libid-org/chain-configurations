//! Testnet top-ups: addresses a network file declares under
//! `[funding.<name>]`, each with the balance `apply --fund` brings it up to
//! from the deployer. One run sends at most the shortfall, so a rerun sends
//! nothing more, and a file may declare a top-up only on a chain
//! [`FUNDED_CHAINS`] lists.

use std::fmt;

use alloy::{
    eips::BlockId,
    primitives::{
        Address,
        U256,
    },
    providers::Provider,
};
use anyhow::{
    anyhow,
    Result,
};

/// A chain whose network file may declare `[funding]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FundedChain {
    /// Its chain id.
    pub chain_id: u64,
    /// The network file that describes it.
    pub network: &'static str,
    /// The most one run sends on the chain: the largest sum of
    /// `top_up_to_wei` its file may declare.
    pub max_top_up_wei: U256,
}

impl fmt::Display for FundedChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.chain_id, self.network)
    }
}

/// The chains whose deployer may fund an address: the three testnets and
/// local-dev's anvil. Their native tokens have no market value; a testnet's cap
/// is a week of the e2e tests' binds.
pub const FUNDED_CHAINS: &[FundedChain] = &[
    FundedChain {
        chain_id: 11_155_111,
        network: "sepolia",
        // 0.74 ETH
        max_top_up_wei: U256::from_limbs([740_000_000_000_000_000, 0, 0, 0]),
    },
    FundedChain {
        chain_id: 421_614,
        network: "arbitrum-sepolia",
        // 0.056 ETH
        max_top_up_wei: U256::from_limbs([56_000_000_000_000_000, 0, 0, 0]),
    },
    FundedChain {
        chain_id: 3_735_928_814,
        network: "eden-testnet",
        // 0.045 TIA
        max_top_up_wei: U256::from_limbs([45_000_000_000_000_000, 0, 0, 0]),
    },
    FundedChain {
        chain_id: 31_337,
        network: "local-dev",
        // 10 ETH
        max_top_up_wei: U256::from_limbs([10_000_000_000_000_000_000, 0, 0, 0]),
    },
];

/// One declared top-up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Funding {
    /// The table key.
    pub name: String,
    /// The address that receives the top-up.
    pub address: Address,
    /// The balance a top-up brings it to, in wei.
    pub target: U256,
}

impl Funding {
    /// Its plan line and summary label, `funding.<name>`.
    pub fn component(&self) -> String {
        format!("funding.{}", self.name)
    }

    /// The top-up an address holding `balance` takes, `None` at or above the
    /// target.
    pub fn top_up(&self, balance: U256) -> Option<TopUp> {
        (balance < self.target).then(|| TopUp {
            funding: self.clone(),
            balance,
        })
    }

    /// The address's balance at `block`.
    pub async fn balance<P: Provider>(
        &self,
        provider: &P,
        block: BlockId,
    ) -> Result<U256> {
        provider
            .get_balance(self.address)
            .block_id(block)
            .await
            .map_err(|e| {
                anyhow!(
                    "{} balance of {:#x} read failed: {e}",
                    self.component(),
                    self.address
                )
            })
    }
}

/// A declared address below its target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopUp {
    /// The declaration.
    pub funding: Funding,
    /// What the address held when apply read it.
    pub balance: U256,
}

impl TopUp {
    /// What brings the address to its target: zero once it holds the target.
    pub fn amount(&self) -> U256 {
        self.funding.target.saturating_sub(self.balance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e2e() -> Funding {
        Funding {
            name: "e2e".into(),
            address: Address::repeat_byte(0x2e),
            target: U256::from(740u64),
        }
    }

    /// Below the target, the top-up is the shortfall, so the address ends
    /// at the target exactly.
    #[test]
    fn a_balance_below_the_target_tops_up_by_the_shortfall() {
        let top_up = e2e().top_up(U256::from(100u64)).expect("below target");
        assert_eq!(top_up.amount(), U256::from(640u64));
        assert_eq!(top_up.balance + top_up.amount(), e2e().target);
    }

    /// At or above the target, nothing is sent.
    #[test]
    fn a_balance_at_or_above_the_target_tops_up_nothing() {
        assert_eq!(e2e().top_up(U256::from(740u64)), None);
        assert_eq!(e2e().top_up(U256::from(741u64)), None);
        assert_eq!(e2e().top_up(U256::MAX), None);
    }
}
