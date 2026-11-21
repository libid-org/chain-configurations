//! The plan lines of the declared testnet top-ups: what each address
//! holds, and what `apply --fund` sends it.

use alloy::{
    eips::BlockId,
    primitives::U256,
};
use anyhow::Result;

use super::{
    checks::Answer,
    Item,
    Planner,
    Status,
};
use crate::funding::Funding;

/// What a declared address holds against its target.
pub(crate) struct FundingBalance {
    /// The declaration.
    pub(crate) funding: Funding,
    /// The address's balance.
    pub(crate) balance: Answer<U256>,
}

impl From<FundingBalance> for Item {
    fn from(check: FundingBalance) -> Self {
        let FundingBalance { funding, balance } = check;
        let component = funding.component();
        let balance = match balance {
            Ok(balance) => balance,
            Err(e) => return Item::new(component, Status::Warn, e),
        };
        let holds = format!(
            "{:#x} holds {balance} wei, tops up to {} wei",
            funding.address, funding.target
        );
        match funding.top_up(balance) {
            None => Item::new(component, Status::Ok, holds),
            Some(top_up) => Item::new(
                component,
                Status::Configure,
                format!("{holds} — apply --fund sends {} wei", top_up.amount()),
            ),
        }
    }
}

impl Planner<'_> {
    /// One line per declared top-up.
    pub(crate) async fn funding(&mut self) -> Result<()> {
        for funding in self.cfg.funding()? {
            let balance = funding
                .balance(&self.provider, BlockId::latest())
                .await
                .map_err(|e| e.to_string());
            self.push(FundingBalance { funding, balance });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::Address;

    use super::*;

    fn check(balance: u64) -> Item {
        Item::from(FundingBalance {
            funding: Funding {
                name: "e2e".into(),
                address: Address::repeat_byte(0x2e),
                target: U256::from(740u64),
            },
            balance: Ok(U256::from(balance)),
        })
    }

    /// An address at its target needs nothing.
    #[test]
    fn an_address_at_its_target_is_ok() {
        let item = check(740);
        assert_eq!(item.component, "funding.e2e");
        assert_eq!(item.status, Status::Ok);
        assert_eq!(
            item.detail,
            format!(
                "{:#x} holds 740 wei, tops up to 740 wei",
                Address::repeat_byte(0x2e)
            )
        );
    }

    /// An address below its target is configured with the amount `--fund`
    /// sends.
    #[test]
    fn an_address_below_its_target_names_what_fund_sends() {
        let item = check(100);
        assert_eq!(item.status, Status::Configure);
        assert!(
            item.detail.ends_with("apply --fund sends 640 wei"),
            "{}",
            item.detail
        );
    }
}
