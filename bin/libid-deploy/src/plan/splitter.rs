//! The plan lines of the referral splitter: whether the identity registry
//! pays it, whether it exists, what it pays through, and whether its
//! settings are the declared ones.

use alloy::primitives::Address;
use anyhow::{
    anyhow,
    Result,
};
use libid_contracts::bindings::identity::IdentityRegistry;

use super::{
    checks::Answer,
    Item,
    Planner,
    Status,
};
use crate::{
    config::Stack,
    splitter::{
        Change,
        FeeCall,
        OnChain,
        Settings,
    },
};

/// Whether the identity registry's implementation pays a fee receiver
/// through `onBindFee`, the only way a bind pays the splitter.
pub(crate) struct RegistryFeeCall {
    /// What the `bindWithFeeCall` probe answered.
    pub(crate) calls: Answer<bool>,
}

impl From<RegistryFeeCall> for Item {
    fn from(check: RegistryFeeCall) -> Self {
        let component = "identity_registry.fee_call";
        match check.calls {
            Ok(true) => {
                Item::new(component, Status::Ok, "bindWithFeeCall pays the splitter")
            }
            Ok(false) => Item::new(
                component,
                Status::Warn,
                "the implementation predates bindWithFeeCall, so no bind pays the \
                 splitter — apply refuses the splitter unless it upgrades the \
                 implementation first (--upgrade identity-registry)",
            ),
            Err(e) => Item::new(component, Status::Warn, e),
        }
    }
}

/// Whether a deployed splitter takes fees from the declared identity
/// registry and pays through the declared escrow. Both are fixed at
/// deploy.
pub(crate) struct SplitterWiring {
    /// The declared stack.
    pub(crate) stack: Stack,
    /// What the splitter holds.
    pub(crate) on_chain: OnChain,
}

impl From<SplitterWiring> for Item {
    fn from(check: SplitterWiring) -> Self {
        let OnChain {
            registry, escrow, ..
        } = check.on_chain;
        let component = "referral_splitter.wiring";
        if check.on_chain.wired_to(&check.stack) {
            Item::new(
                component,
                Status::Ok,
                format!("paid by {registry:#x}, pays through {escrow:#x}"),
            )
        } else {
            Item::new(
                component,
                Status::Warn,
                format!(
                    "paid by {registry:#x}, pays through {escrow:#x}; the file declares \
                     {:#x} and {:#x} — apply stops here: neither moves, a new canonical \
                     splitter name deploys another",
                    check.stack.identity_registry, check.stack.handle_escrow
                ),
            )
        }
    }
}

/// Whether a splitter holds the declared settings, and who can set them.
pub(crate) struct SplitterSettings {
    /// What the file declares.
    pub(crate) declared: Settings,
    /// The key apply signs with.
    pub(crate) deployer: Address,
    /// The splitter's owner.
    pub(crate) owner: Address,
    /// What the splitter holds, or holds right after apply deploys it.
    pub(crate) held: Settings,
    /// Whether apply deploys the splitter first.
    pub(crate) deploys: bool,
}

impl From<SplitterSettings> for Item {
    fn from(check: SplitterSettings) -> Self {
        let component = "referral_splitter.settings";
        let SplitterSettings {
            declared,
            deployer,
            owner,
            held,
            deploys,
        } = check;
        let holds = if deploys {
            format!("the constructor sets {held}")
        } else {
            format!("{held} on-chain")
        };
        let changes = held.changes_to(&declared);
        if changes.is_empty() {
            return Item::new(component, Status::Ok, holds);
        }
        let calls = changes
            .iter()
            .map(Change::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        if owner == deployer {
            Item::new(
                component,
                Status::Configure,
                format!("{holds} — apply sends {calls}"),
            )
        } else {
            Item::new(
                component,
                Status::Warn,
                format!(
                    "{holds} — apply sends no setting: its owner {owner:#x} signs {calls}"
                ),
            )
        }
    }
}

impl Planner<'_> {
    /// The splitter's lines, when the file declares one.
    pub(crate) async fn referral_splitter(
        &mut self,
        stack: Stack,
        identity_registry_present: bool,
    ) -> Result<()> {
        let Some(splitter) = self.cfg.splitter()? else {
            return Ok(());
        };
        if identity_registry_present {
            let calls = IdentityRegistry::new(stack.identity_registry, &self.provider)
                .calls_fee_receiver()
                .await
                .map_err(|e| e.to_string());
            self.push(RegistryFeeCall { calls });
        }
        let deployer = self.cfg.accounts.deployer_address()?;
        let present = self
            .code("contracts.referral_splitter", splitter.address)
            .await?;
        let held = if present {
            match splitter.on_chain(&self.provider).await {
                Ok(on_chain) => {
                    self.push(SplitterWiring { stack, on_chain });
                    Ok((on_chain.owner, on_chain.settings))
                }
                Err(e) => Err(e),
            }
        } else {
            // Apply deploys it owned by the identity registry's owner, the
            // deployer on a chain that has no registry yet.
            self.splitter_owner(stack, identity_registry_present, deployer)
                .await
                .map(|owner| (owner, splitter.settings))
        };
        match held {
            Ok((owner, held)) => self.push(SplitterSettings {
                declared: splitter.settings,
                deployer,
                owner,
                held,
                deploys: !present,
            }),
            Err(e) => self.push(Item::new(
                "referral_splitter.settings",
                Status::Warn,
                e.to_string(),
            )),
        }
        Ok(())
    }

    /// The owner apply deploys the splitter with.
    async fn splitter_owner(
        &self,
        stack: Stack,
        identity_registry_present: bool,
        deployer: Address,
    ) -> Result<Address> {
        if !identity_registry_present {
            return Ok(deployer);
        }
        IdentityRegistry::new(stack.identity_registry, &self.provider)
            .owner()
            .call()
            .await
            .map_err(|e| anyhow!("IdentityRegistry.owner read failed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::U256;

    use super::*;

    const DEPLOYER: Address = Address::repeat_byte(0xdd);

    fn declared() -> Settings {
        Settings {
            treasury: Address::repeat_byte(0x7e),
            share_bps: 3_000,
            min_referral_fee: U256::from(1_850_000_000_000_000u64),
        }
    }

    fn check(owner: Address, held: Settings) -> Item {
        Item::from(SplitterSettings {
            declared: declared(),
            deployer: DEPLOYER,
            owner,
            held,
            deploys: false,
        })
    }

    /// Drift the deployer can sign for is configured.
    #[test]
    fn drift_under_the_deployer_is_configured() {
        let item = check(
            DEPLOYER,
            Settings {
                share_bps: 2_000,
                ..declared()
            },
        );
        assert_eq!(item.status, Status::Configure);
        assert!(
            item.detail.ends_with("apply sends setShare(3000)"),
            "{}",
            item.detail
        );
    }

    /// Drift under another owner names the calls it signs.
    #[test]
    fn drift_under_another_owner_is_reported() {
        let owner = Address::repeat_byte(0xaa);
        let item = check(
            owner,
            Settings {
                share_bps: 2_000,
                ..declared()
            },
        );
        assert_eq!(item.status, Status::Warn);
        assert!(
            item.detail
                .contains(&format!("its owner {owner:#x} signs setShare(3000)")),
            "{}",
            item.detail
        );
    }

    /// A new splitter's constructor sets every declared setting.
    #[test]
    fn a_new_splitter_needs_no_call_after_its_deploy() {
        let item = Item::from(SplitterSettings {
            declared: declared(),
            deployer: DEPLOYER,
            owner: DEPLOYER,
            held: declared(),
            deploys: true,
        });
        assert_eq!(item.status, Status::Ok);
        assert!(
            item.detail.starts_with("the constructor sets "),
            "{}",
            item.detail
        );
    }
}
