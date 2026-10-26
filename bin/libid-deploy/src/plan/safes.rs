//! The plan lines of the declared Safes: the Safe v1.4.1 contracts they
//! are created through, whether each Safe exists, and whether its owners
//! and threshold are the declared ones.

use alloy::primitives::B256;
use anyhow::Result;

use super::{
    checks::Answer,
    Item,
    Planner,
    Status,
};
use crate::safes::{
    OwnerSet,
    Safe,
    SafeContract,
    SAFE_CONTRACTS,
};

/// Whether a Safe v1.4.1 contract sits at its canonical address.
pub(crate) struct SafeContractCode {
    /// The contract.
    pub(crate) contract: SafeContract,
    /// The code hash at its address, `None` without code.
    pub(crate) codehash: Option<B256>,
}

impl SafeContractCode {
    /// Whether the chain holds the release's code there.
    fn is_canonical(&self) -> bool {
        self.codehash == Some(self.contract.codehash)
    }
}

impl From<SafeContractCode> for Item {
    fn from(check: SafeContractCode) -> Self {
        let SafeContract {
            key, name, address, ..
        } = check.contract;
        let component = format!("safe_contracts.{key}");
        match check.codehash {
            _ if check.is_canonical() => Item::new(
                component,
                Status::Ok,
                format!("{address:#x} ({name} v1.4.1)"),
            ),
            None => Item::new(
                component,
                Status::Warn,
                format!(
                    "no code at {address:#x}: this chain has no Safe v1.4.1 {name}, so \
                     apply refuses to create or change any declared Safe"
                ),
            ),
            Some(hash) => Item::new(
                component,
                Status::Warn,
                format!(
                    "{address:#x} holds codehash {hash:#x}, not Safe v1.4.1 {name}'s — \
                     apply refuses to create or change any declared Safe"
                ),
            ),
        }
    }
}

/// Whether a declared Safe exists with the declared owners and threshold.
pub(crate) struct SafeOwners<'a> {
    /// The Safe.
    pub(crate) safe: Safe<'a>,
    /// What the file declares.
    pub(crate) declared: OwnerSet,
    /// What the chain holds, `None` while the Safe has no code.
    pub(crate) on_chain: Option<Answer<OwnerSet>>,
}

impl From<SafeOwners<'_>> for Item {
    fn from(check: SafeOwners<'_>) -> Self {
        let SafeOwners {
            safe,
            declared,
            on_chain,
        } = check;
        let component = format!("safes.{}.owners", safe.name);
        let address = safe.address();
        match on_chain {
            None if declared.same_as(&safe.bootstrap_owners()) => Item::new(
                component,
                Status::Deploy,
                format!("apply creates it as {declared}"),
            ),
            None => Item::new(
                component,
                Status::Deploy,
                format!(
                    "apply creates it as {}, then hands it to {declared} in one Safe \
                     transaction",
                    safe.bootstrap_owners()
                ),
            ),
            Some(Err(e)) => Item::new(component, Status::Warn, e),
            Some(Ok(current)) if current.same_as(&declared) => {
                Item::new(component, Status::Ok, current.to_string())
            }
            Some(Ok(current)) if current.signs_alone(safe.deployer) => Item::new(
                component,
                Status::Configure,
                format!(
                    "{current} on-chain, file declares {declared} — apply sends one Safe \
                     transaction signed by the deployer"
                ),
            ),
            Some(Ok(current)) => {
                let calls: Vec<String> = current
                    .calls_to(&declared)
                    .iter()
                    .enumerate()
                    .map(|(i, data)| {
                        format!("{}. to {address:#x} value 0 data {data}", i + 1)
                    })
                    .collect();
                Item::new(
                    component,
                    Status::Warn,
                    format!(
                        "{current} on-chain, file declares {declared}. apply sends \
                         nothing: the owners sign this batch in the Safe app, each call \
                         from the Safe to itself: {}",
                        calls.join(" ")
                    ),
                )
            }
        }
    }
}

impl Planner<'_> {
    /// The Safe contracts, then every declared Safe, when the file declares
    /// any.
    pub(crate) async fn safes(&mut self) -> Result<()> {
        let cfg = self.cfg;
        if cfg.safes.is_empty() {
            return Ok(());
        }
        let mut canonical = true;
        for contract in SAFE_CONTRACTS {
            let check = SafeContractCode {
                contract,
                codehash: contract.codehash_at(&self.provider).await?,
            };
            canonical &= check.is_canonical();
            self.push(check);
        }
        if !canonical {
            return Ok(());
        }
        let deployer = cfg.accounts.deployer_address()?;
        for (name, declared) in &cfg.safes {
            let safe = Safe { name, deployer };
            let present = self.code(&format!("safes.{name}"), safe.address()).await?;
            let on_chain = if present {
                Some(
                    safe.owner_set(&self.provider)
                        .await
                        .map_err(|e| e.to_string()),
                )
            } else {
                None
            };
            self.push(SafeOwners {
                safe,
                declared: declared.owner_set(),
                on_chain,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::Address;

    use super::*;

    const DEPLOYER: Address = Address::repeat_byte(0xdd);
    const OWNER: Address = Address::repeat_byte(0xaa);

    fn check(on_chain: OwnerSet) -> Item {
        Item::from(SafeOwners {
            safe: Safe {
                name: "notary_fees",
                deployer: DEPLOYER,
            },
            declared: OwnerSet {
                owners: vec![OWNER],
                threshold: 1,
            },
            on_chain: Some(Ok(on_chain)),
        })
    }

    /// While the deployer signs alone, apply converges the owners.
    #[test]
    fn a_deployer_signing_alone_is_configured() {
        let item = check(OwnerSet {
            owners: vec![DEPLOYER],
            threshold: 1,
        });
        assert_eq!(item.status, Status::Configure);
    }

    /// Once the owners took over, the plan prints the calls they sign.
    #[test]
    fn after_the_hand_off_the_plan_prints_the_owner_calls() {
        let item = check(OwnerSet {
            owners: vec![Address::repeat_byte(0xbb), Address::repeat_byte(0xcc)],
            threshold: 2,
        });
        assert_eq!(item.status, Status::Warn);
        assert!(item.detail.contains("1. to 0x"), "{}", item.detail);
        assert!(item.detail.contains("3. to 0x"), "{}", item.detail);
    }

    /// A Safe without code is a deploy.
    #[test]
    fn a_missing_safe_is_a_deploy() {
        let item = Item::from(SafeOwners {
            safe: Safe {
                name: "notary_fees",
                deployer: DEPLOYER,
            },
            declared: OwnerSet {
                owners: vec![OWNER],
                threshold: 1,
            },
            on_chain: None,
        });
        assert_eq!(item.status, Status::Deploy);
    }
}
