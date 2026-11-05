//! Deploying the referral splitter and converging its settings.

use alloy::primitives::U256;
use anyhow::{
    anyhow,
    bail,
    Result,
};
use libid_contracts::{
    bindings::{
        escrow::HandleEscrow,
        identity::IdentityRegistry,
        referral::ReferralSplitter,
    },
    send_with_nonce_retry,
};

use super::{
    Applier,
    Upgrade,
};
use crate::{
    names,
    splitter::{
        Change,
        FeeCall,
    },
};

impl Applier<'_> {
    /// Whether the declared splitter still has to deploy through the
    /// factory. Refuses, before anything is sent, a splitter the identity
    /// registry would never pay: one whose implementation predates
    /// `bindWithFeeCall` and that this run does not upgrade.
    pub(crate) async fn splitter_deploys(
        &self,
        identity_registry_present: bool,
    ) -> Result<bool> {
        let Some(splitter) = self.cfg.splitter()? else {
            return Ok(false);
        };
        let registry = self.stack.identity_registry;
        if identity_registry_present
            && !self.opts.upgrades.contains(&Upgrade::IdentityRegistry)
            && !IdentityRegistry::new(registry, &self.provider)
                .calls_fee_receiver()
                .await?
        {
            bail!(
                "contracts.referral_splitter is declared but the IdentityRegistry at \
                 {registry:#x} predates bindWithFeeCall, so no bind would pay the \
                 splitter: apply --upgrade identity-registry"
            );
        }
        Ok(!self.code_present(splitter.address).await?)
    }

    /// The referral splitter, on a network that declares one: deployed after
    /// the escrow it pays through, owned by the identity registry's owner,
    /// and moved onto the declared settings while the deployer owns it. A
    /// splitter another key owns is reported with the calls that key signs.
    pub(crate) async fn referral_splitter(&mut self) -> Result<()> {
        let Some(splitter) = self.cfg.splitter()? else {
            return Ok(());
        };
        let stack = self.stack;
        if !self.code_present(splitter.address).await? {
            let owner = IdentityRegistry::new(stack.identity_registry, &self.provider)
                .owner()
                .call()
                .await
                .map_err(|e| anyhow!("IdentityRegistry.owner read failed: {e}"))?;
            let code = splitter.creation_code(&self.artifacts, &stack, owner)?;
            let addr = self
                .factory_deploy_named(names::REFERRAL_SPLITTER, code)
                .await?;
            tracing::info!(
                %addr,
                name = names::REFERRAL_SPLITTER,
                %owner,
                "ReferralSplitter deployed"
            );
            debug_assert_eq!(addr, splitter.address);
            self.summary
                .deployed
                .push(("contracts.referral_splitter".into(), addr));
        }

        let on_chain = splitter.on_chain(&self.provider).await?;
        if !on_chain.wired_to(&stack) {
            bail!(
                "the ReferralSplitter at {:#x} takes fees from {:#x} and pays through \
                 {:#x}, not the declared IdentityRegistry {:#x} and HandleEscrow {:#x}. \
                 Neither moves: a new canonical splitter name deploys another",
                splitter.address,
                on_chain.registry,
                on_chain.escrow,
                stack.identity_registry,
                stack.handle_escrow
            );
        }
        let changes = on_chain.settings.changes_to(&splitter.settings);
        if changes.is_empty() {
            return Ok(());
        }
        let calls = changes
            .iter()
            .map(Change::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        if on_chain.owner != self.sender {
            tracing::warn!(
                owner = %on_chain.owner,
                %calls,
                "ReferralSplitter settings differ from the file; its owner signs the change"
            );
            self.summary.configured.push(format!(
                "referral_splitter NOT converged: its owner {:#x} signs {calls}",
                on_chain.owner
            ));
            return Ok(());
        }

        // `setExpiry` refuses a nonzero expiry under the escrow's refund
        // grace: checked before the first call is sent.
        let expiry = changes.iter().find_map(|change| match change {
            Change::Expiry(expiry) if expiry.seconds() != 0 => Some(*expiry),
            _ => None,
        });
        if let Some(expiry) = expiry {
            let grace = HandleEscrow::new(stack.handle_escrow, &self.provider)
                .REFUND_GRACE()
                .call()
                .await
                .map_err(|e| anyhow!("HandleEscrow.REFUND_GRACE read failed: {e}"))?;
            if U256::from(expiry.seconds()) < grace {
                bail!(
                    "referral_splitter.expiry is {expiry} but the splitter takes none \
                     under the escrow's refund grace of {grace} seconds"
                );
            }
        }

        let contract = ReferralSplitter::new(splitter.address, &self.provider);
        for change in changes {
            let label = format!("ReferralSplitter.{change}");
            match change {
                Change::Treasury(treasury) => send_with_nonce_retry!(
                    contract.setTreasury(treasury),
                    label,
                    &self.provider,
                    self.sender
                )?,
                Change::Share(share_bps) => send_with_nonce_retry!(
                    contract.setShare(share_bps),
                    label,
                    &self.provider,
                    self.sender
                )?,
                Change::MinReferralFee(fee) => send_with_nonce_retry!(
                    contract.setMinReferralFee(fee),
                    label,
                    &self.provider,
                    self.sender
                )?,
                Change::Expiry(expiry) => send_with_nonce_retry!(
                    contract.setExpiry(expiry.seconds()),
                    label,
                    &self.provider,
                    self.sender
                )?,
            };
        }
        tracing::info!(%calls, "ReferralSplitter settings converged");
        self.summary
            .configured
            .push(format!("referral splitter {calls}"));
        Ok(())
    }
}
