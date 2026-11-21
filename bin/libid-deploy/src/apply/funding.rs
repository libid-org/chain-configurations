//! Topping up the declared `[funding.<name>]` addresses from the deployer.

use alloy::{
    eips::BlockId,
    network::TransactionBuilder,
    providers::Provider,
    rpc::types::TransactionRequest,
};
use anyhow::{
    anyhow,
    Result,
};
use libid_contracts::deploy::Mined;

use super::Applier;
use crate::funding::TopUp;

impl Applier<'_> {
    /// Each declared address below its target: sent the shortfall under
    /// `--fund`, recorded in the summary otherwise. An address at or above
    /// its target gets nothing, so a rerun sends nothing more.
    pub(crate) async fn funding(&mut self) -> Result<()> {
        for funding in self.cfg.funding()? {
            let balance = funding.balance(&self.provider, BlockId::latest()).await?;
            let Some(top_up) = funding.top_up(balance) else {
                continue;
            };
            if self.opts.fund {
                self.send_top_up(&top_up).await?;
                self.summary.funded.push(top_up);
            } else {
                tracing::info!(
                    name = %funding.name,
                    address = %funding.address,
                    %balance,
                    target = %funding.target,
                    amount = %top_up.amount(),
                    "below its funding target; apply --fund sends the amount"
                );
                self.summary.underfunded.push(top_up);
            }
        }
        Ok(())
    }

    /// Send `top_up`'s amount from the deployer and read the balance it
    /// left, in the block that mined it. A balance still below the target
    /// there means the address spent in that block, which is no error.
    async fn send_top_up(&self, top_up: &TopUp) -> Result<()> {
        let funding = &top_up.funding;
        let label = funding.component();
        let amount = top_up.amount();
        let nonce = self
            .provider
            .get_transaction_count(self.sender)
            .await
            .map_err(|e| anyhow!("{label} top-up failed to fetch nonce: {e}"))?;
        let tx = TransactionRequest::default()
            .with_to(funding.address)
            .with_value(amount)
            .with_nonce(nonce);
        let receipt = self
            .provider
            .send_transaction(tx)
            .await
            .map_err(|e| anyhow!("{label} top-up send failed: {e}"))?
            .get_receipt()
            .await
            .map_err(|e| anyhow!("{label} top-up confirmation failed: {e}"))?
            .succeeded(&format!("{label} top-up"))?;
        let after = funding.balance(&self.provider, receipt.block()).await?;
        if after < funding.target {
            tracing::warn!(
                name = %funding.name,
                address = %funding.address,
                %amount,
                balance = %after,
                target = %funding.target,
                tx = %receipt.transaction_hash,
                "top-up sent, but the address holds less than its target after the \
                 block that mined it"
            );
        } else {
            tracing::info!(
                name = %funding.name,
                address = %funding.address,
                %amount,
                balance = %after,
                tx = %receipt.transaction_hash,
                "address topped up"
            );
        }
        Ok(())
    }
}
