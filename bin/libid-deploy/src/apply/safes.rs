//! Creating the declared Safes and handing each to its declared owners.

use anyhow::{
    bail,
    Result,
};
use libid_contracts::send_with_nonce_retry;

use super::Applier;
use crate::safes::{
    ISafe,
    ISafeProxyFactory,
    OwnerSet,
    Safe,
    PROXY_FACTORY,
    SAFE_CONTRACTS,
};

impl Applier<'_> {
    /// Create every declared Safe the chain lacks, and set the declared
    /// owners and threshold on each one the deployer can still sign for
    /// alone. A Safe its owners have taken over is reported, never sent to.
    pub(crate) async fn safes(&mut self) -> Result<()> {
        let cfg = self.cfg;
        if cfg.safes.is_empty() {
            return Ok(());
        }
        for contract in SAFE_CONTRACTS {
            let codehash = contract.codehash_at(&self.provider).await?;
            if codehash != Some(contract.codehash) {
                bail!(
                    "{:#x} on '{}' holds no Safe v1.4.1 {} (codehash {codehash:?}); every \
                     declared Safe is created and configured through it",
                    contract.address,
                    cfg.network.name,
                    contract.name
                );
            }
        }
        for (name, declared) in &cfg.safes {
            let safe = Safe {
                name,
                deployer: self.sender,
            };
            self.safe(safe, declared.owner_set()).await?;
        }
        Ok(())
    }

    /// One Safe: created as the deployer's 1-of-1 when missing, then moved
    /// onto `declared` in one Safe transaction while the deployer signs
    /// alone.
    async fn safe(&mut self, safe: Safe<'_>, declared: OwnerSet) -> Result<()> {
        let address = safe.address();
        let component = format!("safes.{}", safe.name);
        if !self.code_present(address).await? {
            let factory = ISafeProxyFactory::new(PROXY_FACTORY, &self.provider);
            send_with_nonce_retry!(
                factory.call_builder(&safe.create_call()),
                format!("SafeProxyFactory.createProxyWithNonce({})", safe.name),
                &self.provider,
                self.sender
            )?;
            if !self.code_present(address).await? {
                bail!(
                    "createProxyWithNonce for Safe '{}' left no code at its predicted \
                     address {address:#x}",
                    safe.name
                );
            }
            tracing::info!(name = safe.name, %address, "Safe created");
            self.summary.deployed.push((component.clone(), address));
        }

        let current = safe.owner_set(&self.provider).await?;
        if current.same_as(&declared) {
            return Ok(());
        }
        if !current.signs_alone(self.sender) {
            tracing::warn!(
                name = safe.name,
                %address,
                on_chain = %current,
                declared = %declared,
                "Safe owners differ from the file; the owners sign the change"
            );
            self.summary.configured.push(format!(
                "{component} NOT converged: {current} on-chain, file declares {declared} \
                 — the owners sign the calls `plan` prints"
            ));
            return Ok(());
        }

        let exec = safe.exec_batch(&current.calls_to(&declared));
        send_with_nonce_retry!(
            ISafe::new(address, &self.provider).call_builder(&exec),
            format!("Safe.execTransaction({})", safe.name),
            &self.provider,
            self.sender
        )?;
        let after = safe.owner_set(&self.provider).await?;
        if !after.same_as(&declared) {
            bail!(
                "Safe '{}' at {address:#x} holds {after} after its owner change, file \
                 declares {declared}",
                safe.name
            );
        }
        tracing::info!(name = safe.name, %address, from = %current, to = %declared, "Safe owners set");
        self.summary
            .configured
            .push(format!("{component} {current} -> {declared}"));
        Ok(())
    }
}
