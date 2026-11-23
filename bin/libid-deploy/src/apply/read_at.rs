//! The block a read of a contract goes to: `latest`, or the block that
//! mined a transaction this run sent.

use std::{
    future::Future,
    time::Duration,
};

use alloy::{
    eips::BlockId,
    rpc::types::TransactionReceipt,
};
use anyhow::Result;
use libid_contracts::deploy::Mined;

/// Tries of a read at a mined block. The n-th retry waits n seconds, so
/// five tries span 10 s.
const TRIES: u32 = 5;

/// Where a read goes.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ReadAt {
    /// `latest`, for state no transaction of this run has just changed.
    Latest,
    /// The block that mined a transaction this run sent. A load-balanced
    /// RPC can route the read to a backend that has not seen it yet, which
    /// answers an error such as `header not found`, so a failed read is
    /// tried again.
    Mined(BlockId),
}

impl ReadAt {
    /// The block that mined `receipt`.
    pub(crate) fn of(receipt: &TransactionReceipt) -> Self {
        Self::Mined(receipt.block())
    }

    /// `read`, given the block to read at. At a mined block a failed read is
    /// tried again, up to [`TRIES`] times in all.
    pub(crate) async fn read<T, F, Fut>(self, what: &str, read: F) -> Result<T>
    where
        F: Fn(BlockId) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let Self::Mined(block) = self else {
            return read(BlockId::latest()).await;
        };
        for attempt in 1..TRIES {
            match read(block).await {
                Ok(answer) => return Ok(answer),
                Err(error) => {
                    tracing::warn!(
                        what,
                        attempt,
                        error = %format!("{error:#}"),
                        "read at the block that mined it failed; trying again"
                    );
                    tokio::time::sleep(Duration::from_secs(u64::from(attempt))).await;
                }
            }
        }
        read(block).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{
        AtomicU32,
        Ordering,
    };

    use alloy::primitives::B256;
    use anyhow::bail;
    use tokio::time::Instant;

    use super::*;

    /// A read that fails its first `failures` calls, counting every call.
    struct Flaky {
        failures: u32,
        calls: AtomicU32,
    }

    impl Flaky {
        fn new(failures: u32) -> Self {
            Self {
                failures,
                calls: AtomicU32::new(0),
            }
        }

        async fn read(&self, _block: BlockId) -> Result<u32> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call <= self.failures {
                bail!("header not found");
            }
            Ok(call)
        }

        fn calls(&self) -> u32 {
            self.calls.load(Ordering::SeqCst)
        }
    }

    fn mined() -> ReadAt {
        ReadAt::Mined(BlockId::hash(B256::repeat_byte(1)))
    }

    #[tokio::test(start_paused = true)]
    async fn a_read_at_a_mined_block_is_tried_again_until_it_answers() {
        let flaky = Flaky::new(2);
        let started = Instant::now();
        let answer = mined()
            .read("probe", |block| flaky.read(block))
            .await
            .expect("the third try answers");
        assert_eq!(answer, 3);
        assert_eq!(started.elapsed(), Duration::from_secs(3));
    }

    #[tokio::test(start_paused = true)]
    async fn a_read_at_a_mined_block_stops_after_five_tries_over_ten_seconds() {
        let flaky = Flaky::new(u32::MAX);
        let started = Instant::now();
        let error = mined()
            .read("probe", |block| flaky.read(block))
            .await
            .expect_err("every try fails");
        assert_eq!(error.to_string(), "header not found");
        assert_eq!(flaky.calls(), TRIES);
        assert_eq!(started.elapsed(), Duration::from_secs(10));
    }

    #[tokio::test(start_paused = true)]
    async fn a_read_at_latest_is_tried_once() {
        let flaky = Flaky::new(1);
        ReadAt::Latest
            .read("probe", |block| flaky.read(block))
            .await
            .expect_err("no second try");
        assert_eq!(flaky.calls(), 1);
    }
}
