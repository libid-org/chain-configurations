//! Safe multisigs at addresses that depend only on the deployer and a name.
//!
//! A Safe proxy's CREATE2 address is a function of its factory, its
//! singleton, its `setup` call and a salt nonce. Every declared Safe is
//! created by the canonical Safe v1.4.1 `SafeProxyFactory` on the `SafeL2`
//! singleton, with `accounts.deployer` as its only owner, threshold 1, the
//! v1.4.1 `CompatibilityFallbackHandler` and the salt nonce
//! `keccak256("libid.safes.<name>")`. Those contracts sit at the same
//! address with the same code on every chain that has them, so one
//! deployer and one name give one Safe address on every EVM chain.
//!
//! The owners and threshold the file declares are set afterwards, by one
//! Safe transaction the deployer signs while it can still sign alone: a
//! `MultiSendCallOnly` batch of owner-manager calls from the Safe to itself.
//! The address never depends on them, so they can change without moving it.

use std::fmt;

use alloy::{
    primitives::{
        address,
        b256,
        keccak256,
        Address,
        Bytes,
        B256,
        U256,
    },
    providers::Provider,
    sol,
    sol_types::SolCall,
};
use anyhow::{
    anyhow,
    Result,
};

sol! {
    /// Safe v1.4.1 `SafeProxyFactory`.
    #[sol(rpc)]
    interface ISafeProxyFactory {
        /// CREATE2-deploys a proxy of `_singleton` and calls it with
        /// `initializer`; the salt is
        /// `keccak256(keccak256(initializer) ++ saltNonce)`.
        function createProxyWithNonce(
            address _singleton,
            bytes initializer,
            uint256 saltNonce
        ) external returns (address proxy);
    }

    /// Safe v1.4.1 `SafeL2`'s owner reads.
    #[sol(rpc)]
    interface ISafe {
        /// The owners, in linked-list order.
        function getOwners() external view returns (address[] owners);
        /// How many owner signatures a transaction needs.
        function getThreshold() external view returns (uint256 threshold);
    }

    /// Safe v1.4.1 `SafeL2`'s setup, owner manager and execution, sent
    /// through an [`ISafe`] instance's `call_builder`.
    interface ISafeCalls {
        /// Initializes a fresh proxy.
        function setup(
            address[] _owners,
            uint256 _threshold,
            address to,
            bytes data,
            address fallbackHandler,
            address paymentToken,
            uint256 payment,
            address paymentReceiver
        ) external;
        /// Executes a Safe transaction its owners signed.
        function execTransaction(
            address to,
            uint256 value,
            bytes data,
            uint8 operation,
            uint256 safeTxGas,
            uint256 baseGas,
            uint256 gasPrice,
            address gasToken,
            address refundReceiver,
            bytes signatures
        ) external payable returns (bool success);
        /// Inserts `owner` at the head of the list and sets the threshold.
        function addOwnerWithThreshold(address owner, uint256 _threshold) external;
        /// Unlinks `owner`, which follows `prevOwner`, and sets the
        /// threshold.
        function removeOwner(address prevOwner, address owner, uint256 _threshold) external;
        /// Sets the threshold.
        function changeThreshold(uint256 _threshold) external;
    }

    /// Safe v1.4.1 `MultiSendCallOnly`, delegatecalled by a Safe.
    interface IMultiSend {
        /// Runs packed `(operation, to, value, length, data)` calls in order.
        function multiSend(bytes transactions) external payable;
    }
}

/// The canonical Safe v1.4.1 `SafeProxyFactory`.
pub const PROXY_FACTORY: Address = address!("4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67");
/// The canonical Safe v1.4.1 `SafeL2` singleton. It emits an event per
/// executed transaction, which the Safe transaction service indexes on
/// chains without tracing; one singleton on every chain keeps one address.
pub const SINGLETON: Address = address!("29fcB43b46531BcA003ddC8FCB67FFE91900C762");
/// The canonical Safe v1.4.1 `CompatibilityFallbackHandler`.
pub const FALLBACK_HANDLER: Address =
    address!("fd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99");
/// The canonical Safe v1.4.1 `MultiSendCallOnly`.
pub const MULTI_SEND_CALL_ONLY: Address =
    address!("9641d764fc13c8B624c04430C7356C1C7C8102e2");

/// `keccak256(SafeProxy creation code ++ uint256(SINGLETON))`: the init code
/// hash of every proxy [`PROXY_FACTORY`] deploys on [`SINGLETON`].
pub const PROXY_INIT_CODE_HASH: B256 =
    b256!("e298282cefe913ab5d282047161268a8222e4bd4ed106300c547894bbefd31ee");

/// The head of a Safe's owner list, `prevOwner` of its first owner.
pub const SENTINEL_OWNERS: Address = address!("0000000000000000000000000000000000000001");

/// One Safe v1.4.1 contract every declared Safe depends on.
#[derive(Debug, Clone, Copy)]
pub struct SafeContract {
    /// Its plan line, under `safe_contracts.`.
    pub key: &'static str,
    /// The contract's name in the Safe release.
    pub name: &'static str,
    /// Its canonical address.
    pub address: Address,
    /// The code hash of its runtime code.
    pub codehash: B256,
}

/// The Safe v1.4.1 contracts a declared Safe is created and reconfigured
/// through.
pub const SAFE_CONTRACTS: [SafeContract; 4] = [
    SafeContract {
        key: "proxy_factory",
        name: "SafeProxyFactory",
        address: PROXY_FACTORY,
        codehash: b256!(
            "50c3cdc4074750a7a974204a716c999edd37482f907608d960b2b025ee0b3317"
        ),
    },
    SafeContract {
        key: "singleton",
        name: "SafeL2",
        address: SINGLETON,
        codehash: b256!(
            "b1f926978a0f44a2c0ec8fe822418ae969bd8c3f18d61e5103100339894f81ff"
        ),
    },
    SafeContract {
        key: "fallback_handler",
        name: "CompatibilityFallbackHandler",
        address: FALLBACK_HANDLER,
        codehash: b256!(
            "7c6007a5d711cea8dfd5d91f5940ec29c7f200fe511eb1fc1397b367af3c42f9"
        ),
    },
    SafeContract {
        key: "multi_send_call_only",
        name: "MultiSendCallOnly",
        address: MULTI_SEND_CALL_ONLY,
        codehash: b256!(
            "ecd5bd14a08c5d2122379900b2f272bdf107a7e92423c10dd5fe3254386c9939"
        ),
    },
];

impl SafeContract {
    /// The code hash at its address, `None` where the chain holds no code.
    pub async fn codehash_at<P: Provider>(&self, provider: &P) -> Result<Option<B256>> {
        let code = provider
            .get_code_at(self.address)
            .await
            .map_err(|e| anyhow!("get_code({}) failed: {e}", self.name))?;
        Ok((!code.is_empty()).then(|| keccak256(&code)))
    }
}

/// A Safe's owners and threshold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerSet {
    /// The owners; on-chain, in the Safe's list order.
    pub owners: Vec<Address>,
    /// How many of them must sign.
    pub threshold: u64,
}

impl OwnerSet {
    /// Whether both hold the same owners, in any order, and threshold.
    pub fn same_as(&self, other: &Self) -> bool {
        self.threshold == other.threshold
            && self.owners.len() == other.owners.len()
            && self.owners.iter().all(|o| other.owners.contains(o))
    }

    /// Whether `key` can execute a Safe transaction on its own signature.
    pub fn signs_alone(&self, key: Address) -> bool {
        self.threshold == 1 && self.owners.contains(&key)
    }

    /// The owner-manager calls, each from the Safe to itself, that turn
    /// this on-chain set into `target`: add the missing owners, remove the
    /// extra ones, then set the threshold. Every intermediate threshold
    /// stays within the owner count, so the batch never reverts on its own
    /// ordering.
    pub fn calls_to(&self, target: &OwnerSet) -> Vec<Bytes> {
        let mut list = self.owners.clone();
        let mut threshold = self.threshold;
        let mut calls = Vec::new();
        for &owner in target.owners.iter().rev() {
            if !list.contains(&owner) {
                calls.push(
                    ISafeCalls::addOwnerWithThresholdCall {
                        owner,
                        _threshold: U256::from(threshold),
                    }
                    .abi_encode()
                    .into(),
                );
                list.insert(0, owner);
            }
        }
        while let Some(index) = list.iter().position(|o| !target.owners.contains(o)) {
            let prev = match index {
                0 => SENTINEL_OWNERS,
                i => list[i - 1],
            };
            let owner = list.remove(index);
            threshold = threshold.min(list.len() as u64);
            calls.push(
                ISafeCalls::removeOwnerCall {
                    prevOwner: prev,
                    owner,
                    _threshold: U256::from(threshold),
                }
                .abi_encode()
                .into(),
            );
        }
        if threshold != target.threshold {
            calls.push(
                ISafeCalls::changeThresholdCall {
                    _threshold: U256::from(target.threshold),
                }
                .abi_encode()
                .into(),
            );
        }
        calls
    }
}

impl fmt::Display for OwnerSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} of [", self.threshold)?;
        for (i, owner) in self.owners.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{owner:#x}")?;
        }
        f.write_str("]")
    }
}

/// A Safe the network file declares under `[safes.<name>]`, created by
/// `deployer`.
#[derive(Debug, Clone, Copy)]
pub struct Safe<'a> {
    /// The table key, which names the Safe and fixes its salt.
    pub name: &'a str,
    /// `accounts.deployer`, the Safe's only owner at creation.
    pub deployer: Address,
}

impl Safe<'_> {
    /// The salt nonce: `keccak256("libid.safes.<name>")`.
    pub fn salt_nonce(&self) -> U256 {
        U256::from_be_bytes(keccak256(format!("libid.safes.{}", self.name)).0)
    }

    /// The `setup` call the proxy is created with.
    pub fn initializer(&self) -> Bytes {
        ISafeCalls::setupCall {
            _owners: vec![self.deployer],
            _threshold: U256::from(1),
            to: Address::ZERO,
            data: Bytes::new(),
            fallbackHandler: FALLBACK_HANDLER,
            paymentToken: Address::ZERO,
            payment: U256::ZERO,
            paymentReceiver: Address::ZERO,
        }
        .abi_encode()
        .into()
    }

    /// The owners the Safe is created with: the deployer alone.
    pub fn bootstrap_owners(&self) -> OwnerSet {
        OwnerSet {
            owners: vec![self.deployer],
            threshold: 1,
        }
    }

    /// Where [`PROXY_FACTORY`] deploys it, on every chain.
    pub fn address(&self) -> Address {
        let mut salt = keccak256(self.initializer()).to_vec();
        salt.extend_from_slice(&self.salt_nonce().to_be_bytes::<32>());
        PROXY_FACTORY.create2(keccak256(salt), PROXY_INIT_CODE_HASH)
    }

    /// Its owners and threshold on-chain.
    pub async fn owner_set<P: Provider>(&self, provider: &P) -> Result<OwnerSet> {
        let safe = ISafe::new(self.address(), provider);
        let owners =
            safe.getOwners().call().await.map_err(|e| {
                anyhow!("Safe '{}' getOwners read failed: {e}", self.name)
            })?;
        let threshold =
            safe.getThreshold().call().await.map_err(|e| {
                anyhow!("Safe '{}' getThreshold read failed: {e}", self.name)
            })?;
        Ok(OwnerSet {
            owners,
            threshold: threshold.try_into().map_err(|e| {
                anyhow!("Safe '{}' threshold {threshold}: {e}", self.name)
            })?,
        })
    }

    /// The factory call that creates it.
    pub fn create_call(&self) -> ISafeProxyFactory::createProxyWithNonceCall {
        ISafeProxyFactory::createProxyWithNonceCall {
            _singleton: SINGLETON,
            initializer: self.initializer(),
            saltNonce: self.salt_nonce(),
        }
    }

    /// The Safe transaction that runs `calls` (each from the Safe to
    /// itself) in one batch, signed by the transaction's sender, the
    /// deployer: a Safe accepts a pre-validated signature from the owner
    /// that sends `execTransaction`.
    pub fn exec_batch(&self, calls: &[Bytes]) -> ISafeCalls::execTransactionCall {
        let safe = self.address();
        let mut packed = Vec::new();
        for data in calls {
            packed.push(0u8);
            packed.extend_from_slice(safe.as_slice());
            packed.extend_from_slice(&U256::ZERO.to_be_bytes::<32>());
            packed.extend_from_slice(&U256::from(data.len()).to_be_bytes::<32>());
            packed.extend_from_slice(data);
        }
        let mut signature = B256::left_padding_from(self.deployer.as_slice()).to_vec();
        signature.extend_from_slice(B256::ZERO.as_slice());
        signature.push(1);
        ISafeCalls::execTransactionCall {
            to: MULTI_SEND_CALL_ONLY,
            value: U256::ZERO,
            data: IMultiSend::multiSendCall {
                transactions: packed.into(),
            }
            .abi_encode()
            .into(),
            // DelegateCall: MultiSendCallOnly runs as the Safe, so each call
            // in the batch comes from the Safe itself.
            operation: 1,
            safeTxGas: U256::ZERO,
            baseGas: U256::ZERO,
            gasPrice: U256::ZERO,
            gasToken: Address::ZERO,
            refundReceiver: Address::ZERO,
            signatures: signature.into(),
        }
    }
}

/// The address table of `deployer`'s Safes, one line per name. Pure
/// computation, no RPC.
pub fn render_address_table<'a>(
    deployer: Address,
    names: impl IntoIterator<Item = &'a String>,
) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    for name in names {
        let safe = Safe { name, deployer };
        let _ = writeln!(
            out,
            "  {:<34} {:<34} {:#x}",
            format!("safes.{name}"),
            "(Safe v1.4.1, deployer 1-of-1)",
            safe.address()
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use alloy::sol_types::SolCall;

    use super::*;

    const A: Address = Address::repeat_byte(0xaa);
    const B: Address = Address::repeat_byte(0xbb);
    const C: Address = Address::repeat_byte(0xcc);
    const D: Address = Address::repeat_byte(0xdd);

    fn set(owners: &[Address], threshold: u64) -> OwnerSet {
        OwnerSet {
            owners: owners.to_vec(),
            threshold,
        }
    }

    /// Plays `calls` against an owner list the way Safe's OwnerManager
    /// does, refusing what it refuses.
    fn replay(start: &OwnerSet, calls: &[Bytes]) -> OwnerSet {
        let mut list = start.owners.clone();
        let mut threshold = start.threshold;
        for call in calls {
            if let Ok(add) = ISafeCalls::addOwnerWithThresholdCall::abi_decode(call) {
                assert!(!list.contains(&add.owner), "GS204");
                list.insert(0, add.owner);
                threshold = add._threshold.to();
            } else if let Ok(remove) = ISafeCalls::removeOwnerCall::abi_decode(call) {
                assert!(list.len() as u64 > remove._threshold.to::<u64>(), "GS201");
                let index = list.iter().position(|o| *o == remove.owner).expect("GS205");
                let prev = if index == 0 {
                    SENTINEL_OWNERS
                } else {
                    list[index - 1]
                };
                assert_eq!(prev, remove.prevOwner, "GS205");
                list.remove(index);
                threshold = remove._threshold.to();
            } else {
                let change = ISafeCalls::changeThresholdCall::abi_decode(call).unwrap();
                threshold = change._threshold.to();
            }
            assert!(
                threshold >= 1 && threshold <= list.len() as u64,
                "GS201/202"
            );
        }
        set(&list, threshold)
    }

    /// The bootstrap hands over to a 2-of-3 without the deployer.
    #[test]
    fn the_bootstrap_hands_over_to_the_declared_owners() {
        let start = set(&[D], 1);
        let target = set(&[A, B, C], 2);
        let calls = start.calls_to(&target);
        assert_eq!(calls.len(), 5);
        let end = replay(&start, &calls);
        assert_eq!(end, set(&[A, B, C], 2), "the list reads in declared order");
    }

    /// A deployer the file lists stays an owner.
    #[test]
    fn a_listed_deployer_stays() {
        let start = set(&[D], 1);
        let target = set(&[D, A], 2);
        assert!(replay(&start, &start.calls_to(&target)).same_as(&target));
    }

    /// Owners removed from the middle, the head and the tail, under a
    /// threshold that has to drop on the way.
    #[test]
    fn removals_keep_every_intermediate_threshold_valid() {
        let start = set(&[A, B, C, D], 4);
        let target = set(&[B], 1);
        assert!(replay(&start, &start.calls_to(&target)).same_as(&target));
    }

    /// A matching set, in another order, needs nothing.
    #[test]
    fn a_matching_set_needs_no_call() {
        let start = set(&[B, A], 2);
        assert!(start.same_as(&set(&[A, B], 2)));
        assert!(start.calls_to(&set(&[A, B], 2)).is_empty());
    }

    /// The salt nonce and the address follow from the name and the
    /// deployer alone.
    #[test]
    fn the_address_moves_with_the_name_and_the_deployer_only() {
        let notary = Safe {
            name: "notary_fees",
            deployer: D,
        };
        let registry = Safe {
            name: "registry_fees",
            deployer: D,
        };
        let other = Safe {
            name: "notary_fees",
            deployer: A,
        };
        assert_eq!(
            notary.salt_nonce(),
            U256::from_be_bytes(keccak256("libid.safes.notary_fees").0)
        );
        assert_ne!(notary.address(), registry.address());
        assert_ne!(notary.address(), other.address());
        assert_eq!(
            notary.address(),
            Safe {
                name: "notary_fees",
                deployer: D,
            }
            .address()
        );
    }

    /// The batch is a delegatecall to MultiSendCallOnly with the sender's
    /// pre-validated signature.
    #[test]
    fn the_batch_carries_a_pre_validated_signature() {
        let safe = Safe {
            name: "notary_fees",
            deployer: D,
        };
        let exec = safe.exec_batch(&safe.bootstrap_owners().calls_to(&set(&[A], 1)));
        assert_eq!(exec.to, MULTI_SEND_CALL_ONLY);
        assert_eq!(exec.operation, 1);
        assert_eq!(exec.signatures.len(), 65);
        assert_eq!(&exec.signatures[12..32], D.as_slice());
        assert_eq!(exec.signatures[64], 1);
    }
}
