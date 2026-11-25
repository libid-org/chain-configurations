//! Desired-state deployment for the libid contract stack.
//!
//! A network file under `networks/` describes what should exist on a chain;
//! this crate compares it with what does ([`plan`]) and converges the chain
//! ([`apply`]). The file is declarative and never rewritten: every
//! canonical address is a CREATE3 function of a frozen name, and an
//! implementation's or a circuit verifier's a CREATE2 function of its code,
//! so the table is known before the chain has anything on it.
//!
//! Everything on-chain goes through the `libid-contracts` crate: typed
//! bindings, embedded forge artifacts (zero filesystem dependencies at
//! runtime, the ceremony circuits' Honk verifiers included), and the
//! deploy/upgrade primitives. The platform tables come from
//! `libid-identity` and `libid-profiles`, generated from the same sources
//! the contracts are. What this crate adds is WHERE things land
//! ([`names`], [`code`], [`circuits`]) and the convergence that puts them there,
//! the referral splitter a bind pays its fee to ([`splitter`]), the Safe
//! multisigs a network holds beside the stack ([`safes`]), and the testnet
//! addresses the deployer tops up ([`funding`]).

pub mod apply;
pub mod circuits;
pub mod code;
pub mod config;
pub mod funding;
pub mod names;
pub mod plan;
pub mod platforms;
pub mod rpc;
pub mod safes;
pub mod signer;
pub mod splitter;
