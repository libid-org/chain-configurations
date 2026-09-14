//! Desired-state deployment for the libid contract stack.
//!
//! A network file under `networks/` describes what should exist on a chain;
//! this crate compares it with what does ([`plan`]) and converges the chain
//! ([`apply`]). The file is declarative and never rewritten: every
//! canonical address is a CREATE3 function of a frozen name, so the table
//! is known before the chain has anything on it.
//!
//! Everything on-chain goes through the `libid-contracts` crate: typed
//! bindings, embedded forge artifacts (zero filesystem dependencies at
//! runtime), and the deploy/upgrade primitives. The platform tables come
//! from `libid-identity` and `libid-profiles`, generated from the same
//! sources the contracts are.

pub mod apply;
pub mod config;
pub mod names;
pub mod plan;
pub mod platforms;
pub mod signer;
