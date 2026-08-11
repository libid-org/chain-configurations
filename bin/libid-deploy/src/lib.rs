//! Desired-state deployment for the libid contract stack.
//!
//! A network file under `networks/` describes what should exist on a chain;
//! this crate compares it with what does ([`plan`]), converges the chain
//! ([`apply`]), and writes the deployed addresses back into the file so the
//! configuration catches up with reality.
//!
//! Everything on-chain goes through the `libid-contracts` crate: typed
//! bindings, embedded forge artifacts (zero filesystem dependencies at
//! runtime), and the deploy/upgrade primitives.

pub mod apply;
pub mod config;
pub mod plan;
pub mod platforms;
pub mod signer;
