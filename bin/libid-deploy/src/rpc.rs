//! Where the JSON-RPC calls go.
//!
//! A network file is the source of truth for what a chain should hold and
//! which chain that is. Where a node listens is a property of the caller's
//! environment, not of the network: `network.rpc_url` names the endpoint
//! the file's own environment reaches — a compose service name for
//! `local-dev`, a public URL for a real network — and `--rpc-url` names it
//! from anywhere else. The flag wins outright, the file is the default,
//! and an override that is unusable is an error, never a fallback. Nothing
//! but the transport moves: the declared chain id is enforced against
//! whatever answers, and every address stays a function of the file's
//! declarations.

use anyhow::{
    anyhow,
    bail,
    Result,
};
use url::Url;

use crate::config::NetworkConfig;

/// Parse an HTTP(S) JSON-RPC URL; `label` names its source in the error.
/// The transport is HTTP only, so any other scheme is rejected here rather
/// than at the first request.
pub fn parse_rpc_url(raw: &str, label: &str) -> Result<Url> {
    let url: Url = raw
        .trim()
        .parse()
        .map_err(|e| anyhow!("invalid {label} {raw:?}: {e}"))?;
    match url.scheme() {
        "http" | "https" => Ok(url),
        scheme => bail!(
            "invalid {label} {raw:?}: scheme '{scheme}' is not http or https — \
             libid-deploy speaks JSON-RPC over HTTP"
        ),
    }
}

/// The endpoint one command talks to, and where that choice came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcEndpoint {
    url: Url,
    /// The file's `network.rpc_url`, kept when `--rpc-url` bypassed it so
    /// prompts and logs can say so.
    bypassed: Option<String>,
}

impl RpcEndpoint {
    /// `--rpc-url` when given, else the file's `network.rpc_url`. An
    /// override that does not parse is an error naming the flag; nothing
    /// falls back to the file.
    pub fn resolve(cfg: &NetworkConfig, override_url: Option<&str>) -> Result<Self> {
        Ok(match override_url {
            Some(raw) => Self {
                url: parse_rpc_url(raw, "--rpc-url")?,
                bypassed: Some(cfg.network.rpc_url.clone()),
            },
            None => Self {
                url: parse_rpc_url(&cfg.network.rpc_url, "network.rpc_url")?,
                bypassed: None,
            },
        })
    }

    /// The endpoint to connect to.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Whether `--rpc-url` bypassed the file's value.
    pub fn is_override(&self) -> bool {
        self.bypassed.is_some()
    }

    /// For prompts, logs and errors: the endpoint and its provenance.
    pub fn describe(&self) -> String {
        match &self.bypassed {
            Some(file) => {
                format!("{} (--rpc-url; network.rpc_url names {file})", self.url)
            }
            None => format!("{} (network.rpc_url)", self.url),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(rpc_url: &str) -> NetworkConfig {
        let text = crate::config::tests::canonical_toml()
            .replace("http://localhost:8545", rpc_url);
        toml::from_str(&text).expect("canonical config parses")
    }

    /// No flag: the file's endpoint, and nothing says it was bypassed.
    #[test]
    fn the_file_is_the_default() {
        let rpc = RpcEndpoint::resolve(&config("http://anvil:8545"), None).unwrap();
        assert_eq!(rpc.url().as_str(), "http://anvil:8545/");
        assert!(!rpc.is_override());
        assert_eq!(rpc.describe(), "http://anvil:8545/ (network.rpc_url)");
    }

    /// The flag wins outright and the file's value is only reported.
    #[test]
    fn the_flag_beats_the_file() {
        let rpc = RpcEndpoint::resolve(
            &config("http://anvil:8545"),
            Some("http://127.0.0.1:8545"),
        )
        .unwrap();
        assert_eq!(rpc.url().as_str(), "http://127.0.0.1:8545/");
        assert!(rpc.is_override());
        assert_eq!(
            rpc.describe(),
            "http://127.0.0.1:8545/ (--rpc-url; network.rpc_url names \
             http://anvil:8545)"
        );
    }

    /// An override that does not parse is an error naming the flag, even
    /// though the file's endpoint is fine — no fallback.
    #[test]
    fn an_unparseable_override_is_an_error_not_a_fallback() {
        for bad in ["", "   ", "127.0.0.1:8545", "not a url"] {
            let err = RpcEndpoint::resolve(&config("http://anvil:8545"), Some(bad))
                .unwrap_err()
                .to_string();
            assert!(err.contains("--rpc-url"), "{bad:?}: {err}");
            assert!(err.contains(&format!("{bad:?}")), "{bad:?}: {err}");
        }
    }

    /// Only HTTP(S) is a transport this binary has; anything else fails
    /// before the first request, wherever it came from.
    #[test]
    fn a_non_http_scheme_is_rejected_from_either_source() {
        let err = RpcEndpoint::resolve(
            &config("http://anvil:8545"),
            Some("ws://127.0.0.1:8546"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("--rpc-url"), "{err}");
        assert!(err.contains("'ws'"), "{err}");

        let err = RpcEndpoint::resolve(&config("ws://anvil:8546"), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("network.rpc_url"), "{err}");
        assert!(err.contains("'ws'"), "{err}");
    }
}
