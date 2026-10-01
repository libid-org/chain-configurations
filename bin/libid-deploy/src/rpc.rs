//! Where the JSON-RPC calls go.
//!
//! A network file is the source of truth for what a chain should hold and
//! which chain that is. Where a node listens is a property of the caller's
//! environment, not of the network, so a real network's file names no
//! endpoint: the apply workflow passes the `RPC_URL` secret of the
//! network's GitHub environment, and a host passes a URL, both as
//! `--rpc-url`. A file may still name the endpoint its own environment
//! reaches — `local-dev` names its compose service — and then the flag
//! wins outright, the file is the default, and an override that is
//! unusable is an error, never a fallback. Nothing but the transport
//! moves: the declared chain id is enforced against whatever answers, and
//! every address stays a function of the file's declarations.

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
    source: Source,
}

/// Where an endpoint came from.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Source {
    /// `--rpc-url`, with the origin of the file's endpoint when the file
    /// names one, so prompts and logs can say what was bypassed.
    Flag { file: Option<String> },
    /// The file's `network.rpc_url`.
    File,
}

/// An endpoint as a line of output names it: scheme, host and port. A
/// private endpoint carries its provider's key in the path or the query,
/// and these lines reach terminals and step summaries.
fn origin_of(url: &Url) -> String {
    url.origin().ascii_serialization()
}

impl RpcEndpoint {
    /// `--rpc-url` when given, else the file's `network.rpc_url`. An
    /// override that does not parse is an error naming the flag; nothing
    /// falls back to the file. Neither at all is an error naming both
    /// places an endpoint comes from.
    pub fn resolve(cfg: &NetworkConfig, override_url: Option<&str>) -> Result<Self> {
        Ok(match (override_url, cfg.network.rpc_url()) {
            (Some(raw), file) => Self {
                url: parse_rpc_url(raw, "--rpc-url")?,
                source: Source::Flag {
                    file: file
                        .map(|f| {
                            parse_rpc_url(f, "network.rpc_url").map(|u| origin_of(&u))
                        })
                        .transpose()?,
                },
            },
            (None, Some(raw)) => Self {
                url: parse_rpc_url(raw, "network.rpc_url")?,
                source: Source::File,
            },
            (None, None) => bail!(
                "no endpoint for '{name}': the network file names none, as a real \
                 network's does not, and no --rpc-url was given — pass --rpc-url on \
                 a host; in the apply workflow set the RPC_URL secret of the \
                 '{name}' GitHub environment",
                name = cfg.network.name
            ),
        })
    }

    /// The endpoint to connect to.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Whether `--rpc-url` named the endpoint.
    pub fn is_override(&self) -> bool {
        matches!(self.source, Source::Flag { .. })
    }

    /// The endpoint by origin: scheme, host and port, never the path or
    /// the query, where a private endpoint carries its key.
    pub fn origin(&self) -> String {
        origin_of(&self.url)
    }

    /// For prompts, logs and errors: the endpoint, by origin, and its
    /// provenance.
    pub fn describe(&self) -> String {
        match &self.source {
            Source::Flag { file: Some(file) } => {
                format!(
                    "{} (--rpc-url; network.rpc_url names {file})",
                    self.origin()
                )
            }
            Source::Flag { file: None } => {
                format!("{} (--rpc-url; the file names no endpoint)", self.origin())
            }
            Source::File => format!("{} (network.rpc_url)", self.origin()),
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
        assert_eq!(rpc.describe(), "http://anvil:8545 (network.rpc_url)");
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
            "http://127.0.0.1:8545 (--rpc-url; network.rpc_url names \
             http://anvil:8545)"
        );
    }

    /// A private endpoint carries its key in the path or the query. The
    /// transport keeps the whole URL; what is written about it is the
    /// origin, so the key reaches no log, prompt or step summary.
    #[test]
    fn a_keyed_endpoint_is_named_by_its_origin_alone() {
        let keyed = "https://eth-sepolia.example/v2/4ba1ed2eKEY?token=TOKEN";
        let rpc =
            RpcEndpoint::resolve(&config("http://anvil:8545"), Some(keyed)).unwrap();
        assert_eq!(rpc.url().as_str(), keyed);
        assert_eq!(rpc.origin(), "https://eth-sepolia.example");
        assert_eq!(
            rpc.describe(),
            "https://eth-sepolia.example (--rpc-url; network.rpc_url names \
             http://anvil:8545)"
        );
        for secret in ["4ba1ed2eKEY", "TOKEN", "/v2/"] {
            assert!(!rpc.describe().contains(secret), "{}", rpc.describe());
        }
    }

    /// A real network's file names no endpoint. The flag serves it, and
    /// the description says the file had nothing to bypass.
    #[test]
    fn the_flag_serves_a_file_that_names_no_endpoint() {
        let rpc =
            RpcEndpoint::resolve(&config(""), Some("http://127.0.0.1:8545")).unwrap();
        assert_eq!(rpc.url().as_str(), "http://127.0.0.1:8545/");
        assert!(rpc.is_override());
        assert_eq!(
            rpc.describe(),
            "http://127.0.0.1:8545 (--rpc-url; the file names no endpoint)"
        );
    }

    /// Without the flag, such a file is an error naming both places an
    /// endpoint comes from — never a guess.
    #[test]
    fn a_file_without_an_endpoint_needs_the_flag() {
        let err = RpcEndpoint::resolve(&config(""), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--rpc-url"), "{err}");
        assert!(err.contains("RPC_URL secret"), "{err}");
        assert!(err.contains("'canonical-test'"), "{err}");
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
