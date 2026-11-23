//! A JSON-RPC endpoint in front of anvil that answers one kind of request
//! the way a load-balanced production endpoint can get it wrong. Every
//! other request passes through unchanged.

use std::convert::Infallible;

use alloy::{
    eips::BlockId,
    primitives::U64,
    providers::{
        DynProvider,
        Provider,
        ProviderBuilder,
    },
    rpc::json_rpc::{
        Id,
        Response,
        ResponsePayload,
        RpcError,
    },
};
use http_body_util::{
    BodyExt,
    Full,
};
use hyper::{
    body::{
        Bytes,
        Incoming,
    },
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::value::{
    to_raw_value,
    RawValue,
};
use tokio::{
    net::TcpListener,
    task::JoinHandle,
};
use url::Url;

/// The state reads that [`Skew::LatestBehind`] answers one block behind,
/// each with the position of its block parameter.
const LAGGED: [(&str, usize); 3] =
    [("eth_call", 1), ("eth_getCode", 1), ("eth_getStorageAt", 2)];

/// What the endpoint gets wrong.
#[derive(Debug, Clone, Copy)]
pub enum Skew {
    /// A state read at `latest` answers from the block before the head: the
    /// backend serving it has not seen the block that mined the transaction
    /// just confirmed. A read at a named block is answered there.
    LatestBehind,
    /// `eth_estimateGas` answers half the gas the transaction needs, so it
    /// is mined and runs out of gas.
    HalfGasEstimate,
}

/// The endpoint, serving until it is dropped.
pub struct SkewedRpc {
    endpoint: String,
    server: JoinHandle<()>,
}

impl SkewedRpc {
    /// Serve on a free local port, forwarding to `upstream` with `skew`.
    pub async fn start(upstream: Url, skew: Skew) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let upstream = Upstream {
            node: ProviderBuilder::new().connect_http(upstream).erased(),
            skew,
        };
        let server = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.expect("accept");
                let upstream = upstream.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request: hyper::Request<Incoming>| {
                        let upstream = upstream.clone();
                        async move {
                            let body = request
                                .into_body()
                                .collect()
                                .await
                                .expect("request body")
                                .to_bytes();
                            Ok::<_, Infallible>(hyper::Response::new(Full::new(
                                upstream.answer(&body).await,
                            )))
                        }
                    });
                    http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await
                        .expect("serve");
                });
            }
        });
        Self { endpoint, server }
    }

    /// `http://127.0.0.1:<port>`.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

impl Drop for SkewedRpc {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// A JSON-RPC request, its `params` left out by a method that takes none.
#[derive(Deserialize)]
struct Call {
    id: Id,
    method: String,
    #[serde(default)]
    params: Vec<Box<RawValue>>,
}

/// The node behind the endpoint, and what the endpoint gets wrong.
#[derive(Clone)]
struct Upstream {
    node: DynProvider,
    skew: Skew,
}

impl Upstream {
    /// The upstream's answer to `body`, skewed.
    async fn answer(&self, body: &[u8]) -> Bytes {
        let mut call: Call = serde_json::from_slice(body).expect("a JSON-RPC request");
        let lagged = LAGGED.iter().find(|(method, _)| *method == call.method);
        if let (Skew::LatestBehind, Some((_, at))) = (self.skew, lagged) {
            self.lag(&mut call.params, *at).await;
        }
        let params = to_raw_value(&call.params).expect("params serialize");
        let payload = match self
            .node
            .raw_request_dyn(call.method.clone().into(), &params)
            .await
        {
            Ok(result) => ResponsePayload::Success(self.skewed(&call.method, result)),
            Err(RpcError::ErrorResp(error)) => ResponsePayload::Failure(error),
            Err(e) => panic!("upstream {}: {e}", call.method),
        };
        let response = Response {
            id: call.id,
            payload,
        };
        serde_json::to_vec(&response)
            .expect("response serializes")
            .into()
    }

    /// Point a read at `latest`, its block at `params[at]` or left out,
    /// at the block before the head.
    async fn lag(&self, params: &mut Vec<Box<RawValue>>, at: usize) {
        let at_latest = params.get(at).is_none_or(|block| {
            serde_json::from_str::<BlockId>(block.get()).expect("a block id")
                == BlockId::latest()
        });
        if !at_latest {
            return;
        }
        let head = self.node.get_block_number().await.expect("head");
        let behind = to_raw_value(&BlockId::number(head.saturating_sub(1)))
            .expect("block serializes");
        match params.get_mut(at) {
            Some(block) => *block = behind,
            None => params.push(behind),
        }
    }

    /// The upstream's `result` for `method`, halved when it is the gas
    /// estimate [`Skew::HalfGasEstimate`] gets wrong.
    fn skewed(&self, method: &str, result: Box<RawValue>) -> Box<RawValue> {
        if !matches!(self.skew, Skew::HalfGasEstimate) || method != "eth_estimateGas" {
            return result;
        }
        let gas: U64 = serde_json::from_str(result.get()).expect("a gas estimate");
        to_raw_value(&(gas / U64::from(2))).expect("gas serializes")
    }
}
