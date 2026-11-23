//! A JSON-RPC endpoint in front of anvil that answers one kind of request
//! the way a load-balanced production endpoint can get it wrong. Every
//! other request passes through unchanged.

use std::{
    convert::Infallible,
    sync::{
        atomic::{
            AtomicU32,
            Ordering,
        },
        Arc,
    },
};

use alloy::{
    eips::BlockId,
    primitives::U64,
    providers::{
        DynProvider,
        Provider,
        ProviderBuilder,
    },
    rpc::json_rpc::{
        ErrorPayload,
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

/// The state reads a skew applies to, each with the position of its block
/// parameter.
const READS: [(&str, usize); 3] =
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
    /// The first this many state reads at a named block answer `header not
    /// found`, as Arbitrum's RPC answers for a block the backend serving the
    /// read has not seen yet.
    UnseenBlock(u32),
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
            unseen: Arc::new(AtomicU32::new(0)),
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

impl Call {
    /// The block this read names at `params[at]`: `None` for `latest` or
    /// none given.
    fn named_block(&self, at: usize) -> Option<BlockId> {
        let block = serde_json::from_str::<BlockId>(self.params.get(at)?.get())
            .expect("a block id");
        (block != BlockId::latest()).then_some(block)
    }
}

/// The node behind the endpoint, and what the endpoint gets wrong.
#[derive(Clone)]
struct Upstream {
    node: DynProvider,
    skew: Skew,
    /// Reads at a named block answered `header not found` so far.
    unseen: Arc<AtomicU32>,
}

impl Upstream {
    /// The upstream's answer to `body`, skewed.
    async fn answer(&self, body: &[u8]) -> Bytes {
        let mut call: Call = serde_json::from_slice(body).expect("a JSON-RPC request");
        if let Some((_, at)) = READS.iter().find(|(method, _)| *method == call.method) {
            match (self.skew, call.named_block(*at)) {
                (Skew::LatestBehind, None) => self.lag(&mut call.params, *at).await,
                (Skew::UnseenBlock(reads), Some(_)) if self.unseen(reads) => {
                    return reply(
                        call.id,
                        ResponsePayload::Failure(ErrorPayload {
                            code: -32000,
                            message: "header not found".into(),
                            data: None,
                        }),
                    );
                }
                _ => {}
            }
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
        reply(call.id, payload)
    }

    /// Whether this read at a named block is one of the first `reads`,
    /// which [`Skew::UnseenBlock`] answers `header not found`.
    fn unseen(&self, reads: u32) -> bool {
        self.unseen
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |answered| {
                (answered < reads).then(|| answered + 1)
            })
            .is_ok()
    }

    /// Point a read at `latest`, its block at `params[at]` or left out,
    /// at the block before the head.
    async fn lag(&self, params: &mut Vec<Box<RawValue>>, at: usize) {
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

/// The response to request `id`.
fn reply(id: Id, payload: ResponsePayload) -> Bytes {
    serde_json::to_vec(&Response { id, payload })
        .expect("response serializes")
        .into()
}
