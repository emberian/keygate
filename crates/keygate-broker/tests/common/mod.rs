//! Shared rig for the `#tooth` tests: a scriptable local HTTP/SSE upstream
//! and a broker on a temp state directory.

#![allow(dead_code)]

use bytes::Bytes;
use http_body_util::{BodyExt, Either, Full};
use hyper::body::{Body, Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use keygate_broker::{
    Broker, BrokerOptions, Caller, HeaderMode, LiveStream, StreamItem, StreamOutcome,
};
use keygate_core::config::Config;
use keygate_core::journal::StreamSummary;
use keygate_core::proto::{Call, Refusal};
use keygate_core::secret::SecretBytes;
use keygate_core::Namespace;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Notify};

pub const SECRET: &str = "sk-ant-secret12345";
pub const OPERATOR: Caller = Caller { uid: Some(0) };
pub const AGENT: Caller = Caller { uid: Some(4242) };
pub const WAIT: Duration = Duration::from_secs(10);

/// One request as the upstream saw it.
#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: hyper::HeaderMap,
    pub body: Bytes,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

pub enum Reply {
    Full {
        status: u16,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    },
    /// A chunked body the test feeds through the channel; closing the
    /// sender ends the body cleanly.
    Stream {
        chunks: mpsc::UnboundedReceiver<Bytes>,
    },
    /// Accept the request and never answer.
    Hang,
}

impl Reply {
    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        Reply::Full {
            status: 200,
            headers: vec![("content-type", "application/json".into())],
            body: body.into(),
        }
    }
}

struct ChannelBody(mpsc::UnboundedReceiver<Bytes>);

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0
            .poll_recv(cx)
            .map(|chunk| chunk.map(|bytes| Ok(Frame::data(bytes))))
    }
}

#[derive(Default)]
struct Counters {
    hits: AtomicUsize,
    connections: AtomicUsize,
    seen: Mutex<Vec<Seen>>,
    arrived: Notify,
}

/// A local HTTP server whose replies the test scripts.
pub struct Upstream {
    pub addr: SocketAddr,
    pub origin: String,
    counters: Arc<Counters>,
    accept: tokio::task::JoinHandle<()>,
}

impl Upstream {
    pub async fn start(handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let counters = Arc::new(Counters::default());
        let handler = Arc::new(handler);
        let accept = tokio::spawn({
            let counters = counters.clone();
            async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    counters.connections.fetch_add(1, Ordering::SeqCst);
                    let counters = counters.clone();
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        let service = service_fn(move |request: Request<Incoming>| {
                            let counters = counters.clone();
                            let handler = handler.clone();
                            async move {
                                let (parts, body) = request.into_parts();
                                let seen = Seen {
                                    method: parts.method.to_string(),
                                    path: parts.uri.path().to_owned(),
                                    query: parts.uri.query().map(str::to_owned),
                                    headers: parts.headers,
                                    body: body
                                        .collect()
                                        .await
                                        .map(|b| b.to_bytes())
                                        .unwrap_or_default(),
                                };
                                counters.hits.fetch_add(1, Ordering::SeqCst);
                                counters.seen.lock().unwrap().push(seen.clone());
                                counters.arrived.notify_one();
                                let response = match handler(&seen) {
                                    Reply::Full {
                                        status,
                                        headers,
                                        body,
                                    } => {
                                        let mut response = Response::builder().status(status);
                                        for (name, value) in headers {
                                            response = response.header(name, value);
                                        }
                                        response
                                            .body(Either::Left(Full::new(Bytes::from(body))))
                                            .unwrap()
                                    }
                                    Reply::Stream { chunks } => Response::builder()
                                        .header("content-type", "text/event-stream")
                                        .body(Either::Right(ChannelBody(chunks)))
                                        .unwrap(),
                                    Reply::Hang => std::future::pending().await,
                                };
                                Ok::<_, Infallible>(response)
                            }
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
            }
        });
        Upstream {
            addr,
            origin: format!("http://{addr}"),
            counters,
            accept,
        }
    }

    /// Requests fully received.
    pub fn hits(&self) -> usize {
        self.counters.hits.load(Ordering::SeqCst)
    }

    /// TCP connections accepted.
    pub fn connections(&self) -> usize {
        self.counters.connections.load(Ordering::SeqCst)
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.counters.seen.lock().unwrap().clone()
    }

    pub fn last(&self) -> Seen {
        self.seen().pop().expect("upstream saw no request")
    }

    /// Wait until one more request has arrived.
    pub async fn arrived(&self) {
        tokio::time::timeout(WAIT, self.counters.arrived.notified())
            .await
            .expect("no request reached the upstream");
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

/// A queue of scripted stream bodies, handed out one per request.
pub struct Script(Mutex<VecDeque<mpsc::UnboundedReceiver<Bytes>>>);

impl Script {
    pub fn next(&self) -> Reply {
        Reply::Stream {
            chunks: self
                .0
                .lock()
                .unwrap()
                .pop_front()
                .expect("more streams opened than scripted"),
        }
    }
}

/// `n` scripted stream bodies: the senders the test feeds, and the script
/// an upstream handler serves them from, in order.
pub fn script(n: usize) -> (Vec<mpsc::UnboundedSender<Bytes>>, Arc<Script>) {
    let (senders, receivers): (Vec<_>, VecDeque<_>) =
        (0..n).map(|_| mpsc::unbounded_channel()).unzip();
    (senders, Arc::new(Script(Mutex::new(receivers))))
}

/// The standard two-table config against one upstream origin.
pub fn config(origin: &str) -> String {
    format!(
        r#"
[broker]
retention_s = 600

[providers.llm]
origin = "{origin}"
auth_header = "x-api-key"
paths = ["/v1/messages"]
models = ["m-small", "m-large"]
max_output_tokens = 1000
output_micro_usd_per_mtok = 1000000
per_day_micro_usd = 2500
caller_headers = ["anthropic-version"]

[services.api]
origin = "{origin}"
methods = ["GET", "POST"]
buffered_paths = ["/repos"]
stream_paths = ["/events"]
caller_headers = ["last-event-id", "x-trace"]
"#
    )
}

pub struct Rig {
    pub dir: tempfile::TempDir,
    pub broker: Broker,
    config: String,
}

impl Rig {
    /// A broker on a fresh state dir with `SECRET` loaded into every row.
    pub fn new(config: &str) -> Self {
        let rig = Rig::unset(config);
        for row in rig.broker.rows() {
            rig.set(row.namespace, &row.row, SECRET, false);
        }
        rig
    }

    /// Same, with no secrets loaded.
    pub fn unset(config: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        Broker::init_state(dir.path()).unwrap();
        let broker = Broker::open(
            dir.path(),
            Config::parse(config).unwrap(),
            BrokerOptions::default(),
        )
        .unwrap();
        Rig {
            dir,
            broker,
            config: config.to_owned(),
        }
    }

    pub fn state(&self) -> &Path {
        self.dir.path()
    }

    /// Stop the broker and start a new one on the same state dir.
    pub fn reopen(self, options: BrokerOptions) -> Self {
        let Rig {
            dir,
            broker,
            config,
        } = self;
        drop(broker);
        let broker = Broker::open(dir.path(), Config::parse(&config).unwrap(), options).unwrap();
        Rig {
            dir,
            broker,
            config,
        }
    }

    pub fn set(&self, ns: Namespace, row: &str, secret: &str, cut_existing: bool) {
        self.broker
            .set(
                ns,
                row,
                SecretBytes::new(secret.as_bytes().to_vec()),
                cut_existing,
                OPERATOR,
            )
            .unwrap();
    }

    /// An unrestricted root token for `seat`.
    pub fn token(&self, seat: &str) -> String {
        self.broker.mint(seat, None, vec![], OPERATOR).unwrap()
    }

    pub async fn forward(
        &self,
        ns: Namespace,
        call: Call,
    ) -> Result<keygate_broker::BufferedReply, Refusal> {
        self.broker
            .forward(ns, AGENT, call, HeaderMode::Strict)
            .await
    }

    pub async fn stream(&self, ns: Namespace, call: Call) -> Result<StreamOutcome, Refusal> {
        self.broker
            .stream(ns, AGENT, call, HeaderMode::Strict)
            .await
    }

    /// Open a stream that must go live.
    pub async fn live(&self, ns: Namespace, call: Call) -> LiveStream {
        match self.stream(ns, call).await {
            Ok(StreamOutcome::Live(live)) => live,
            Ok(StreamOutcome::Spent { summary, .. }) => {
                panic!("stream was already spent: {summary:?}")
            }
            Err(refusal) => panic!("stream refused: {refusal}"),
        }
    }
}

pub fn call(token: &str, row: &str, method: &str, path: &str, body: &[u8]) -> Call {
    Call {
        token: token.to_owned(),
        row: row.to_owned(),
        method: method.to_owned(),
        path: path.to_owned(),
        query: None,
        headers: Vec::new(),
        body: body.to_vec(),
        request_id: None,
        last_event_id: None,
    }
}

/// A provider request body.
pub fn llm(model: &str, max_tokens: u64, stream: bool) -> Vec<u8> {
    serde_json::json!({ "model": model, "max_tokens": max_tokens, "stream": stream, "messages": [{ "role": "user", "content": "hi" }] })
        .to_string()
        .into_bytes()
}

pub async fn next_item(live: &mut LiveStream) -> StreamItem {
    tokio::time::timeout(WAIT, live.items.recv())
        .await
        .expect("stream stalled")
        .expect("relay vanished without a summary")
}

pub async fn next_chunk(live: &mut LiveStream) -> Bytes {
    match next_item(live).await {
        StreamItem::Chunk(bytes) => bytes,
        StreamItem::End(summary) => panic!("stream ended early: {summary:?}"),
    }
}

/// Read to the end: everything delivered, and the closing summary.
pub async fn drain(live: &mut LiveStream) -> (Vec<u8>, StreamSummary) {
    let mut delivered = Vec::new();
    loop {
        match next_item(live).await {
            StreamItem::Chunk(bytes) => delivered.extend_from_slice(&bytes),
            StreamItem::End(summary) => return (delivered, summary),
        }
    }
}

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Every regular file under `dir`, with its bytes.
pub fn files_under(dir: &Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let meta = std::fs::symlink_metadata(&path).unwrap();
        if meta.is_dir() {
            out.extend(files_under(&path));
        } else if meta.is_file() {
            let bytes = std::fs::read(&path).unwrap();
            out.push((path, bytes));
        }
    }
    out
}

/// No file in the state directory holds `secret` in the clear.
pub fn assert_no_plaintext(dir: &Path, secret: &str) {
    for (path, bytes) in files_under(dir) {
        assert!(
            !contains(&bytes, secret.as_bytes()),
            "{} contains the plaintext secret",
            path.display()
        );
    }
}
