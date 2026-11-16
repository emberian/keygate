//! `keygate-broker`: the async half of keygate.
//!
//! [`Broker`] is the engine (admission, tickets, audit-before-effect,
//! upstream relay). [`unix`] speaks the framed socket protocol with peer
//! credentials, [`gateway`] is the opt-in loopback HTTP listener, and
//! [`client`] is the socket client the CLI and tests use.

pub mod client;
pub mod engine;
pub mod gateway;
pub mod unix;
pub mod vault;
pub mod wire;

pub use engine::{
    Authorized, Broker, BrokerOptions, BufferedReply, Caller, HeaderMode, LiveStream, StreamItem,
    StreamOutcome,
};
pub use keygate_core as core;
pub use vault::RowEpoch;

use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum BootError {
    #[error("config: {0}")]
    Config(String),
    #[error(transparent)]
    ConfigFile(#[from] keygate_core::config::ConfigError),
    #[error(transparent)]
    Seal(#[from] keygate_core::seal::SealError),
    #[error(transparent)]
    Journal(#[from] keygate_core::journal::JournalError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// The broker's bound listeners, ready to serve.
pub struct Listeners {
    pub socket_path: PathBuf,
    pub http_addr: Option<SocketAddr>,
    unix: tokio::net::UnixListener,
    http: Option<tokio::net::TcpListener>,
}

impl Listeners {
    /// Bind the Unix socket and, if configured, the loopback HTTP gateway.
    pub async fn bind(broker: &Broker) -> std::io::Result<Self> {
        let cfg = broker.config();
        let socket_path = broker.state_dir().join(&cfg.socket);
        let unix = unix::bind(&socket_path, cfg.socket_mode)?;
        let http = match cfg.http_listen {
            Some(addr) => Some(gateway::bind(addr).await?),
            None => None,
        };
        let http_addr = http.as_ref().map(|l| l.local_addr()).transpose()?;
        Ok(Listeners {
            socket_path,
            http_addr,
            unix,
            http,
        })
    }

    /// Serve until one listener fails.
    pub async fn run(self, broker: Broker) -> std::io::Result<()> {
        match self.http {
            Some(http) => tokio::select! {
                done = unix::serve(broker.clone(), self.unix) => done,
                done = gateway::serve(broker, http) => done,
            },
            None => unix::serve(broker, self.unix).await,
        }
    }
}
