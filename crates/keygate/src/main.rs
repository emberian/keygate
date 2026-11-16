//! `keygate`: broker daemon and CLI.
//!
//! Secrets and tokens never appear in argv: `set` reads the secret from
//! stdin, and commands that need a macaroon take it from `KEYGATE_TOKEN`
//! or `--token-file` (`-` for stdin).

use clap::{Args, Parser, Subcommand};
use keygate_broker::client::Client;
use keygate_broker::engine::{CONFIG_FILE, MASTER_KEY_FILE};
use keygate_broker::{Broker, BrokerOptions, Listeners};
use keygate_core::config::{Config, EXAMPLE};
use keygate_core::macaroon::{Caveat, MacaroonV1};
use keygate_core::proto::{Call, Request, Response, ServiceAuthorize};
use keygate_core::{now_unix_s, Namespace};
use std::error::Error;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zeroize::Zeroize;

type Fallible<T> = Result<T, Box<dyn Error>>;

#[derive(Parser)]
#[command(
    name = "keygate",
    version,
    about = "Capability-membrane and streaming secret custody broker"
)]
struct Cli {
    /// State directory (master key, config, sealed rows, journal, audit log).
    #[arg(long, env = "KEYGATE_STATE", global = true)]
    state: Option<PathBuf>,
    /// Broker socket; defaults to <state>/keygate.sock.
    #[arg(long, env = "KEYGATE_SOCKET", global = true)]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create the state directory, a master key and a starter keygate.toml.
    Init,
    /// Run the broker.
    Serve,
    /// Show how the broker sees this caller.
    Hello,
    /// Operator: load or rotate a row's secret, read from stdin.
    Set {
        namespace: Namespace,
        row: String,
        /// Also cut streams still running on the previous secret.
        #[arg(long)]
        cut_existing: bool,
    },
    /// Operator: destroy a row's secret and cut every stream using it.
    Revoke { namespace: Namespace, row: String },
    /// Operator: invalidate every macaroon minted for a seat so far.
    RevokeSeat { seat: String },
    /// Operator: list rows and their epochs.
    Ls,
    /// Operator: broker status.
    Status,
    /// Operator: mint a root macaroon for a seat.
    Mint {
        #[arg(long)]
        seat: String,
        /// Bind the token to this Unix peer uid.
        #[arg(long)]
        uid: Option<u32>,
        #[command(flatten)]
        caveats: CaveatArgs,
    },
    /// Append caveats to a token. Offline: needs no broker and no key.
    Attenuate {
        #[command(flatten)]
        token: TokenArgs,
        #[command(flatten)]
        caveats: CaveatArgs,
    },
    /// Print a token's seat binding and caveats (offline, unverified).
    Inspect {
        #[command(flatten)]
        token: TokenArgs,
    },
    /// Check a call and reserve its ticket without sending it.
    Authorize {
        #[command(flatten)]
        call: CallArgs,
        /// For service rows: authorize the stream operation.
        #[arg(long)]
        stream: bool,
    },
    /// Send a buffered call; the reply body goes to stdout.
    Forward {
        #[command(flatten)]
        call: CallArgs,
    },
    /// Open a stream; chunks go to stdout as they arrive.
    Stream {
        #[command(flatten)]
        call: CallArgs,
    },
}

#[derive(Args)]
struct TokenArgs {
    /// File holding the kgm_ token, or `-` for stdin. Defaults to $KEYGATE_TOKEN.
    #[arg(long)]
    token_file: Option<PathBuf>,
}

#[derive(Args)]
struct CaveatArgs {
    /// Require the token's seat to be exactly this.
    #[arg(long)]
    bind_seat: Option<String>,
    #[arg(long)]
    namespace: Option<Namespace>,
    #[arg(long, value_delimiter = ',')]
    rows: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    methods: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    path_prefixes: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    models: Vec<String>,
    #[arg(long)]
    max_request_bytes: Option<usize>,
    /// Cumulative spend ceiling for this token and everything attenuated from it.
    #[arg(long)]
    max_spend_micro_usd: Option<u64>,
    /// Absolute expiry, Unix seconds.
    #[arg(long)]
    expires_at: Option<u64>,
    /// Expiry relative to now, seconds.
    #[arg(long, conflicts_with = "expires_at")]
    ttl_s: Option<u64>,
}

impl CaveatArgs {
    fn caveats(self) -> Vec<Caveat> {
        let list = |items: Vec<String>, make: fn(Vec<String>) -> Caveat| {
            (!items.is_empty()).then(|| make(items))
        };
        [
            self.bind_seat.map(Caveat::Seat),
            self.namespace.map(Caveat::Namespace),
            list(self.rows, Caveat::Rows),
            list(self.methods, Caveat::Methods),
            list(self.path_prefixes, Caveat::PathPrefixes),
            list(self.models, Caveat::Models),
            self.max_request_bytes.map(Caveat::MaxRequestBytes),
            self.max_spend_micro_usd.map(Caveat::MaxSpendMicroUsd),
            self.expires_at
                .or(self.ttl_s.map(|ttl| now_unix_s().saturating_add(ttl)))
                .map(Caveat::ExpiresAtUnixS),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

#[derive(Args)]
struct CallArgs {
    namespace: Namespace,
    row: String,
    method: String,
    /// Plain upstream path, e.g. /v1/messages
    path: String,
    #[arg(long)]
    query: Option<String>,
    /// Extra header, `name: value`. Repeatable; must be allowed by the row.
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,
    /// Request body file, or `-` for stdin.
    #[arg(long)]
    body_file: Option<PathBuf>,
    /// Distinguishes deliberate repeats of an otherwise identical request.
    #[arg(long)]
    request_id: Option<String>,
    #[arg(long)]
    last_event_id: Option<String>,
    #[command(flatten)]
    token: TokenArgs,
}

fn read_source(path: &Path) -> Fallible<Vec<u8>> {
    let mut bytes = Vec::new();
    if path == Path::new("-") {
        std::io::stdin().lock().read_to_end(&mut bytes)?;
    } else {
        std::fs::File::open(path)?.read_to_end(&mut bytes)?;
    }
    Ok(bytes)
}

impl TokenArgs {
    fn load(&self) -> Fallible<String> {
        let raw = match &self.token_file {
            Some(path) => String::from_utf8(read_source(path)?)?,
            None => std::env::var("KEYGATE_TOKEN")
                .map_err(|_| "no token: set KEYGATE_TOKEN or pass --token-file")?,
        };
        Ok(raw.trim().to_owned())
    }
}

impl CallArgs {
    fn into_call(self) -> Fallible<(Namespace, Call)> {
        let token = self.token.load()?;
        let headers = self
            .headers
            .iter()
            .map(|h| {
                let (name, value) = h
                    .split_once(':')
                    .ok_or_else(|| format!("header {h:?} is not `name: value`"))?;
                Ok((name.trim().to_owned(), value.trim().to_owned()))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let body = match &self.body_file {
            Some(path) => read_source(path)?,
            None => Vec::new(),
        };
        let call = Call {
            token,
            row: self.row,
            method: self.method.to_ascii_uppercase(),
            path: self.path,
            query: self.query,
            headers,
            body,
            request_id: self.request_id,
            last_event_id: self.last_event_id,
        };
        Ok((self.namespace, call))
    }
}

fn state_dir(cli_state: &Option<PathBuf>) -> Fallible<&Path> {
    cli_state
        .as_deref()
        .ok_or_else(|| "no state directory: pass --state or set KEYGATE_STATE".into())
}

async fn connect(socket: &Option<PathBuf>, state: &Option<PathBuf>) -> Fallible<Client> {
    let socket = match (socket, state) {
        (Some(socket), _) => socket.clone(),
        (None, Some(state)) => state.join("keygate.sock"),
        (None, None) => {
            return Err(
                "no broker socket: pass --socket/--state or set KEYGATE_SOCKET/KEYGATE_STATE"
                    .into(),
            )
        }
    };
    Client::connect(&socket)
        .await
        .map_err(|e| format!("cannot reach the broker at {}: {e}", socket.display()).into())
}

/// Turn a refusal frame into an error; pass everything else through.
fn accepted(response: Response) -> Fallible<Response> {
    match response {
        Response::Error(refusal) => Err(Box::new(refusal)),
        other => Ok(other),
    }
}

fn print_json<T: serde::Serialize>(value: &T) -> Fallible<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn init(state: &Path) -> Fallible<()> {
    if state.join(MASTER_KEY_FILE).exists() {
        return Err(format!("{} is already initialized", state.display()).into());
    }
    Broker::init_state(state)?;
    let config = state.join(CONFIG_FILE);
    if !config.exists() {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&config)?
            .write_all(EXAMPLE.as_bytes())?;
    }
    println!("initialized {}", state.display());
    println!("edit {} and run `keygate serve`", config.display());
    Ok(())
}

async fn serve(state: &Path) -> Fallible<()> {
    let config_path = state.join(CONFIG_FILE);
    let text = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("{}: {e}", config_path.display()))?;
    let config = Config::parse(&text)?;
    let broker = Broker::open(state, config, BrokerOptions::default())?;
    let listeners = Listeners::bind(&broker).await?;
    let socket_path = listeners.socket_path.clone();
    eprintln!("keygate: listening on {}", socket_path.display());
    if let Some(addr) = listeners.http_addr {
        eprintln!("keygate: loopback gateway on http://{addr}");
    }
    for row in broker.rows() {
        eprintln!(
            "keygate: {}/{} -> {} [{}]",
            row.namespace, row.row, row.origin, row.state
        );
    }

    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let outcome = tokio::select! {
        served = listeners.run(broker) => served.map_err(Into::into),
        _ = tokio::signal::ctrl_c() => Ok(()),
        _ = terminate.recv() => Ok(()),
    };
    let _ = std::fs::remove_file(&socket_path);
    outcome
}

async fn set(
    client: &mut Client,
    namespace: Namespace,
    row: String,
    cut_existing: bool,
) -> Fallible<()> {
    use base64::Engine;
    let mut secret = Vec::new();
    std::io::stdin().lock().read_to_end(&mut secret)?;
    while matches!(secret.last(), Some(b'\n' | b'\r')) {
        secret.pop();
    }
    let secret_b64 = base64::engine::general_purpose::STANDARD.encode(&secret);
    secret.zeroize();
    let mut request = Request::Set {
        namespace,
        row,
        secret_b64,
        cut_existing,
    };
    let response = client.call(&request).await;
    if let Request::Set { secret_b64, .. } = &mut request {
        secret_b64.zeroize();
    }
    accepted(response?)?;
    println!("ok");
    Ok(())
}

async fn run(cli: Cli) -> Fallible<ExitCode> {
    let Cli {
        state,
        socket,
        command,
    } = cli;
    match command {
        Command::Init => init(state_dir(&state)?)?,
        Command::Serve => serve(state_dir(&state)?).await?,
        Command::Attenuate { token, caveats } => {
            let narrowed = caveats
                .caveats()
                .into_iter()
                .try_fold(MacaroonV1::decode(&token.load()?)?, MacaroonV1::attenuate)?;
            println!("{}", narrowed.encode());
        }
        Command::Inspect { token } => {
            let token = MacaroonV1::decode(&token.load()?)?;
            let root = token.root();
            print_json(&serde_json::json!({
                "seat": root.seat,
                "allowed_uid": root.allowed_uid,
                "root_epoch": root.root_epoch,
                "caveats": token.caveats(),
            }))?;
        }
        Command::Hello => {
            let mut client = connect(&socket, &state).await?;
            print_json(&accepted(client.call(&Request::Hello).await?)?)?;
        }
        Command::Ls => {
            let mut client = connect(&socket, &state).await?;
            if let Response::Rows { rows } = accepted(client.call(&Request::Ls).await?)? {
                for row in rows {
                    println!(
                        "{}\t{}\t{}\tgen={}\tfloor={}\t{}",
                        row.namespace,
                        row.row,
                        row.state,
                        row.generation,
                        row.revoked_floor,
                        row.origin
                    );
                }
            }
        }
        Command::Status => {
            let mut client = connect(&socket, &state).await?;
            print_json(&accepted(client.call(&Request::Status).await?)?)?;
        }
        Command::Set {
            namespace,
            row,
            cut_existing,
        } => {
            let mut client = connect(&socket, &state).await?;
            set(&mut client, namespace, row, cut_existing).await?;
        }
        Command::Revoke { namespace, row } => {
            let mut client = connect(&socket, &state).await?;
            accepted(client.call(&Request::Revoke { namespace, row }).await?)?;
            println!("revoked");
        }
        Command::RevokeSeat { seat } => {
            let mut client = connect(&socket, &state).await?;
            accepted(client.call(&Request::RevokeSeat { seat }).await?)?;
            println!("revoked");
        }
        Command::Mint { seat, uid, caveats } => {
            let mut client = connect(&socket, &state).await?;
            let request = Request::MintMacaroon {
                seat,
                allowed_uid: uid,
                caveats: caveats.caveats(),
            };
            if let Response::Token { token } = accepted(client.call(&request).await?)? {
                println!("{token}");
            }
        }
        Command::Authorize { call, stream } => {
            let mut client = connect(&socket, &state).await?;
            let (namespace, call) = call.into_call()?;
            let request = match namespace {
                Namespace::Provider => Request::ProviderAuthorize(call),
                Namespace::Service => Request::ServiceAuthorize(ServiceAuthorize { call, stream }),
            };
            print_json(&accepted(client.call(&request).await?)?)?;
        }
        Command::Forward { call } => {
            let mut client = connect(&socket, &state).await?;
            let (namespace, call) = call.into_call()?;
            let request = match namespace {
                Namespace::Provider => Request::ProviderForward(call),
                Namespace::Service => Request::ServiceForward(call),
            };
            if let Response::Reply {
                ticket,
                status,
                body,
                replayed,
                ..
            } = accepted(client.call(&request).await?)?
            {
                eprintln!("keygate: status={status} ticket={ticket} replayed={replayed}");
                std::io::stdout().write_all(&body)?;
            }
        }
        Command::Stream { call } => {
            let mut client = connect(&socket, &state).await?;
            let (namespace, call) = call.into_call()?;
            let request = match namespace {
                Namespace::Provider => Request::ProviderStream(call),
                Namespace::Service => Request::ServiceStream(call),
            };
            client.send(&request).await?;
            let mut stdout = std::io::stdout();
            loop {
                match accepted(client.recv().await?)? {
                    Response::Head { ticket, status, .. } => {
                        eprintln!("keygate: status={status} ticket={ticket}")
                    }
                    Response::Chunk { data } => {
                        stdout.write_all(&data)?;
                        stdout.flush()?;
                    }
                    Response::End { summary, spent, .. } => {
                        eprintln!(
                            "keygate: stream ended spent={spent} {}",
                            serde_json::to_string(&summary)?
                        );
                        return Ok(if summary.complete && !spent {
                            ExitCode::SUCCESS
                        } else {
                            ExitCode::from(3)
                        });
                    }
                    _ => return Err("unexpected frame in stream".into()),
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("keygate: {e}");
            ExitCode::FAILURE
        }
    }
}
