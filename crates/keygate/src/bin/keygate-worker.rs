//! Length-framed worker pool. Each pool serves one attenuated authority.
use clap::Parser;
use keygate_broker::{
    client::Client,
    wire::{read_frame_limited, write_frame},
};
use keygate_core::{
    git_land::GitLand,
    journal::TicketId,
    macaroon::{Caveat, MacaroonV1},
    proto::{Call, Request, Response, ServiceAuthorize},
    Namespace,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    io,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::{
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::{mpsc, Mutex},
    time::timeout,
};
use zeroize::Zeroizing;

const LIMIT: usize = 65536;
#[derive(Parser)]
struct Options {
    #[arg(long)]
    socket: PathBuf,
    #[arg(long)]
    token_file: PathBuf,
    #[arg(long)]
    seat: String,
    #[arg(long)]
    pod_row: String,
    #[arg(long)]
    git_row: String,
    #[arg(long)]
    max_spend_micro_usd: u64,
    /// Operations granted to this pool (comma separated).
    #[arg(long,value_delimiter=',',required=true,value_parser=["pod.claim","pod.done","git.land","git.reconcile"])]
    allow: Vec<String>,
    #[arg(long,default_value_t=2,value_parser=clap::value_parser!(u8).range(1..=32))]
    workers: u8,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    id: u64,
    source: String,
    #[serde(default)]
    input: Value,
}

struct Worker {
    _child: Child,
    reader: ChildStdout,
    writer: ChildStdin,
}
fn bad() -> io::Error {
    io::Error::other("invalid worker protocol")
}

impl Worker {
    async fn start() -> io::Result<Self> {
        let mut sandbox = Command::new("/usr/bin/prlimit");
        sandbox.env_clear().current_dir("/").args([
            "--as=1073741824",
            "--core=0",
            "--nofile=64",
            "--fsize=0",
            "/usr/bin/bwrap",
            "--unshare-all",
            "--unshare-user",
            "--disable-userns",
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--dir",
            "/usr/bin",
            "--ro-bind",
            "/usr/bin/node",
            "/usr/bin/node",
            "--ro-bind",
            "/usr/lib",
            "/usr/lib",
            "--symlink",
            "usr/lib",
            "/lib",
        ]);
        for dir in ["/usr/lib64", "/usr/share/nodejs"] {
            if Path::new(dir).is_dir() {
                sandbox.args(["--ro-bind", dir, dir]);
            }
        }
        if Path::new("/lib64").exists() {
            sandbox.args(["--symlink", "usr/lib64", "/lib64"]);
        }
        let mut child = sandbox
            .args([
                "--remount-ro",
                "/",
                "/usr/bin/node",
                "--jitless",
                "--no-expose-wasm",
                "--max-old-space-size=48",
                "-e",
                include_str!("context.cjs"),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let mut w = Self {
            reader: child.stdout.take().ok_or_else(bad)?,
            writer: child.stdin.take().ok_or_else(bad)?,
            _child: child,
        };
        if timeout(Duration::from_secs(5), w.frame()).await?? != json!({"ready":true}) {
            return Err(bad());
        }
        Ok(w)
    }
    async fn frame(&mut self) -> io::Result<Value> {
        let bytes = read_frame_limited(&mut self.reader, LIMIT)
            .await?
            .ok_or_else(bad)?;
        Ok(serde_json::from_slice(&bytes)?)
    }
    async fn invoke(&mut self, job: &Job, bridge: &mut Bridge) -> io::Result<Value> {
        write_frame(&mut self.writer, job).await?;
        for _ in 0..64 {
            let msg = self.frame().await?;
            if msg["done"] == true {
                return Ok(json!({"ok":true,"value":msg["value"]}));
            }
            if msg["failed"] == true {
                return Ok(json!({"ok":false,"reason":"handler"}));
            }
            let answer = match serde_json::from_value(msg["effect"].clone()) {
                Ok(effect) if bridge.allows(&effect) => bridge.apply(effect).await?,
                Ok(_) => json!({"ok":false}),
                Err(_) => json!({"ok":false}),
            };
            write_frame(&mut self.writer, &answer).await?;
        }
        Err(bad())
    }
}

#[derive(Deserialize)]
#[serde(tag = "op", content = "body", deny_unknown_fields)]
enum Effect {
    #[serde(rename = "pod.claim")]
    Claim(PodClaim),
    #[serde(rename = "pod.done")]
    Done(PodDone),
    #[serde(rename = "git.land")]
    Land(GitRequest),
    #[serde(rename = "git.reconcile")]
    Reconcile(Reconcile),
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PodClaim {
    pod: String,
    task: String,
    lease_seconds: u32,
    request_id: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PodDone {
    pod: String,
    task: String,
    fencing_token: String,
    request_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GitRequest {
    cas: GitLand,
    request_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reconcile {
    cas: GitLand,
    request_id: String,
    ticket: TicketId,
}

struct Bridge {
    options: Arc<Options>,
    token: Arc<Zeroizing<String>>,
    client: Option<Client>,
}
impl Bridge {
    fn allows(&self, effect: &Effect) -> bool {
        let name = match effect {
            Effect::Claim(_) => "pod.claim",
            Effect::Done(_) => "pod.done",
            Effect::Land(_) => "git.land",
            Effect::Reconcile(_) => "git.reconcile",
        };
        self.options.allow.iter().any(|op| op == name)
    }
    async fn call(&mut self, request: &Request) -> io::Result<Response> {
        if self.client.is_none() {
            self.client = Some(Client::connect(&self.options.socket).await?)
        }
        self.client.as_mut().expect("connected").call(request).await
    }
    async fn apply(&mut self, effect: Effect) -> io::Result<Value> {
        let mut ticket = None;
        let (row, path, body, id) = match effect {
            Effect::Claim(c) => (
                &self.options.pod_row,
                "/pod/claim",
                json!({"pod":c.pod,"task":c.task,"lease_seconds":c.lease_seconds}),
                c.request_id,
            ),
            Effect::Done(c) => (
                &self.options.pod_row,
                "/pod/done",
                json!({"pod":c.pod,"task":c.task,"fencing_token":c.fencing_token}),
                c.request_id,
            ),
            Effect::Land(g) => (
                &self.options.git_row,
                "/git/land",
                serde_json::to_value(g.cas)?,
                g.request_id,
            ),
            Effect::Reconcile(g) => {
                ticket = Some(g.ticket);
                (
                    &self.options.git_row,
                    "/git/land",
                    serde_json::to_value(g.cas)?,
                    g.request_id,
                )
            }
        };
        if id.is_empty() || id.len() > 128 {
            return Ok(json!({"ok":false}));
        }
        let git = path == "/git/land";
        let call = Call {
            token: self.token.to_string(),
            row: row.clone(),
            method: "POST".into(),
            path: path.into(),
            query: None,
            headers: if git {
                vec![]
            } else {
                vec![("content-type".into(), "application/json".into())]
            },
            body: serde_json::to_vec(&body)?,
            request_id: Some(id),
            last_event_id: None,
        };
        if let Some(ticket) = ticket {
            return Ok(
                match self
                    .call(&Request::ReconcileGitPush { ticket, call })
                    .await?
                {
                    Response::Authorized { state, .. } => json!({"ok":true,"state":state}),
                    _ => json!({"ok":false}),
                },
            );
        }
        let ticket = if git {
            match self
                .call(&Request::ServiceAuthorize(ServiceAuthorize {
                    call: call.clone(),
                    stream: false,
                }))
                .await?
            {
                Response::Authorized { ticket, .. } => Some(ticket),
                _ => return Ok(json!({"ok":false})),
            }
        } else {
            None
        };
        match self.call(&Request::ServiceForward(call)).await? {
            Response::Reply { status, body, .. } if (200..300).contains(&status) => {
                if git {
                    return Ok(json!({"ok":true,"ticket":ticket}));
                }
                let fence = serde_json::from_slice::<Value>(&body)
                    .ok()
                    .and_then(|v| v["fencing_token"].as_str()?.parse::<i64>().ok());
                Ok(match fence {
                    Some(n) if n > 0 => json!({"ok":true,"fencing_token":n.to_string()}),
                    _ => json!({"ok":false}),
                })
            }
            _ => Ok(json!({"ok":false,"ticket":ticket})),
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Arc::new(Options::parse());
    let raw = Zeroizing::new(std::fs::read_to_string(&opt.token_file)?);
    let token = MacaroonV1::decode(raw.trim())?
        .attenuate(Caveat::Seat(opt.seat.clone()))?
        .attenuate(Caveat::Namespace(Namespace::Service))?
        .attenuate(Caveat::Rows(vec![opt.pod_row.clone(), opt.git_row.clone()]))?
        .attenuate(Caveat::Methods(vec!["POST".into()]))?
        .attenuate(Caveat::PathPrefixes(vec![
            "/pod/claim".into(),
            "/pod/done".into(),
            "/git/land".into(),
        ]))?
        .attenuate(Caveat::MaxSpendMicroUsd(opt.max_spend_micro_usd))?;
    let token = Arc::new(Zeroizing::new(token.encode()));
    let (send, recv) = mpsc::channel::<Job>(usize::from(opt.workers));
    let recv = Arc::new(Mutex::new(recv));
    let out = Arc::new(Mutex::new(tokio::io::stdout()));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..opt.workers {
        let mut worker = Some(Worker::start().await?);
        let (recv, out) = (recv.clone(), out.clone());
        let mut bridge = Bridge {
            options: opt.clone(),
            token: token.clone(),
            client: None,
        };
        tasks.spawn(async move {
            loop {
                let job={recv.lock().await.recv().await};
                let Some(job)=job else{break};
                if worker.is_none(){worker=Worker::start().await.ok()}
                let mut result=if let Some(w)=&mut worker {
                    match timeout(Duration::from_millis(50),w.invoke(&job,&mut bridge)).await {
                        Ok(Ok(value))=>value,
                        failure=>{
                            worker.take();
                            bridge.client.take();
                            json!({"ok":false,"reason":if failure.is_err(){"timeout"}else{"worker"}})
                        }
                    }
                }else{json!({"ok":false,"reason":"unavailable"})};
                result["id"]=job.id.into();
                write_frame(&mut *out.lock().await,&result).await?;
            }
            Ok::<_,io::Error>(())
        });
    }
    write_frame(&mut *out.lock().await, &json!({"ready":true})).await?;
    let mut input = tokio::io::stdin();
    while let Some(bytes) = read_frame_limited(&mut input, LIMIT).await? {
        send.send(serde_json::from_slice(&bytes)?)
            .await
            .map_err(|_| bad())?;
    }
    drop(send);
    while let Some(result) = tasks.join_next().await {
        result??
    }
    Ok(())
}
