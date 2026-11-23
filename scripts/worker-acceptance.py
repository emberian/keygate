"""Cross-project Linux acceptance. Put keygate, keygate-worker and landd on PATH."""
import argparse
from collections import Counter
import contextlib
import hashlib
import http.server
import json
import os
from pathlib import Path
import secrets
import statistics
import struct
import subprocess
import tempfile
import threading
import time


def run(*args, data=None, cwd=None):
    return subprocess.run(args, input=data, capture_output=True, check=True,
                          text=True, cwd=cwd).stdout.strip()


def launch(stack, *args, **kwargs):
    child = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, **kwargs)
    def close():
        child.terminate()
        child.wait(timeout=5)
    stack.callback(close)
    return child


def frame(pipe):
    size, = struct.unpack(">I", pipe.read(4))
    assert size <= 65536
    return json.loads(pipe.read(size))


def acceptance(root, stack, socket_parent=None):
    state, db, token = (root / n for n in ("state", "pod.db", "token"))
    socket_dir = (Path(stack.enter_context(tempfile.TemporaryDirectory(dir=socket_parent)))
                  if socket_parent else state)
    sock = socket_dir / "keygate.sock"
    secret = secrets.token_hex(24)
    pod_args = ["--database", db, "--lead", "lead", "--principal", "ci"]
    tasks = [str(i) for i in range(66)]
    run("landd", "pod-step", "--database", db, "--lead", "lead", "--principal", "lead",
        data=json.dumps({"pod":"batch", "action":{"op":"create_pod", "tasks":tasks}}))
    pod = launch(stack, "landd", "pod-service", *pod_args, "--listen", "127.0.0.1:0",
                 "--credential-sha256", hashlib.sha256(secret.encode()).hexdigest())
    pod_origin = "http://" + pod.stdout.readline().decode().strip()
    repo = root / "git"
    run("git", "init", "-q", "-b", "main", repo)
    def git(*args):
        return run("git", "-c", "user.name=Builder", "-c", "user.email=b@example.org",
                   "-c", "commit.gpgsign=false", *args, cwd=repo)
    git("commit", "--allow-empty", "-m", "base")
    old = git("rev-parse", "HEAD")
    git("switch", "-c", "candidate")
    git("commit", "--allow-empty", "-m", "candidate")
    new = git("rev-parse", "HEAD")
    cas = dict(repo="forge", reference="refs/heads/main", expected_old=old, new_oid=new)
    class Forge(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert self.path == "/git/land" and self.headers["Authorization"] == "Bearer " + secret
            assert body["repo"] == "forge" and body["reference"] == cas["reference"]
            old,new=body["expected_old"],body["new_oid"]
            git("merge-base", "--is-ancestor", old, new)
            git("update-ref", cas["reference"], new, old)
            # Drop the response after the real CAS. Only an authoritative
            # ref probe can distinguish committed from safe-to-retry.
            self.close_connection = True
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Forge)
    stack.callback(server.server_close)
    stack.callback(server.shutdown)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    def kg(*args, data=None):
        return run("keygate", "--state", state, "--socket", sock, *args, data=data)
    kg("init")
    (state / "keygate.toml").write_text(f'''[broker]
socket={json.dumps(str(sock))}
deployment="development"
git_land_targets={{forge="{repo}/.git"}}
git_land_micro_usd=1
pod_seats={{pods="ci"}}
pod_micro_usd=1
[services.pods]
origin="{pod_origin}"
methods=["POST"]
buffered_paths=["/pod"]
[services.forge]
origin="http://127.0.0.1:{server.server_port}"
methods=["POST"]
buffered_paths=["/git/land"]
''')
    launch(stack, "keygate", "--state", state, "serve")
    deadline = time.monotonic()+5
    while not sock.exists():
        assert time.monotonic()<deadline
        time.sleep(.01)
    for row in ["pods", "forge"]:
        kg("set", "service", row, data=secret)
    token.write_text(kg("mint", "--seat", "ci", "--namespace", "service", "--max-spend-micro-usd", "146"))
    token.chmod(0o600)
    worker_args = ["keygate-worker", "--socket", sock, "--token-file", token,
                   "--allow", "pod.claim,pod.done,git.land,git.reconcile", "--pod-row", "pods", "--git-row", "forge", "--max-spend-micro-usd", "500", "--workers", "1"]
    def start(seat):
        proc = launch(stack, *worker_args, "--seat", seat, env={**os.environ, "BROKER_CANARY":secret})
        assert frame(proc.stdout) == {"ready":True}
        return proc
    worker = start("ci")
    def invoke(src, arg=None, proc=worker):
        data = json.dumps(dict(id=7, source=src, input=arg)).encode()
        now=time.perf_counter_ns()
        proc.stdin.write(struct.pack(">I", len(data))+data)
        proc.stdin.flush()
        response = frame(proc.stdout)
        assert secret not in json.dumps(response)
        return response,(time.perf_counter_ns()-now)/1e6
    for src in ["return process.env", "return globalThis.fetch('/')", "return new Function('return 1')()",
                "return Object.getPrototypeOf(()=>{}).constructor('return 1')()"]:
        assert not invoke(src)[0]["ok"]
    assert invoke("return [typeof fs, typeof env, typeof eval, typeof process]")[0]["value"] == ["undefined"]*4
    failed,elapsed=invoke("for(;;){}")
    assert not failed["ok"] and elapsed < 150,(failed,elapsed)
    assert invoke("return 42")[0]["value"]==42
    timeouts = Counter()

    def sample(name, source, arg):
        answer, first_ms = invoke(source, arg)
        if answer.get("reason") == "timeout":
            timeouts[name] += 1
            # Restore the fixture with the same request ID. The first attempt
            # stays in the median and its timeout still fails acceptance.
            for _ in range(3):
                answer, _ = invoke(source, arg)
                if answer.get("reason") != "timeout":
                    break
        return answer, first_ms

    def measure(name, source, inputs, check):
        times = []
        for arg in inputs:
            answer, ms = sample(name, source, arg)
            assert check(arg, answer), answer
            times.append(ms)
        return statistics.median(times)

    warm = measure("dispatch", "return input+1", range(64),
                   lambda arg, reply: reply["ok"] and reply["value"] == arg + 1)
    take="return yield caps.pod.claim({pod:'batch',task:input,request_id:input,lease_seconds:600})"
    done="return yield caps.pod.done({pod:'batch',task:input.task,request_id:input.task,fencing_token:input.token})"
    def ok(v): return v["ok"] and v["value"]["ok"]
    wrong=start("other")
    assert not invoke(take,"64",wrong)[0]["value"]["ok"]
    tokens={}
    def claimed(task, answer):
        if not ok(answer):
            return False
        tokens[task] = answer["value"]["fencing_token"]
        return True

    claim_ms = measure("pod.claim", take, tasks[:64], claimed)
    assert not invoke(done,dict(task="0",token=str(int(tokens["0"])+1)))[0]["value"]["ok"]
    done_ms=measure("pod.done", done, [dict(task=t,token=tokens[t]) for t in tasks[:64]], lambda _, v: ok(v))
    land,_=sample("git.land", "return yield caps.git.land(input)", dict(cas=cas,request_id="land"))
    assert not land["value"]["ok"] and land["value"]["ticket"],land
    args=dict(cas=cas,request_id="land",ticket=land["value"]["ticket"])
    reconcile="return yield caps.git.reconcile(input)"
    def committed(v): return ok(v) and v["value"]["state"]=="committed"
    first,probe_ms=sample("git.reconcile", reconcile,args)
    assert committed(first) and git("rev-parse",cas["reference"])==new
    replay_ms=measure("settled ticket", reconcile, [args]*64, lambda _, v: committed(v))
    probes=[]
    for i in range(16):
        old=new
        git("commit","--allow-empty","-m",f"candidate-{i}")
        new=git("rev-parse","HEAD")
        cas.update(expected_old=old,new_oid=new)
        req=dict(cas=cas,request_id=f"land-{i}")
        uncertain,_=sample("git.land", "return yield caps.git.land(input)",req)
        assert not uncertain["value"]["ok"]
        result,ms=sample("git.reconcile", reconcile,dict(**req,ticket=uncertain["value"]["ticket"]))
        assert committed(result) and git("rev-parse",cas["reference"])==new
        probes.append(ms)
    git_ms=statistics.median(probes)
    assert not invoke(take,"64")[0]["value"]["ok"]
    print(f"median ms: dispatch {warm:.3f}, pod.claim {claim_ms:.3f}, pod.done {done_ms:.3f}, "
          f"git.reconcile {git_ms:.3f}, settled ticket {replay_ms:.3f}; cold ref probe {probe_ms:.3f}; loop cutoff {elapsed:.3f}",flush=True)
    assert not timeouts, f"first-attempt timeouts: {dict(timeouts)}"
    assert warm<1 and max(claim_ms,done_ms,git_ms)<2


if __name__=="__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket-dir", type=Path, help="parent for the private Unix socket when the data filesystem cannot host it")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
        acceptance(Path(tmp), stack, args.socket_dir)
