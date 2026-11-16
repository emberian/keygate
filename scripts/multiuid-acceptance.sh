#!/bin/bash
# Acceptance test of keygate's separated deployment with real kernel uids.
#
#   scripts/multiuid-acceptance.sh /path/to/keygate
#
# Needs no root and touches no host account. It enters a private user,
# mount, pid and network namespace in which this user is uid 0 and a range
# of subordinate uids is mapped (unshare --map-auto), builds a throwaway
# root filesystem on a tmpfs there, and runs the broker as uid 0 with
# callers as uids 1 and 2. Peer credentials, file permissions and the
# broker's own-uid rule are then enforced by the kernel between genuinely
# different uids. Everything lives in one mktemp directory and one pid
# namespace, both gone when the script exits.
#
# Exit status: 0 all checks passed, 77 the host cannot build the namespace
# (reported as SKIPPED), anything else a failed check.
set -euo pipefail
# chroot and mount are often in sbin, which unprivileged PATHs omit.
PATH=$PATH:/usr/sbin:/sbin
# Fixture directories must not be group-writable: the broker refuses a
# state directory under one.
umask 022

if [ "${KEYGATE_MULTIUID_STAGE:-}" != inside ]; then
    [ $# -eq 1 ] || { echo "usage: $0 /path/to/keygate" >&2; exit 2; }
    bin=$(readlink -f "$1")
    [ -x "$bin" ] || { echo "$bin is not executable" >&2; exit 2; }
    ns=(unshare --user --map-auto --map-root-user --mount --pid --net --fork --kill-child)
    for tool in unshare setpriv chroot mount; do
        command -v "$tool" >/dev/null || { echo "SKIPPED: $tool is not installed"; exit 77; }
    done
    if ! "${ns[@]}" setpriv --reuid=1 --regid=1 --clear-groups true 2>/dev/null; then
        echo "SKIPPED: this host cannot map subordinate uids into a user namespace"
        exit 77
    fi
    work=$(mktemp -d "${TMPDIR:-/tmp}/keygate-multiuid.XXXXXX")
    trap 'rm -rf "$work"' EXIT
    KEYGATE_MULTIUID_STAGE=inside "${ns[@]}" "$(readlink -f "$0")" "$bin" "$work"
    exit $?
fi

if [ "${KEYGATE_MULTIUID_ROOTED:-}" != yes ]; then
    # Namespace uid 0, still on the host's filesystem. Build a root whose
    # every directory belongs to namespace root, so path custody checks see
    # what a real deployment would: nothing above the state directory that
    # another uid could rearrange.
    bin=$1
    root=$2/root
    mkdir "$root"
    # Room for the binary (a debug build can be large) plus the fixture.
    size_kb=$(( $(stat -c %s "$bin") / 1024 + 65536 ))
    mount -t tmpfs -o "size=${size_kb}k,mode=0755" tmpfs "$root"
    mkdir "$root/usr" "$root/proc" "$root/dev" "$root/kg"
    mkdir -m 1777 "$root/tmp"
    mount --rbind /usr "$root/usr"
    mount --rbind /dev "$root/dev"
    mount -t proc proc "$root/proc"
    for dir in bin sbin lib lib32 lib64 libx32; do
        if [ -L "/$dir" ]; then
            ln -s "$(readlink "/$dir")" "$root/$dir"
        elif [ -d "/$dir" ]; then
            mkdir "$root/$dir"
            mount --rbind "/$dir" "$root/$dir"
        fi
    done
    cp "$bin" "$root/kg/keygate"
    cp "$(readlink -f "$0")" "$root/kg/acceptance.sh"
    chmod 755 "$root/kg/keygate" "$root/kg/acceptance.sh"
    KEYGATE_MULTIUID_ROOTED=yes exec chroot "$root" /bin/bash /kg/acceptance.sh
fi

# Inside the throwaway root: uid 0 is the broker and operator, uids 1 and 2
# are callers.
kg=/kg/keygate
state=/kg/state
pub=/kg/pub
sock=$pub/keygate.sock
as() { local uid=$1; shift; setpriv --reuid="$uid" --regid="$uid" --clear-groups "$@"; }
fail() { echo "FAIL: $*"; exit 1; }
pass() { echo "PASS: $*"; }
refused() { # refused <why-substring> <command...>: must fail and say why
    local why=$1; shift
    local out
    if out=$("$@" 2>&1); then fail "succeeded but should not have: $*"; fi
    case "$out" in *"$why"*) ;; *) fail "refused, but not for '$why': $out";; esac
}

mkdir -m 755 "$pub"
"$kg" --state "$state" init >/dev/null
cat > "$state/keygate.toml" <<CONFIG
[broker]
deployment = "separated"
operator_uids = [0]
socket = "$sock"
socket_mode = 438
shutdown_grace_ms = 1000

[services.fixture]
origin = "https://example.invalid"
methods = ["GET", "POST"]
buffered_paths = ["/api"]
max_request_bytes = 4096
CONFIG
"$kg" --state "$state" serve >"$pub/broker.log" 2>&1 </dev/null &
broker=$!
for _ in $(seq 1 200); do
    [ -S "$sock" ] && break
    kill -0 "$broker" 2>/dev/null || break
    sleep 0.02
done
[ -S "$sock" ] || { cat "$pub/broker.log"; fail "the broker did not start"; }

# The operator (uid 0) loads a secret and mints a token bound to uid 1.
printf '%s' 'fixture-secret-for-peer-isolation-123456789' | "$kg" --socket "$sock" set service fixture >/dev/null
"$kg" --socket "$sock" mint --seat fixture-seat --uid 1 --namespace service --rows fixture \
    --methods GET --path-prefixes /api --ttl-s 300 >"$pub/token"
chmod 644 "$pub/token"
call=(authorize service fixture GET /api --token-file "$pub/token")

# 1. A caller under another uid is identified by the kernel and served.
hello=$(as 1 "$kg" --socket "$sock" hello)
for want in '"uid": 1' '"operator": false' '"caller": true' '"deployment": "separated"'; do
    case "$hello" in *"$want"*) ;; *) fail "hello as uid 1 lacks $want: $hello";; esac
done
as 1 "$kg" --socket "$sock" "${call[@]}" | grep -q '"ticket"' || fail "uid 1 could not use its token"
pass "kernel peer uid 1 is served as a caller with its scoped token"

# 2. That caller cannot reach the broker's custody by any route.
for path in "$state" "$state/master.key" "$state/keygate.toml" "$state/journal.wal" "$state/services/fixture.sealed"; do
    if as 1 cat "$path" >/dev/null 2>&1 || as 1 ls "$path" >/dev/null 2>&1; then
        fail "uid 1 can read $path"
    fi
done
if as 1 cat "/proc/$broker/environ" >/dev/null 2>&1 || as 1 head -c1 "/proc/$broker/mem" >/dev/null 2>&1; then
    fail "uid 1 can read the broker's process memory or environment"
fi
pass "uid 1 cannot read the master key, sealed rows, journal, config or broker memory"

# 3. Nor can it operate the broker.
refused not_operator as 1 "$kg" --socket "$sock" mint --seat stolen
refused not_operator as 1 "$kg" --socket "$sock" ls
refused not_operator as 1 "$kg" --socket "$sock" revoke service fixture
refused not_operator as 1 "$kg" --socket "$sock" forget service fixture
refused not_operator as 1 bash -c "printf attacker-chosen-secret-0001 | $kg --socket $sock set service fixture"
"$kg" --socket "$sock" ls | grep -q 'active.*gen=1' || fail "a non-operator changed the row"
pass "uid 1 cannot mint, list, set, revoke or forget"

# 4. A uid-bound token does not work for another uid.
refused 'bound to uid 1' as 2 "$kg" --socket "$sock" "${call[@]}"
pass "uid 2 cannot use the token bound to uid 1"

# 5. The broker's own uid is not served as a caller.
"$kg" --socket "$sock" mint --seat own-uid >"$pub/unbound"
refused 'own uid' "$kg" --socket "$sock" authorize service fixture GET /api --token-file "$pub/unbound"
pass "the broker's own uid is refused on the data plane"

# 6. The client will not hand a secret to someone else's listener: a
#    socket planted by uid 1 in a directory uid 1 controls is refused by
#    the operator's client unless that uid is named explicitly.
if command -v python3 >/dev/null; then
    as 1 mkdir /tmp/planted
    as 1 python3 -c '
import socket, sys, time
s = socket.socket(socket.AF_UNIX); s.bind("/tmp/planted/keygate.sock"); s.listen(4)
open("/tmp/planted/ready", "w").close()
c, _ = s.accept(); got = c.recv(65536)
open("/tmp/planted/captured", "wb").write(got); time.sleep(5)' &
    for _ in $(seq 1 200); do [ -e /tmp/planted/ready ] && break; sleep 0.02; done
    refused 'neither root nor' bash -c "printf operator-secret-must-not-leak-01 | $kg --socket /tmp/planted/keygate.sock set service fixture"
    refused 'not the expected uid' bash -c "printf operator-secret-must-not-leak-01 | $kg --socket /tmp/planted/keygate.sock --broker-uid 0 set service fixture"
    if [ -s /tmp/planted/captured ]; then fail "bytes were sent to the planted listener"; fi
    pass "the operator's client sends nothing to a listener planted by uid 1"
else
    echo "NOTE: python3 not present; planted-listener check not run"
fi

kill "$broker"
wait "$broker" || true
echo "multiuid: all checks passed"
