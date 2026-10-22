#!/bin/bash
# Network-namespace integration test for dapapa-helper. Needs root and a kernel with nftables and NFQUEUE.
# Only the namespaces created here are modified; the host ruleset and resolver are never touched.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
IT="$ROOT/tests/integration"
mkdir -p "$ROOT/artifacts"
WORK=$(mktemp -d "$ROOT/artifacts/integration.XXXXXX")
HELPER="dotnet $ROOT/src/Dapapa.Helper/bin/Release/net10.0/dapapa-helper.dll"
CTL="dotnet $ROOT/src/Dapapa.Cli/bin/Release/net10.0/dapapactl.dll"
SOCK="$WORK/helper.sock"
# tcpdump drops privileges after opening its output, so captures are written to a world-writable directory under /tmp.
CAPTURES=$(mktemp -d /tmp/dapapa-captures.XXXXXX)
chmod 777 "$CAPTURES"
PASSED=0
FAILED=0
PIDS=()

pass() { echo "PASS: $1"; PASSED=$((PASSED + 1)); }
fail() { echo "FAIL: $1"; FAILED=$((FAILED + 1)); }
expect() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected '$3', got '$2')"; fi; }
check() { local name=$1; shift; if "$@"; then pass "$name"; else fail "$name"; fi; }
in_cli() { ip netns exec dapapa-cli "$@"; }
in_srv() { ip netns exec dapapa-srv "$@"; }

wait_for() { # wait_for SECONDS COMMAND...
    local deadline=$((SECONDS + $1)); shift
    until "$@" >/dev/null 2>&1; do
        [ $SECONDS -ge $deadline ] && return 1
        sleep 0.2
    done
}

cleanup() {
    for pid in "${PIDS[@]}"; do kill -9 "$pid" 2>/dev/null; done
    ip netns del dapapa-cli 2>/dev/null
    ip netns del dapapa-srv 2>/dev/null
    if [ $FAILED -gt 0 ]; then cp "$CAPTURES"/* "$WORK" 2>/dev/null; echo "Logs and captures kept in $WORK"; else rm -rf "$WORK"; fi
    rm -rf "$CAPTURES"
}
trap cleanup EXIT

# dig refuses to run when the host resolv.conf names a server scoped to an interface that the namespace lacks
# (for example fe80::1%eth0). It therefore reads a private copy that points at the test server; the host file is never changed.
printf 'nameserver 10.77.0.2\n' > "$WORK/resolv.conf"
resolve() {
    in_cli unshare --mount sh -c 'mount --bind "$1" /etc/resolv.conf && exec dig +short +time=3 +tries=1 @10.77.0.2 "$2"' \
        sh "$WORK/resolv.conf" "$1" | tail -n 1
}
tls() { in_cli timeout 10 python3 "$IT/client.py" tls "$1" "$2" 2>&1; }
udp_count() { grep -c "^udp $1 " "$WORK/server.log"; }
table_present() { in_cli nft list table ip dapapa >/dev/null 2>&1 && echo yes || echo no; }
pcap_check() { python3 "$IT/pcap.py" "$CAPTURES/$1.pcap" 10.77.0.3 "$2"; }

# Background processes are started directly (not through shell functions) so that $! is the real process.
capture() { # capture NAME FILTER; stop with stop_capture
    ip netns exec dapapa-srv tcpdump --immediate-mode -i veth1 -U -w "$CAPTURES/$1.pcap" "$2" 2>"$CAPTURES/$1.err" &
    CAPTURE_PID=$!
    PIDS+=("$CAPTURE_PID")
    sleep 1
}
stop_capture() { sleep 0.5; kill "$CAPTURE_PID"; wait "$CAPTURE_PID" 2>/dev/null; }

start_run() {
    ip netns exec dapapa-cli $CTL run --socket "$SOCK" --domain target.test "$@" > "$WORK/run.log" 2>&1 &
    RUN_PID=$!
    PIDS+=("$RUN_PID")
    wait_for 20 grep -q "Protection is running" "$WORK/run.log" || { fail "protection start"; cat "$WORK/run.log"; return 1; }
    wait_for 20 sh -c "$CTL refresh --socket $SOCK | grep -q 'target.test .*1 IPv4'"
}
stop_run() { kill -TERM "$RUN_PID"; wait "$RUN_PID" 2>/dev/null; }

HELPER_RUNS=0
start_helper() {
    HELPER_RUNS=$((HELPER_RUNS + 1))
    local log="$WORK/helper.$HELPER_RUNS.log"
    ip netns exec dapapa-cli $HELPER --socket "$SOCK" --socket-group root --doh-endpoint https://10.77.0.2/dns-query \
        --trust-ca "$WORK/ca.pem" --lease-grace 2 > "$log" 2>&1 &
    HELPER_PID=$!
    PIDS+=("$HELPER_PID")
    wait_for 20 grep -q "ready" "$log"
}

# --- Topology: client namespace with the helper, server namespace with DNS/DoH/TLS/UDP endpoints ---
ip netns add dapapa-cli
ip netns add dapapa-srv
ip link add veth0 netns dapapa-cli type veth peer name veth1 netns dapapa-srv
in_cli ip addr add 10.77.0.1/24 dev veth0
in_srv ip addr add 10.77.0.2/24 dev veth1
in_srv ip addr add 10.77.0.3/24 dev veth1
in_srv ip addr add 10.77.0.4/24 dev veth1
for ns in dapapa-cli dapapa-srv; do ip netns exec $ns ip link set lo up; done
in_cli ip link set veth0 up
in_srv ip link set veth1 up
in_cli ip route add default via 10.77.0.2
# Full checksums on the wire make the capture checks meaningful for kernel-generated packets too.
in_cli ethtool -K veth0 tx off >/dev/null

# --- Certificates for the test DoH server and TLS sites ---
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=dapapa-test-ca -keyout "$WORK/ca.key" -out "$WORK/ca.pem" 2>/dev/null
for cert in "doh IP:10.77.0.2" "site DNS:target.test,DNS:other.test"; do
    set -- $cert
    openssl req -newkey rsa:2048 -nodes -subj "/CN=$1" -keyout "$WORK/$1.key" -out "$WORK/$1.csr" 2>/dev/null
    openssl x509 -req -in "$WORK/$1.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" -CAcreateserial -days 1 \
        -extfile <(printf "subjectAltName=%s" "$2") -out "$WORK/$1.pem" 2>/dev/null
done

ip netns exec dapapa-srv python3 "$IT/servers.py" "$WORK" "$WORK/server.log" &
PIDS+=($!)
wait_for 15 grep -q ready "$WORK/server.log" || { echo "servers did not start"; exit 1; }
start_helper || { echo "helper did not start"; cat "$WORK/helper.1.log"; exit 1; }
pass "helper starts as root with a socket and no rules installed"
expect "no ruleset before protection" "$(table_present)" "no"

# --- Standard profile ---
start_run || exit 1
expect "rules installed while protected" "$(table_present)" "yes"
expect "selected domain resolves through DoH" "$(resolve target.test)" "10.77.0.3"
expect "selected subdomain resolves through DoH" "$(resolve www.target.test)" "10.77.0.3"
expect "unselected domain keeps the system DNS path" "$(resolve other.test)" "10.77.0.99"
expect "selected queries never reach the plain DNS server" "$(grep -c '^plain .*target.test' "$WORK/server.log")" "0"

capture standard "tcp and dst host 10.77.0.3 and dst port 443"
expect "TLS handshake to a selected site completes" "$(tls target.test 10.77.0.3)" "OK"
stop_capture
check "Standard sends the ClientHello tail first and the 2-byte head second" pcap_check standard standard

capture other "tcp and dst host 10.77.0.3 and dst port 443"
expect "TLS handshake to an unselected site completes" "$(tls other.test 10.77.0.3)" "OK"
stop_capture
check "unselected ClientHello is not split" pcap_check other unsplit

before3=$(udp_count 10.77.0.3); before4=$(udp_count 10.77.0.4)
in_cli python3 "$IT/client.py" udp 10.77.0.3 3 >/dev/null
in_cli python3 "$IT/client.py" udp 10.77.0.4 3 >/dev/null
sleep 1
expect "QUIC to a selected IP is blocked" "$(( $(udp_count 10.77.0.3) - before3 ))" "0"
expect "QUIC to other IPs passes" "$(( $(udp_count 10.77.0.4) - before4 ))" "3"

in_cli nft -f - <<'EOF'
table inet userfw {
    chain input {
        type filter hook input priority filter; policy drop;
        ct state established,related accept
        iifname "lo" accept
    }
}
EOF
expect "selected DNS works behind a stateful firewall" "$(resolve target.test)" "10.77.0.3"
expect "TLS works behind a stateful firewall" "$(tls target.test 10.77.0.3)" "OK"
expect "the foreign firewall table is left untouched" "$(in_cli nft list table inet userfw | grep -c 'policy drop')" "1"
in_cli nft delete table inet userfw

stop_run
expect "disconnect removes the ruleset" "$(table_present)" "no"
expect "after disconnect the system DNS path is used" "$(resolve target.test)" "10.77.0.99"

# --- Custom profile: forward split inside the hostname, bad-checksum fake, QUIC fragmentation ---
cat > "$WORK/custom.json" <<'EOF'
{"TcpFragmentation":true,"ReverseSegments":false,"SplitAtHostname":true,"FakeWrongChecksum":true,
 "BlockQuic":false,"UdpIpFragmentation":true,"UdpFragmentSize":24,"UdpQuicInitial":true}
EOF
start_run --options "$WORK/custom.json" || exit 1
capture custom "tcp and dst host 10.77.0.3 and dst port 443"
expect "TLS completes with a fake packet and hostname split" "$(tls target.test 10.77.0.3)" "OK"
stop_capture
check "bad-checksum fake precedes the real hostname split in forward order" pcap_check custom fakesplit

capture quic "udp and dst host 10.77.0.3"
before=$(udp_count 10.77.0.3)
in_cli python3 "$IT/client.py" udp 10.77.0.3 1 >/dev/null
stop_capture
expect "QUIC Initial leaves as two IP fragments" \
    "$(python3 "$IT/pcap.py" "$CAPTURES/quic.pcap" 10.77.0.3 udp | awk '{print $2":"$3}' | paste -sd,)" "0:1,24:0"
expect "the server reassembles the original datagram" "$(grep '^udp 10.77.0.3 ' "$WORK/server.log" | tail -n 1)" "udp 10.77.0.3 1250"
expect "exactly one datagram is delivered" "$(( $(udp_count 10.77.0.3) - before ))" "1"
stop_run

# --- Lease: a client that disappears without stopping ---
start_run || exit 1
kill -9 "$RUN_PID"; wait "$RUN_PID" 2>/dev/null
sleep 4
expect "protection stops after the owning client vanishes" "$(table_present)" "no"

# --- Helper crash: traffic must keep flowing and the next start cleans up ---
start_run || exit 1
kill -9 "$HELPER_PID"; wait "$HELPER_PID" 2>/dev/null
expect "rules outlive a killed helper" "$(table_present)" "yes"
expect "DNS still works after a helper crash (fail-open)" "$(resolve target.test)" "10.77.0.99"
expect "TLS still works after a helper crash (fail-open)" "$(tls target.test 10.77.0.3)" "OK"
kill -9 "$RUN_PID" 2>/dev/null; wait "$RUN_PID" 2>/dev/null
start_helper || fail "helper restart"
expect "a restarted helper removes stale rules" "$(table_present)" "no"

echo "Integration: $PASSED passed, $FAILED failed."
[ $FAILED -eq 0 ]
