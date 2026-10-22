# Network lifecycle

## Ownership

The helper owns exactly one nftables table, `ip dapapa`. It is created and replaced in a single atomic transaction (`table … / delete table … / table … {}` in one `nft -f` run) and removed the same way. No other table is read or modified, and `flush ruleset` is never used.

| Chain | Hook / priority | Purpose |
| --- | --- | --- |
| `capture_out` | output / raw (-300) | Queue candidate packets: DNS, TLS ClientHello and HTTP request starts, QUIC/UDP per enabled methods. |
| `capture_in` | input / raw (-300) | Queue inbound SYN+ACK from ports 80/443, only when AutoTTL is enabled. |
| `dns_redirect` | nat output / dstnat (-100) | Redirect DNS queries that the helper marked as selected to `127.0.0.1:5300`. |

Kernel pre-filters only decide what is *queued*. Domain selection (TLS SNI / HTTP Host / DNS question) is always made in userspace, so a connection whose IP is not yet known is still recognised by its hostname.

## Marks and queue

| Value | Meaning |
| --- | --- |
| Queue `2701` | NFQUEUE number (`--queue` to change). Binding fails if another program already uses it. |
| Mark bit `0x10000000` | Packets sent by the helper (raw injections and its own DoH connections). The capture chain accepts them first, so nothing is captured twice. |
| Mark bit `0x20000000` | Set by the helper's verdict on selected DNS queries; consumed by `dns_redirect`. OR-ed into the existing mark so other software's mark bits survive. |

Loopback traffic (`oifname "lo"`) is never captured, so a local stub such as systemd-resolved (`127.0.0.53`) is not handled twice; its upstream queries are.

## DNS path

1. A queued outbound UDP/53 query is parsed. If its question is a selected domain (or subdomain), the verdict is *accept with the DNS mark*; otherwise *accept* unchanged.
2. `dns_redirect` DNATs the marked query to the local resolver on `127.0.0.1:5300`.
3. The local resolver answers through the selected DoH provider (RFC 8484 POST). On failure it returns `SERVFAIL`; it never falls back to unencrypted DNS.
4. Conntrack reverses the NAT, so the client sees the reply from the server it queried.

**Why not inject the reply directly (as on Windows)?** Dropping the original query also drops its conntrack entry, so an injected reply arrives as a *new* inbound flow. Any stateful firewall (`ct state established accept; policy drop`, ufw, firewalld) then discards it. The mark + DNAT path keeps conntrack consistent; the integration test checks it behind such a firewall.

Limitations: TCP/53, DNS over TLS and applications with their own DoH client are not covered. Conntrack binds NAT per flow, so if an unselected query and a later selected query use the same socket and 5-tuple, the later one follows the first (unredirected) path.

## Packet path

For TLS/HTTP/UDP packets the processor returns a decision. Unmodified packets are accepted. Modified ones are rebuilt in userspace, checksums are computed (fakes get deliberately invalid ones), every piece is sent through a raw socket carrying the bypass mark with `IP_NODEFRAG`, and the original is dropped. If the first real piece cannot be sent, the original is accepted instead (fail-open); if a later piece fails, TCP retransmits.

The queue copies whole packets. The kernel segments GSO packets and completes partial checksums before queueing, so the processor always sees wire-format packets.

## Start and stop order

Start: remove stale rules → start the local resolver (fails if port 5300 is taken) → open the raw socket → bind the queue → install rules → start target refresh. Any failure rolls back everything already started.

Stop: remove rules first (traffic immediately follows the normal path) → stop the queue → stop target refresh → stop the resolver → flush the systemd-resolved cache when that resolver is in use.

When the user stops protection (or the owning client's lease expires), the helper also closes the connections it rewrote, right after the rules are removed. Otherwise an open connection, such as a Discord voice or gateway session, would keep working until the application reconnects. The helper records each rewritten flow (protocol, local port, remote address and port; at most 8192 per session) and asks the kernel to destroy exactly those sockets with `ss -K` from iproute2. Other connections, including ones to the same server, are not touched. Removing a domain with a live `Update` closes that domain's flows the same way. Restarts for a DoH provider change and failures do not close anything. This needs `CONFIG_INET_DIAG_DESTROY`, which every official Arch kernel enables; without it the sockets simply stay open.

## Failure handling

| Situation | Result |
| --- | --- |
| GUI/CLI crash or kill | Lease expires after 10 s; protection stops and rules are removed. |
| Helper crash or `SIGKILL` | Rules use `queue … bypass` and the queue is fail-open, so traffic keeps flowing on the normal path. systemd's `ExecStopPost` removes the table; a restarted helper also removes it on startup. |
| Queue overflow | Fail-open: excess packets pass unmodified. |
| Queue consumer error | Protection switches to `Failed`, rules are removed. |
| Port 5300 in use | Protection does not start. |

Changes are never written to persistent nftables configuration, `/etc/hosts`, `/etc/resolv.conf`, NetworkManager or resolver settings.
