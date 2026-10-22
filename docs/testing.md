# Testing

All automated tests run in the Arch Linux development container (`docker/Dockerfile`). On Arch itself the same commands work without `./dev.sh`.

```bash
./dev.sh dotnet build dapapa-linux.slnx -c Release
./dev.sh sh -c 'cd tests/Dapapa.Core.Tests && dotnet run -c Release --no-build'
./dev.sh sh -c 'cd tests/Dapapa.Helper.Tests && dotnet run -c Release --no-build'
./dev.sh sh -c 'cd tests/Dapapa.App.Tests && dotnet run -c Release --no-build -- /src/artifacts/screenshots'
./dev.sh bash tests/integration/run.sh
./dev.sh sh tests/wayland/smoke.sh
```

`./dev.sh` runs the container with `--privileged` because the helper tests use nftables and the integration test creates network namespaces. The host's own ruleset and resolver are never changed.

## Suites

| Suite | Scope | Container (2026-10-22, kernel 6.18 WSL2) | Arch Linux host (2026-10-22, kernel 7.2.11-zen) |
| --- | --- | --- | --- |
| `Dapapa.Core.Tests` | Ported from the Windows suite: DNS wire format and fuzzing, DoH cache/TTL/coalescing/limits, real loopback resolver, packet processor for every TCP/HTTP/UDP method, domains, groups, discovery, settings, localisation, traffic statistics, log rotation, kernel-upgrade detection, names without an IPv4 address. | 71 groups pass | 73 groups pass |
| `Dapapa.Helper.Tests` | nftables rules for all 128 capture-relevant option combinations validated with `nft --check`; rule scope; checksum preparation; flow parsing and the exact `ss -K` filter (closing a real loopback connection is skipped on kernels without `CONFIG_INET_DIAG_DESTROY`, such as WSL's). | 4 groups pass (socket close skipped) | 4 groups pass, socket close included |
| `Dapapa.App.Tests` | Headless Avalonia with Skia rendering and a fake helper: start/stop, failed start and unreachable helper, watchdog, live target/DPI/DoH updates, validation, language switching with open dialogs, statistics, dialogs, closing to tray and exit, autostart entry, tray icon attached to the application, notifications and a missing notification server, single instance, palette and sizes. Renders every screen and dialog in both languages to PNG. | 20 groups pass | 22 groups pass |
| `tests/wayland/smoke.sh` | Starts the real GUI on a headless Weston compositor and checks the Wayland protocol trace: native `xdg_toplevel`, app id, minimum size, title, committed frames, no crash. | 6 checks pass | not run (no Weston); see the Hyprland session below |
| `tests/integration/run.sh` | Real packets between two network namespaces with a test DoH server, a plain DNS server, TLS and UDP servers, verified from `tcpdump` captures. | 28 checks pass | 28 checks pass |

The Windows core suite had 82 groups; 11 tested Windows-only parts (WinDivert structures and filters, hosts file, scheduled task, WPF exit hook) and were replaced by the helper and integration tests.

## Integration test coverage

- Selected domains and subdomains resolve through DoH; other names keep the system DNS path; selected queries never reach the plain server.
- Standard: the ClientHello tail leaves before the 2-byte head; the TLS handshake completes. Unselected hosts are not split.
- QUIC to a selected IP is dropped; other IPs pass.
- DNS and TLS work behind a stateful `policy drop` firewall, and that table is left untouched.
- Custom: a bad-checksum fake precedes a forward-order hostname split; the handshake completes. A QUIC Initial leaves as two IP fragments and the server reassembles the original datagram.
- Disconnect removes the rules and restores the system DNS path.
- A client killed with `SIGKILL` loses its lease and protection stops.
- A helper killed with `SIGKILL` leaves traffic flowing (fail-open); the next helper removes the stale rules.

## Real Arch + Hyprland session

Checked on 2026-10-22 on an Arch Linux desktop (kernel 7.2.11-zen, Hyprland 0.56 started from ly without uwsm, Waybar):

- The package built by `packaging/arch/build.sh` installs over an older version with `pacman -U`; every file is owned by root and `pacman -Qkk dapapa` reports no altered files.
- Socket activation: `dapapactl status` starts `dapapa-helper.service` through `dapapa-helper.socket`, and the helper reports its version.
- The GUI opens with class and title `dapapa`, through XWayland by default and as a native Wayland window (`xwayland: 0`) with `DAPAPA_WAYLAND=1`; the README's float rule opens it at 520×640 in the middle of the monitor.
- Animation frame rate, measured on a 280 Hz monitor while the connected pulse runs: about 280 updates per second per animated element through XWayland (95th percentile interval 3.7 ms), against 28 per second natively on Wayland (92 ms). The cause is in Avalonia 12.1.4's Wayland backend: a 16 ms `DispatcherTimer` fires every 94–100 ms there and every 16 ms on X11; its GLib main loop option does not help.
- The tray icon registers with Waybar's StatusNotifierWatcher and shows the same menu as the Windows app.
- The tray menu works end to end: Connect starts protection, the menu and tooltip switch to "Protection active"/Disconnect, and Disconnect stops it and removes the table.
- Desktop notifications reach dunst with the app name, icon and a 3-second timeout; "Connecting..." and "Done" share one bubble.
- Real network (Türk Telekom, which blocks Discord through DNS): without protection `discord.com`, `gateway.discord.gg` and `cdn.discordapp.com` resolve to the operator's block address and HTTPS fails. With `dapapactl run` for the Discord domains they resolve to Cloudflare addresses and the TLS handshakes complete (HTTP 200/404/403 from Discord itself); stopping closes the protected connections, removes the table and returns to the system DNS path. `discordapp.net` produced no DNS failure lines.
- After a kernel upgrade without a reboot, starting protection fails with a message asking for a restart instead of a raw `nft`/NFQUEUE error, and no rules are left behind.

Found and fixed during this check: the tray icon never registered (Avalonia 12 only creates it for icons attached to the application), each start logged an error when `~/.config/autostart` did not exist, and `discordapp.net` (no A record) was logged as a DNS failure every 30 seconds. The integration test's `dig` calls failed when the host `resolv.conf` named an interface-scoped IPv6 server; they now use a private copy.

## Not covered yet

- Autostart at login on Hyprland: Hyprland does not run XDG autostart entries unless the session is started through uwsm (or another tool that runs them), so "Start on login" has no effect on a plain Hyprland session. Run `dapapa --tray` from the Hyprland configuration instead (`exec-once` in `hyprland.conf`, `hl.exec_cmd` in a `hyprland.start` handler in `hyprland.lua`).
- Other ISPs and the Discord client itself; success against a particular DPI system is never guaranteed.
