# Architecture

dapapa-linux is split into an unprivileged client side and a small privileged helper.

```
┌──────────────────────┐   Unix socket (JSON lines, v1)   ┌──────────────────────────────┐
│ GUI (dapapa) /       │ ───────────────────────────────▶ │ dapapa-helper (root, systemd) │
│ dapapactl            │ ◀─────────────── status, logs ── │                              │
└──────────────────────┘   /run/dapapa/helper.sock        │  nftables table `ip dapapa`  │
        user session        group `dapapa`, mode 0660     │  NFQUEUE consumer            │
                                                          │  raw IPv4 sender             │
                                                          │  local DoH resolver :5300    │
                                                          │  Cloudflare target refresh   │
                                                          └──────────────────────────────┘
```

| Project | Role |
| --- | --- |
| `src/Dapapa.Core` | Platform-independent code ported from the Windows app: DNS wire format, DoH client and cache, local resolver, packet processor and every DPI method, domain normalisation, related-domain discovery, settings, localisation, traffic statistics and the helper protocol/client. |
| `src/Dapapa.Helper` | Root daemon. Owns the nftables table, the netfilter queue, raw injection, the local resolver and target-IP refresh. Accepts only structured requests; never runs shell commands, rule text or paths supplied by a client. |
| `src/Dapapa.Cli` | `dapapactl`, a command-line client for testing and scripting. |
| `src/Dapapa.App` | Avalonia GUI (`dapapa`): a port of the WPF window and dialogs. It runs unprivileged, talks to the helper through `HelperProtectionService`, and handles settings, start on login (XDG autostart), the tray icon, desktop notifications and single-instance activation. |

## Runtime and dependencies

- .NET 10 LTS (supported until November 2028), framework-dependent, using Arch's `dotnet-runtime`.
- `libnetfilter_queue` for NFQUEUE, `nftables` for the rules, `iproute2` (`ss -K`) to close protected connections on stop.
- AngleSharp 1.8.5 for HTML parsing during discovery.
- Tmds.DBus.Protocol 0.94.1 (the version Avalonia uses) for desktop notifications.
- Avalonia 12.1.4 for the GUI with Skia rendering. The window uses X11 (XWayland on Hyprland, WM class `dapapa`) because Avalonia 12.1.4's Wayland backend fires a 16 ms `DispatcherTimer` about every 100 ms, which limits animations and transitions to about 10 frames per second; through XWayland they follow the display. `DAPAPA_WAYLAND=1`, or a session without an X server, selects the native Wayland backend (app id `dapapa`). Third-party licenses are listed in [THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md).

## GUI

The window keeps the WPF structure and element names, so behaviour was ported method by method; see [visual-parity.md](visual-parity.md) for the look. The differences come from the privilege split:

| Windows app | Linux GUI |
| --- | --- |
| Starts WinDivert in-process | Sends `Start`, then `Refresh`; protection is running once targets are resolved |
| Restarts the engine for DPI changes | Sends `Update`; the helper swaps its nftables table atomically |
| Restarts the engine for a DoH change | Sends `Update` with the provider; the helper restarts its resolver |
| Counters read from the engine | Counters from helper status events; "Reset" keeps a local baseline |
| Watchdog restarts WinDivert | Watchdog reconnects to the helper and starts again (helper restarts, failed sessions) |
| Hosts file and Windows DNS cache cleanup | Not needed; the helper flushes systemd-resolved itself |

Logs go to `$XDG_STATE_HOME/dapapa/dapapa.log` and settings to `$XDG_CONFIG_HOME/dapapa/settings.json`. A second launch signals the running instance through `$XDG_RUNTIME_DIR/dapapa/app.sock` to show its window; `--tray` starts hidden (used by the autostart entry).

## Privilege model

- The helper runs as root under `dapapa-helper.service` with `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW`.
- It is socket-activated: systemd creates `/run/dapapa/helper.sock` owned by `root:dapapa` with mode `0660`. Users in the `dapapa` group can control protection; peer credentials are logged for every connection.
- The GUI never runs as root, and no file capabilities are added to the .NET runtime.
- Polkit is deliberately not used: membership of the `dapapa` group is the only grant. It needs no authentication agent, which a plain Hyprland session does not start, and an administrator decides once who may change the network path instead of a prompt deciding each time.

## Protocol

Newline-delimited JSON, at most 1 MiB per message, protocol version 1 (`HelperProtocol`). A client must send `Hello` first.

| Command | Purpose |
| --- | --- |
| `Hello` | Protocol negotiation; returns the current status. |
| `Start` | Starts protection with a domain list, DPI options and DoH provider. |
| `Update` | Live change of domains, options or provider. |
| `Stop` | Stops protection, removes the rules and closes the connections it rewrote. |
| `Status` | Current state and counters. |
| `Refresh` | Re-resolves targets through Cloudflare and returns per-domain counts. |

The helper pushes `Status` and bounded `Log` events to every connected client.

**Lease:** protection belongs to the connection that last started or updated it. If that connection closes without `Stop`, protection stops after a grace period (10 s by default), so a crashed or killed GUI never leaves interception running.
