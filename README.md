<div align="center">

<img src="assets/app.png" width="88" alt="dapapa logo">

# dapapa for Linux

**Lightweight DPI circumvention and encrypted DNS for Linux — per domain, without a VPN.**

![Platform](https://img.shields.io/badge/platform-Arch%20Linux-1793D1?logo=archlinux&logoColor=white)
![.NET](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet)
![UI](https://img.shields.io/badge/UI-Avalonia%2012-5865F2)
![Netfilter](https://img.shields.io/badge/nftables-NFQUEUE-3BA55D)
![License](https://img.shields.io/badge/license-MIT-green)

</div>

---

This repository is the Linux port of [dapapa](https://github.com/ouxan/dapapa), forked from its `main` branch. The packet processing, DPI methods, DNS-over-HTTPS client and user interface are ported from the Windows application; the Windows-specific parts (WinDivert, the hosts file, scheduled tasks and WPF) are replaced by an unprivileged Avalonia client and a small privileged helper built on nftables and NFQUEUE.

## What is dapapa?

Some internet providers block websites by reading the name of the site inside your connection — a technique called **Deep Packet Inspection (DPI)**. dapapa slightly reshapes those first packets so the filter can no longer recognise the site name, while the real website still receives a perfectly normal connection. It also resolves the addresses of those sites through **encrypted DNS**, so the lookups cannot be read or tampered with.

- You choose which sites it applies to — everything else is left untouched.
- It is **not a VPN**: your IP address and internet speed stay the same, and nothing is routed through another server.
- It runs in the system tray, shows desktop notifications and can start with your session.

<p align="center">
  <img src="docs/images/settings-targets.png" width="30%" alt="Target list">
  &nbsp;
  <img src="docs/images/settings-dpi.png" width="30%" alt="DPI methods">
  &nbsp;
  <img src="docs/images/statistics.png" width="30%" alt="Statistics">
</p>

## Quick start

The release package targets Arch Linux. All of its dependencies come from the official repositories.

1. Download `dapapa-<version>-x86_64.pkg.tar.zst` from the [Releases](../../releases/latest) page and install it:

   ```bash
   sudo pacman -U dapapa-*-x86_64.pkg.tar.zst
   ```

2. Enable the privileged helper and allow your user to control it, then log out and back in:

   ```bash
   sudo systemctl enable --now dapapa-helper.socket
   sudo usermod -aG dapapa "$USER"
   ```

3. Start **dapapa** from your application launcher, or run `dapapa`.
4. Go to **Settings → My targets → Add domain**, choose **Domain list** and paste your domains — one per line.
5. Press **CONNECT** on the home screen.

If a site still does not open, follow [Finding a working setup](https://github.com/ouxan/dapapa#finding-a-working-setup) in the original documentation.

### Example: Discord

Paste the list below into **Add domain → Domain list** and name the group `Discord`. Every subdomain is included automatically (for example `cdn.discordapp.com` and `gateway.discord.gg`).

```text
discord.com
discord.gg
discordapp.com
discordapp.net
discord.media
discordcdn.com
discord.dev
discord.new
discord.gift
discordstatus.com
dis.gd
```

After connecting, restart Discord so that it opens new connections.

> [!NOTE]
> This list is only an example of how to group domains. dapapa is not affiliated with or endorsed by Discord Inc. Make sure your use complies with the laws of your country.

## How it works

```
 Application ──► nftables (table ip dapapa) ──► NFQUEUE ──► dapapa-helper ──► Network
                         │
                         ├─ TCP 80/443 first data packets  →  split / reorder / fake packets / HTTP header changes
                         ├─ UDP 53 for target domains      →  local resolver (127.0.0.1:5300) → DNS over HTTPS
                         └─ UDP to target IPs              →  block QUIC or apply UDP methods
```

| Component | Runs as | Role |
| --- | --- | --- |
| `dapapa` | your user | Avalonia GUI with tray icon and notifications; a port of the Windows window and dialogs |
| `dapapactl` | your user | Command-line client for testing and scripting |
| `dapapa-helper` | root, systemd | Owns the `ip dapapa` nftables table, consumes the netfilter queue, injects rebuilt packets through a raw socket and runs the local DNS-over-HTTPS resolver |

The helper is socket-activated through `/run/dapapa/helper.sock`, which is owned by the `dapapa` group. Its systemd unit grants only `CAP_NET_ADMIN` and `CAP_NET_RAW`. Protection belongs to the client connection that started it: if that client exits or crashes, the helper stops protection after a short grace period and removes its rules. If the helper itself is killed, the queue is configured to fail open, so traffic keeps flowing.

The DPI modes, TCP, fake-packet, HTTP, QUIC and UDP methods, and the DNS-over-HTTPS providers behave as in the Windows application and are documented in the [original README](https://github.com/ouxan/dapapa#detailed-documentation). Further Linux documentation:

- [Architecture](docs/architecture.md): components, privilege model and helper protocol
- [Network lifecycle](docs/network-lifecycle.md): nftables ownership, DNS path and failure handling
- [Visual parity](docs/visual-parity.md): the Linux GUI next to the Windows application
- [Testing](docs/testing.md): test suites and results

## Differences from the Windows version

| Windows | Linux |
| --- | --- |
| WinDivert driver inside the application | Separate root helper with nftables and NFQUEUE; the GUI never runs as root |
| Administrator prompt on start | Membership of the `dapapa` group |
| Windows DNS cache flush and `hosts` cleanup | The helper flushes systemd-resolved when it is in use; no system file is changed |
| Start with Windows (scheduled task) | Start on login through an XDG autostart entry |
| Tray balloons | Desktop notifications through `org.freedesktop.Notifications` |
| Stopping leaves existing connections open | Stopping closes the connections that only worked through dapapa, so the change takes effect at once |

## Hyprland and other Wayland compositors

- **Window backend.** The window runs through XWayland with the class `dapapa`. Avalonia 12.1.4's native Wayland backend currently limits animations to about 10 frames per second; set `DAPAPA_WAYLAND=1` to use it anyway. Sessions without an X server always use the native Wayland backend.
- **Tray icon.** The icon is a StatusNotifierItem and appears in a panel with a tray module, such as Waybar's.
- **Floating window.** Hyprland tiles new windows. To keep the original window size, float and centre it with a window rule:

  ```lua
  -- hyprland.lua (Hyprland 0.56 and later)
  hl.window_rule({
      name  = "dapapa-float",
      match = { class = "^dapapa$" },
      float = true,
      move  = "(monitor_w-window_w)/2 (monitor_h-window_h)/2",
  })
  ```

  With a `hyprland.conf`, use a `windowrule` with `float` and `center` for the same class.
- **Start on login.** Hyprland runs XDG autostart entries only when the session is started through uwsm. Otherwise, start dapapa from the Hyprland configuration: `exec-once = dapapa --tray` in `hyprland.conf`, or `hl.on("hyprland.start", function() hl.exec_cmd("dapapa --tray") end)` in `hyprland.lua`.

## Command-line client

`dapapactl` controls the same helper as the GUI:

```bash
dapapactl run --domain discord.com --domain discord.gg   # protect until Ctrl+C
dapapactl run --domains targets.txt --options custom.json --provider Cloudflare
dapapactl status
dapapactl refresh --force
dapapactl stop
```

`--options` takes Custom DPI settings as JSON. `--provider` accepts `Quad9Ecs` (default), `Quad9`, `Cloudflare`, `Google` and `AdGuard`.

## Limitations

- IPv4 only; IPv6 traffic passes through unchanged.
- ECH (Encrypted Client Hello), per-process filtering and DNS over TCP are not supported.
- After a kernel upgrade, restart the computer before starting protection: the running kernel's netfilter modules are no longer installed. dapapa reports this instead of failing with a low-level error.
- Closing the window hides dapapa in the tray when that setting is on; use **Exit** from the tray menu to quit.

---

## Building from source

Requires `dotnet-sdk` (10), `nftables`, `libnetfilter_queue` and `iproute2`; `base-devel` is needed to build the package. All are in the official Arch repositories.

```bash
git clone https://github.com/ouxan/dapapa-linux.git
cd dapapa-linux
dotnet build dapapa-linux.slnx -c Release
```

Build and install the Arch package from the current commit:

```bash
packaging/arch/build.sh
sudo pacman -U artifacts/package/dapapa-*-x86_64.pkg.tar.zst
```

To run from the build output without installing, start the helper in one terminal (the `wheel` group stands in for the package's `dapapa` group) and the GUI in another:

```bash
sudo dotnet src/Dapapa.Helper/bin/Release/net10.0/dapapa-helper.dll --socket /run/dapapa/helper.sock --socket-group wheel
dotnet src/Dapapa.App/bin/Release/net10.0/dapapa.dll
```

Run the test suites:

```bash
(cd tests/Dapapa.Core.Tests && dotnet run -c Release --no-build)
(cd tests/Dapapa.App.Tests && dotnet run -c Release --no-build -- ../../artifacts/screenshots)
sudo dotnet tests/Dapapa.Helper.Tests/bin/Release/net10.0/Dapapa.Helper.Tests.dll
sudo bash tests/integration/run.sh
```

The helper and integration tests need root; the integration test works only inside network namespaces that it creates and removes. An Arch Linux development container is also available; see [docs/testing.md](docs/testing.md).

<details>
<summary><b>Project structure</b></summary>

```
├── src/Dapapa.Core     Packet processing, DPI methods, DNS/DoH, settings, localisation, helper protocol
├── src/Dapapa.Helper   Privileged helper: nftables, NFQUEUE, raw sockets, local resolver
├── src/Dapapa.Cli      dapapactl
├── src/Dapapa.App      Avalonia GUI, tray icon, notifications, autostart
├── tests/              Unit, GUI, helper, Wayland and network-namespace integration tests
├── packaging/          PKGBUILD, systemd units, sysusers entry, desktop file
├── docker/             Arch Linux development and test container
└── docs/               Architecture, network lifecycle, visual parity and testing
```

</details>

## Data and privacy

- Settings: `$XDG_CONFIG_HOME/dapapa/settings.json` (usually `~/.config/dapapa/settings.json`)
- Log: `$XDG_STATE_HOME/dapapa/dapapa.log` (usually `~/.local/state/dapapa/dapapa.log`; rotated at 2 MiB, one old log kept)
- Helper log: the systemd journal (`journalctl -u dapapa-helper`)

dapapa has no telemetry. Network requests are limited to the selected DoH provider, Cloudflare DoH for target IP resolution, the DoH response-time measurement while the window is open and connected, and — only when you start it — related domain discovery for the site you entered.

## Acknowledgements

- [dapapa](https://github.com/ouxan/dapapa) — the original Windows application this port is based on (MIT)
- [Avalonia](https://github.com/AvaloniaUI/Avalonia) — cross-platform user interface (MIT)
- [libnetfilter_queue](https://netfilter.org/projects/libnetfilter_queue/) and [nftables](https://netfilter.org/projects/nftables/) — packet queueing and filtering
- [Tmds.DBus](https://github.com/tmds/Tmds.DBus) — D-Bus for the tray icon and notifications (MIT)
- [AngleSharp](https://github.com/AngleSharp/AngleSharp) — HTML parsing for domain discovery (MIT)
- [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) and [zapret](https://github.com/bol-van/zapret) — reference for DPI circumvention techniques; dapapa implements them independently and runs no external tools.

## Disclaimer

dapapa is intended for accessing information and services in accordance with the laws of your jurisdiction. You are responsible for how you use it. The software is provided "as is", without warranty of any kind. All product names and trademarks belong to their respective owners.

## License

Released under the [MIT License](LICENSE). Bundled third-party components keep their own licenses — see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
