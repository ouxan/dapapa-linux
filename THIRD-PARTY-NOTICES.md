# Third-party notices

dapapa-linux is MIT licensed (see [LICENSE](LICENSE)). It uses the following components, which keep their own licenses.

| Component | Use | License |
| --- | --- | --- |
| [AngleSharp](https://github.com/AngleSharp/AngleSharp) | HTML parsing for related-domain discovery | MIT ([text](assets/AngleSharp-LICENSE.txt)) |
| [Avalonia](https://github.com/AvaloniaUI/Avalonia) (Avalonia, Desktop, Wayland, X11, FreeDesktop, Skia, HarfBuzz, Themes.Fluent) | GUI framework | MIT |
| [SkiaSharp](https://github.com/mono/SkiaSharp) with the native Skia library | Rendering | MIT; Skia is BSD-3-Clause |
| [HarfBuzzSharp](https://github.com/mono/SkiaSharp) with the native HarfBuzz library | Text shaping | MIT; HarfBuzz is the "Old MIT" license |
| [Tmds.DBus.Protocol](https://github.com/tmds/Tmds.DBus) | D-Bus for the tray icon (through Avalonia) and desktop notifications | MIT |
| [NWayland](https://github.com/kekekeks/NWayland), [MicroCom.Runtime](https://github.com/kekekeks/MicroCom) | Wayland bindings and interop (through Avalonia) | MIT |
| [Selawik](https://github.com/microsoft/Selawik) | Embedded UI font, unmodified | SIL Open Font License 1.1 ([text](assets/Selawik-LICENSE.txt)) |
| [libnetfilter_queue](https://netfilter.org/projects/libnetfilter_queue/), [nftables](https://netfilter.org/projects/nftables/) | Used at run time from the system packages; not bundled | GPL-2.0-or-later |

Avalonia's build tooling (`Avalonia.BuildServices`) reports anonymous build statistics. `Directory.Build.targets` replaces that step with an empty target, so no build of this repository sends them, and the development container also sets `AVALONIA_TELEMETRY_OPTOUT=1`. The application sends nothing at run time.
