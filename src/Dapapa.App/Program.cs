using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Dapapa.App.Services;

namespace Dapapa.App
{
    internal static class Program
    {
        [STAThread]
        public static int Main(string[] args)
        {
            // Avalonia reports problems such as a failed GPU setup (and the slower software fallback) through Trace.
            System.Diagnostics.Trace.Listeners.Add(new System.Diagnostics.ConsoleTraceListener(useErrorStream: true));
            bool tray = args.Contains("--tray");
            using var instance = SingleInstance.TryAcquire(showExisting: !tray);
            if (instance == null) return 0;
            App.Instance = instance;
            App.StartedFromLogin = tray;
            return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args, ShutdownMode.OnExplicitShutdown);
        }

        public static AppBuilder BuildAvaloniaApp()
        {
            var builder = AppBuilder.Configure<App>().UsePlatformDetect();
            if (UseNativeWayland(Environment.GetEnvironmentVariable("DISPLAY"), Environment.GetEnvironmentVariable("DAPAPA_WAYLAND")))
                builder = builder.UseWaylandWithFallback();
            return builder
                .With(new WaylandPlatformOptions { AppId = "dapapa" })
                .With(new X11PlatformOptions { WmClass = "dapapa" })
                .With(new FontManagerOptions { DefaultFamilyName = "avares://dapapa/Assets/Fonts#Selawik" })
                .LogToTrace();
        }

        /// <summary>
        /// Selects X11 (XWayland on Wayland compositors) unless DAPAPA_WAYLAND=1 is set or no X server is available.
        /// Avalonia 12.1.4's Wayland backend fires a 16 ms DispatcherTimer only about every 100 ms, which limits animations
        /// and transitions to roughly 10 frames per second; under X11 they follow the display refresh rate.
        /// </summary>
        internal static bool UseNativeWayland(string? display, string? waylandOptIn) =>
            waylandOptIn == "1" || string.IsNullOrEmpty(display);
    }
}
