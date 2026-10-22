using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using Dapapa.App.Services;
using Dapapa.Core;

namespace Dapapa.App
{
    public partial class App : Application
    {
        internal static SingleInstance? Instance { get; set; }
        internal static bool StartedFromLogin { get; set; }

        public override void Initialize() => AvaloniaXamlLoader.Load(this);

        public override void OnFrameworkInitializationCompleted()
        {
            if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                var tray = new TrayService(this);
                var notifier = new DesktopNotifier();
                var window = new MainWindow(new HelperProtectionService(), new SettingsService(), tray, notifier: notifier);
                if (Instance != null) Instance.ShowRequested += () => Dispatcher.UIThread.Post(window.RestoreFromTray);
                desktop.Exit += (_, _) =>
                {
                    tray.Dispose();
                    notifier.Dispose();
                };
                Dispatcher.UIThread.Post(async () => await window.InitializeAsync(StartedFromLogin));
            }
            base.OnFrameworkInitializationCompleted();
        }
    }
}
