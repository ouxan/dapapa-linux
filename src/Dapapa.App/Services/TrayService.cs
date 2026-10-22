using Avalonia;
using Avalonia.Controls;
using Avalonia.Platform;
using Dapapa.Core;

namespace Dapapa.App.Services
{
    /// <summary>
    /// Status notifier (tray) icon with the same menu as the Windows app. On Hyprland it appears in a panel that
    /// hosts StatusNotifierItems, such as Waybar's tray module; without one the app keeps working without it.
    /// </summary>
    public sealed class TrayService : IDisposable
    {
        private readonly TrayIcon _icon;
        private readonly NativeMenuItem _header = new() { IsEnabled = false };
        private readonly NativeMenuItem _showHide = new();
        private readonly NativeMenuItem _toggle = new();
        private readonly NativeMenuItem _exit = new();
        private bool _connected;

        public event Action? ShowRequested;
        public event Action? ConnectRequested;
        public event Action? DisconnectRequested;
        public event Action? ExitRequested;

        public TrayService(Application application)
        {
            _showHide.Click += (_, _) => ShowRequested?.Invoke();
            _toggle.Click += (_, _) => (_connected ? DisconnectRequested : ConnectRequested)?.Invoke();
            _exit.Click += (_, _) => ExitRequested?.Invoke();
            var menu = new NativeMenu();
            menu.Items.Add(_header);
            menu.Items.Add(new NativeMenuItemSeparator());
            menu.Items.Add(_showHide);
            menu.Items.Add(new NativeMenuItemSeparator());
            menu.Items.Add(_toggle);
            menu.Items.Add(new NativeMenuItemSeparator());
            menu.Items.Add(_exit);
            using var stream = AssetLoader.Open(new Uri("avares://dapapa/Assets/app.png"));
            _icon = new TrayIcon { Icon = new WindowIcon(stream), Menu = menu, IsVisible = true };
            _icon.Clicked += (_, _) => ShowRequested?.Invoke();
            // Since Avalonia 12 the platform icon is only created for icons attached to the application.
            TrayIcon.SetIcons(application, [_icon]);
            RefreshTexts();
        }

        public void SetConnectedState(bool connected)
        {
            _connected = connected;
            RefreshTexts();
        }

        public void RefreshTexts()
        {
            string appName = Localization.T("AppName");
            string status = Localization.T(_connected ? "ConnectedStatus" : "NotConnected");
            _header.Header = $"{(_connected ? "●" : "○")}  {appName} - {status}";
            _icon.ToolTipText = $"{appName} - {status}";
            _showHide.Header = Localization.T("ShowHide");
            _toggle.Header = Localization.T(_connected ? "TrayDisconnect" : "TrayConnect");
            _exit.Header = Localization.T("Exit");
        }

        public void Dispose()
        {
            _icon.IsVisible = false;
            _icon.Dispose();
        }
    }
}
