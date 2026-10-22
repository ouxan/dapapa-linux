using System.Collections.ObjectModel;
using System.Net.Sockets;
using Avalonia;
using Avalonia.Animation;
using Avalonia.Animation.Easings;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Media.Transformation;
using Avalonia.Styling;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Dapapa.App.Dialogs;
using Dapapa.App.Services;
using Dapapa.Core;
using Dapapa.Core.Ipc;
using Dapapa.Core.Models;

namespace Dapapa.App
{
    public partial class MainWindow : Window
    {
        private readonly IProtectionService _protection;
        private readonly SettingsService _settingsService;
        private readonly TrayService? _tray;
        private readonly INotifier? _notifier;
        private readonly RelatedDomainDiscoveryService _discoveryService = new();
        private readonly Dictionary<string, RelatedDomainsDialog> _discoveryDialogs = new();
        private readonly LogFileWriter _logWriter;

        private AppSettings _settings = new();
        private bool _isLoadingSettings;

        private List<ProtectedApp> _allApps = new();
        private Dictionary<string, bool> _savedTargetSelection = new();
        private readonly ObservableCollection<ProtectedApp> _filteredApps = new();
        private CancellationTokenSource? _operationCts;
        private bool _isConnected;
        private bool _isBusy;
        private bool _reallyExit;
        private bool _closingAfterDisconnect;

        private readonly DispatcherTimer _statusTimer;
        private readonly LatencyAndEndpointService _latencyService = new();
        private readonly DispatcherTimer _latencyTimer;
        private bool _isMeasuringPing;
        private bool _isSyncingIps;
        private long? _lastDnsLatency;
        private string? _busyStatusKey;

        private readonly TrafficStatisticsService _trafficService = new();
        private readonly DispatcherTimer _statsTimer;
        private bool _userWantsConnected;
        private DateTime? _watchdogDropSince;
        private DateTime _lastWatchdogAttemptTime = DateTime.MinValue;
        private DateTime _watchdogSuppressedUntil = DateTime.MinValue;
        private long _packetsBase;
        private long _dnsRepliesBase;

        private readonly List<double> _dlHistory = new();
        private readonly List<double> _ulHistory = new();
        private const int ChartHistoryLimit = 30;

        public MainWindow() : this(new HelperProtectionService(), new SettingsService(), null) { }

        internal MainWindow(IProtectionService protection, SettingsService settingsService, TrayService? tray, LogFileWriter? logWriter = null,
            INotifier? notifier = null)
        {
            _protection = protection;
            _settingsService = settingsService;
            _tray = tray;
            _notifier = notifier;
            _logWriter = logWriter ?? new LogFileWriter(Path.Combine(XdgPaths.StateHome, "dapapa", "dapapa.log"));
            _isLoadingSettings = true;
            try { InitializeComponent(); }
            finally { _isLoadingSettings = false; }

            AppsItemsControl.ItemsSource = _filteredApps;

            DomainDnsResolver.Log += OnServiceLog;
            _settingsService.Log += OnServiceLog;
            _protection.Log += OnServiceLog;
            _protection.StatusChanged += _ => UpdateStatisticsLabels();
            _protection.ConnectionLost += () =>
            {
                if (_userWantsConnected) AppendLog(Localization.T("LogConnectionLost"));
            };
            if (_tray != null)
            {
                _tray.ShowRequested += ToggleFromTray;
                _tray.ConnectRequested += () => _ = StartConnectionFlowAsync();
                _tray.DisconnectRequested += () => _ = StopConnectionFlowAsync();
                _tray.ExitRequested += () => { _reallyExit = true; Close(); };
            }

            LoadSettingsIntoUi();

            _statusTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            _statusTimer.Tick += async (_, _) =>
            {
                await PollStatusAsync();
                await CheckWatchdogAsync();
            };
            _latencyTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
            _latencyTimer.Tick += async (_, _) => await UpdatePingAsync();
            _latencyTimer.Start();
            _statsTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _statsTimer.Tick += (_, _) => UpdateTrafficStats();
            _statsTimer.Start();

            Opened += (_, _) =>
            {
                RootBorder.Opacity = 1;
                RootBorder.RenderTransform = TransformOperations.Parse("translateY(0px)");
            };
            Closing += MainWindow_Closing;
        }

        internal bool IsConnected => _isConnected;
        internal bool IsBusy => _isBusy;
        internal AppSettings Settings => _settings;

        /// <summary>Runs the start-up work once the window exists; it may stay hidden when started into the tray.</summary>
        public async Task InitializeAsync(bool startedFromLogin)
        {
            AppendLog(Localization.T("RuntimeVersion", typeof(MainWindow).Assembly.GetName().Version?.ToString() ?? "unknown", Environment.ProcessPath ?? "-"));
            if (!(_settings.StartMinimizedToTray || startedFromLogin)) Show();
            try { AutostartService.SetEnabled(_settings.RunOnLogin); }
            catch (Exception ex) { AppendLog(Localization.T("GenericError", ex.Message)); }
            if (_settings.AutoConnectOnLaunch && _settings.GetEffectiveDomains().Count > 0)
                await StartConnectionFlowAsync();
            else
                SetConnectionVisualState(false);
            _statusTimer.Start();
        }

        private async Task PollStatusAsync()
        {
            if (_isBusy || !_userWantsConnected) return;
            try { await _protection.PollAsync(); }
            catch (Exception ex) when (IsHelperFailure(ex)) { }
            if (!_isBusy && _userWantsConnected && _protection.IsRunning != _isConnected)
            {
                SetConnectionVisualState(_protection.IsRunning);
                AppendLog(Localization.T(_protection.IsRunning ? "LogConnectionRestored" : "LogConnectionLost"));
            }
        }

        private async void MainWindow_Closing(object? sender, WindowClosingEventArgs e)
        {
            if (!_reallyExit && _settings.MinimizeToTrayOnClose)
            {
                e.Cancel = true;
                Hide();
                _notifier?.Show(Localization.T("AppName"), Localization.T("StillRunningInTray"));
                return;
            }
            if (!_closingAfterDisconnect)
            {
                e.Cancel = true;
                _closingAfterDisconnect = true;
                _reallyExit = true;
                _statusTimer.Stop();
                var discoveryDialogs = _discoveryDialogs.Values.ToArray();
                foreach (var dialog in discoveryDialogs) dialog.Close();
                await Task.WhenAll(discoveryDialogs.Select(dialog => dialog.Completion));
                try { await StopProtectionAsync(); }
                catch (Exception ex) { AppendLog(Describe(ex)); }
                Close();
                return;
            }
            _latencyService.Dispose();
            _discoveryService.Dispose();
            _latencyTimer.Stop();
            _statsTimer.Stop();
            DomainDnsResolver.Log -= OnServiceLog;
            _settingsService.Log -= OnServiceLog;
            _protection.Log -= OnServiceLog;
            await _protection.DisposeAsync();
            await _logWriter.DisposeAsync();
            (Application.Current?.ApplicationLifetime as Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime)?.Shutdown();
        }

        private void MainTabControl_SelectionChanged(object? sender, SelectionChangedEventArgs e)
        {
            if (!ReferenceEquals(e.Source, MainTabControl) || e.AddedItems.Count == 0) return;
            if (e.AddedItems[0] is not TabItem tabItem) return;
            Control content = ReferenceEquals(tabItem, StatsTabItem) ? StatsPage
                : ReferenceEquals(tabItem, SettingsTabItem) ? SettingsPage : HomePage;
            foreach (var page in new Control[] { HomePage, StatsPage, SettingsPage }) page.IsVisible = ReferenceEquals(page, content);
            if (ReferenceEquals(tabItem, StatsTabItem)) StatsScrollViewer.Offset = default;
            RefreshVisibleWork();
            content.RenderTransform = new TranslateTransform();
            var animation = new Animation
            {
                Duration = TimeSpan.FromMilliseconds(220),
                Easing = new CubicEaseOut(),
                FillMode = FillMode.Forward,
                Children =
                {
                    new KeyFrame { Cue = new Cue(0), Setters = { new Setter(OpacityProperty, 0d), new Setter(TranslateTransform.YProperty, 8d) } },
                    new KeyFrame { Cue = new Cue(1), Setters = { new Setter(OpacityProperty, 1d), new Setter(TranslateTransform.YProperty, 0d) } }
                }
            };
            _ = animation.RunAsync(content);
        }

        protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
        {
            base.OnPropertyChanged(change);
            if (change.Property == IsVisibleProperty) RefreshVisibleWork();
            if (change.Property != WindowStateProperty) return;
            RefreshVisibleWork();
            RootBorder.CornerRadius = WindowState is WindowState.Maximized or WindowState.FullScreen ? new CornerRadius(0) : new CornerRadius(12);
            if (WindowState == WindowState.Minimized && _settings.MinimizeToTrayOnClose && _tray != null) Hide();
        }

        private void TitleBar_PointerPressed(object? sender, PointerPressedEventArgs e)
        {
            if (e.Source is Visual source && source.FindAncestorOfType<Button>(includeSelf: true) != null) return;
            if (!e.GetCurrentPoint(this).Properties.IsLeftButtonPressed) return;
            if (e.ClickCount == 2)
            {
                WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
                return;
            }
            BeginMoveDrag(e);
        }

        private void ResizeGrip_PointerPressed(object? sender, PointerPressedEventArgs e)
        {
            if (sender is not Control { Tag: string edge } || WindowState != WindowState.Normal) return;
            if (!e.GetCurrentPoint(this).Properties.IsLeftButtonPressed) return;
            BeginResizeDrag(Enum.Parse<WindowEdge>(edge), e);
            e.Handled = true;
        }

        private void MinimizeButton_Click(object? sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

        private void CloseButton_Click(object? sender, RoutedEventArgs e) => Close();

        public void RestoreFromTray()
        {
            if (!IsVisible) Show();
            if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
            Activate();
        }

        private void ToggleFromTray()
        {
            if (IsVisible && IsActive) Hide();
            else RestoreFromTray();
        }

        private async void ToggleConnectionButton_Click(object? sender, RoutedEventArgs e)
        {
            if (_isBusy) return;
            if (_isConnected || _userWantsConnected) await StopConnectionFlowAsync();
            else await StartConnectionFlowAsync();
        }

        private async Task StartConnectionFlowAsync()
        {
            if (_isBusy) return;
            if (_settings.GetEffectiveDomains().Count == 0)
            {
                AppendLog(Localization.T("NoActiveTargets"));
                return;
            }
            _isBusy = true;
            SetBusyUi(true, "Connecting");
            SuppressWatchdog(TimeSpan.FromSeconds(20));
            _operationCts?.Dispose();
            _operationCts = new CancellationTokenSource();
            _userWantsConnected = true;
            try
            {
                await StartProtectionCoreAsync(_operationCts.Token);
                SetConnectionVisualState(true);
                SuppressWatchdog(TimeSpan.FromSeconds(5));
            }
            catch (Exception ex)
            {
                // The helper reports this in English; show it in the selected language.
                string message = ex is HelperException && KernelModules.RunningKernelMissing()
                    ? Localization.T("KernelUpdatedRestart")
                    : Describe(ex);
                AppendLog(message);
                try { await StopProtectionAsync(); }
                catch (Exception cleanupError) { AppendLog(Describe(cleanupError)); }
                if (!_closingAfterDisconnect && IsVisible && ex is not OperationCanceledException)
                    await MessageDialog.ShowAsync(this, message, Localization.T("Error"));
            }
            finally
            {
                _isBusy = false;
                SetBusyUi(false, null);
            }
        }

        private async Task StartProtectionCoreAsync(CancellationToken ct)
        {
            await _protection.StartAsync(_settings.GetEffectiveDomains(), _settings.GetDpiOptions(), _settings.DohProvider, ct);
            _packetsBase = _dnsRepliesBase = 0;
            var result = await RefreshTargetsAsync(false, ct);
            if (!result.Applied || !_protection.IsRunning)
                throw new InvalidOperationException(Localization.T("ProtectionStartFailed"));
        }

        private async Task StopProtectionAsync()
        {
            _userWantsConnected = false;
            _watchdogDropSince = null;
            _operationCts?.Cancel();
            try { await _protection.StopAsync(); }
            catch (Exception ex) when (IsHelperFailure(ex)) { }
            finally
            {
                try { DomainDnsResolver.ClearCache(); }
                finally { SetConnectionVisualState(false); }
            }
        }

        private async Task StopConnectionFlowAsync()
        {
            if (_isBusy) return;
            _isBusy = true;
            SetBusyUi(true, "Disconnecting");
            try { await StopProtectionAsync(); }
            catch (Exception ex) { AppendLog(Describe(ex)); }
            finally
            {
                _isBusy = false;
                SetBusyUi(false, null);
            }
        }

        private async Task<(int Services, int Ips, int Failed, bool Applied)> RefreshTargetsAsync(bool force, CancellationToken ct)
        {
            var result = await _protection.RefreshAsync(force, ct);
            if (!result.Applied) return (0, 0, 0, false);
            var counts = new Dictionary<string, int>(result.Domains, StringComparer.OrdinalIgnoreCase);
            return Summarize(counts, applied: true);
        }

        private (int Services, int Ips, int Failed, bool Applied) Summarize(IReadOnlyDictionary<string, int> counts, bool applied)
        {
            int services = _settings.Apps.Count(a => a.Enabled && a.GetDomains().Any(d => counts.TryGetValue(d, out int ips) && ips > 0));
            return (services, counts.Values.Sum(), counts.Count(pair => pair.Value == 0), applied);
        }

        private void SetBusyUi(bool busy, string? statusKey)
        {
            _busyStatusKey = busy ? statusKey ?? "Preparing" : null;
            ToggleConnectionButton.IsEnabled = !busy;
            DohProviderComboBox.IsEnabled = !busy;
            _notifier?.Show(Localization.T("AppName"), Localization.T(_busyStatusKey ?? "OperationDone"));
            if (!busy) return;
            StatusText.Text = Localization.T(_busyStatusKey!);
            StatusSubText.Text = Localization.T("PleaseWait");
            SetStatusColor("AccentColor");
            SetDotPulse(DotPulseMode.Busy);
        }

        private void SetConnectionVisualState(bool connected)
        {
            bool changed = _isConnected != connected;
            _isConnected = connected;
            SetStatusColor(connected ? "SuccessColor" : "DangerColor");
            StatusText.Text = Localization.T(connected ? "ConnectedStatus" : "NotConnected");
            StatusSubText.Text = connected
                ? Localization.T(_settings.GetDpiOptions().HasTrafficMethods ? "ConnectedHint" : "DnsOnlyHint")
                : Localization.T("StartHint");
            ToggleConnectionButton.Content = Localization.T(connected ? "DisconnectButton" : "ConnectButton");
            ToggleConnectionButton.Theme = (ControlTheme)Resource(connected ? "DangerButton" : "AccentButton");
            SetDotPulse(connected ? DotPulseMode.Idle : DotPulseMode.None);
            _tray?.SetConnectedState(connected);

            if (connected)
            {
                if (changed) _trafficService.StartSession();
                SessionStatusValueText.Text = Localization.T("ProtectionActive");
                SessionStatusDot.Fill = Brush("SuccessBrush");
                StatsLiveDot.Fill = Brush("SuccessBrush");
                StatsLiveText.Text = Localization.T("StatsLive");
                UpdateProtectedTargetsText();
                _ = UpdatePingAsync();
            }
            else
            {
                _trafficService.StopSession();
                SessionStatusValueText.Text = Localization.T("ProtectionInactive");
                SessionStatusDot.Fill = Brush("DangerBrush");
                StatsLiveDot.Fill = Brush("TextMutedBrush");
                StatsLiveText.Text = Localization.T("StatsIdle");
                _lastDnsLatency = null;
                PingValueText.Text = "-- ms";
                PingBadge.IsVisible = false;
                LatencyIndicatorDot.Fill = Brush("TextMutedBrush");
                DownloadSpeedValueText.Text = Localization.T("IdleSpeed", 0);
                UploadSpeedValueText.Text = Localization.T("IdleSpeed", 0);
            }
        }

        private void SetStatusColor(string colorKey)
        {
            var color = (Color)Resource(colorKey);
            StatusDot.Background = new SolidColorBrush(color);
            StatusHalo.Stroke = new SolidColorBrush(color);
            StatusCard.BorderBrush = new SolidColorBrush(color);
            // A box shadow instead of a blur effect: the dot pulses forever and an effect would be re-blurred every frame.
            StatusDot.BoxShadow = new BoxShadows(new BoxShadow { Blur = 16, Color = Color.FromArgb(230, color.R, color.G, color.B) });
        }

        private enum DotPulseMode { None, Idle, Busy }

        private DotPulseMode _pulseMode;

        private void SetDotPulse(DotPulseMode mode)
        {
            _pulseMode = mode;
            ApplyDotPulse();
        }

        /// <summary>True while the user can actually see the given page; hidden windows and other tabs need no updates.</summary>
        private bool IsShowing(Control page) => IsVisible && WindowState != WindowState.Minimized && page.IsVisible;

        // The pulse animations run on the render clock for as long as their style applies, so they only apply while visible.
        private void ApplyDotPulse()
        {
            bool visible = IsShowing(HomePage);
            StatusIndicator.Classes.Set("idle", visible && _pulseMode == DotPulseMode.Idle);
            StatusIndicator.Classes.Set("busy", visible && _pulseMode == DotPulseMode.Busy);
        }

        /// <summary>Catches up on what was skipped while hidden: the pulse, the chart and the labels.</summary>
        private void RefreshVisibleWork()
        {
            ApplyDotPulse();
            if (!IsShowing(StatsPage)) return;
            UpdateWaveformChart();
            UpdateStatisticsLabels();
        }

        private void SuppressWatchdog(TimeSpan duration)
        {
            _watchdogSuppressedUntil = DateTime.Now + duration;
            _watchdogDropSince = null;
        }

        private static object Resource(string key) =>
            Application.Current!.FindResource(key) ?? throw new KeyNotFoundException(key);

        private static IBrush Brush(string key) => (IBrush)Resource(key);

        private static bool IsHelperFailure(Exception ex) => ex is HelperException or IOException or SocketException or OperationCanceledException;

        /// <summary>User-facing text for a failed operation; socket errors mean the helper service is not reachable.</summary>
        private static string Describe(Exception ex) => ex switch
        {
            SocketException or IOException => Localization.T("HelperUnavailable", ex.Message),
            _ => Localization.T("GenericError", ex.Message)
        };

        private void OnServiceLog(string line) => _logWriter.Write(line);

        private void AppendLog(string line) => _logWriter.Write(line);

        private void LoadSettingsIntoUi()
        {
            _isLoadingSettings = true;
            try
            {
                _settings = _settingsService.Load();
                Localization.Current = string.Equals(_settings.Language, "tr", StringComparison.OrdinalIgnoreCase)
                    ? AppLanguage.Turkish
                    : AppLanguage.English;
                LanguageComboBox.SelectedIndex = Localization.Current == AppLanguage.Turkish ? 1 : 0;
                RunOnStartupCheckBox.IsChecked = _settings.RunOnLogin;
                StartMinimizedCheckBox.IsChecked = _settings.StartMinimizedToTray;
                MinimizeToTrayCheckBox.IsChecked = _settings.MinimizeToTrayOnClose;
                AutoConnectCheckBox.IsChecked = _settings.AutoConnectOnLaunch;
                ConnectionWatchdogCheckBox.IsChecked = _settings.EnableConnectionWatchdog;
                LoadDpiSettingsIntoUi();
                LoadDohSettingsIntoUi();
                _allApps = _settings.Apps;
                _savedTargetSelection = _allApps.ToDictionary(a => a.Id, a => a.Enabled);
                ApplyLanguage();
            }
            finally { _isLoadingSettings = false; }
            FilterCatalog();
        }

        private void ApplyLanguage()
        {
            ApplyDohLanguage();
            SubtitleText.Text = Localization.T("Subtitle");
            ToolTip.SetTip(HomeTabItem, Localization.T("TabHome"));
            ToolTip.SetTip(StatsTabItem, Localization.T("TabStats"));
            ToolTip.SetTip(SettingsTabItem, Localization.T("TabSettings"));

            StatsSectionTitleText.Text = Localization.T("StatsSectionTitle");
            StatsDescriptionText.Text = Localization.T("StatsDescription");
            DownloadSpeedLabelText.Text = Localization.T("DownloadSpeed");
            CurrentDownloadSubtext.Text = Localization.T("CurrentDownload");
            UploadSpeedLabelText.Text = Localization.T("UploadSpeed");
            CurrentUploadSubtext.Text = Localization.T("CurrentUpload");
            DataCounterHeaderText.Text = Localization.T("DataCounterSection");
            TotalTransferredLabelText.Text = Localization.T("TotalTransferred");
            ReceivedLabelText.Text = Localization.T("ReceivedLabel");
            SentLabelText.Text = Localization.T("SentLabel");
            SessionInfoHeaderText.Text = Localization.T("SessionInfoSection");
            SessionStatusLabelText.Text = Localization.T("SessionStatusLabel");
            SessionUptimeLabelText.Text = Localization.T("SessionUptimeLabel");
            AdapterLabelText.Text = Localization.T("AdapterLabel");
            ResetStatsButtonText.Text = Localization.T("ResetStatsButton");
            ChartHeaderText.Text = Localization.T("ChartSectionTitle");
            ChartDownloadLegendText.Text = Localization.T("ChartDownloadLegend");
            ChartUploadLegendText.Text = Localization.T("ChartUploadLegend");
            DpiStatsHeaderText.Text = Localization.T("DpiStatsHeader");
            BypassedPacketsLabelText.Text = Localization.T("BypassedPacketsLabel");
            BypassedPacketsSubtext.Text = Localization.T("BypassedPacketsSubtext");
            SafeDnsLabelText.Text = Localization.T("SafeDnsLabel");
            SafeDnsSubtext.Text = Localization.T("SafeDnsSubtext");
            ProtectedTargetsLabelText.Text = Localization.T("ProtectedTargetsLabel");
            SessionStatusValueText.Text = Localization.T(_isConnected ? "ProtectionActive" : "ProtectionInactive");
            UpdateProtectedTargetsText();

            StatusText.Text = Localization.T(_isConnected ? "ConnectedStatus" : "NotConnected");
            StatusSubText.Text = _isConnected
                ? Localization.T(_settings.GetDpiOptions().HasTrafficMethods ? "ConnectedHint" : "DnsOnlyHint")
                : Localization.T("StartHint");
            ToggleConnectionButton.Content = Localization.T(_isConnected ? "DisconnectButton" : "ConnectButton");

            GeneralHeaderText.Text = Localization.T("General");
            RunOnStartupCheckBox.Content = Localization.T("RunOnStartup");
            StartMinimizedCheckBox.Content = Localization.T("StartMinimized");
            MinimizeToTrayCheckBox.Content = Localization.T("MinimizeOnClose");
            AutoConnectCheckBox.Content = Localization.T("AutoConnectOnLaunch");
            ConnectionWatchdogCheckBox.Content = Localization.T("ConnectionWatchdog");
            LanguageLabelText.Text = Localization.T("Language");
            ApplyDpiLanguage();

            TrafficHeaderText.Text = Localization.T("MyTargets");
            CatalogSearchPlaceholder.Text = Localization.T("SearchPlaceholder");
            AddCustomAppButton.Content = Localization.T("AddCustomApp");
            SyncIpsButtonText.Text = Localization.T(_isSyncingIps ? "SyncingIps" : "SyncIps");
            ToolTip.SetTip(SyncIpsButton, Localization.T("SyncIpsTooltip"));
            ToolTip.SetTip(ClearSearchButton, Localization.T("ClearSearch"));
            foreach (var app in _allApps) app.RefreshLocalization();

            NoteText.Text = Localization.T("Note");
            SaveSettingsButtonText.Content = Localization.T("SaveSettings");

            FilterCatalog();
            UpdateActiveServicesCount();
            UpdateStatisticsLabels();
            _tray?.RefreshTexts();

            LatencyHeaderText.Text = Localization.T("LatencySectionTitle");
            UpdatePingTargetLabel();
            StatsLiveText.Text = Localization.T(_isConnected ? "StatsLive" : "StatsIdle");
            PingLiveBadgeText.Text = Localization.T("StatsLive");
            UpdateWaveformChart();

            if (_isBusy && _busyStatusKey != null)
            {
                StatusText.Text = Localization.T(_busyStatusKey);
                StatusSubText.Text = Localization.T("PleaseWait");
            }
            else if (_watchdogDropSince != null)
            {
                StatusText.Text = Localization.T("WatchdogReconnecting");
                StatusSubText.Text = Localization.T("WatchdogReconnectingHint");
            }

            if (_isConnected)
            {
                if (_lastDnsLatency is long latency)
                {
                    PingValueText.Text = latency >= 0 ? Localization.T("PingUnit", latency) : Localization.T("DohProbeFailed");
                    if (latency >= 0) PingQualityText.Text = Localization.T(latency < 60 ? "PingGood" : latency < 120 ? "PingFair" : "PingPoor");
                }
                _ = UpdatePingAsync();
            }
        }

        private void LanguageComboBox_SelectionChanged(object? sender, SelectionChangedEventArgs e)
        {
            if (_isLoadingSettings) return;
            if (_isBusy)
            {
                RestoreLanguageSelection();
                return;
            }
            var candidate = _settings.Copy();
            candidate.Language = LanguageComboBox.SelectedIndex == 1 ? "tr" : "en";
            try { _settingsService.Save(candidate); }
            catch (Exception ex)
            {
                RestoreLanguageSelection();
                AppendLog(Localization.T("SettingsSaveError", ex.Message));
                return;
            }
            _settings.Language = candidate.Language;
            Localization.Current = candidate.Language == "tr" ? AppLanguage.Turkish : AppLanguage.English;
            ApplyLanguage();
        }

        private void RestoreLanguageSelection()
        {
            _isLoadingSettings = true;
            try { LanguageComboBox.SelectedIndex = _settings.Language == "tr" ? 1 : 0; }
            finally { _isLoadingSettings = false; }
        }

        private void SettingCheckBox_Changed(object? sender, RoutedEventArgs e)
        {
            if (_isLoadingSettings) return;
            if (_isBusy) { RestoreGeneralSettingsUi(); return; }
            var previous = _settings.Copy();
            var candidate = _settings.Copy();
            candidate.RunOnLogin = RunOnStartupCheckBox.IsChecked == true;
            candidate.StartMinimizedToTray = StartMinimizedCheckBox.IsChecked == true;
            candidate.MinimizeToTrayOnClose = MinimizeToTrayCheckBox.IsChecked == true;
            candidate.AutoConnectOnLaunch = AutoConnectCheckBox.IsChecked == true;
            candidate.EnableConnectionWatchdog = ConnectionWatchdogCheckBox.IsChecked == true;
            bool startupChanged = previous.RunOnLogin != candidate.RunOnLogin;
            bool saved = false;
            try
            {
                _settingsService.Save(candidate);
                saved = true;
                if (startupChanged) AutostartService.SetEnabled(candidate.RunOnLogin);
                _settings.RunOnLogin = candidate.RunOnLogin;
                _settings.StartMinimizedToTray = candidate.StartMinimizedToTray;
                _settings.MinimizeToTrayOnClose = candidate.MinimizeToTrayOnClose;
                _settings.AutoConnectOnLaunch = candidate.AutoConnectOnLaunch;
                _settings.EnableConnectionWatchdog = candidate.EnableConnectionWatchdog;
                if (!_settings.EnableConnectionWatchdog) _watchdogDropSince = null;
            }
            catch (Exception ex)
            {
                if (saved)
                {
                    try { _settingsService.Save(_settings); }
                    catch (Exception rollback) { AppendLog(Localization.T("SettingsSaveError", rollback.Message)); }
                }
                AppendLog(Localization.T("GenericError", ex.Message));
            }
            finally { RestoreGeneralSettingsUi(); }
        }

        private void RestoreGeneralSettingsUi()
        {
            bool loading = _isLoadingSettings;
            _isLoadingSettings = true;
            try
            {
                RunOnStartupCheckBox.IsChecked = _settings.RunOnLogin;
                StartMinimizedCheckBox.IsChecked = _settings.StartMinimizedToTray;
                MinimizeToTrayCheckBox.IsChecked = _settings.MinimizeToTrayOnClose;
                AutoConnectCheckBox.IsChecked = _settings.AutoConnectOnLaunch;
                ConnectionWatchdogCheckBox.IsChecked = _settings.EnableConnectionWatchdog;
            }
            finally { _isLoadingSettings = loading; }
        }

        private async void SaveSettingsButton_Click(object? sender, RoutedEventArgs e)
        {
            if (_isBusy || DpiValidationText.IsVisible) return;
            _isBusy = true;
            SaveSettingsButtonText.IsEnabled = false;
            try
            {
                _settings.Apps = _allApps.ToList();
                _settingsService.Save(_settings);
                if (_userWantsConnected)
                {
                    await _protection.UpdateAsync(_settings.GetEffectiveDomains(), _settings.GetDpiOptions(), _settings.DohProvider,
                        _operationCts?.Token ?? CancellationToken.None);
                    var result = await RefreshTargetsAsync(false, _operationCts?.Token ?? CancellationToken.None);
                    if (!result.Applied || !_protection.IsRunning) throw new InvalidOperationException(Localization.T("ProtectionStartFailed"));
                    SetConnectionVisualState(true);
                    AppendLog(Localization.T("SettingsSavedAndApplied"));
                }
                else AppendLog(Localization.T("SettingsSaved"));
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                await MessageDialog.ShowAsync(this, Localization.T("SettingsSaveError", ex.Message), Localization.T("Error"));
            }
            finally
            {
                _isBusy = false;
                SaveSettingsButtonText.IsEnabled = true;
                SaveSettingsButtonText.Content = Localization.T("SaveSettings");
            }
        }

        private void UpdateTrafficStats()
        {
            _trafficService.Update(_isConnected);
            _dlHistory.Add(_isConnected ? _trafficService.DownloadSpeedBytesPerSec : 0);
            _ulHistory.Add(_isConnected ? _trafficService.UploadSpeedBytesPerSec : 0);
            while (_dlHistory.Count > ChartHistoryLimit) _dlHistory.RemoveAt(0);
            while (_ulHistory.Count > ChartHistoryLimit) _ulHistory.RemoveAt(0);
            UpdateWaveformChart();
            UpdateStatisticsLabels();
        }

        private void UpdateStatisticsLabels()
        {
            if (!IsShowing(StatsPage)) return;
            DownloadSpeedValueText.Text = _isConnected ? TrafficStatisticsService.FormatSpeed(_trafficService.DownloadSpeedBytesPerSec) : Localization.T("IdleSpeed", 0);
            UploadSpeedValueText.Text = _isConnected ? TrafficStatisticsService.FormatSpeed(_trafficService.UploadSpeedBytesPerSec) : Localization.T("IdleSpeed", 0);
            TotalTransferredValueText.Text = TrafficStatisticsService.FormatBytes(_trafficService.SessionTotalBytes);
            SessionReceivedValueText.Text = TrafficStatisticsService.FormatBytes(_trafficService.SessionDownloadedBytes);
            SessionSentValueText.Text = TrafficStatisticsService.FormatBytes(_trafficService.SessionUploadedBytes);
            AdapterValueText.Text = _trafficService.AdapterName;
            if (_isConnected) SessionUptimeValueText.Text = TrafficStatisticsService.FormatDuration(_trafficService.Uptime);
            long packets = Math.Max(0, (_protection.Status?.BypassedPackets ?? 0) - _packetsBase);
            long queries = Math.Max(0, (_protection.Status?.DnsReplies ?? 0) - _dnsRepliesBase);
            BypassedPacketsValueText.Text = Localization.T(packets == 1 ? "PacketCount" : "PacketsCount", packets);
            SafeDnsValueText.Text = Localization.T(queries == 1 ? "QueryCount" : "QueriesCount", queries);
            UpdateProtectedTargetsText();
        }

        private void ChartContainer_SizeChanged(object? sender, SizeChangedEventArgs e) => UpdateWaveformChart();

        private void UpdateWaveformChart()
        {
            if (!IsShowing(StatsPage)) return;
            double w = ChartContainer.Bounds.Width;
            double h = ChartContainer.Bounds.Height;
            if (w <= 10 || h <= 10) return;

            double peak = 1024;
            foreach (var value in _dlHistory) if (value > peak) peak = value;
            foreach (var value in _ulHistory) if (value > peak) peak = value;
            ChartPeakText.Text = Localization.T("ChartPeak", TrafficStatisticsService.FormatSpeed(peak));

            double stepX = w / (ChartHistoryLimit - 1);
            int startOffset = ChartHistoryLimit - _dlHistory.Count;
            var dlLine = new List<Point>();
            var ulLine = new List<Point>();
            double startX = startOffset * stepX;
            var dlArea = new List<Point> { new(startX, h) };
            var ulArea = new List<Point> { new(startX, h) };
            for (int i = 0; i < _dlHistory.Count; i++)
            {
                double x = (startOffset + i) * stepX;
                var dl = new Point(x, h - 5 - Math.Clamp(_dlHistory[i] / peak, 0, 1) * (h - 10));
                var ul = new Point(x, h - 5 - Math.Clamp(_ulHistory[i] / peak, 0, 1) * (h - 10));
                dlLine.Add(dl); dlArea.Add(dl);
                ulLine.Add(ul); ulArea.Add(ul);
            }
            double lastX = (startOffset + Math.Max(0, _dlHistory.Count - 1)) * stepX;
            dlArea.Add(new Point(lastX, h));
            ulArea.Add(new Point(lastX, h));
            DownloadPolyline.Points = dlLine;
            DownloadPolygon.Points = dlArea;
            UploadPolyline.Points = ulLine;
            UploadPolygon.Points = ulArea;
        }

        private void ResetStatsButton_Click(object? sender, RoutedEventArgs e)
        {
            _trafficService.Reset();
            _packetsBase = _protection.Status?.BypassedPackets ?? 0;
            _dnsRepliesBase = _protection.Status?.DnsReplies ?? 0;
            _dlHistory.Clear();
            _ulHistory.Clear();
            UpdateWaveformChart();
            SessionUptimeValueText.Text = "00:00";
            UpdateStatisticsLabels();
            AppendLog(Localization.T("StatsResetDone"));
        }

        private async Task CheckWatchdogAsync()
        {
            if (_settings.GetEffectiveDomains().Count == 0 || !_userWantsConnected || _isBusy || !_settings.EnableConnectionWatchdog ||
                DateTime.Now < _watchdogSuppressedUntil || _protection.IsRunning) return;
            if ((DateTime.Now - _lastWatchdogAttemptTime).TotalSeconds < 3) return;
            _lastWatchdogAttemptTime = DateTime.Now;
            _isBusy = true;
            try
            {
                SetConnectionVisualState(false);
                _watchdogDropSince ??= DateTime.Now;
                StatusText.Text = Localization.T("WatchdogReconnecting");
                StatusSubText.Text = Localization.T("WatchdogReconnectingHint");
                AppendLog(Localization.T("WatchdogDropDetected"));
                _operationCts?.Cancel();
                _operationCts?.Dispose();
                _operationCts = new CancellationTokenSource();
                await StartProtectionCoreAsync(_operationCts.Token);
                _watchdogDropSince = null;
                SetConnectionVisualState(true);
                AppendLog(Localization.T("WatchdogRestored"));
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                // Keep trying while the user wants protection; the helper may be restarting.
                AppendLog(Describe(ex));
                try { await _protection.StopAsync(); }
                catch (Exception cleanupError) when (IsHelperFailure(cleanupError)) { }
                SetConnectionVisualState(false);
                StatusText.Text = Localization.T("WatchdogReconnecting");
                StatusSubText.Text = Localization.T("WatchdogReconnectingHint");
            }
            finally { _isBusy = false; }
        }

        private void UpdatePingTargetLabel()
        {
            string endpoint = _settings.GetDohEndpoint();
            string target = Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) ? uri.Authority : "--";
            PingTargetText.Text = Localization.T("PingToDoh", target);
        }

        private async Task UpdatePingAsync()
        {
            if (_isMeasuringPing || !IsVisible) return;
            UpdatePingTargetLabel();
            if (!_isConnected)
            {
                _lastDnsLatency = null;
                PingValueText.Text = "-- ms";
                PingBadge.IsVisible = false;
                LatencyIndicatorDot.Fill = Brush("TextMutedBrush");
                return;
            }
            _isMeasuringPing = true;
            try
            {
                string endpoint = _settings.GetDohEndpoint();
                CancellationToken ct = _operationCts?.Token ?? CancellationToken.None;
                long latency = await _latencyService.MeasureDohAsync(endpoint, ct: ct);
                if (!IsVisible || !_isConnected || ct.IsCancellationRequested || endpoint != _settings.GetDohEndpoint()) return;
                _lastDnsLatency = latency;
                if (latency >= 0)
                {
                    PingValueText.Text = Localization.T("PingUnit", latency);
                    PingBadge.IsVisible = true;
                    (string text, string brush, uint badge) = latency < 60 ? ("PingGood", "SuccessBrush", 0x253BA55Du)
                        : latency < 120 ? ("PingFair", "AccentBrush", 0x255865F2u) : ("PingPoor", "DangerBrush", 0x25ED4245u);
                    PingQualityText.Text = Localization.T(text);
                    PingQualityText.Foreground = Brush(brush);
                    PingBadge.Background = new SolidColorBrush(badge);
                    LatencyIndicatorDot.Fill = Brush(brush);
                }
                else
                {
                    PingValueText.Text = Localization.T("DohProbeFailed");
                    PingBadge.IsVisible = false;
                    LatencyIndicatorDot.Fill = Brush("DangerBrush");
                }
            }
            catch (Exception) { }
            finally { _isMeasuringPing = false; }
        }

        private List<ProtectedApp> GetCurrentMatchingApps()
        {
            string query = (CatalogSearchTextBox.Text ?? "").Trim();
            return _allApps.Where(a => a.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                a.GetDomains().Any(d => d.Contains(query, StringComparison.OrdinalIgnoreCase))).ToList();
        }

        private void FilterCatalog()
        {
            if (_isLoadingSettings) return;
            bool hasQuery = !string.IsNullOrWhiteSpace(CatalogSearchTextBox.Text);
            ClearSearchButton.IsVisible = hasQuery;
            CatalogSearchPlaceholder.IsVisible = !hasQuery;
            var matching = GetCurrentMatchingApps();
            var included = matching.ToHashSet();
            for (int i = _filteredApps.Count - 1; i >= 0; i--)
                if (!included.Contains(_filteredApps[i])) _filteredApps.RemoveAt(i);
            for (int i = 0; i < matching.Count; i++)
            {
                if (i < _filteredApps.Count && ReferenceEquals(_filteredApps[i], matching[i])) continue;
                int existing = _filteredApps.IndexOf(matching[i]);
                if (existing >= 0) _filteredApps.Move(existing, i);
                else _filteredApps.Insert(i, matching[i]);
            }
            NoResultsText.Text = Localization.T(_allApps.Count == 0 ? "TargetsEmpty" : "NoResultsFound");
            NoResultsText.IsVisible = matching.Count == 0;
            UpdateActiveServicesCount();
        }

        private void UpdateActiveServicesCount()
        {
            ActiveServicesCountText.Text = Localization.T("ActiveServicesCount", _allApps.Count(a => a.Enabled), _allApps.Count);
            UpdateProtectedTargetsText();
        }

        private void UpdateProtectedTargetsText()
        {
            int groups = _allApps.Count(a => a.Enabled);
            int domains = _protection.IsRunning && _protection.Status!.ActiveDomains > 0
                ? _protection.Status.ActiveDomains
                : _settings.GetEffectiveDomains().Count;
            ProtectedTargetsValueText.Text = Localization.T("ProtectedTargetCounts", groups, domains);
        }

        private void CatalogSearchTextBox_TextChanged(object? sender, TextChangedEventArgs e) => FilterCatalog();

        private void ClearSearchButton_Click(object? sender, RoutedEventArgs e)
        {
            CatalogSearchTextBox.Text = string.Empty;
            CatalogSearchTextBox.Focus();
        }

        private bool SaveAppsAndSyncTargets(List<ProtectedApp> apps)
        {
            if (_isBusy) { AppendLog(Localization.T("PleaseWait")); return false; }
            var candidate = _settings.Copy();
            candidate.Apps = apps;
            try { _settingsService.Save(candidate); }
            catch (Exception ex) { AppendLog(Localization.T("SettingsSaveError", ex.Message)); return false; }
            var previous = _allApps.ToDictionary(a => a.Id);
            _isLoadingSettings = true;
            try
            {
                _allApps = apps.Select(next =>
                {
                    if (!previous.TryGetValue(next.Id, out var app)) return next;
                    app.Apply(next);
                    return app;
                }).ToList();
                _settings.Apps = _allApps;
                _savedTargetSelection = _allApps.ToDictionary(a => a.Id, a => a.Enabled);
                foreach (var removed in previous.Values.Where(a => !_allApps.Contains(a)))
                    if (_discoveryDialogs.TryGetValue(removed.Id, out var dialog)) dialog.Close();
            }
            finally { _isLoadingSettings = false; }
            FilterCatalog();
            UpdateActiveServicesCount();
            if (!_userWantsConnected || !_protection.IsRunning) return true;
            var domains = _settings.GetEffectiveDomains();
            if (domains.Count == 0) _ = StopEmptyProtectionAsync();
            else _ = UpdateTargetsAsync(domains);
            return true;
        }

        private async Task UpdateTargetsAsync(IReadOnlyList<string> domains)
        {
            try { await _protection.UpdateAsync(domains, null, null, _operationCts?.Token ?? CancellationToken.None); }
            catch (OperationCanceledException) { }
            catch (Exception ex) { AppendLog(Describe(ex)); }
        }

        private async Task StopEmptyProtectionAsync()
        {
            bool wasBusy = _isBusy;
            _isBusy = true;
            SetBusyUi(true, "Disconnecting");
            try { await StopProtectionAsync(); }
            catch (Exception ex) { AppendLog(Describe(ex)); }
            finally
            {
                if (!wasBusy) { _isBusy = false; SetBusyUi(false, null); }
            }
        }

        private void AppEnabledCheckBox_Changed(object? sender, RoutedEventArgs e)
        {
            if (_isLoadingSettings) return;
            if (sender is not CheckBox { DataContext: ProtectedApp app } checkbox ||
                !_savedTargetSelection.TryGetValue(app.Id, out bool saved) || saved == (checkbox.IsChecked == true)) return;
            if (_isBusy) { checkbox.SetCurrentValue(ToggleButton.IsCheckedProperty, saved); return; }
            var candidate = _allApps.Select(a => a.Copy()).ToList();
            candidate.First(a => a.Id == app.Id).Enabled = checkbox.IsChecked == true;
            if (!SaveAppsAndSyncTargets(candidate))
            {
                _isLoadingSettings = true;
                try { checkbox.SetCurrentValue(ToggleButton.IsCheckedProperty, saved); }
                finally { _isLoadingSettings = false; }
            }
        }

        private async void SyncIpsButton_Click(object? sender, RoutedEventArgs e)
        {
            if (_isBusy) return;
            _isBusy = true;
            _isSyncingIps = true;
            SyncIpsButton.IsEnabled = false;
            SyncIpsButtonText.Text = Localization.T("SyncingIps");
            SyncCompleteDialog? completion = null;
            try
            {
                if (_userWantsConnected && _protection.IsRunning)
                {
                    var result = await RefreshTargetsAsync(true, _operationCts?.Token ?? CancellationToken.None);
                    if (!result.Applied) throw new InvalidOperationException(Localization.T("ProtectionStartFailed"));
                    completion = new SyncCompleteDialog(result.Services, result.Ips, true, result.Failed);
                }
                else
                {
                    var resolved = await DomainDnsResolver.ResolveAllAsync(_settings.GetEffectiveDomains(), true);
                    var counts = resolved.ToDictionary(pair => pair.Key, pair => pair.Value.Count, StringComparer.OrdinalIgnoreCase);
                    var result = Summarize(counts, applied: false);
                    completion = new SyncCompleteDialog(result.Services, result.Ips, false, result.Failed);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                await MessageDialog.ShowAsync(this, Localization.T("SyncError", ex.Message), Localization.T("Error"));
            }
            finally
            {
                _isBusy = false;
                _isSyncingIps = false;
                SyncIpsButton.IsEnabled = true;
                SyncIpsButtonText.Text = Localization.T("SyncIps");
            }
            if (completion != null) await completion.ShowDialog(this);
        }

        private async void AddCustomAppButton_Click(object? sender, RoutedEventArgs e)
        {
            if (_isBusy) return;
            var dialog = new AddAppDialog();
            if (await dialog.ShowDialog<bool>(this) != true) return;
            if (_allApps.Any(a => a.Domain.Equals(dialog.Domain, StringComparison.OrdinalIgnoreCase)))
            {
                await MessageDialog.ShowAsync(this, Localization.T("AppAlreadyExists", dialog.Domain), Localization.T("Warning"));
                return;
            }
            var app = new ProtectedApp { Name = dialog.AppName, Domain = dialog.Domain, Enabled = true };
            app.SetDomains(dialog.Domains);
            var candidate = _allApps.Select(a => a.Copy()).ToList();
            candidate.Insert(0, app);
            if (!SaveAppsAndSyncTargets(candidate)) return;
            CatalogSearchTextBox.Text = string.Empty;
            FilterCatalog();
            if (dialog.DiscoverRelated) await ShowDiscoveryAsync(_allApps.First(a => a.Id == app.Id));
        }

        private void TargetActionsButton_Click(object? sender, RoutedEventArgs e)
        {
            if (sender is not Button { Tag: ProtectedApp app } button) return;
            var discover = new MenuItem { Header = Localization.T("DiscoverRelated") };
            discover.Click += async (_, _) => await ShowDiscoveryAsync(app);
            var edit = new MenuItem { Header = Localization.T("EditDomainGroup") };
            edit.Click += async (_, _) => await EditTargetAsync(app);
            var delete = new MenuItem { Header = Localization.T("Delete") };
            delete.Click += async (_, _) => await RemoveTargetAsync(app);
            var menu = new ContextMenu { ItemsSource = new[] { discover, edit, delete } };
            menu.Open(button);
        }

        private async Task ShowDiscoveryAsync(ProtectedApp app)
        {
            if (!_allApps.Contains(app) || _closingAfterDisconnect) return;
            if (_discoveryDialogs.TryGetValue(app.Id, out var existing)) { if (existing.IsVisible) existing.Activate(); return; }
            string sourceDomain = app.Domain;
            var dialog = new RelatedDomainsDialog(app.Domain, _discoveryService,
                () => _allApps.Contains(app) && app.Domain == sourceDomain && !_closingAfterDisconnect,
                () => app.GetDomains().ToArray(), selected =>
                {
                    if (!_allApps.Contains(app) || app.Domain != sourceDomain || _closingAfterDisconnect) return;
                    if (_isBusy) throw new InvalidOperationException(Localization.T("PleaseWait"));
                    var candidate = _allApps.Select(a => a.Copy()).ToList();
                    candidate.First(a => a.Id == app.Id).AddRelatedDomains(selected);
                    if (!SaveAppsAndSyncTargets(candidate)) throw new IOException(Localization.T("SettingsInvalid"));
                    FilterCatalog();
                });
            _discoveryDialogs.Add(app.Id, dialog);
            try { dialog.Show(this); await dialog.Completion; }
            catch (Exception ex) { AppendLog(Localization.T("GenericError", ex.Message)); }
            finally { _discoveryDialogs.Remove(app.Id); }
        }

        private async Task EditTargetAsync(ProtectedApp app)
        {
            if (_isBusy || !_allApps.Contains(app)) return;
            var dialog = new AddAppDialog(app);
            if (await dialog.ShowDialog<bool>(this) != true) return;
            if (_allApps.Any(a => !ReferenceEquals(a, app) && a.Domain.Equals(dialog.Domain, StringComparison.OrdinalIgnoreCase)))
            {
                await MessageDialog.ShowAsync(this, Localization.T("AppAlreadyExists", dialog.Domain), Localization.T("Warning"));
                return;
            }
            var candidate = _allApps.Select(a => a.Copy()).ToList();
            var edited = candidate.First(a => a.Id == app.Id);
            edited.SetDomains(dialog.Domains);
            edited.Name = dialog.AppName;
            if (!SaveAppsAndSyncTargets(candidate)) return;
            if (_discoveryDialogs.TryGetValue(app.Id, out var discovery)) discovery.Close();
            FilterCatalog();
        }

        private async Task RemoveTargetAsync(ProtectedApp app)
        {
            if (_isBusy || !_allApps.Contains(app)) return;
            if (!await MessageDialog.ShowAsync(this, Localization.T("RemoveGroupConfirm", app.Name, app.GetDomains().Count()),
                    Localization.T("Confirm"), MessageDialogButtons.YesNo)) return;
            if (!SaveAppsAndSyncTargets(_allApps.Where(a => a.Id != app.Id).Select(a => a.Copy()).ToList())) return;
            FilterCatalog();
        }
    }
}
