using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Headless;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Styling;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Dapapa.App;
using Dapapa.App.Dialogs;
using Dapapa.App.Services;
using Dapapa.Core;
using Dapapa.Core.Models;

/// <summary>Headless GUI tests. Rendering uses Skia, the same renderer as the desktop window, so screenshots match it.</summary>
internal static partial class Program
{
    private static int _passed;
    private static readonly string Work = Path.Combine(Path.GetTempPath(), "dapapa-app-tests-" + Guid.NewGuid().ToString("N")[..8]);
    private static readonly List<(string Message, string Title)> Shown = [];
    private static Func<bool> _answer = () => true;

    private static int Main(string[] args)
    {
        string screenshots = args.Length > 0 ? args[0] : Path.Combine(Work, "screenshots");
        Directory.CreateDirectory(Work);
        try
        {
            using var session = HeadlessUnitTestSession.StartNew(typeof(TestApp));
            return session.Dispatch(async () =>
            {
                MessageDialog.ShowHandler = (_, message, title, _) => { Shown.Add((message, title)); return Task.FromResult(_answer()); };
                await Run("window loads saved settings without writing or contacting the helper", LoadsWithoutSideEffects);
                await Run("connect and disconnect drive the helper and the status card", ConnectAndDisconnect);
                await Run("a failed start rolls back and reports an unreachable helper", FailedStartRollsBack);
                await Run("no active target never contacts the helper", NoTargetsNoHelper);
                await Run("watchdog reconnects after the helper drops protection", WatchdogReconnects);
                await Run("target switches save and update live protection", TargetSwitchesUpdateLive);
                await Run("search, removal and duplicate checks keep the list and settings in sync", TargetListEditing);
                await Run("Custom DPI validates every field before saving or applying", DpiValidation);
                await Run("DPI dependents follow their parent options", DpiDependents);
                await Run("DoH provider switch while connected re-resolves through the helper", DohSwitch);
                await Run("language switch retranslates the window and open dialogs", LanguageSwitch);
                await Run("statistics show helper counters and reset to a baseline", Statistics);
                await Run("the status pulse only runs while the Home page is on screen", PulseOnlyWhenVisible);
                await Run("add dialog validates single domains, lists and edits", AddDialog);
                await Run("sync dialog distinguishes live refresh, offline check and partial failure", SyncDialog);
                await Run("related domains are added only when selected", RelatedDomains);
                await Run("closing goes to the tray; exit stops protection and releases the helper", Closing);
                await Run("autostart entry and single-instance socket", AutostartAndSingleInstance);
                await Run("the tray icon is attached to the application", TrayAttached);
                await Run("X11 is the default backend; Wayland is opt-in or used without an X server", BackendChoice);
                await Run("notifications follow the Windows balloons and never fail without a server", Notifications);
                await Run("theme matches the Windows palette and control sizes", ThemeParity);
                await Run("screenshots of every screen and dialog", () => Screenshots(screenshots));
                Console.WriteLine($"PASS: {_passed} GUI test groups. Screenshots: {screenshots}");
                return 0;
            }, CancellationToken.None).GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex);
            return 1;
        }
        finally
        {
            try { Directory.Delete(Path.Combine(Work, "case"), true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }

    private static async Task Run(string name, Func<Task> test)
    {
        Shown.Clear();
        _answer = () => true;
        Localization.Current = AppLanguage.English;
        await test();
        _passed++;
        Console.WriteLine("PASS: " + name);
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    // --- Harness ---

    private sealed class FakeNotifier : INotifier
    {
        public List<(string Title, string Text)> Shown { get; } = [];
        public void Show(string title, string text) => Shown.Add((title, text));
    }

    private sealed class Harness(MainWindow window, FakeProtection helper, SettingsService settings, string settingsPath, FakeNotifier notifier)
    {
        public MainWindow Window { get; } = window;
        public FakeProtection Helper { get; } = helper;
        public FakeNotifier Notifier { get; } = notifier;
        public SettingsService Service { get; } = settings;
        public string SettingsPath { get; } = settingsPath;
        public AppSettings Saved => new SettingsService(SettingsPath).Load();
        public DateTime WriteTime => File.GetLastWriteTimeUtc(SettingsPath);
        public T Find<T>(string name) where T : Control => Window.FindControl<T>(name) ?? throw new InvalidOperationException("Missing control " + name);
    }

    private static AppSettings DefaultSettings() => new()
    {
        TargetListVersion = AppSettings.CurrentTargetListVersion,
        Language = "en",
        MinimizeToTrayOnClose = false,
        Apps =
        [
            new ProtectedApp { Id = "discord", Name = "Discord", Domain = "discord.com", RelatedDomains = ["discord.gg", "discordapp.com"] },
            new ProtectedApp { Id = "example", Name = "Example", Domain = "example.com" },
            new ProtectedApp { Id = "off", Name = "Disabled", Domain = "disabled.example", Enabled = false }
        ]
    };

    private static async Task<Harness> Open(Action<AppSettings>? configure = null, FakeProtection? helper = null, bool show = true)
    {
        string directory = Path.Combine(Work, "case", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "settings.json");
        var settings = DefaultSettings();
        configure?.Invoke(settings);
        File.WriteAllText(path, JsonSerializer.Serialize(settings));
        File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddMinutes(-5));
        helper ??= new FakeProtection();
        var service = new SettingsService(path);
        var notifier = new FakeNotifier();
        var window = new MainWindow(helper, service, null, new LogFileWriter(Path.Combine(directory, "dapapa.log")), notifier);
        if (show) window.Show();
        await Flush();
        return new Harness(window, helper, service, path, notifier);
    }

    private static async Task Flush(int rounds = 6)
    {
        for (int i = 0; i < rounds; i++)
        {
            await Task.Delay(5);
            Dispatcher.UIThread.RunJobs();
        }
    }

    /// <summary>Lets transitions and animations finish before a frame is captured.</summary>
    private static async Task Settle(int milliseconds = 450)
    {
        var until = DateTime.UtcNow.AddMilliseconds(milliseconds);
        while (DateTime.UtcNow < until)
        {
            AvaloniaHeadlessPlatform.ForceRenderTimerTick();
            await Task.Delay(16);
            Dispatcher.UIThread.RunJobs();
        }
    }

    private static async Task Click(Button button)
    {
        button.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        await Flush();
    }

    private static async Task Enter(TextBox box, string text)
    {
        box.Text = text;
        box.RaiseEvent(new KeyEventArgs { RoutedEvent = InputElement.KeyDownEvent, Key = Key.Enter });
        await Flush();
    }

    private static Task Call(object target, string method, params object[] args)
    {
        var info = target.GetType().GetMethod(method, BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public)
            ?? throw new MissingMethodException(target.GetType().Name, method);
        return info.Invoke(target, args) as Task ?? Task.CompletedTask;
    }

    private static void SetField(object target, string field, object? value) =>
        (target.GetType().GetField(field, BindingFlags.Instance | BindingFlags.NonPublic) ?? throw new MissingFieldException(field))
            .SetValue(target, value);

    private static object Resource(string key) => Application.Current!.FindResource(key)!;

    private static async Task<CheckBox> TargetSwitch(Harness h, string id)
    {
        h.Find<TabControl>("MainTabControl").SelectedIndex = 2;
        await Flush();
        var list = h.Find<ListBox>("AppsItemsControl");
        ScrollTo(h.Find<ScrollViewer>("SettingsScrollViewer"), list);
        await Flush();
        return list.GetVisualDescendants().OfType<CheckBox>()
            .First(c => c.DataContext is ProtectedApp app && app.Id == id);
    }

    // --- Behaviour ---

    private static async Task LoadsWithoutSideEffects()
    {
        var h = await Open();
        var before = h.WriteTime;
        Check(h.Helper.Calls.Count == 0, "Loading contacted the helper.");
        Check(h.WriteTime == before, "Loading rewrote settings.");
        Check(h.Find<TextBlock>("StatusText").Text == Localization.T("NotConnected"), "Initial status text wrong.");
        Check((string?)h.Find<Button>("ToggleConnectionButton").Content == Localization.T("ConnectButton"), "Initial button text wrong.");
        Check(h.Find<Button>("ToggleConnectionButton").Theme == Resource("AccentButton"), "Initial button is not the accent style.");
        Check(h.Find<ListBox>("AppsItemsControl").ItemCount == 3, "Target list incomplete.");
        Check(h.Find<TextBlock>("ActiveServicesCountText").Text == Localization.T("ActiveServicesCount", 2, 3), "Active count wrong.");
        Check(!h.Find<StackPanel>("DpiCustomPanel").IsVisible, "Custom DPI panel visible in Standard mode.");
        Check(h.Find<ComboBox>("DohProviderComboBox").ItemCount == DohProviders.All.Count, "DoH presets missing.");
        Check(h.Find<TabControl>("MainTabControl").ItemCount == 3, "Tabs missing.");
        h.Window.Close();
        await Flush();
    }

    private static async Task ConnectAndDisconnect()
    {
        var h = await Open();
        var toggle = h.Find<Button>("ToggleConnectionButton");
        await Click(toggle);
        Check(h.Helper.Starts == 1 && h.Helper.Refreshes == 1, "Connect did not start and resolve targets.");
        Check(h.Helper.Domains.SequenceEqual(["discord.com", "discord.gg", "discordapp.com", "example.com"]), "Wrong target domains sent.");
        Check(h.Helper.Options == DpiOptions.Standard && h.Helper.Provider == DohProvider.Quad9Ecs, "Wrong options or provider sent.");
        Check(h.Window.IsConnected && !h.Window.IsBusy, "Window not connected after start.");
        Check(h.Find<TextBlock>("StatusText").Text == Localization.T("ConnectedStatus"), "Connected text missing.");
        Check(h.Find<TextBlock>("StatusSubText").Text == Localization.T("ConnectedHint"), "Connected hint missing.");
        Check((string?)toggle.Content == Localization.T("DisconnectButton") && toggle.Theme == Resource("DangerButton"), "Disconnect button not shown.");
        Check(h.Find<Grid>("StatusIndicator").Classes.Contains("idle"), "Connected pulse not running.");
        Check(h.Find<TextBlock>("SessionStatusValueText").Text == Localization.T("ProtectionActive"), "Statistics status stale.");
        Check(h.Find<TextBlock>("ProtectedTargetsValueText").Text == Localization.T("ProtectedTargetCounts", 2, 4), "Protected target counts wrong.");
        await Click(toggle);
        Check(h.Helper.Stops == 1 && !h.Window.IsConnected, "Disconnect did not stop protection.");
        Check(h.Find<TextBlock>("StatusText").Text == Localization.T("NotConnected") && toggle.Theme == Resource("AccentButton"), "Disconnected state not restored.");
        Check(!h.Find<Grid>("StatusIndicator").Classes.Contains("idle") && !h.Find<Grid>("StatusIndicator").Classes.Contains("busy"), "Pulse left running.");
        h.Window.Close();
        await Flush();
    }

    private static async Task FailedStartRollsBack()
    {
        var helper = new FakeProtection { FailStart = new SocketException((int)SocketError.ConnectionRefused) };
        var h = await Open(helper: helper);
        await Click(h.Find<Button>("ToggleConnectionButton"));
        Check(!h.Window.IsConnected && !h.Window.IsBusy, "Failed start left the window connected or busy.");
        Check(helper.Stops == 1, "Failed start did not clean up.");
        Check(Shown.Count == 1 && Shown[0].Message.StartsWith(Localization.T("HelperUnavailable", "").TrimEnd()), "Helper error not shown to the user.");
        Check(h.Find<Button>("ToggleConnectionButton").IsEnabled, "Button stayed disabled.");

        helper.FailStart = null;
        helper.FailRefresh = new InvalidOperationException("refresh failed");
        await Click(h.Find<Button>("ToggleConnectionButton"));
        Check(!h.Window.IsConnected && helper.Stops == 2 && Shown.Count == 2, "Failed target refresh left protection running.");
        h.Window.Close();
        await Flush();
    }

    private static async Task NoTargetsNoHelper()
    {
        var h = await Open(s => s.Apps.ForEach(a => a.Enabled = false));
        await Click(h.Find<Button>("ToggleConnectionButton"));
        Check(h.Helper.Calls.Count == 0 && !h.Window.IsConnected, "Empty target list contacted the helper.");
        h.Window.Close();
        await Flush();
    }

    private static async Task WatchdogReconnects()
    {
        var h = await Open();
        await Click(h.Find<Button>("ToggleConnectionButton"));
        h.Helper.Drop();
        await Call(h.Window, "PollStatusAsync");
        Check(!h.Window.IsConnected, "Dropped protection still shown as connected.");
        await Call(h.Window, "CheckWatchdogAsync");
        Check(h.Helper.Starts == 1, "Watchdog ignored its start-up grace period.");
        SetField(h.Window, "_watchdogSuppressedUntil", DateTime.MinValue);
        await Call(h.Window, "CheckWatchdogAsync");
        Check(h.Helper.Starts == 2 && h.Window.IsConnected, "Watchdog did not restore protection.");

        h.Helper.Drop();
        h.Helper.FailStart = new IOException("helper restarting");
        SetField(h.Window, "_lastWatchdogAttemptTime", DateTime.MinValue);
        await Call(h.Window, "CheckWatchdogAsync");
        Check(!h.Window.IsConnected && h.Find<TextBlock>("StatusText").Text == Localization.T("WatchdogReconnecting"), "Failed retry not shown as reconnecting.");
        Check(Shown.Count == 0, "Watchdog retries must not open dialogs.");

        h.Find<CheckBox>("ConnectionWatchdogCheckBox").IsChecked = false;
        await Flush();
        SetField(h.Window, "_lastWatchdogAttemptTime", DateTime.MinValue);
        int starts = h.Helper.Starts;
        await Call(h.Window, "CheckWatchdogAsync");
        Check(h.Helper.Starts == starts && !h.Saved.EnableConnectionWatchdog, "Disabled watchdog still reconnected or was not saved.");
        h.Window.Close();
        await Flush();
    }

    private static async Task TargetSwitchesUpdateLive()
    {
        var h = await Open();
        await Click(h.Find<Button>("ToggleConnectionButton"));
        (await TargetSwitch(h, "example")).IsChecked = false;
        await Flush();
        Check(!h.Saved.Apps.First(a => a.Id == "example").Enabled, "Switch not saved.");
        Check(h.Helper.Updates == 1 && h.Helper.LastUpdateDomains!.SequenceEqual(["discord.com", "discord.gg", "discordapp.com"]), "Live targets not updated.");
        Check(h.Find<TextBlock>("ActiveServicesCountText").Text == Localization.T("ActiveServicesCount", 1, 3), "Count not refreshed.");
        (await TargetSwitch(h, "discord")).IsChecked = false;
        await Flush();
        Check(h.Helper.Stops == 1 && !h.Window.IsConnected, "Disabling the last target left protection running.");
        (await TargetSwitch(h, "off")).IsChecked = true;
        await Flush();
        Check(h.Helper.Updates == 1 && h.Saved.Apps.First(a => a.Id == "off").Enabled, "Offline switch contacted the helper or was not saved.");
        h.Window.Close();
        await Flush();
    }

    private static async Task TargetListEditing()
    {
        var h = await Open();
        var search = h.Find<TextBox>("CatalogSearchTextBox");
        var list = h.Find<ListBox>("AppsItemsControl");
        search.Text = "discordapp";
        await Flush();
        Check(list.ItemCount == 1 && h.Find<Button>("ClearSearchButton").IsVisible && !h.Find<TextBlock>("CatalogSearchPlaceholder").IsVisible,
            "Search did not match related domains.");
        search.Text = "nothing-matches";
        await Flush();
        Check(list.ItemCount == 0 && h.Find<TextBlock>("NoResultsText").IsVisible, "Empty search result not reported.");
        await Click(h.Find<Button>("ClearSearchButton"));
        Check(list.ItemCount == 3, "Clearing search did not restore the list.");

        await Click(h.Find<Button>("ToggleConnectionButton"));
        var example = h.Window.Settings.Apps.First(a => a.Id == "example");
        _answer = () => false;
        await Call(h.Window, "RemoveTargetAsync", example);
        Check(h.Saved.Apps.Count == 3, "Declined removal deleted the target.");
        _answer = () => true;
        await Call(h.Window, "RemoveTargetAsync", example);
        await Flush();
        Check(h.Saved.Apps.Select(a => a.Id).SequenceEqual(["discord", "off"]) && list.ItemCount == 2, "Removal not saved.");
        Check(h.Helper.LastUpdateDomains!.SequenceEqual(["discord.com", "discord.gg", "discordapp.com"]), "Removal not applied live.");
        h.Window.Close();
        await Flush();
    }

    private static async Task DpiValidation()
    {
        var h = await Open();
        await Click(h.Find<Button>("ToggleConnectionButton"));
        var mode = h.Find<ComboBox>("DpiModeComboBox");
        mode.SelectedIndex = 1;
        await Flush();
        Check(h.Saved.DpiMode == DpiMode.Custom && h.Find<StackPanel>("DpiCustomPanel").IsVisible, "Custom mode not saved or shown.");
        Check(h.Helper.Updates == 1 && h.Helper.LastUpdateOptions == h.Saved.CustomDpi, "Custom options not applied live.");

        var validation = h.Find<TextBlock>("DpiValidationText");
        var before = h.WriteTime;
        int updates = h.Helper.Updates;
        await Enter(h.Find<TextBox>("DpiFakeTtlTextBox"), "0");
        Check(validation.IsVisible && validation.Text == Localization.T("DpiNumberError", Localization.T("DpiFakeTtl"), 1, 64), "Invalid TTL not reported.");
        Check(h.WriteTime == before && h.Helper.Updates == updates, "Invalid TTL saved or applied.");
        await Enter(h.Find<TextBox>("DpiFakeTtlTextBox"), "8");
        Check(!validation.IsVisible && h.Saved.CustomDpi.FakeTtl == 8 && h.Helper.Updates == updates + 1, "Valid TTL not saved and applied.");

        await Enter(h.Find<TextBox>("DpiUdpFragmentSizeTextBox"), "20");
        Check(validation.Text == Localization.T("DpiUdpFragmentSizeError"), "Unaligned fragment size accepted.");
        await Enter(h.Find<TextBox>("DpiSplitPositionsTextBox"), "host+1,bogus");
        Check(validation.IsVisible, "Validation cleared by another invalid field.");
        await Enter(h.Find<TextBox>("DpiUdpFragmentSizeTextBox"), "16");
        Check(validation.Text == Localization.T("DpiInvalidMarkers"), "Invalid split markers accepted.");
        await Enter(h.Find<TextBox>("DpiSplitPositionsTextBox"), "1,host+1");
        await Enter(h.Find<TextBox>("DpiFakeHostnameTextBox"), "not a host");
        Check(validation.Text == Localization.T("InvalidDomain"), "Invalid fake hostname accepted.");

        mode.SelectedIndex = 0;
        await Flush();
        Check(!validation.IsVisible && h.Saved.GetDpiOptions() == DpiOptions.Standard, "Standard did not recover from invalid input.");
        Check(h.Helper.LastUpdateOptions == DpiOptions.Standard, "Standard not applied live.");
        h.Window.Close();
        await Flush();
    }

    private static async Task DpiDependents()
    {
        var h = await Open(s => s.DpiMode = DpiMode.Custom);
        var tcp = h.Find<CheckBox>("DpiTcpFragmentationCheckBox");
        tcp.IsChecked = true;
        await Flush();
        Check(h.Find<StackPanel>("DpiTcpOptionsPanel").IsEnabled && h.Find<TextBox>("DpiSplitSizeTextBox").IsEnabled, "TCP dependents disabled.");
        h.Find<CheckBox>("DpiMultiSplitCheckBox").IsChecked = true;
        await Flush();
        Check(h.Find<TextBox>("DpiSplitPositionsTextBox").IsEnabled && !h.Find<TextBox>("DpiSplitSizeTextBox").IsEnabled &&
            !h.Find<CheckBox>("DpiSplitAtHostnameCheckBox").IsEnabled, "Multisplit dependents wrong.");
        h.Find<CheckBox>("DpiFakeLowTtlCheckBox").IsChecked = true;
        await Flush();
        Check(h.Find<TextBox>("DpiFakeTtlTextBox").IsEnabled, "Fixed TTL disabled.");
        h.Find<CheckBox>("DpiFakeAutoTtlCheckBox").IsChecked = true;
        await Flush();
        Check(!h.Find<TextBox>("DpiFakeTtlTextBox").IsEnabled, "AutoTTL left fixed TTL editable.");
        tcp.IsChecked = false;
        await Flush();
        Check(!h.Find<StackPanel>("DpiTcpOptionsPanel").IsEnabled && h.Find<CheckBox>("DpiMultiSplitCheckBox").IsChecked == true,
            "TCP dependents stayed active or were erased.");
        h.Find<CheckBox>("DpiUdpIpFragmentationCheckBox").IsChecked = true;
        h.Find<CheckBox>("DpiBlockQuicCheckBox").IsChecked = true;
        await Flush();
        Check(h.Find<StackPanel>("DpiUdpFragmentPanel").IsEnabled && h.Find<TextBlock>("DpiUdpQuicBlockedText").IsVisible, "UDP dependents wrong.");
        var saved = h.Saved.CustomDpi;
        Check(saved.MultiSplit && saved.FakeAutoTtl && saved.UdpIpFragmentation && saved.BlockQuic && !saved.TcpFragmentation, "Options not saved.");
        h.Window.Close();
        await Flush();
    }

    private static async Task DohSwitch()
    {
        var h = await Open();
        var combo = h.Find<ComboBox>("DohProviderComboBox");
        combo.SelectedItem = combo.Items.Cast<ComboBoxItem>().First(i => (DohProvider)i.Tag! == DohProvider.Cloudflare);
        await Flush();
        Check(h.Saved.DohProvider == DohProvider.Cloudflare && h.Helper.Calls.Count == 0, "Offline provider change not saved or contacted the helper.");
        Check(h.Find<TextBlock>("DohProviderDescriptionText").Text == Localization.T(DohProviders.GetDescriptionKey(DohProvider.Cloudflare)), "Description stale.");

        await Click(h.Find<Button>("ToggleConnectionButton"));
        Check(h.Helper.Provider == DohProvider.Cloudflare, "Start ignored the saved provider.");
        combo.SelectedItem = combo.Items.Cast<ComboBoxItem>().First(i => (DohProvider)i.Tag! == DohProvider.Google);
        await Flush();
        Check(h.Helper.LastUpdateProvider == DohProvider.Google && h.Helper.Provider == DohProvider.Google, "Live provider switch not sent.");
        Check(h.Helper.Calls[^1] == "refresh" && h.Window.IsConnected && combo.IsEnabled, "Switch did not re-resolve or left the UI busy.");
        Check(h.Find<TextBlock>("PingTargetText").Text == Localization.T("PingToDoh", new Uri(DohProviders.GetEndpoint(DohProvider.Google)).Authority),
            "Latency target not updated.");

        h.Helper.FailUpdate = new Dapapa.Core.Ipc.HelperException("resolver port busy");
        combo.SelectedItem = combo.Items.Cast<ComboBoxItem>().First(i => (DohProvider)i.Tag! == DohProvider.AdGuard);
        await Flush();
        Check(!h.Window.IsConnected && h.Helper.Stops == 1 && Shown.Count == 1 && Shown[0].Message.Contains("resolver port busy"),
            "Failed switch did not stop protection and report the error.");
        Check(h.Saved.DohProvider == DohProvider.AdGuard && combo.IsEnabled, "Selection lost or UI left busy after failure.");
        h.Window.Close();
        await Flush();
    }

    private static async Task LanguageSwitch()
    {
        var h = await Open();
        var add = new AddAppDialog();
        add.Show(h.Window);
        add.FindControl<RadioButton>("DomainListRadio")!.IsChecked = true;
        add.FindControl<TextBox>("DomainListTextBox")!.Text = "ok.example\nnot valid";
        await Click(add.FindControl<Button>("ContinueButtonText")!);
        var sync = new SyncCompleteDialog(2, 1234, true, 1);
        sync.Show(h.Window);
        await Flush();

        h.Find<ComboBox>("LanguageComboBox").SelectedIndex = 1;
        await Flush();
        Check(h.Saved.Language == "tr" && Localization.Current == AppLanguage.Turkish, "Language not saved.");
        Check(h.Find<TextBlock>("StatusText").Text == Localization.T("NotConnected") && Localization.T("NotConnected") != "Protection off",
            "Status not translated.");
        Check(h.Find<CheckBox>("RunOnStartupCheckBox").Content as string == "Oturum açılışında başlat", "Login option not translated.");
        Check(ToolTip.GetTip(h.Find<TabItem>("SettingsTabItem")) as string == Localization.T("TabSettings"), "Tab tooltip stale.");
        Check(add.Title == Localization.T("AddAppDialogHeading"), "Open add dialog stale.");
        Check(add.FindControl<TextBlock>("InputErrorText")!.IsVisible &&
            add.FindControl<TextBlock>("InputErrorText")!.Text == Localization.T("InvalidDomainLine", 2), "Validation error lost or stale.");
        Check(sync.FindControl<TextBlock>("ServicesUpdatedText")!.Text == Localization.T("SyncServicesUpdated", 2, 1234), "Sync dialog stale.");
        add.Close();
        sync.Close();
        h.Find<ComboBox>("LanguageComboBox").SelectedIndex = 0;
        await Flush();
        Check(Localization.Current == AppLanguage.English && h.Find<TextBlock>("StatusText").Text == Localization.T("NotConnected"),
            "English not restored.");
        h.Window.Close();
        await Flush();
    }

    private static async Task PulseOnlyWhenVisible()
    {
        var h = await Open();
        await Click(h.Find<Button>("ToggleConnectionButton"));
        var indicator = h.Find<Grid>("StatusIndicator");
        Check(indicator.Classes.Contains("idle"), "Connected status does not pulse.");
        h.Find<TabControl>("MainTabControl").SelectedIndex = 1;
        await Flush();
        Check(!indicator.Classes.Contains("idle"), "Pulse keeps running on another page.");
        h.Find<TabControl>("MainTabControl").SelectedIndex = 0;
        await Flush();
        Check(indicator.Classes.Contains("idle"), "Pulse did not resume on the Home page.");
        h.Window.Hide();
        await Flush();
        Check(!indicator.Classes.Contains("idle"), "Pulse keeps running in a hidden window.");
        h.Window.Show();
        await Flush();
        Check(indicator.Classes.Contains("idle"), "Pulse did not resume after showing the window.");
        h.Window.Close();
        await Flush();
    }

    private static async Task Statistics()
    {
        var h = await Open();
        Check(h.Find<TextBlock>("BypassedPacketsValueText").Text == Localization.T("PacketsCount", 0), "Idle packet count wrong.");
        Check(h.Find<TextBlock>("DownloadSpeedValueText").Text == Localization.T("IdleSpeed", 0), "Idle speed wrong.");
        await Click(h.Find<Button>("ToggleConnectionButton"));
        // Statistics are only updated while their page is showing; the Home page skips that work.
        h.Find<TabControl>("MainTabControl").SelectedIndex = 1;
        await Flush();
        h.Helper.SetCounters(1234, 1);
        await Flush();
        Check(h.Find<TextBlock>("BypassedPacketsValueText").Text == Localization.T("PacketsCount", 1234), "Packet counter not shown.");
        Check(h.Find<TextBlock>("SafeDnsValueText").Text == Localization.T("QueryCount", 1), "Singular DNS counter wrong.");
        await Click(h.Find<Button>("ResetStatsButton"));
        Check(h.Find<TextBlock>("BypassedPacketsValueText").Text == Localization.T("PacketsCount", 0), "Reset did not zero counters.");
        h.Helper.SetCounters(1240, 3);
        await Flush();
        Check(h.Find<TextBlock>("BypassedPacketsValueText").Text == Localization.T("PacketsCount", 6) &&
            h.Find<TextBlock>("SafeDnsValueText").Text == Localization.T("QueriesCount", 2), "Counters after reset not relative.");
        Check(!string.IsNullOrEmpty(h.Find<TextBlock>("AdapterValueText").Text), "Adapter name missing.");
        h.Window.Close();
        await Flush();
    }

    private static async Task AddDialog()
    {
        var owner = new Window();
        owner.Show();
        var add = new AddAppDialog();
        var result = add.ShowDialog<bool>(owner);
        await Flush();
        Check(add.FindControl<CheckBox>("DiscoverRelatedCheckBox")!.IsChecked == false, "Discovery enabled by default.");
        add.FindControl<TextBox>("DomainTextBox")!.Text = "not a domain";
        await Click(add.FindControl<Button>("ContinueButtonText")!);
        Check(add.FindControl<TextBlock>("InputErrorText")!.Text == Localization.T("InvalidDomain") && !result.IsCompleted, "Invalid domain accepted.");
        add.FindControl<TextBox>("DomainTextBox")!.Text = "https://WWW.Example.com/path?q=1";
        add.FindControl<CheckBox>("DiscoverRelatedCheckBox")!.IsChecked = true;
        await Click(add.FindControl<Button>("ContinueButtonText")!);
        Check(await result.WaitAsync(TimeSpan.FromSeconds(5)) && add.Domain == "www.example.com" && add.AppName == "www.example.com" && add.DiscoverRelated, "URL not normalised.");

        var list = new AddAppDialog();
        var listResult = list.ShowDialog<bool>(owner);
        list.FindControl<RadioButton>("DomainListRadio")!.IsChecked = true;
        list.FindControl<TextBox>("AppNameTextBox")!.Text = "My group";
        list.FindControl<TextBox>("DomainListTextBox")!.Text = "group.example\n\nCDN.other.net\ngroup.example\n";
        await Flush();
        Check(list.FindControl<TextBox>("DomainListTextBox")!.IsVisible && !list.FindControl<TextBox>("DomainTextBox")!.IsVisible, "List mode not shown.");
        await Click(list.FindControl<Button>("ContinueButtonText")!);
        Check(await listResult.WaitAsync(TimeSpan.FromSeconds(5)) && list.Domains.SequenceEqual(["group.example", "cdn.other.net"]) && list.AppName == "My group", "Domain list not parsed.");

        var target = new ProtectedApp { Name = "Group", Domain = "group.example", RelatedDomains = ["api.old.net"] };
        var edit = new AddAppDialog(target);
        var editResult = edit.ShowDialog<bool>(owner);
        await Flush();
        Check(!edit.FindControl<CheckBox>("DiscoverRelatedCheckBox")!.IsVisible && edit.Title == Localization.T("EditDomainGroup"), "Edit mode wrong.");
        edit.FindControl<TextBox>("DomainListTextBox")!.Text = "group.example\napi.new.net";
        await Click(edit.FindControl<Button>("ContinueButtonText")!);
        Check(await editResult.WaitAsync(TimeSpan.FromSeconds(5)) && edit.Domains.SequenceEqual(["group.example", "api.new.net"]), "Edit did not replace a member.");

        var cancel = new AddAppDialog();
        var cancelResult = cancel.ShowDialog<bool>(owner);
        await Click(cancel.FindControl<Button>("CancelButtonText")!);
        Check(!await cancelResult.WaitAsync(TimeSpan.FromSeconds(5)), "Cancel returned success.");
        owner.Close();
        await Flush();
    }

    private static async Task SyncDialog()
    {
        var live = new SyncCompleteDialog(3, 9, true);
        live.Show();
        Check(live.Title == Localization.T("SyncCompleteDialogTitle") && live.FindControl<Grid>("DnsCacheRow")!.IsVisible &&
            live.FindControl<TextBlock>("TargetStatusText")!.Text == Localization.T("SyncTargetsAppliedLive"), "Live sync dialog wrong.");
        live.Close();
        var offline = new SyncCompleteDialog(1, 2, false);
        offline.Show();
        Check(!offline.FindControl<Grid>("DnsCacheRow")!.IsVisible && !offline.FindControl<Grid>("DnsFlushedRow")!.IsVisible &&
            offline.FindControl<TextBlock>("TargetStatusText")!.Text == Localization.T("SyncTargetsCached"), "Offline sync claims cache changes.");
        offline.Close();
        var partial = new SyncCompleteDialog(1, 2, true, 2);
        partial.Show();
        Check(partial.Title == Localization.T("SyncIncompleteHeading") &&
            partial.FindControl<TextBlock>("SubheadingText")!.Text == Localization.T("SyncPartialFailure", 2), "Partial failure reported as success.");
        partial.Close();
        await Flush();
    }

    private sealed class StaticHandler(string html) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(html, System.Text.Encoding.UTF8, "text/html"),
                RequestMessage = request
            });
    }

    internal static RelatedDomainDiscoveryService FakeDiscovery() => new(new HttpClient(new StaticHandler("""
        <html><head><link rel="stylesheet" href="https://cdn.examplecdn.net/site.css">
        <script src="https://static.example-assets.com/app.js"></script></head>
        <body><img src="https://images.example.com/logo.png"></body></html>
        """)));

    private static async Task RelatedDomains()
    {
        var owner = new Window();
        owner.Show();
        string[]? added = null;
        using var discovery = FakeDiscovery();
        var dialog = new RelatedDomainsDialog("example.com", discovery, () => true, () => ["example.com"], s => added = s);
        dialog.Show(owner);
        await Settle(300);
        var choices = dialog.FindControl<ItemsControl>("CandidatesItemsControl")!;
        var add = dialog.FindControl<Button>("AddSelectedButton")!;
        Check(choices.ItemCount == 2 && !add.IsEnabled, "Subdomains of the target were offered or something was preselected.");
        var boxes = choices.GetVisualDescendants().OfType<CheckBox>().ToArray();
        Check(boxes.Length == 2 && boxes.All(b => b.IsChecked == false), "Candidates not clear by default.");
        boxes[0].IsChecked = true;
        await Flush();
        Check(add.IsEnabled, "Selecting a candidate did not enable adding.");
        await Click(add);
        Check(added is { Length: 1 } && added[0] == ((DiscoveryChoice)boxes[0].DataContext!).Domain, "Added something other than the selection.");
        await dialog.Completion.WaitAsync(TimeSpan.FromSeconds(5));
        owner.Close();
        await Flush();
    }

    private static async Task Closing()
    {
        var h = await Open(s => s.MinimizeToTrayOnClose = true);
        await Click(h.Find<Button>("ToggleConnectionButton"));
        h.Window.Close();
        await Flush();
        Check(!h.Window.IsVisible && h.Helper.Stops == 0 && !h.Helper.Disposed, "Close to tray stopped protection.");
        h.Window.RestoreFromTray();
        await Flush();
        Check(h.Window.IsVisible, "Restore from tray failed.");
        SetField(h.Window, "_reallyExit", true);
        h.Window.Close();
        await Flush(20);
        Check(h.Helper.Stops == 1 && h.Helper.Disposed && !h.Window.IsVisible, "Exit did not stop protection and release the helper.");
    }

    private static async Task Notifications()
    {
        var h = await Open(s => s.MinimizeToTrayOnClose = true);
        await Click(h.Find<Button>("ToggleConnectionButton"));
        await Flush(20);
        Check(h.Window.IsConnected, "Connect failed.");
        Check(h.Notifier.Shown.SequenceEqual([("dapapa", "Connecting..."), ("dapapa", "Done")]),
            "Connect notifications differ from the Windows app: " + string.Join(" | ", h.Notifier.Shown));
        h.Notifier.Shown.Clear();
        h.Window.Close();
        await Flush();
        Check(h.Notifier.Shown.SequenceEqual([("dapapa", "Running in the background.")]), "Closing to the tray did not notify.");
        SetField(h.Window, "_reallyExit", true);
        h.Window.Close();
        await Flush(20);

        // No session bus or notification server: nothing is shown and nothing throws.
        string missing = "unix:path=" + Path.Combine(Work, "no-bus.sock");
        using (var notifier = new DesktopNotifier(missing))
            Check(!await notifier.ShowAsync("dapapa", "test") && !await notifier.ShowAsync("dapapa", "again"), "Unreachable bus reported a notification.");
        using (var empty = new DesktopNotifier(""))
            Check(!await empty.ShowAsync("dapapa", "test"), "Missing bus address reported a notification.");
        var disposed = new DesktopNotifier(missing);
        disposed.Dispose();
        Check(!await disposed.ShowAsync("dapapa", "test"), "Disposed notifier sent a notification.");
    }

    private static Task BackendChoice()
    {
        Check(!Dapapa.App.Program.UseNativeWayland(":0", null), "XWayland was not the default with an X server.");
        Check(!Dapapa.App.Program.UseNativeWayland(":0", "0"), "DAPAPA_WAYLAND=0 selected Wayland.");
        Check(Dapapa.App.Program.UseNativeWayland(":0", "1"), "DAPAPA_WAYLAND=1 did not select Wayland.");
        Check(Dapapa.App.Program.UseNativeWayland(null, null) && Dapapa.App.Program.UseNativeWayland("", null),
            "A session without an X server did not fall back to Wayland.");
        return Task.CompletedTask;
    }

    private static Task TrayAttached()
    {
        // Avalonia 12 creates the StatusNotifierItem only for icons attached to the application; a detached icon never shows.
        using (var tray = new TrayService(Application.Current!))
        {
            var icons = TrayIcon.GetIcons(Application.Current!);
            Check(icons is { Count: 1 } && icons[0].IsVisible && icons[0].Menu?.Items.Count > 0, "Tray icon is not attached to the application.");
        }
        return Task.CompletedTask;
    }

    private static async Task AutostartAndSingleInstance()
    {
        string entry = AutostartService.BuildEntry(["/opt/my app/dapapa", "a$b%c"]);
        Check(entry.Contains("Exec=\"/opt/my app/dapapa\" \"a\\\\$b%%c\" --tray\n"), "Exec line not quoted per the Desktop Entry spec: " + entry);
        Check(entry.Contains("Type=Application\n") && entry.Contains("Icon=dapapa\n"), "Desktop entry incomplete.");
        string path = Path.Combine(Work, "autostart", "dapapa.desktop");
        AutostartService.SetEnabled(true, path);
        Check(File.ReadAllText(path).StartsWith("[Desktop Entry]\n"), "Autostart entry not written.");
        AutostartService.SetEnabled(false, path);
        Check(!File.Exists(path), "Autostart entry not removed.");
        AutostartService.SetEnabled(false, path);
        AutostartService.SetEnabled(false, Path.Combine(Work, "no-autostart-dir", "autostart", "dapapa.desktop"));

        string socket = Path.Combine(Work, "runtime", "dapapa", "app.sock");
        using (var first = SingleInstance.TryAcquire(true, socket))
        {
            Check(first != null, "First instance not acquired.");
            var shown = new TaskCompletionSource();
            first!.ShowRequested += () => shown.TrySetResult();
            Check(SingleInstance.TryAcquire(false, socket) == null, "Second tray instance not refused.");
            Check(SingleInstance.TryAcquire(true, socket) == null, "Second instance not refused.");
            await shown.Task.WaitAsync(TimeSpan.FromSeconds(5));
        }
        Check(!File.Exists(socket), "Socket left behind.");
        File.WriteAllText(socket, "");
        using var stale = SingleInstance.TryAcquire(true, socket);
        Check(stale != null, "Stale socket file blocked start-up.");
    }

    private static async Task ThemeParity()
    {
        Check(((Color)Resource("BgDarkColor")).ToString() == "#ff1a1b26" && ((Color)Resource("AccentColor")).ToString() == "#ff5865f2" &&
            ((Color)Resource("DangerColor")).ToString() == "#ffed4245" && ((Color)Resource("SuccessColor")).ToString() == "#ff3ba55d",
            "Palette differs from the Windows app.");
        var h = await Open();
        await Settle();
        Check(h.Window.Width == 520 && h.Window.Height == 640 && h.Window.MinWidth == 460 && h.Window.MinHeight == 560, "Window size differs.");
        var tabs = h.Window.GetVisualDescendants().OfType<TabItem>().ToArray();
        Check(tabs.Length == 3 && tabs.All(t => Math.Abs(t.Bounds.Width - 70) < 0.5 && Math.Abs(t.Bounds.Height - 48) < 0.5), "Tab buttons are not 70x48.");
        h.Find<TabControl>("MainTabControl").SelectedIndex = 2;
        await Settle(300);
        var settings = h.Find<ScrollViewer>("SettingsScrollViewer");
        var bar = settings.GetVisualDescendants().OfType<ScrollBar>().First(s => s.TemplatedParent == settings && s.Orientation == Avalonia.Layout.Orientation.Vertical);
        Check(bar.IsVisible && Math.Abs(bar.Bounds.Width - 8) < 0.5, "Settings scroll bar is not the thin visible style.");
        var font = h.Find<TextBlock>("StatusText").FontFamily;
        Check(font.Name.Contains("Selawik") || font.ToString().Contains("Selawik"), "Embedded font not used: " + font);
        Check(FontManager.Current.TryGetGlyphTypeface(new Typeface(font), out var typeface) && typeface.FamilyName == "Selawik", "Selawik not loaded.");
        h.Window.Close();
        await Flush();
    }
}

public static class TestApp
{
    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<App>()
        .UseSkia()
        .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false })
        .With(new FontManagerOptions { DefaultFamilyName = "avares://dapapa/Assets/Fonts#Selawik" });
}
