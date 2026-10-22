using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Media.Imaging;
using Dapapa.App.Dialogs;
using Dapapa.Core;
using Dapapa.Core.Models;

internal static partial class Program
{
    /// <summary>Renders every screen and dialog in both languages for visual comparison with the Windows app.</summary>
    private static async Task Screenshots(string directory)
    {
        Directory.CreateDirectory(directory);
        foreach (var language in new[] { AppLanguage.English, AppLanguage.Turkish })
        {
            string suffix = language == AppLanguage.Turkish ? "-tr" : "";
            var h = await Open(s => s.Language = language == AppLanguage.Turkish ? "tr" : "en");
            await Capture(h.Window, directory, "home-off" + suffix);
            await Click(h.Find<Button>("ToggleConnectionButton"));
            h.Helper.SetCounters(18342, 127);
            await Capture(h.Window, directory, "home-on" + suffix);

            var tabs = h.Find<TabControl>("MainTabControl");
            tabs.SelectedIndex = 1;
            await Capture(h.Window, directory, "statistics" + suffix);

            tabs.SelectedIndex = 2;
            await Capture(h.Window, directory, "settings" + suffix);

            var scroller = h.Find<ScrollViewer>("SettingsScrollViewer");
            var mode = h.Find<ComboBox>("DpiModeComboBox");
            mode.SelectedIndex = 1;
            h.Find<CheckBox>("DpiTcpFragmentationCheckBox").IsChecked = true;
            h.Find<CheckBox>("DpiFakeWrongChecksumCheckBox").IsChecked = true;
            await Flush();
            ScrollTo(scroller, h.Find<TextBlock>("DpiSettingsHeaderText"));
            await Capture(h.Window, directory, "settings-dpi" + suffix);

            h.Find<Expander>("DpiUdpExpander").IsExpanded = true;
            await Flush();
            ScrollTo(scroller, h.Find<CheckBox>("DpiBlockQuicCheckBox"));
            await Capture(h.Window, directory, "settings-udp" + suffix);

            ScrollTo(scroller, h.Find<TextBlock>("LatencyHeaderText"));
            await Capture(h.Window, directory, "settings-targets" + suffix);

            var add = new AddAppDialog();
            add.Show(h.Window);
            await Capture(add, directory, "dialog-add" + suffix);
            add.FindControl<RadioButton>("DomainListRadio")!.IsChecked = true;
            add.FindControl<TextBox>("DomainListTextBox")!.Text = "discord.com\ndiscord.gg\ndiscordapp.com\ndiscord.media";
            await Capture(add, directory, "dialog-add-list" + suffix);
            add.Close();

            var sync = new SyncCompleteDialog(2, 14, true);
            sync.Show(h.Window);
            await Capture(sync, directory, "dialog-sync" + suffix);
            sync.Close();

            var partial = new SyncCompleteDialog(1, 6, true, 1);
            partial.Show(h.Window);
            await Capture(partial, directory, "dialog-sync-partial" + suffix);
            partial.Close();

            using (var discovery = FakeDiscovery())
            {
                var related = new RelatedDomainsDialog("example.com", discovery, () => true, () => ["example.com"], _ => { });
                related.Show(h.Window);
                await Settle(300);
                await Capture(related, directory, "dialog-related" + suffix);
                related.Close();
            }

            var message = new MessageDialog(Localization.T("RemoveGroupConfirm", "Discord", 3), Localization.T("Confirm"), MessageDialogButtons.YesNo);
            message.Show(h.Window);
            await Capture(message, directory, "dialog-confirm" + suffix);
            message.Close();

            SetField(h.Window, "_reallyExit", true);
            h.Window.Close();
            await Flush(20);
        }
    }

    private static void ScrollTo(ScrollViewer scroller, Control target)
    {
        var point = target.TranslatePoint(new Point(0, 0), (Visual)scroller.Content!) ?? default;
        scroller.Offset = new Vector(0, Math.Max(0, point.Y - 12));
    }

    private static async Task Capture(TopLevel window, string directory, string name)
    {
        await Settle();
        var frame = window.CaptureRenderedFrame() ?? throw new InvalidOperationException("No frame rendered for " + name);
        frame.Save(Path.Combine(directory, name + ".png"), PngBitmapEncoderOptions.Default);
        Check(frame.PixelSize.Width > 100 && frame.PixelSize.Height > 100, "Empty frame for " + name);
    }
}
