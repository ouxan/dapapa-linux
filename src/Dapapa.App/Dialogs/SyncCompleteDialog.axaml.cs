using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Threading;
using Dapapa.Core;

namespace Dapapa.App.Dialogs
{
    public partial class SyncCompleteDialog : Window
    {
        private readonly int _serviceCount;
        private readonly int _ipCount;
        private readonly bool _appliedLive;
        private readonly int _failedDomains;
        private bool _closed;

        public SyncCompleteDialog() : this(0, 0, false) { }

        /// <param name="appliedLive">True when the helper refreshed running protection; otherwise the targets were only checked.</param>
        public SyncCompleteDialog(int serviceCount, int ipCount, bool appliedLive, int failedDomains = 0)
        {
            _serviceCount = serviceCount;
            _ipCount = ipCount;
            _appliedLive = appliedLive;
            _failedDomains = failedDomains;
            InitializeComponent();
            ApplyLanguage();
            KeyDown += (_, e) => { if (e.Key is Key.Enter or Key.Escape) Close(true); };
            Opened += (_, _) => OkButton.Focus();
            Localization.Changed += OnLanguageChanged;
            Closed += (_, _) => { _closed = true; Localization.Changed -= OnLanguageChanged; };
        }

        private void OnLanguageChanged()
        {
            if (!Dispatcher.UIThread.CheckAccess()) { Dispatcher.UIThread.Post(OnLanguageChanged); return; }
            if (!_closed) ApplyLanguage();
        }

        private void ApplyLanguage()
        {
            Title = Localization.T(_failedDomains > 0 ? "SyncIncompleteHeading" : "SyncCompleteDialogTitle");
            HeadingText.Text = Localization.T("SyncCompleteDialogHeading");
            SubheadingText.Text = Localization.T("SyncCompleteDialogSubheading");
            if (_failedDomains > 0)
            {
                HeadingText.Text = Localization.T("SyncIncompleteHeading");
                SubheadingText.Text = Localization.T(_failedDomains == 1 ? "SyncPartialFailureSingle" : "SyncPartialFailure", _failedDomains);
                var danger = (IBrush)Application.Current!.FindResource("DangerBrush")!;
                SubheadingText.Foreground = danger;
                ResultIconBorder.BorderBrush = danger;
                ResultIcon.Stroke = danger;
                ResultIcon.Data = Geometry.Parse("M 5,5 L 19,19 M 19,5 L 5,19");
            }
            ServicesUpdatedText.Text = Localization.T("SyncServicesUpdated", _serviceCount, _ipCount);
            DnsFlushedText.Text = Localization.T("SyncDnsFlushed");
            DnsCacheStatusText.Text = Localization.T("SyncDnsCacheStatus");
            // Only a live refresh goes through the helper, which owns the DoH cache and flushes the system resolver.
            DnsFlushedRow.IsVisible = DnsCacheRow.IsVisible = _appliedLive;
            TargetStatusLiveDot.IsVisible = _appliedLive;
            TargetStatusSavedPath.IsVisible = !_appliedLive;
            TargetStatusText.Text = Localization.T(_appliedLive ? "SyncTargetsAppliedLive" : "SyncTargetsCached");
            OkButton.Content = Localization.T("OK");
        }

        private void OkButton_Click(object? sender, RoutedEventArgs e) => Close(true);

        private void Root_PointerPressed(object? sender, PointerPressedEventArgs e)
        {
            if (e.GetCurrentPoint(this).Properties.IsLeftButtonPressed) BeginMoveDrag(e);
        }
    }
}
