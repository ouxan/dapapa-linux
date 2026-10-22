using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Threading;
using Dapapa.Core;

namespace Dapapa.App.Dialogs
{
    public partial class RelatedDomainsDialog : Window
    {
        private readonly string _domain;
        private readonly RelatedDomainDiscoveryService _service;
        private readonly Func<bool> _targetExists;
        private readonly Func<string[]> _existing;
        private readonly Action<string[]> _add;
        private readonly CancellationTokenSource _cancellation = new();
        private readonly TaskCompletionSource _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private Task _load = Task.CompletedTask;
        private List<DiscoveryChoice> _choices = [];
        private bool _closed;
        private DiscoveryResult? _result;
        internal Task Completion => _completion.Task;

        /// <summary>Required by the XAML compiler; the dialog is always created with a target domain.</summary>
        public RelatedDomainsDialog() => throw new NotSupportedException();

        internal RelatedDomainsDialog(string domain, RelatedDomainDiscoveryService service, Func<bool> targetExists,
            Func<string[]> existing, Action<string[]> add)
        {
            InitializeComponent();
            _domain = domain;
            _service = service;
            _targetExists = targetExists;
            _existing = existing;
            _add = add;
            ApplyLanguage();
            Localization.Changed += OnLanguageChanged;
            Opened += (_, _) => { if (!_closed) _load = LoadAsync(); };
            Closed += async (_, _) =>
            {
                _closed = true;
                Localization.Changed -= OnLanguageChanged;
                _cancellation.Cancel();
                try { await _load; }
                finally { _cancellation.Dispose(); _completion.TrySetResult(); }
            };
            KeyDown += (_, e) => { if (e.Key == Key.Escape) Close(); };
        }

        private void OnLanguageChanged()
        {
            if (!Dispatcher.UIThread.CheckAccess()) { Dispatcher.UIThread.Post(OnLanguageChanged); return; }
            if (!_closed) ApplyLanguage();
        }

        private void ApplyLanguage()
        {
            Title = HeadingText.Text = Localization.T("DiscoveryTitle", _domain);
            DescriptionText.Text = Localization.T("DiscoveryDescription");
            CancelButton.Content = Localization.T("Cancel");
            AddSelectedButton.Content = Localization.T("DiscoveryAddSelected");
            foreach (var choice in _choices) choice.RefreshLocalization();
            if (_result == null) { StatusText.Text = Localization.T("DiscoveryLoading"); return; }
            StatusText.Text = _result.Completed
                ? Localization.T(_choices.Count == 0 ? "DiscoveryNone" : _choices.Count == 1 ? "DiscoveryFoundSingle" : "DiscoveryFound", _choices.Count)
                : Localization.T(_choices.Count == 0 ? "DiscoveryFailed" : "DiscoveryPartial", _result.Error ?? "");
        }

        private async Task LoadAsync()
        {
            try
            {
                var result = await _service.DiscoverAsync(_domain, _cancellation.Token);
                if (_closed || !_targetExists()) return;
                _result = result;
                var existing = _existing();
                _choices = result.Candidates.Where(c => !existing.Any(d => c.Domain.Equals(d, StringComparison.OrdinalIgnoreCase) ||
                    c.Domain.EndsWith("." + d, StringComparison.OrdinalIgnoreCase))).Select(c => new DiscoveryChoice(c)).ToList();
                CandidatesItemsControl.ItemsSource = _choices;
                ApplyLanguage();
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                if (!_closed) StatusText.Text = Localization.T("DiscoveryFailed", ex.Message);
            }
        }

        private void SelectionChanged(object? sender, RoutedEventArgs e) =>
            Dispatcher.UIThread.Post(() => { if (!_closed) AddSelectedButton.IsEnabled = _choices.Any(c => c.Selected); });

        private void AddSelectedButton_Click(object? sender, RoutedEventArgs e)
        {
            if (_closed || !_targetExists() || !_load.IsCompletedSuccessfully) return;
            string[] selected = DiscoveryChoice.SelectedDomains(_choices, _existing());
            if (selected.Length == 0) return;
            try { _add(selected); Close(); }
            catch (Exception ex) { StatusText.Text = Localization.T("DiscoveryFailed", ex.Message); }
        }

        private void CancelButton_Click(object? sender, RoutedEventArgs e) => Close();

        private void Header_PointerPressed(object? sender, PointerPressedEventArgs e)
        {
            if (e.GetCurrentPoint(this).Properties.IsLeftButtonPressed) BeginMoveDrag(e);
        }
    }
}
