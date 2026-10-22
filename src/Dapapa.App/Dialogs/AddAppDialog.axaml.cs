using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Threading;
using Dapapa.Core;
using Dapapa.Core.Models;

namespace Dapapa.App.Dialogs
{
    public partial class AddAppDialog : Window
    {
        public string AppName { get; private set; } = string.Empty;
        public string Domain { get; private set; } = string.Empty;
        public string[] Domains { get; private set; } = [];
        public bool DiscoverRelated => DiscoverRelatedCheckBox.IsChecked == true;
        private readonly bool _editing;
        private bool _closed;

        public AddAppDialog() : this(null) { }

        internal AddAppDialog(ProtectedApp? target)
        {
            InitializeComponent();
            _editing = target != null;
            ApplyLanguage();
            if (target != null)
            {
                AppNameTextBox.Text = target.Name;
                DomainTextBox.Text = target.Domain;
                DomainListTextBox.Text = string.Join(Environment.NewLine, target.GetDomains());
                DomainListRadio.IsChecked = true;
                DiscoverRelatedCheckBox.IsVisible = false;
            }
            UpdateInputMode();
            Opened += (_, _) => { if (DomainListRadio.IsChecked == true) DomainListTextBox.Focus(); else DomainTextBox.Focus(); };
            AppNameTextBox.KeyDown += Input_KeyDown;
            DomainTextBox.KeyDown += Input_KeyDown;
            DomainListTextBox.AddHandler(KeyDownEvent, Input_KeyDown, RoutingStrategies.Tunnel);
            Localization.Changed += OnLanguageChanged;
            Closed += (_, _) => { _closed = true; Localization.Changed -= OnLanguageChanged; };
        }

        private void OnLanguageChanged()
        {
            if (!Dispatcher.UIThread.CheckAccess()) { Dispatcher.UIThread.Post(OnLanguageChanged); return; }
            if (_closed) return;
            bool hadError = InputErrorText.IsVisible;
            ApplyLanguage();
            UpdateInputMode();
            if (!hadError) return;
            if (DomainListRadio.IsChecked == true)
            {
                if (!DomainList.TryParse(DomainListTextBox.Text ?? "", out _, out var error)) ShowError(error);
            }
            else if (!DomainName.TryNormalize(DomainTextBox.Text ?? "", out _)) ShowError(Localization.T("InvalidDomain"));
        }

        private void ApplyLanguage()
        {
            Title = HeadingText.Text = Localization.T(_editing ? "EditDomainGroup" : "AddAppDialogHeading");
            DescriptionText.Text = Localization.T("AddAppDialogDescription");
            AppNameLabelText.Text = Localization.T("AppNameLabel");
            DomainLabelText.Text = Localization.T("DomainFieldLabel");
            CancelButtonText.Content = Localization.T("Cancel");
            ContinueButtonText.Content = Localization.T(_editing ? "SaveGroup" : "AddButton");
            DomainScopeText.Text = Localization.T("DomainScope");
            DiscoverRelatedCheckBox.Content = Localization.T("DiscoverRelated");
            SingleDomainRadio.Content = Localization.T("SingleDomain");
            DomainListRadio.Content = Localization.T("DomainList");
            DomainListHintText.Text = Localization.T("DomainListHint", DomainList.MaxDomains);
        }

        private void InputMode_Changed(object? sender, RoutedEventArgs e) => UpdateInputMode();

        private void UpdateInputMode()
        {
            if (DomainListTextBox == null || DomainScopeText == null) return;
            bool list = DomainListRadio.IsChecked == true;
            DomainTextBox.IsVisible = !list;
            DomainListTextBox.IsVisible = DomainListHintText.IsVisible = list;
            DomainLabelText.Text = Localization.T(list ? "DomainList" : "DomainFieldLabel");
            DomainScopeText.Text = Localization.T(list ? "DomainListScope" : "DomainScope");
            InputErrorText.IsVisible = false;
        }

        private void Input_KeyDown(object? sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter && (sender != DomainListTextBox || e.KeyModifiers.HasFlag(KeyModifiers.Control)))
            {
                Continue();
                e.Handled = true;
            }
            else if (e.Key == Key.Escape)
            {
                Close(false);
                e.Handled = true;
            }
        }

        private void ContinueButton_Click(object? sender, RoutedEventArgs e) => Continue();

        private void Continue()
        {
            string[] domains;
            if (DomainListRadio.IsChecked == true)
            {
                if (!DomainList.TryParse(DomainListTextBox.Text ?? "", out domains, out var error)) { ShowError(error); return; }
            }
            else
            {
                if (!DomainName.TryNormalize(DomainTextBox.Text ?? "", out var domain)) { ShowError(Localization.T("InvalidDomain")); return; }
                domains = [domain];
            }
            AppName = string.IsNullOrWhiteSpace(AppNameTextBox.Text) ? domains[0] : AppNameTextBox.Text.Trim();
            Domains = domains;
            Domain = domains[0];
            Close(true);
        }

        private void ShowError(string error)
        {
            InputErrorText.Text = error;
            InputErrorText.IsVisible = true;
        }

        private void CancelButton_Click(object? sender, RoutedEventArgs e) => Close(false);

        private void Root_PointerPressed(object? sender, PointerPressedEventArgs e)
        {
            if (e.Source is TextBox) return;
            if (e.GetCurrentPoint(this).Properties.IsLeftButtonPressed) BeginMoveDrag(e);
        }
    }
}
