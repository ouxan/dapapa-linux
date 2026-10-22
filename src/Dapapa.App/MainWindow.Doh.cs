using Avalonia.Controls;
using Dapapa.App.Dialogs;
using Dapapa.Core;
using Dapapa.Core.Models;

namespace Dapapa.App
{
    public partial class MainWindow
    {
        private void LoadDohSettingsIntoUi()
        {
            bool loading = _isLoadingSettings;
            _isLoadingSettings = true;
            try
            {
                if (DohProviderComboBox.ItemCount == 0)
                    foreach (var provider in DohProviders.All)
                        DohProviderComboBox.Items.Add(new ComboBoxItem { Tag = provider });
                DohProviderComboBox.SelectedItem = DohProviderComboBox.Items.Cast<ComboBoxItem>()
                    .First(item => (DohProvider)item.Tag! == _settings.DohProvider);
                ApplyDohLanguage();
            }
            finally { _isLoadingSettings = loading; }
        }

        private void ApplyDohLanguage()
        {
            DohSettingsHeaderText.Text = Localization.T("DohSettingsHeader");
            foreach (ComboBoxItem item in DohProviderComboBox.Items.Cast<ComboBoxItem>())
                item.Content = Localization.T(DohProviders.GetLabelKey((DohProvider)item.Tag!));
            DohProviderDescriptionText.Text = Localization.T(DohProviders.GetDescriptionKey(_settings.DohProvider));
            DohSettingsHintText.Text = Localization.T("DohHint");
        }

        private async void DohProvider_SelectionChanged(object? sender, SelectionChangedEventArgs e) => await ApplyDohProviderSelectionAsync();

        private async Task ApplyDohProviderSelectionAsync()
        {
            if (_isLoadingSettings) return;
            if (_isBusy) { LoadDohSettingsIntoUi(); return; }
            if (DohProviderComboBox.SelectedItem is not ComboBoxItem { Tag: DohProvider provider } || provider == _settings.DohProvider) return;
            var previous = _settings.DohProvider;
            _settings.DohProvider = provider;
            try { _settingsService.Save(_settings); }
            catch (Exception ex)
            {
                _settings.DohProvider = previous;
                LoadDohSettingsIntoUi();
                await MessageDialog.ShowAsync(this, Localization.T("SettingsSaveError", ex.Message), Localization.T("Error"));
                return;
            }
            ApplyDohLanguage();
            _lastDnsLatency = null;
            PingValueText.Text = "-- ms";
            PingBadge.IsVisible = false;
            UpdatePingTargetLabel();
            if (!_userWantsConnected && !_protection.IsRunning)
            {
                AppendLog(Localization.T("DohSelectionSaved", Localization.T(DohProviders.GetLabelKey(provider))));
                return;
            }
            _isBusy = true;
            SetConnectionVisualState(false);
            SetBusyUi(true, "DohSwitching");
            SuppressWatchdog(TimeSpan.FromSeconds(20));
            _operationCts?.Cancel();
            _operationCts?.Dispose();
            _operationCts = new CancellationTokenSource();
            var ct = _operationCts.Token;
            try
            {
                // The helper restarts its resolver for a new provider; targets are refreshed before the switch is reported.
                await _protection.UpdateAsync(null, null, provider, ct);
                var result = await RefreshTargetsAsync(false, ct);
                if (!result.Applied || !_protection.IsRunning)
                    throw new InvalidOperationException(Localization.T("ProtectionStartFailed"));
                SetConnectionVisualState(true);
                AppendLog(Localization.T("DohSelectionApplied", Localization.T(DohProviders.GetLabelKey(provider))));
                SuppressWatchdog(TimeSpan.FromSeconds(5));
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
            catch (Exception ex)
            {
                try { await StopProtectionAsync(); }
                catch (Exception cleanupError) { AppendLog(Describe(cleanupError)); }
                string message = Localization.T("DohSwitchFailed", ex.Message);
                AppendLog(message);
                await MessageDialog.ShowAsync(this, message, Localization.T("Error"));
            }
            finally
            {
                _isBusy = false;
                SetConnectionVisualState(_protection.IsRunning && _userWantsConnected);
                SetBusyUi(false, null);
            }
        }
    }
}
