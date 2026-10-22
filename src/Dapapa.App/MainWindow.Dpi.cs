using System.Globalization;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Dapapa.App.Dialogs;
using Dapapa.Core;
using Dapapa.Core.Models;

namespace Dapapa.App
{
    public partial class MainWindow
    {
        private void LoadDpiSettingsIntoUi()
        {
            var options = _settings.CustomDpi;
            DpiModeComboBox.SelectedIndex = _settings.DpiMode == DpiMode.Custom ? 1 : 0;
            DpiTcpFragmentationCheckBox.IsChecked = options.TcpFragmentation;
            DpiReverseSegmentsCheckBox.IsChecked = options.ReverseSegments;
            DpiSplitAtHostnameCheckBox.IsChecked = options.SplitAtHostname;
            DpiFakeWrongChecksumCheckBox.IsChecked = options.FakeWrongChecksum;
            DpiHttpHostHeaderCaseCheckBox.IsChecked = options.HttpHostHeaderCase;
            DpiHttpHostDomainCaseCheckBox.IsChecked = options.HttpHostDomainCase;
            DpiHttpHostRemoveSpaceCheckBox.IsChecked = options.HttpHostRemoveSpace;
            DpiBlockQuicCheckBox.IsChecked = options.BlockQuic;
            DpiMultiSplitCheckBox.IsChecked = options.MultiSplit;
            DpiFakeWrongSequenceCheckBox.IsChecked = options.FakeWrongSequence;
            DpiFakeLowTtlCheckBox.IsChecked = options.FakeLowTtl;
            DpiFakeAutoTtlCheckBox.IsChecked = options.FakeAutoTtl;
            DpiFakeMd5SignatureCheckBox.IsChecked = options.FakeMd5Signature;
            DpiFakeTimestampCheckBox.IsChecked = options.FakeTimestamp;
            DpiFakeDataNoAckCheckBox.IsChecked = options.FakeDataNoAck;
            DpiFakeRandomizeTlsCheckBox.IsChecked = options.FakeRandomizeTls;
            DpiFakeMixSegmentsCheckBox.IsChecked = options.FakeMixSegments;
            DpiHttpMethodSpaceCheckBox.IsChecked = options.HttpMethodSpace;
            DpiHttpMethodEolCheckBox.IsChecked = options.HttpMethodEol;
            DpiHttpHostTabCheckBox.IsChecked = options.HttpHostTab;
            DpiUdpFakeWrongChecksumCheckBox.IsChecked = options.UdpFakeWrongChecksum;
            DpiUdpFakeLowTtlCheckBox.IsChecked = options.UdpFakeLowTtl;
            DpiUdpIpFragmentationCheckBox.IsChecked = options.UdpIpFragmentation;
            DpiUdpReverseFragmentsCheckBox.IsChecked = options.UdpReverseFragments;
            DpiUdpLengthPaddingCheckBox.IsChecked = options.UdpLengthPadding;
            DpiUdpQuicInitialCheckBox.IsChecked = options.UdpQuicInitial;
            DpiUdpStunCheckBox.IsChecked = options.UdpStun;
            DpiUdpWireGuardCheckBox.IsChecked = options.UdpWireGuard;
            DpiUdpDiscordDiscoveryCheckBox.IsChecked = options.UdpDiscordDiscovery;
            DpiUdpUnknownCheckBox.IsChecked = options.UdpUnknown;
            DpiUdpFakeTtlTextBox.Text = options.UdpFakeTtl.ToString(CultureInfo.InvariantCulture);
            DpiUdpFakeRepeatsTextBox.Text = options.UdpFakeRepeats.ToString(CultureInfo.InvariantCulture);
            DpiUdpFragmentSizeTextBox.Text = options.UdpFragmentSize.ToString(CultureInfo.InvariantCulture);
            DpiUdpPaddingSizeTextBox.Text = options.UdpPaddingSize.ToString(CultureInfo.InvariantCulture);
            DpiUdpPacketLimitTextBox.Text = options.UdpPacketLimit.ToString(CultureInfo.InvariantCulture);
            DpiSplitSizeTextBox.Text = options.TcpSplitSize.ToString(CultureInfo.InvariantCulture);
            DpiSplitPositionsTextBox.Text = options.SplitPositions;
            DpiFakeTtlTextBox.Text = options.FakeTtl.ToString(CultureInfo.InvariantCulture);
            DpiFakeRepeatsTextBox.Text = options.FakeRepeats.ToString(CultureInfo.InvariantCulture);
            DpiFakeHostnameTextBox.Text = options.FakeHostname;
            DpiMaxPayloadTextBox.Text = options.MaxPayloadSize.ToString(CultureInfo.InvariantCulture);
            UpdateDpiUi();
        }

        private void ApplyDpiLanguage()
        {
            DpiSettingsHeaderText.Text = Localization.T("DpiSettingsHeader");
            DpiStandardModeItem.Content = Localization.T("DpiStandardMode");
            DpiCustomModeItem.Content = Localization.T("DpiCustomMode");
            DpiTcpFragmentationCheckBox.Content = Localization.T("DpiTcpFragmentation");
            ToolTip.SetTip(DpiTcpFragmentationCheckBox, Localization.T("DpiTcpFragmentationHint"));
            DpiReverseSegmentsCheckBox.Content = Localization.T("DpiReverseSegments");
            ToolTip.SetTip(DpiReverseSegmentsCheckBox, Localization.T("DpiReverseSegmentsHint"));
            DpiSplitAtHostnameCheckBox.Content = Localization.T("DpiSplitAtHostname");
            ToolTip.SetTip(DpiSplitAtHostnameCheckBox, Localization.T("DpiSplitAtHostnameHint"));
            DpiFakeWrongChecksumCheckBox.Content = Localization.T("DpiFakeWrongChecksum");
            ToolTip.SetTip(DpiFakeWrongChecksumCheckBox, Localization.T("DpiFakeWrongChecksumHint"));
            DpiHttpMethodsLabelText.Text = Localization.T("DpiHttpMethodsLabel");
            DpiHttpHostHeaderCaseCheckBox.Content = Localization.T("DpiHttpHostHeaderCase");
            ToolTip.SetTip(DpiHttpHostHeaderCaseCheckBox, Localization.T("DpiHttpHostHeaderCaseHint"));
            DpiHttpHostDomainCaseCheckBox.Content = Localization.T("DpiHttpHostDomainCase");
            ToolTip.SetTip(DpiHttpHostDomainCaseCheckBox, Localization.T("DpiHttpHostDomainCaseHint"));
            DpiHttpHostRemoveSpaceCheckBox.Content = Localization.T("DpiHttpHostRemoveSpace");
            ToolTip.SetTip(DpiHttpHostRemoveSpaceCheckBox, Localization.T("DpiHttpHostRemoveSpaceHint"));
            DpiBlockQuicCheckBox.Content = Localization.T("DpiBlockQuic");
            ToolTip.SetTip(DpiBlockQuicCheckBox, Localization.T("DpiBlockQuicHint"));
            DpiCustomCompatibilityText.Text = Localization.T("DpiCustomCompatibility");
            DpiMultiSplitCheckBox.Content = Localization.T("DpiMultiSplit");
            ToolTip.SetTip(DpiMultiSplitCheckBox, Localization.T("DpiMultiSplitHint"));
            DpiFakeWrongSequenceCheckBox.Content = Localization.T("DpiFakeWrongSequence");
            ToolTip.SetTip(DpiFakeWrongSequenceCheckBox, Localization.T("DpiFakeWrongSequenceHint"));
            DpiFakeLowTtlCheckBox.Content = Localization.T("DpiFakeLowTtl");
            ToolTip.SetTip(DpiFakeLowTtlCheckBox, Localization.T("DpiFakeLowTtlHint"));
            DpiFakeAutoTtlCheckBox.Content = Localization.T("DpiFakeAutoTtl");
            ToolTip.SetTip(DpiFakeAutoTtlCheckBox, Localization.T("DpiFakeAutoTtlHint"));
            DpiFakeMd5SignatureCheckBox.Content = Localization.T("DpiFakeMd5Signature");
            ToolTip.SetTip(DpiFakeMd5SignatureCheckBox, Localization.T("DpiFakeMd5SignatureHint"));
            DpiFakeTimestampCheckBox.Content = Localization.T("DpiFakeTimestamp");
            ToolTip.SetTip(DpiFakeTimestampCheckBox, Localization.T("DpiFakeTimestampHint"));
            DpiFakeDataNoAckCheckBox.Content = Localization.T("DpiFakeDataNoAck");
            ToolTip.SetTip(DpiFakeDataNoAckCheckBox, Localization.T("DpiFakeDataNoAckHint"));
            DpiFakeRandomizeTlsCheckBox.Content = Localization.T("DpiFakeRandomizeTls");
            ToolTip.SetTip(DpiFakeRandomizeTlsCheckBox, Localization.T("DpiFakeRandomizeTlsHint"));
            DpiHttpMethodSpaceCheckBox.Content = Localization.T("DpiHttpMethodSpace");
            ToolTip.SetTip(DpiHttpMethodSpaceCheckBox, Localization.T("DpiHttpMethodSpaceHint"));
            DpiHttpMethodEolCheckBox.Content = Localization.T("DpiHttpMethodEol");
            ToolTip.SetTip(DpiHttpMethodEolCheckBox, Localization.T("DpiHttpMethodEolHint"));
            DpiHttpHostTabCheckBox.Content = Localization.T("DpiHttpHostTab");
            ToolTip.SetTip(DpiHttpHostTabCheckBox, Localization.T("DpiHttpHostTabHint"));
            DpiSplitSizeLabelText.Text = Localization.T("DpiSplitSize");
            DpiSplitPositionsLabelText.Text = Localization.T("DpiSplitPositions");
            DpiFakeTtlLabelText.Text = Localization.T("DpiFakeTtl");
            DpiFakeRepeatsLabelText.Text = Localization.T("DpiFakeRepeats");
            DpiFakeHostnameLabelText.Text = Localization.T("DpiFakeHostname");
            DpiMaxPayloadLabelText.Text = Localization.T("DpiMaxPayload");
            DpiFakeAdvancedExpander.Header = Localization.T("DpiFakeAdvanced");
            DpiFakeMixSegmentsCheckBox.Content = Localization.T("DpiFakeMixSegments");
            ToolTip.SetTip(DpiFakeMixSegmentsCheckBox, Localization.T("DpiFakeMixSegmentsHint"));
            DpiUdpExpander.Header = Localization.T("DpiUdpHeader");
            DpiUdpScopeText.Text = Localization.T("DpiUdpScope");
            DpiUdpFakeWrongChecksumCheckBox.Content = Localization.T("DpiUdpFakeWrongChecksum");
            ToolTip.SetTip(DpiUdpFakeWrongChecksumCheckBox, Localization.T("DpiUdpFakeWrongChecksumHint"));
            DpiUdpFakeLowTtlCheckBox.Content = Localization.T("DpiUdpFakeLowTtl");
            ToolTip.SetTip(DpiUdpFakeLowTtlCheckBox, Localization.T("DpiUdpFakeLowTtlHint"));
            DpiUdpIpFragmentationCheckBox.Content = Localization.T("DpiUdpIpFragmentation");
            ToolTip.SetTip(DpiUdpIpFragmentationCheckBox, Localization.T("DpiUdpIpFragmentationHint"));
            DpiUdpReverseFragmentsCheckBox.Content = Localization.T("DpiUdpReverseFragments");
            DpiUdpLengthPaddingCheckBox.Content = Localization.T("DpiUdpLengthPadding");
            ToolTip.SetTip(DpiUdpLengthPaddingCheckBox, Localization.T("DpiUdpLengthPaddingHint"));
            DpiUdpQuicInitialCheckBox.Content = Localization.T("DpiUdpQuicInitial");
            DpiUdpStunCheckBox.Content = Localization.T("DpiUdpStun");
            DpiUdpWireGuardCheckBox.Content = Localization.T("DpiUdpWireGuard");
            DpiUdpDiscordDiscoveryCheckBox.Content = Localization.T("DpiUdpDiscordDiscovery");
            DpiUdpUnknownCheckBox.Content = Localization.T("DpiUdpUnknown");
            DpiUdpFakeTtlLabelText.Text = Localization.T("DpiUdpFakeTtl");
            DpiUdpFakeRepeatsLabelText.Text = Localization.T("DpiUdpFakeRepeats");
            DpiUdpFragmentSizeLabelText.Text = Localization.T("DpiUdpFragmentSize");
            DpiUdpPaddingSizeLabelText.Text = Localization.T("DpiUdpPaddingSize");
            DpiUdpPacketLimitLabelText.Text = Localization.T("DpiUdpPacketLimit");
            DpiUdpProtocolsLabelText.Text = Localization.T("DpiUdpProtocols");
            DpiUdpQuicBlockedText.Text = Localization.T("DpiUdpQuicBlocked");
            if (DpiValidationText.IsVisible) TryReadDpiParameters(_settings.CustomDpi, out _);
            UpdateDpiUi();
        }

        private void UpdateDpiUi()
        {
            bool custom = DpiModeComboBox.SelectedIndex == 1;
            DpiCustomPanel.IsVisible = custom;
            DpiTcpOptionsPanel.IsEnabled = custom && DpiTcpFragmentationCheckBox.IsChecked == true;
            DpiModeHintText.Text = Localization.T(custom ? "DpiCustomHint" : "DpiStandardHint");
            DpiSplitSizeTextBox.IsEnabled = custom && DpiTcpFragmentationCheckBox.IsChecked == true && DpiMultiSplitCheckBox.IsChecked != true && DpiSplitAtHostnameCheckBox.IsChecked != true;
            DpiSplitPositionsTextBox.IsEnabled = custom && DpiTcpFragmentationCheckBox.IsChecked == true && DpiMultiSplitCheckBox.IsChecked == true;
            DpiSplitAtHostnameCheckBox.IsEnabled = custom && DpiTcpFragmentationCheckBox.IsChecked == true && DpiMultiSplitCheckBox.IsChecked != true;
            DpiFakeTtlTextBox.IsEnabled = custom && DpiFakeLowTtlCheckBox.IsChecked == true && DpiFakeAutoTtlCheckBox.IsChecked != true;
            DpiFakeMixSegmentsCheckBox.IsEnabled = custom && DpiTcpFragmentationCheckBox.IsChecked == true;
            DpiUdpFragmentPanel.IsEnabled = custom && DpiUdpIpFragmentationCheckBox.IsChecked == true;
            DpiUdpFakeTtlTextBox.IsEnabled = custom && DpiUdpFakeLowTtlCheckBox.IsChecked == true;
            DpiUdpFakeRepeatsTextBox.IsEnabled = custom && (DpiUdpFakeLowTtlCheckBox.IsChecked == true || DpiUdpFakeWrongChecksumCheckBox.IsChecked == true);
            DpiUdpPaddingSizeTextBox.IsEnabled = custom && DpiUdpLengthPaddingCheckBox.IsChecked == true;
            DpiUdpQuicBlockedText.IsVisible = DpiBlockQuicCheckBox.IsChecked == true;
        }

        private void DpiMode_SelectionChanged(object? sender, SelectionChangedEventArgs e) => DpiSetting_Changed(sender, e);

        private async void DpiSetting_Changed(object? sender, RoutedEventArgs e)
        {
            UpdateDpiUi();
            if (_isLoadingSettings) return;
            if (_isBusy) { ReloadDpiSettings(); return; }
            var previousMode = _settings.DpiMode;
            var previousOptions = _settings.CustomDpi;
            var basicOptions = new DpiOptions
            {
                TcpFragmentation = DpiTcpFragmentationCheckBox.IsChecked == true,
                ReverseSegments = DpiReverseSegmentsCheckBox.IsChecked == true,
                SplitAtHostname = DpiSplitAtHostnameCheckBox.IsChecked == true,
                FakeWrongChecksum = DpiFakeWrongChecksumCheckBox.IsChecked == true,
                HttpHostHeaderCase = DpiHttpHostHeaderCaseCheckBox.IsChecked == true,
                HttpHostDomainCase = DpiHttpHostDomainCaseCheckBox.IsChecked == true,
                HttpHostRemoveSpace = DpiHttpHostRemoveSpaceCheckBox.IsChecked == true,
                BlockQuic = DpiBlockQuicCheckBox.IsChecked == true
            };
            DpiOptions customOptions = previousOptions;
            if (DpiModeComboBox.SelectedIndex == 1 && !TryReadDpiParameters(basicOptions, out customOptions)) return;
            bool standard = DpiModeComboBox.SelectedIndex != 1;
            if (standard) DpiValidationText.IsVisible = false;
            _settings.DpiMode = standard ? DpiMode.Standard : DpiMode.Custom;
            _settings.CustomDpi = customOptions;
            if (previousMode == _settings.DpiMode && previousOptions == _settings.CustomDpi) return;
            bool saved = false;
            try
            {
                _settingsService.Save(_settings);
                saved = true;
                // The helper swaps its rules atomically, so a live change never needs a reconnect.
                if (_protection.IsRunning) await _protection.UpdateAsync(null, _settings.GetDpiOptions(), null);
                if (standard) ReloadDpiSettings();
                if (_isConnected && !_isBusy)
                    StatusSubText.Text = Localization.T(_settings.GetDpiOptions().HasTrafficMethods ? "ConnectedHint" : "DnsOnlyHint");
                AppendLog(Localization.T("DpiSettingsApplied", Localization.T(_settings.DpiMode == DpiMode.Custom ? "DpiCustomMode" : "DpiStandardMode")));
            }
            catch (Exception ex)
            {
                if (!saved)
                {
                    _settings.DpiMode = previousMode;
                    _settings.CustomDpi = previousOptions;
                }
                ReloadDpiSettings();
                await MessageDialog.ShowAsync(this, saved ? Describe(ex) : Localization.T("SettingsSaveError", ex.Message), Localization.T("Error"));
            }
        }

        private void ReloadDpiSettings()
        {
            bool loading = _isLoadingSettings;
            _isLoadingSettings = true;
            try { LoadDpiSettingsIntoUi(); }
            finally { _isLoadingSettings = loading; }
        }

        private void DpiInput_KeyDown(object? sender, KeyEventArgs e)
        {
            if (e.Key != Key.Enter) return;
            DpiSetting_Changed(sender, e);
            e.Handled = true;
        }

        private bool TryReadDpiParameters(DpiOptions basic, out DpiOptions options)
        {
            options = basic;
            bool Number(TextBox input, string label, int min, int max, out int value)
            {
                if (int.TryParse((input.Text ?? "").Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out value) && value >= min && value <= max) return true;
                DpiValidationText.Text = Localization.T("DpiNumberError", Localization.T(label), min, max);
                DpiValidationText.IsVisible = true; return false;
            }
            if (!Number(DpiSplitSizeTextBox, "DpiSplitSize", 1, 1024, out int split) ||
                !Number(DpiFakeTtlTextBox, "DpiFakeTtl", 1, 64, out int ttl) ||
                !Number(DpiFakeRepeatsTextBox, "DpiFakeRepeats", 1, 6, out int repeats) ||
                !Number(DpiMaxPayloadTextBox, "DpiMaxPayload", 0, 65535, out int maxPayload) ||
                !Number(DpiUdpFakeTtlTextBox, "DpiUdpFakeTtl", 1, 64, out int udpTtl) ||
                !Number(DpiUdpFakeRepeatsTextBox, "DpiUdpFakeRepeats", 1, 6, out int udpRepeats) ||
                !Number(DpiUdpFragmentSizeTextBox, "DpiUdpFragmentSize", 8, 1440, out int udpFragment) ||
                !Number(DpiUdpPaddingSizeTextBox, "DpiUdpPaddingSize", 1, 64, out int udpPadding) ||
                !Number(DpiUdpPacketLimitTextBox, "DpiUdpPacketLimit", 1, 20, out int udpLimit)) return false;
            if (udpFragment % 8 != 0)
            {
                DpiValidationText.Text = Localization.T("DpiUdpFragmentSizeError");
                DpiValidationText.IsVisible = true; return false;
            }
            string markers = (DpiSplitPositionsTextBox.Text ?? "").Trim();
            if (!TcpSplitPositions.IsValid(markers))
            {
                DpiValidationText.Text = Localization.T("DpiInvalidMarkers"); DpiValidationText.IsVisible = true; return false;
            }
            string hostname = (DpiFakeHostnameTextBox.Text ?? "").Trim();
            if (hostname.Length > 0 && !DomainName.TryNormalize(hostname, out hostname))
            {
                DpiValidationText.Text = Localization.T("InvalidDomain"); DpiValidationText.IsVisible = true; return false;
            }
            options = basic with
            {
                TcpSplitSize = split, SplitPositions = markers, FakeTtl = ttl, FakeRepeats = repeats,
                FakeHostname = hostname, MaxPayloadSize = maxPayload,
                MultiSplit = DpiMultiSplitCheckBox.IsChecked == true,
                FakeWrongSequence = DpiFakeWrongSequenceCheckBox.IsChecked == true,
                FakeLowTtl = DpiFakeLowTtlCheckBox.IsChecked == true,
                FakeAutoTtl = DpiFakeAutoTtlCheckBox.IsChecked == true,
                FakeMd5Signature = DpiFakeMd5SignatureCheckBox.IsChecked == true,
                FakeTimestamp = DpiFakeTimestampCheckBox.IsChecked == true,
                FakeDataNoAck = DpiFakeDataNoAckCheckBox.IsChecked == true,
                FakeRandomizeTls = DpiFakeRandomizeTlsCheckBox.IsChecked == true,
                FakeMixSegments = DpiFakeMixSegmentsCheckBox.IsChecked == true,
                HttpMethodSpace = DpiHttpMethodSpaceCheckBox.IsChecked == true,
                HttpMethodEol = DpiHttpMethodEolCheckBox.IsChecked == true,
                HttpHostTab = DpiHttpHostTabCheckBox.IsChecked == true,
                UdpFakeWrongChecksum = DpiUdpFakeWrongChecksumCheckBox.IsChecked == true,
                UdpFakeLowTtl = DpiUdpFakeLowTtlCheckBox.IsChecked == true,
                UdpIpFragmentation = DpiUdpIpFragmentationCheckBox.IsChecked == true,
                UdpReverseFragments = DpiUdpReverseFragmentsCheckBox.IsChecked == true,
                UdpLengthPadding = DpiUdpLengthPaddingCheckBox.IsChecked == true,
                UdpQuicInitial = DpiUdpQuicInitialCheckBox.IsChecked == true,
                UdpStun = DpiUdpStunCheckBox.IsChecked == true,
                UdpWireGuard = DpiUdpWireGuardCheckBox.IsChecked == true,
                UdpDiscordDiscovery = DpiUdpDiscordDiscoveryCheckBox.IsChecked == true,
                UdpUnknown = DpiUdpUnknownCheckBox.IsChecked == true,
                UdpFakeTtl = udpTtl, UdpFakeRepeats = udpRepeats, UdpFragmentSize = udpFragment,
                UdpPaddingSize = udpPadding, UdpPacketLimit = udpLimit
            };
            DpiValidationText.IsVisible = false;
            return true;
        }
    }
}
