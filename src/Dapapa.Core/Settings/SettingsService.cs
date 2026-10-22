using System.Globalization;
using System.Text.Json;
using Dapapa.Core.Models;

namespace Dapapa.Core
{
    public class SettingsService
    {
        private readonly string _settingsPath;
        private readonly bool _userSettings;
        private readonly Action<string, string> _backup;
        private readonly Action<string, string> _replace;
        private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
        public string SettingsFilePath => _settingsPath;
        public event Action<string>? Log;
        private void Emit(string line) => Log?.Invoke(line);

        public SettingsService() : this(Path.Combine(XdgPaths.ConfigHome, "dapapa", "settings.json"))
        {
            _userSettings = true;
        }

        internal SettingsService(string path, Action<string, string>? backup = null, Action<string, string>? replace = null)
        {
            _settingsPath = path;
            _backup = backup ?? ((source, destination) => File.Copy(source, destination, false));
            _replace = replace ?? ((source, destination) => File.Move(source, destination, true));
        }

        public static string GetDefaultLanguage()
        {
            string? locale = Environment.GetEnvironmentVariable("LC_ALL") is { Length: > 0 } all ? all :
                Environment.GetEnvironmentVariable("LC_MESSAGES") is { Length: > 0 } messages ? messages :
                Environment.GetEnvironmentVariable("LANG");
            if (!string.IsNullOrWhiteSpace(locale)) return locale.StartsWith("tr", StringComparison.OrdinalIgnoreCase) ? "tr" : "en";
            return CultureInfo.CurrentUICulture.TwoLetterISOLanguageName.Equals("tr", StringComparison.OrdinalIgnoreCase) ? "tr" : "en";
        }

        public AppSettings Load()
        {
            Emit(Localization.T("SettingsReading", _settingsPath));
            AppSettings settings;
            bool migrated = false;
            if (File.Exists(_settingsPath))
            {
                try
                {
                    settings = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(_settingsPath))
                        ?? throw new InvalidDataException(Localization.T("SettingsInvalid"));
                    if (settings.TargetListVersion > AppSettings.CurrentTargetListVersion)
                        throw new InvalidDataException(Localization.T("SettingsNewerVersion"));
                    if (settings.TargetListVersion < AppSettings.CurrentTargetListVersion)
                    {
                        string directory = Path.GetDirectoryName(_settingsPath)!;
                        string backupPath = Path.Combine(directory, "settings.pre-manual-targets-" +
                            DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff") + "-" + Guid.NewGuid().ToString("N")[..8] + ".bak");
                        _backup(_settingsPath, backupPath);
                        settings.Apps = [];
                        settings.TargetListVersion = AppSettings.CurrentTargetListVersion;
                        Save(settings);
                        migrated = true;
                        Emit(Localization.T("TargetsMigrated", backupPath));
                    }
                }
                catch (Exception ex)
                {
                    Emit(Localization.T("SettingsReadError", ex.Message));
                    throw;
                }
            }
            else
            {
                settings = new AppSettings { TargetListVersion = AppSettings.CurrentTargetListVersion,
                    Language = _userSettings ? GetDefaultLanguage() : "en" };
                Save(settings);
            }
            settings.NormalizeTargets();
            if (string.IsNullOrWhiteSpace(settings.Language)) settings.Language = _userSettings ? GetDefaultLanguage() : "en";
            if (migrated) Emit(Localization.T("NoActiveTargets"));
            return settings;
        }

        public void Save(AppSettings settings)
        {
            string? temporary = null;
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_settingsPath)!);
                temporary = _settingsPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
                File.WriteAllText(temporary, JsonSerializer.Serialize(settings, JsonOptions));
                _replace(temporary, _settingsPath);
                Emit(Localization.T("SettingsSaved"));
            }
            catch (Exception ex)
            {
                Emit(Localization.T("SettingsSaveError", ex.Message));
                throw;
            }
            finally { if (temporary != null && File.Exists(temporary)) File.Delete(temporary); }
        }
    }

    public static class XdgPaths
    {
        public static string ConfigHome => Resolve("XDG_CONFIG_HOME", ".config");
        public static string StateHome => Resolve("XDG_STATE_HOME", Path.Combine(".local", "state"));

        private static string Resolve(string variable, string fallback)
        {
            string? value = Environment.GetEnvironmentVariable(variable);
            return !string.IsNullOrWhiteSpace(value) && Path.IsPathRooted(value) ? value
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), fallback);
        }
    }
}
