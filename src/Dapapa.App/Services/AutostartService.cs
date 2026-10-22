using System.Text;
using Dapapa.Core;

namespace Dapapa.App.Services
{
    /// <summary>Start on login through an XDG autostart entry in the user's config directory.</summary>
    public static class AutostartService
    {
        public static string EntryPath => Path.Combine(XdgPaths.ConfigHome, "autostart", "dapapa.desktop");

        public static void SetEnabled(bool enabled, string? path = null)
        {
            path ??= EntryPath;
            if (!enabled)
            {
                // File.Delete throws when ~/.config/autostart itself does not exist, which is common on Hyprland.
                if (File.Exists(path)) File.Delete(path);
                return;
            }
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            string temp = path + ".tmp";
            File.WriteAllText(temp, BuildEntry(LaunchCommand()), new UTF8Encoding(false));
            File.Move(temp, path, overwrite: true);
        }

        internal static string BuildEntry(IReadOnlyList<string> command) => $"""
            [Desktop Entry]
            Type=Application
            Name=dapapa
            Comment=Per-domain DPI circumvention
            Exec={string.Join(' ', command.Select(QuoteExecArgument))} --tray
            Icon=dapapa
            Terminal=false
            X-GNOME-Autostart-enabled=true

            """;

        /// <summary>The packaged launcher, or the current executable (and assembly when running under the dotnet host).</summary>
        internal static IReadOnlyList<string> LaunchCommand()
        {
            const string packaged = "/usr/bin/dapapa";
            if (File.Exists(packaged)) return [packaged];
            string process = Environment.ProcessPath ?? packaged;
            if (Path.GetFileNameWithoutExtension(process) == "dotnet")
                return [process, typeof(AutostartService).Assembly.Location];
            return [process];
        }

        /// <summary>Quotes an Exec argument as the Desktop Entry Specification requires.</summary>
        internal static string QuoteExecArgument(string argument)
        {
            if (argument.Length > 0 && argument.All(c => char.IsAsciiLetterOrDigit(c) || "/._-+=:,@".Contains(c))) return argument;
            var quoted = new StringBuilder("\"");
            foreach (char c in argument)
            {
                if (c is '"' or '`' or '$' or '\\') quoted.Append('\\');
                quoted.Append(c);
            }
            // In the key-file format a backslash itself is escaped once more, and % starts a field code.
            return quoted.Append('"').ToString().Replace("\\", "\\\\").Replace("%", "%%");
        }
    }
}
