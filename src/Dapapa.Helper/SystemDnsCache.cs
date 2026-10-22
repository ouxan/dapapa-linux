using System.Diagnostics;
using Dapapa.Core;

namespace Dapapa.Helper
{
    /// <summary>Flushes the systemd-resolved cache when that resolver is in use; other resolvers are left untouched.</summary>
    internal static class SystemDnsCache
    {
        private const string ResolvectlPath = "/usr/bin/resolvectl";

        public static void Flush(Action<string> log)
        {
            if (!File.Exists(ResolvectlPath) || !Directory.Exists("/run/systemd/resolve")) return;
            try
            {
                using var process = Process.Start(new ProcessStartInfo(ResolvectlPath, "flush-caches")
                {
                    RedirectStandardError = true,
                    RedirectStandardOutput = true,
                    UseShellExecute = false
                }) ?? throw new IOException("Unable to start resolvectl.");
                if (!process.WaitForExit(5000))
                {
                    process.Kill();
                    throw new TimeoutException("resolvectl timed out.");
                }
                if (process.ExitCode != 0) throw new IOException(process.StandardError.ReadToEnd().Trim());
            }
            catch (Exception ex) { log(Localization.T("GenericError", "resolvectl flush-caches: " + ex.Message)); }
        }
    }
}
