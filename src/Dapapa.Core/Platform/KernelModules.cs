namespace Dapapa.Core
{
    /// <summary>
    /// Detects a kernel upgrade that has not been followed by a reboot. Arch removes the running kernel's module directory,
    /// so nftables and NFQUEUE modules that were not loaded yet cannot be loaded until the next boot.
    /// </summary>
    public static class KernelModules
    {
        public static bool RunningKernelMissing(string releasePath = "/proc/sys/kernel/osrelease", string modulesRoot = "/usr/lib/modules")
        {
            try
            {
                string release = File.ReadAllText(releasePath).Trim();
                // Containers often have no kernel installed at all; only another installed kernel indicates an upgrade.
                return release.Length > 0 && !Directory.Exists(Path.Combine(modulesRoot, release))
                    && Directory.Exists(modulesRoot) && Directory.EnumerateDirectories(modulesRoot).Any();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
        }
    }
}
