using System.IO;
using Dapapa.Core;

internal static partial class Program
{
    private static void KernelModulesMissing()
    {
        string root = Path.Combine(Path.GetTempPath(), "dapapa-kernel-" + Guid.NewGuid().ToString("N"));
        try
        {
            string release = Path.Combine(root, "osrelease");
            string modules = Path.Combine(root, "modules");
            Directory.CreateDirectory(modules);
            File.WriteAllText(release, "7.2.7-zen1-1-zen\n");

            Check(!KernelModules.RunningKernelMissing(release, modules), "An empty module directory (container) was reported as an upgrade.");
            Check(!KernelModules.RunningKernelMissing(release, Path.Combine(root, "absent")), "A missing module root was reported as an upgrade.");
            Directory.CreateDirectory(Path.Combine(modules, "7.2.11-zen1-1-zen"));
            Check(KernelModules.RunningKernelMissing(release, modules), "An upgraded kernel without the running kernel's modules was not detected.");
            Directory.CreateDirectory(Path.Combine(modules, "7.2.7-zen1-1-zen"));
            Check(!KernelModules.RunningKernelMissing(release, modules), "Installed modules of the running kernel were reported missing.");
            Check(!KernelModules.RunningKernelMissing(Path.Combine(root, "no-release"), modules), "An unreadable kernel release was reported as an upgrade.");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
