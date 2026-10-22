using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Dapapa.Core.Ipc;
using Dapapa.Helper;
using Dapapa.Helper.Native;

const string Usage = """
    Usage: dapapa-helper [options]
      --socket PATH          Unix socket path when not socket-activated (default /run/dapapa/helper.sock)
      --socket-group NAME    Group allowed to use the socket (default dapapa)
      --queue NUMBER         Netfilter queue number (default 2701)
      --lease-grace SECONDS  Time to wait for a disconnected client before stopping (default 10)
      --doh-endpoint URL     Test only: use this DoH endpoint for every query
      --trust-ca FILE        Test only: trust this PEM root certificate for DoH
    """;

string socketPath = HelperProtocol.DefaultSocketPath;
string socketGroup = "dapapa";
var config = new HelperConfig();
var leaseGrace = TimeSpan.FromSeconds(10);
for (int i = 0; i < args.Length; i++)
{
    string Value() => i + 1 < args.Length ? args[++i] : throw new ArgumentException($"{args[i]} requires a value.");
    switch (args[i])
    {
        case "--socket": socketPath = Value(); break;
        case "--socket-group": socketGroup = Value(); break;
        case "--queue": config = config with { QueueNumber = ushort.Parse(Value()) }; break;
        case "--lease-grace": leaseGrace = TimeSpan.FromSeconds(double.Parse(Value())); break;
        case "--doh-endpoint": config = config with { DohEndpointOverride = Value() }; break;
        case "--trust-ca": config = config with { ExtraTrustedRoot = X509Certificate2.CreateFromPem(File.ReadAllText(Value())) }; break;
        case "--help": Console.WriteLine(Usage); return 0;
        default: Console.Error.WriteLine(Usage); return 2;
    }
}

if (LibC.geteuid() != 0)
{
    Console.Error.WriteLine("dapapa-helper must run as root (normally through dapapa-helper.service).");
    return 1;
}

await using var engine = new ProtectionEngine(config);
engine.CleanupStaleRules();
using var stop = new CancellationTokenSource();
using var sigterm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, context => { context.Cancel = true; stop.Cancel(); });
using var sigint = PosixSignalRegistration.Create(PosixSignal.SIGINT, context => { context.Cancel = true; stop.Cancel(); });

using var listener = SocketActivation.TryGetListener() ?? CreateListener(socketPath, socketGroup);
Console.WriteLine($"dapapa-helper {typeof(ProtectionEngine).Assembly.GetName().Version?.ToString(3)} ready.");
await new HelperServer(engine, leaseGrace).RunAsync(listener, stop.Token);
await engine.StopAsync();
return 0;

static Socket CreateListener(string path, string group)
{
    Directory.CreateDirectory(Path.GetDirectoryName(path)!);
    if (File.Exists(path)) File.Delete(path);
    var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
    socket.Bind(new UnixDomainSocketEndPoint(path));
    File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.GroupWrite);
    if (SocketActivation.LookupGroup(group) is int gid && SocketActivation.chown(path, 0, gid) != 0)
        throw LibC.LastError("chown(socket)");
    socket.Listen(16);
    return socket;
}

internal static partial class SocketActivation
{
    /// <summary>Returns the first listening socket passed by systemd, if this process was socket-activated.</summary>
    public static Socket? TryGetListener()
    {
        if (Environment.GetEnvironmentVariable("LISTEN_PID") != Environment.ProcessId.ToString() ||
            !int.TryParse(Environment.GetEnvironmentVariable("LISTEN_FDS"), out int count) || count < 1) return null;
        return new Socket(new SafeSocketHandle(3, ownsHandle: true));
    }

    public static int? LookupGroup(string name)
    {
        foreach (string line in File.ReadLines("/etc/group"))
        {
            string[] fields = line.Split(':');
            if (fields.Length >= 3 && fields[0] == name && int.TryParse(fields[2], out int gid)) return gid;
        }
        return null;
    }

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int chown(string path, int owner, int group);
}
