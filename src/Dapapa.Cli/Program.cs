using System.Text.Json;
using Dapapa.Core.Ipc;
using Dapapa.Core.Models;

const string Usage = """
    Usage: dapapactl <command> [options]

    Commands:
      run      Start protection and keep it running until Ctrl+C
               --domain NAME      Target domain (repeatable)
               --domains FILE     File with one domain per line
               --provider NAME    Quad9Ecs (default), Quad9, Cloudflare, Google, AdGuard
               --options FILE     Custom DPI options as JSON (default: Standard)
      status   Print the helper status
      refresh  Re-resolve target IPs through Cloudflare (--force clears the cache)
      stop     Stop protection

    Global options:
      --socket PATH   Helper socket (default /run/dapapa/helper.sock)
    """;

if (args.Length == 0 || args[0] is "-h" or "--help")
{
    Console.WriteLine(Usage);
    return 0;
}

string command = args[0];
string? socket = null;
var domains = new List<string>();
DohProvider provider = DohProvider.Quad9Ecs;
DpiOptions options = DpiOptions.Standard;
bool force = false;
for (int i = 1; i < args.Length; i++)
{
    string Value() => i + 1 < args.Length ? args[++i] : throw new ArgumentException($"{args[i]} requires a value.");
    switch (args[i])
    {
        case "--socket": socket = Value(); break;
        case "--domain": domains.Add(Value()); break;
        case "--domains": domains.AddRange(File.ReadLines(Value()).Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith('#'))); break;
        case "--provider": provider = Enum.Parse<DohProvider>(Value(), ignoreCase: true); break;
        case "--options":
            options = JsonSerializer.Deserialize<DpiOptions>(File.ReadAllText(Value()), HelperProtocol.JsonOptions) ?? DpiOptions.Standard;
            break;
        case "--force": force = true; break;
        default:
            Console.Error.WriteLine(Usage);
            return 2;
    }
}

try
{
    await using var client = await HelperClient.ConnectAsync(socket);
    switch (command)
    {
        case "status":
            PrintStatus((await client.SendAsync(new HelperRequest(0, HelperCommand.Status))).Status);
            return 0;
        case "stop":
            await client.SendAsync(new HelperRequest(0, HelperCommand.Stop));
            Console.WriteLine("Protection stopped.");
            return 0;
        case "refresh":
            var refresh = (await client.SendAsync(new HelperRequest(0, HelperCommand.Refresh) { Force = force })).Refresh;
            foreach (var (domain, count) in refresh?.Domains ?? new Dictionary<string, int>())
                Console.WriteLine($"{domain,-50} {(count > 0 ? count + " IPv4" : "unresolved")}");
            return 0;
        case "run":
            if (domains.Count == 0) throw new ArgumentException("run requires at least one --domain or --domains file.");
            using (var stop = new CancellationTokenSource())
            {
                Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Cancel(); };
                using var sigterm = System.Runtime.InteropServices.PosixSignalRegistration.Create(
                    System.Runtime.InteropServices.PosixSignal.SIGTERM, context => { context.Cancel = true; stop.Cancel(); });
                client.EventReceived += e =>
                {
                    if (e.Kind == HelperEventKind.Log) Console.WriteLine(e.Text);
                    else if (e.Status is { State: ProtectionState.Failed } failed) Console.Error.WriteLine("Failed: " + failed.Error);
                };
                client.Disconnected += _ => stop.Cancel();
                var started = await client.SendAsync(new HelperRequest(0, HelperCommand.Start)
                    { Domains = domains, Options = options, Provider = provider });
                PrintStatus(started.Status);
                Console.WriteLine("Protection is running. Press Ctrl+C to stop.");
                try { await Task.Delay(Timeout.Infinite, stop.Token); } catch (OperationCanceledException) { }
                try { await client.SendAsync(new HelperRequest(0, HelperCommand.Stop)); } catch (IOException) { }
                Console.WriteLine("Protection stopped.");
            }
            return 0;
        default:
            Console.Error.WriteLine(Usage);
            return 2;
    }
}
catch (Exception ex) when (ex is HelperException or IOException or System.Net.Sockets.SocketException or ArgumentException)
{
    Console.Error.WriteLine("dapapactl: " + ex.Message);
    return 1;
}

static void PrintStatus(HelperStatus? status)
{
    if (status == null) return;
    Console.WriteLine($"State:           {status.State}{(status.Error != null ? " (" + status.Error + ")" : "")}");
    Console.WriteLine($"Target domains:  {status.ActiveDomains}");
    Console.WriteLine($"DNS provider:    {status.Provider}");
    Console.WriteLine($"Bypassed:        {status.BypassedPackets} packets");
    Console.WriteLine($"DNS replies:     {status.DnsReplies}");
    if (status.LastTarget != null) Console.WriteLine($"Last target:     {status.LastTarget} at {status.LastBypassed:HH:mm:ss}");
    Console.WriteLine($"Helper version:  {status.HelperVersion}");
}
