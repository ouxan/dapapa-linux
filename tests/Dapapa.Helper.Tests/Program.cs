using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Dapapa.Core;
using Dapapa.Core.Models;
using Dapapa.Helper.Firewall;

internal static class Program
{
    private static int _passed;

    private static int Main()
    {
        try
        {
            Run("generated nftables rules are valid for every capture-relevant option combination", RulesetSyntax);
            Run("capture rules follow enabled methods and never touch other tables", RulesetScope);
            Run("checksum preparation produces valid packets and targeted corruption", Checksums);
            Run("rewritten flows are read from packets and closed by an exact ss filter", ConnectionClosing);
            Console.WriteLine($"PASS: {_passed} helper test groups.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex);
            return 1;
        }
    }

    private static void Run(string name, Action test)
    {
        test();
        _passed++;
        Console.WriteLine("PASS: " + name);
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private static readonly NftRuleset Rules = new(2701, 0x10000000, 0x20000000, 5300);

    private static void RulesetSyntax()
    {
        bool[] flags = [false, true];
        int checkedSets = 0;
        foreach (bool tcp in flags)
        foreach (bool fake in flags)
        foreach (bool http in flags)
        foreach (bool quic in flags)
        foreach (bool autoTtl in flags)
        foreach (bool udp in flags)
        foreach (bool unknown in flags)
        {
            var options = new DpiOptions
            {
                TcpFragmentation = tcp, FakeWrongChecksum = fake, HttpHostHeaderCase = http, BlockQuic = quic,
                FakeAutoTtl = autoTtl, UdpIpFragmentation = udp, UdpUnknown = unknown,
                UdpStun = true, UdpWireGuard = true, UdpDiscordDiscovery = true
            };
            NftCheck(Rules.Build(options));
            checkedSets++;
        }
        Check(checkedSets == 128, "Not every combination was validated.");
    }

    private static void RulesetScope()
    {
        string standard = Rules.Build(DpiOptions.Standard);
        Check(standard.Contains("tcp dport 443 @ih,0,16 0x1603") && standard.Contains("udp dport 443 queue"), "Standard capture is incomplete.");
        Check(!standard.Contains("capture_in") && !standard.Contains("udp length >="), "Standard captured AutoTTL or UDP method traffic.");
        Check(standard.Contains("meta mark & 0x20000000 == 0x20000000 udp dport 53 dnat to 127.0.0.1:5300"), "DNS redirect missing.");
        Check(standard.IndexOf("meta mark & 0x10000000", StringComparison.Ordinal) < standard.IndexOf("queue num", StringComparison.Ordinal),
            "Injected packets would be captured again.");
        Check(standard.Contains("oifname \"lo\" accept"), "Loopback DNS stubs would be handled twice.");
        string none = Rules.Build(new DpiOptions { TcpFragmentation = false, BlockQuic = false });
        Check(!none.Contains("tcp dport") && !none.Contains("udp dport 443"), "Disabled methods still capture traffic.");
        string quicOnly = Rules.Build(DpiOptions.Standard with { BlockQuic = false, UdpFakeWrongChecksum = true });
        Check(quicOnly.Contains("udp length >= 1208 @ih,0,8 & 0xc0 == 0xc0") && !quicOnly.Contains("0x2112a442"),
            "UDP capture did not follow the selected protocols.");
        Check(Rules.Build(DpiOptions.Standard with { FakeAutoTtl = true }).Contains("chain capture_in"), "AutoTTL did not capture SYN+ACK.");
        foreach (string text in new[] { standard, none, quicOnly })
        {
            var tables = text.Split('\n').Where(line => line.StartsWith("table ") || line.StartsWith("delete table ")).ToArray();
            Check(tables.All(line => line.Contains(" ip dapapa")), "Ruleset references a foreign table.");
            Check(!text.Contains("flush ruleset"), "Ruleset flushes foreign rules.");
        }
    }

    private static void Checksums()
    {
        byte[] udp = new byte[28 + 5];
        udp[0] = 0x45; udp[8] = 64; udp[9] = 17;
        udp[2] = 0; udp[3] = (byte)udp.Length;
        new byte[] { 192, 0, 2, 1, 203, 0, 113, 7 }.CopyTo(udp, 12);
        udp[20] = 0xC3; udp[21] = 0x50; udp[22] = 0x01; udp[23] = 0xBB; udp[25] = 13;
        PacketChecksum.Prepare(udp);
        Check(PacketChecksum.IsValid(udp), "Prepared UDP packet is invalid.");
        byte[] bad = [.. udp];
        PacketChecksum.Prepare(bad, invalidUdpChecksum: true);
        Check(!PacketChecksum.IsValid(bad) && (bad[26] != 0 || bad[27] != 0), "Invalid UDP checksum was zero or valid.");
        byte[] fragment = [.. udp];
        fragment[6] = 0x20;
        fragment[26] = 0x12; fragment[27] = 0x34;
        PacketChecksum.Prepare(fragment);
        Check(fragment[26] == 0x12 && fragment[27] == 0x34 && PacketChecksum.IsValid(fragment), "Fragment UDP checksum was recomputed.");
    }

    private static void ConnectionClosing()
    {
        byte[] tcp = new byte[40];
        tcp[0] = 0x46; tcp[9] = 6; // 24-byte IP header with options
        new byte[] { 192, 0, 2, 1, 162, 159, 128, 233 }.CopyTo(tcp, 12);
        tcp[24] = 0xC3; tcp[25] = 0x50; tcp[26] = 0x01; tcp[27] = 0xBB;
        Check(ProtectedFlow.TryRead(tcp, out var flow) && flow == new ProtectedFlow(true, 50000, 0xA29F80E9, 443),
            "TCP flow was read incorrectly.");
        tcp[9] = 1;
        Check(!ProtectedFlow.TryRead(tcp, out _) && !ProtectedFlow.TryRead(tcp.AsSpan(0, 22), out _), "Non-TCP/UDP packet was read as a flow.");

        var args = ConnectionCloser.BuildArguments(false, [flow with { Tcp = false }, new(false, 1, 0x7F000001, 53)]);
        Check(string.Join(' ', args) == "-K -n -H -u -a ( dst 162.159.128.233:443 and sport = :50000 ) or ( dst 127.0.0.1:53 and sport = :1 )",
            "Unexpected ss arguments: " + string.Join(' ', args));
        args.Remove("-K");
        var info = new ProcessStartInfo("ss") { RedirectStandardError = true, RedirectStandardOutput = true };
        foreach (string argument in args) info.ArgumentList.Add(argument);
        using (var process = Process.Start(info)!)
        {
            string error = process.StandardError.ReadToEnd();
            process.WaitForExit();
            Check(process.ExitCode == 0 && error.Length == 0, "ss rejected the filter: " + error);
        }

        // A real loopback connection: only the recorded one must be closed, if the kernel supports socket destroy.
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var target = new TcpClient();
        target.Connect(IPAddress.Loopback, port);
        using var other = new TcpClient();
        other.Connect(IPAddress.Loopback, port);
        using var accepted1 = listener.AcceptTcpClient();
        using var accepted2 = listener.AcceptTcpClient();
        var local = (IPEndPoint)target.Client.LocalEndPoint!;
        var log = new List<string>();
        int closed = new ConnectionCloser().Close([new ProtectedFlow(true, (ushort)local.Port, 0x7F000001, (ushort)port)], log.Add);
        if (log.Any(line => line.Contains("not supported", StringComparison.OrdinalIgnoreCase)) || closed == 0)
        {
            Console.WriteLine("SKIP: kernel without socket destroy (CONFIG_INET_DIAG_DESTROY): " + string.Join("; ", log));
            return;
        }
        Check(closed == 1, $"Expected one closed socket, got {closed}.");
        Check(!IsOpen(target.Client), "Recorded connection is still open.");
        Check(IsOpen(other.Client), "An unrelated connection was closed.");
    }

    private static bool IsOpen(Socket socket)
    {
        try
        {
            socket.Send([0]);
            return !(socket.Poll(0, SelectMode.SelectRead) && socket.Available == 0);
        }
        catch (SocketException) { return false; }
    }

    private static void NftCheck(string ruleset)
    {
        var info = new ProcessStartInfo("nft", "--check -f -")
        {
            RedirectStandardInput = true, RedirectStandardError = true, RedirectStandardOutput = true, UseShellExecute = false
        };
        using var process = Process.Start(info)!;
        process.StandardInput.Write(ruleset);
        process.StandardInput.Close();
        string error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        Check(process.ExitCode == 0, "nft rejected the ruleset: " + error + "\n" + ruleset);
    }
}
