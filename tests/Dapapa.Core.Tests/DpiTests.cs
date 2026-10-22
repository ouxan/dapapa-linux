using System.IO;
using System.Text;
using System.Text.Json;
using Dapapa.Core.Models;
using Dapapa.Core;

internal static partial class Program
{
    private static void DpiTestGroups()
    {
        Run("old settings retain Standard behavior and Custom choices persist", DpiSettings);
        Run("Standard injection order and payload match the previous TCP strategy", StandardDpi);
        Run("hostname splitting, forward order, sequence wrap and TCP options", CustomTcp);
        Run("HTTP methods preserve length, body and authority semantics", HttpMethods);
        Run("fake packets have invalid TCP checksums while real packets remain valid", FakeChecksums);
        Run("all 256 method combinations retain target isolation, DNS and QUIC scope", DpiCombinations);
        Run("live DPI changes retain targets and in-flight packet snapshots", LiveDpiOptions);
        Run("malformed HTTP, unsupported flags and truncated TLS pass unchanged", DpiBoundaries);
        AdvancedDpiTests();
        UdpDpiTests();
    }

    private static byte[] HttpPacket(string host = "example.com", string extraHeaders = "", string body = "")
    {
        byte[] packet = TcpPacket(Encoding.ASCII.GetBytes("POST /path HTTP/1.1\r\nHost: " + host +
            "\r\nContent-Length: " + Encoding.ASCII.GetByteCount(body) + "\r\n" + extraHeaders + "\r\n" + body));
        Write16(packet, 22, 80);
        return packet;
    }

    private static PacketProcessor DpiProcessor(DpiOptions options)
    {
        var processor = Processor("example.com");
        processor.UpdateTargets(["example.com"], ["203.0.113.20/32"]);
        processor.UpdateOptions(options);
        return processor;
    }

    private static byte[] ReassembleReal(byte[] original, IReadOnlyList<PacketInjection> injections)
    {
        Check(PacketProcessor.TryReadHeaders(original, out int ipLength, out _), "Bad test original.");
        uint sequence = Read32(original, ipLength + 4);
        return injections.Where(i => !i.IsFake && !i.InvalidTcpChecksum).OrderBy(i => unchecked(Read32(i.Packet, ipLength + 4) - sequence))
            .SelectMany(i => {
                Check(PacketProcessor.TryReadHeaders(i.Packet, out int ip, out int tcp), "Bad generated packet.");
                return i.Packet[(ip + tcp)..];
            }).ToArray();
    }

    private static void VerifyDpiChecksums(IReadOnlyList<PacketInjection> injections)
    {
        foreach (var injection in injections)
        {
            byte[] packet = injection.Packet.ToArray();
            PacketChecksum.Prepare(packet, injection.InvalidTcpChecksum);
            Check(PacketProcessor.TryReadHeaders(packet, out int ip, out _), "Generated packet headers invalid.");
            Check(Sum(packet.AsSpan(0, ip)) == 0xFFFF, "DPI IPv4 checksum invalid.");
            var pseudo = new List<byte>(packet.AsSpan(12, 8).ToArray()) { 0, 6, (byte)((packet.Length - ip) >> 8), (byte)(packet.Length - ip) };
            pseudo.AddRange(packet.AsSpan(ip).ToArray());
            Check((Sum([.. pseudo]) != 0xFFFF) == injection.InvalidTcpChecksum, "Only fake packets may have invalid TCP checksums.");
        }
    }

    private static void DpiSettings()
    {
        string directory = Path.Combine(Path.GetTempPath(), "dapapa-dpi-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            string path = Path.Combine(directory, "settings.json");
            File.WriteAllText(path, "{\"TargetListVersion\":1,\"Language\":\"tr\",\"AutoConnectOnLaunch\":true,\"EnableTcpFragmentation\":false," +
                "\"Apps\":[{\"Name\":\"Mine\",\"Domain\":\"example.com\",\"Enabled\":false,\"RelatedDomains\":[\"other.net\"]}]}");
            var store = new SettingsService(path);
            var settings = store.Load();
            Check(settings.DpiMode == DpiMode.Standard && settings.GetDpiOptions() == DpiOptions.Standard, "Legacy switch changed Standard behavior.");
            Check(settings.Apps.Count == 1 && !settings.Apps[0].Enabled && settings.Apps[0].RelatedDomains.SequenceEqual(["other.net"]) &&
                settings.Language == "tr" && settings.AutoConnectOnLaunch, "DPI migration changed existing settings.");
            settings.DpiMode = DpiMode.Custom;
            settings.CustomDpi = new DpiOptions { TcpFragmentation = false, ReverseSegments = false, SplitAtHostname = true,
                FakeWrongChecksum = true, HttpHostHeaderCase = true, HttpHostDomainCase = true, HttpHostRemoveSpace = true, BlockQuic = false };
            store.Save(settings);
            var loaded = store.Load();
            Check(loaded.DpiMode == DpiMode.Custom && loaded.GetDpiOptions() == settings.CustomDpi, "Custom methods did not round-trip.");
            loaded.DpiMode = DpiMode.Standard; store.Save(loaded); loaded = store.Load();
            Check(loaded.GetDpiOptions() == DpiOptions.Standard && loaded.CustomDpi == settings.CustomDpi, "Standard selection lost Custom choices.");
            Check(!Directory.EnumerateFiles(directory, "*.bak").Any(), "DPI options caused target-list migration.");
            var invalid = JsonSerializer.Deserialize<AppSettings>("{\"DpiMode\":42,\"CustomDpi\":null}")!;
            invalid.NormalizeTargets();
            Check(invalid.DpiMode == DpiMode.Standard && invalid.GetDpiOptions() == DpiOptions.Standard && invalid.CustomDpi != null, "Invalid profile not normalized.");
        }
        finally { Directory.Delete(directory, true); }
    }

    private static void StandardDpi()
    {
        var processor = DpiProcessor(DpiOptions.Standard);
        foreach (byte[] packet in new[] { TcpPacket(ClientHello("example.com")), HttpPacket() })
        {
            var decision = processor.Process(packet, true);
            var injections = PacketProcessor.BuildInjections(packet, decision);
            var (head, tail) = PacketProcessor.SplitTcpPacket(packet);
            Check(decision.Action == PacketAction.Fragment && injections.Count == 2 &&
                injections[0].Packet.SequenceEqual(tail) && injections[1].Packet.SequenceEqual(head) &&
                injections.All(i => !i.InvalidTcpChecksum), "Standard changed the previous reversed 2-byte split.");
            Check(ReassembleReal(packet, injections).SequenceEqual(packet[40..]), "Standard changed stream bytes.");
            VerifyDpiChecksums(injections);
        }
    }

    private static void CustomTcp()
    {
        var options = DpiOptions.Standard with { SplitAtHostname = true, ReverseSegments = false };
        var processor = DpiProcessor(options);
        foreach (byte[] source in new[] { TcpPacket(ClientHello("api.example.com")), HttpPacket("api.example.com:8080") })
        {
            // Preserve both IPv4 and TCP options while wrapping the sequence number.
            byte[] packet = new byte[source.Length + 16];
            source.AsSpan(0, 20).CopyTo(packet); packet[0] = 0x46;
            source.AsSpan(20, 20).CopyTo(packet.AsSpan(24)); packet[36] = 0x80;
            source.AsSpan(40).CopyTo(packet.AsSpan(56)); Write16(packet, 2, (ushort)packet.Length);
            Write32(packet, 28, uint.MaxValue - 3);
            var decision = processor.Process(packet, true);
            int host = Encoding.ASCII.GetString(packet[56..]).IndexOf("api.example.com", StringComparison.Ordinal);
            Check(decision.SplitPosition == host + "api.example.com".Length / 2, "Split did not land inside hostname.");
            var injections = PacketProcessor.BuildInjections(packet, decision);
            Check(injections.Count == 2 && Read32(injections[0].Packet, 28) == uint.MaxValue - 3 &&
                Read32(injections[1].Packet, 28) == unchecked(uint.MaxValue - 3 + (uint)decision.SplitPosition), "Forward order or sequence wrap incorrect.");
            Check(ReassembleReal(packet, injections).SequenceEqual(packet[56..]), "Options or hostname split changed data.");
            VerifyDpiChecksums(injections);
        }
    }

    private static void HttpMethods()
    {
        byte[] packet = HttpPacket("example.com:8080", "X-Test: untouched\r\n", "Host: body.example\r\nbody");
        var options = DpiOptions.Standard with { TcpFragmentation = false, BlockQuic = false };
        foreach (var method in new[] { options with { HttpHostHeaderCase = true }, options with { HttpHostDomainCase = true },
            options with { HttpHostRemoveSpace = true }, options with { HttpHostHeaderCase = true, HttpHostDomainCase = true, HttpHostRemoveSpace = true } })
        {
            var processor = DpiProcessor(method);
            var decision = processor.Process(packet, true);
            Check(decision.Action == PacketAction.Modify, "HTTP method ignored with TCP segmentation off.");
            var injections = PacketProcessor.BuildInjections(packet, decision);
            byte[] changed = injections.Single().Packet;
            string text = Encoding.ASCII.GetString(changed[40..]);
            string name = method.HttpHostHeaderCase ? "hOsT" : "Host";
            string host = method.HttpHostDomainCase ? "ExAmPlE.CoM" : "example.com";
            Check(text.Contains(name + ":" + (method.HttpHostRemoveSpace ? "" : " ") + host + ":8080" +
                (method.HttpHostRemoveSpace ? " " : "") + "\r\n"), "HTTP authority or whitespace incorrect.");
            Check(changed.Length == packet.Length && changed.AsSpan(20, 20).SequenceEqual(packet.AsSpan(20, 20)) &&
                text.EndsWith("Host: body.example\r\nbody") && text.Contains("X-Test: untouched\r\n"), "HTTP method changed length, sequence, body or another header.");
            Check(processor.Process(TcpPacket(ClientHello("example.com")), true).Action == PacketAction.Pass, "HTTP-only method changed HTTPS.");
            VerifyDpiChecksums(injections);
        }
        var whitespaceProcessor = DpiProcessor(options with { HttpHostRemoveSpace = true });
        byte[] spaced = HttpPacket(" \texample.com:8080\t ");
        var spacedInjections = PacketProcessor.BuildInjections(spaced, whitespaceProcessor.Process(spaced, true));
        Check(Encoding.ASCII.GetString(spacedInjections[0].Packet[40..]).Contains("Host: \texample.com:8080\t  \r\n"), "Multiple optional whitespace corrupted authority.");
    }

    private static void FakeChecksums()
    {
        var processor = DpiProcessor(DpiOptions.Standard with { FakeWrongChecksum = true });
        foreach (byte[] packet in new[] { TcpPacket(ClientHello("example.com")), HttpPacket() })
        {
            var injections = PacketProcessor.BuildInjections(packet, processor.Process(packet, true));
            Check(injections.Count == 3 && injections[0].InvalidTcpChecksum && injections.Skip(1).All(i => !i.InvalidTcpChecksum), "Fake packet was not first or real packets marked invalid.");
            Check(!Encoding.ASCII.GetString(injections[0].Packet[40..]).Contains("example.com") &&
                ReassembleReal(packet, injections).SequenceEqual(packet[40..]), "Fake hostname not replaced or real stream changed.");
            VerifyDpiChecksums(injections);
        }
    }

    private static void DpiCombinations()
    {
        byte[] tls = TcpPacket(ClientHello("api.example.com"));
        byte[] http = HttpPacket("api.example.com", body: "unchanged body");
        byte[] dns = UdpPacket(DnsQuestion("api.example.com", 23), "192.0.2.1", "1.1.1.1", 52000, 53);
        byte[] quic = UdpPacket([1, 2, 3], "192.0.2.1", "203.0.113.20", 52000, 443);
        for (int bits = 0; bits < 256; bits++)
        {
            bool Bit(int index) => (bits & (1 << index)) != 0;
            var options = new DpiOptions { TcpFragmentation = Bit(0), ReverseSegments = Bit(1), SplitAtHostname = Bit(2),
                HttpHostHeaderCase = Bit(3), HttpHostDomainCase = Bit(4), HttpHostRemoveSpace = Bit(5), FakeWrongChecksum = Bit(6), BlockQuic = Bit(7) };
            var processor = DpiProcessor(options);
            foreach (byte[] packet in new[] { tls, http })
            {
                bool isHttp = packet == http;
                var decision = processor.Process(packet, true);
                PacketAction expected = options.TcpFragmentation ? PacketAction.Fragment :
                    options.FakeWrongChecksum || (isHttp && options.HasHttpMethods) ? PacketAction.Modify : PacketAction.Pass;
                Check(decision.Action == expected, "Method combination decision incorrect: " + bits);
                var injections = PacketProcessor.BuildInjections(packet, decision);
                int expectedCount = (options.TcpFragmentation ? 2 : 1) + (options.FakeWrongChecksum ? 1 : 0);
                Check(injections.Count == expectedCount, "Method combination packet count incorrect: " + bits);
                byte[] rebuilt = ReassembleReal(packet, injections);
                if (!isHttp) Check(rebuilt.SequenceEqual(packet[40..]), "TLS handshake modified: " + bits);
                else Check(rebuilt.Length == packet.Length - 40 && Encoding.ASCII.GetString(rebuilt).EndsWith("unchanged body"), "HTTP stream length/body changed: " + bits);
                VerifyDpiChecksums(injections);
            }
            Check(processor.Process(dns, true).Action == PacketAction.DnsQuery, "DPI choice disabled DNS handling.");
            Check(processor.Process(quic, true).Action == (options.BlockQuic ? PacketAction.Drop : PacketAction.Pass), "QUIC choice ignored.");
            foreach (byte[] unrelated in new[] { TcpPacket(ClientHello("unrelated.example")), HttpPacket("unrelated.example"), HttpPacket("example.com.other.net"),
                UdpPacket([1], "192.0.2.1", "203.0.113.21", 52000, 443) })
            {
                byte[] original = unrelated.ToArray();
                Check(processor.Process(unrelated, true).Action == PacketAction.Pass && unrelated.SequenceEqual(original), "Unselected traffic changed: " + bits);
            }
            Check(processor.Process(tls, false).Action == PacketAction.Pass && processor.Process(http, false).Action == PacketAction.Pass, "Inbound traffic changed.");
        }
    }

    private static void LiveDpiOptions()
    {
        var processor = DpiProcessor(DpiOptions.Standard);
        byte[] packet = TcpPacket(ClientHello("example.com"));
        var inFlight = processor.Process(packet, true);
        var disabled = new DpiOptions { TcpFragmentation = false, BlockQuic = false };
        processor.UpdateOptions(disabled);
        Check(!disabled.HasTrafficMethods && processor.DomainsCount == 1 && processor.Process(packet, true).Action == PacketAction.Pass, "Live options failed or cleared targets.");
        var oldPackets = PacketProcessor.BuildInjections(packet, inFlight);
        Check(oldPackets.Count == 2 && oldPackets[0].Packet.Length > oldPackets[1].Packet.Length, "In-flight strategy mixed with the new profile.");
        byte[] query = UdpPacket(DnsQuestion("example.com", 7), "192.0.2.1", "1.1.1.1", 52000, 53);
        long version = processor.Process(query, true).TargetVersion;
        processor.UpdateOptions(DpiOptions.Standard);
        Check(processor.Process(query, true).TargetVersion == version && processor.Process(packet, true).Action == PacketAction.Fragment, "DPI changes reset DNS target sessions.");
    }

    private static void DpiBoundaries()
    {
        var processor = DpiProcessor(new DpiOptions { SplitAtHostname = true, FakeWrongChecksum = true,
            HttpHostHeaderCase = true, HttpHostDomainCase = true, HttpHostRemoveSpace = true });
        byte[] hello = TcpPacket(ClientHello("example.com"));
        foreach (byte flags in new byte[] { 0x02, 0x04, 0x20, 0x1A, 0x38 })
        {
            byte[] packet = hello.ToArray(); packet[33] = flags;
            Check(processor.Process(packet, true).Action == PacketAction.Pass, "Unsupported TCP flags transformed.");
        }
        foreach (string payload in new[] { "GET / HTTP/1.1\r\nHost: example.com", "GET \r\nHost: example.com\r\n\r\n", "GET / HTTP/2\r\nHost: example.com\r\n\r\n", "GET / HTTP/1.1\r\nHost: example.com\r\nHost: other.net\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: example.com\r\n folded\r\n\r\n", "GET / HTTP/1.1\r\nHost: example.com:bad\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: example.com.other.net\r\n\r\n", "GET / HTTP/1.1\r\nX-Pad: " + new string('x', 8192) + "\r\nHost: example.com\r\n\r\n" })
        {
            byte[] packet = TcpPacket(Encoding.ASCII.GetBytes(payload)); Write16(packet, 22, 80);
            byte[] original = packet.ToArray();
            Check(processor.Process(packet, true).Action == PacketAction.Pass && packet.SequenceEqual(original), "Malformed or unselected HTTP transformed.");
        }
        for (int length = 40; length < hello.Length; length++)
        {
            byte[] shortPacket = hello[..length]; Write16(shortPacket, 2, (ushort)length);
            Check(processor.Process(shortPacket, true).Action == PacketAction.Pass, "Incomplete SNI transformed.");
        }
        Check(PacketProcessor.BuildInjections([1, 2], new(PacketAction.Fragment, Options: DpiOptions.Standard)).Single().Packet.SequenceEqual(new byte[] { 1, 2 }), "Malformed transform input not preserved.");
    }
}
