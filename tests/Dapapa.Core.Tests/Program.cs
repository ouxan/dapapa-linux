using System.Buffers.Binary;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Dapapa.Core.Models;
using Dapapa.Core;

internal static partial class Program
{
    private const string UploadDomain = "discord-attachments-uploads-prd.storage.googleapis.com";
    private static int _passed;

    private static async Task<int> Main(string[] args)
    {
        try
        {
            if (args.Contains("--probe-providers")) return await ProbeProviders();
            Run("selected DNS queries and transaction matching", DnsRouting);
            Run("unmatched DNS replies remain unchanged", UnmatchedDns);
            Run("DNS compression and answer-derived QUIC targets", LearnedTargets);
            Run("selected QUIC targets and live target changes", QuicTargets);
            Run("SNI selection and incomplete TLS pass-through", TlsSelection);
            Run("segmented ClientHello with complete SNI", SegmentedClientHello);
            Run("TCP split, sequence wrap and native checksums", TcpFragments);
            Run("malformed packet boundaries and parser fuzz", ParserBoundaries);
            Run("legacy settings migrate once with a complete backup", LegacySettings);
            await ManualTargetTestGroups();
            await DomainGroupTestGroups();
            Run("localized protection and statistics labels", LocalizedLabels);
            await LocalizationTestGroups();
            DpiTestGroups();
            await RunAsync("DNS TTL expires and does not cache stale errors", DnsCache);
            await RunAsync("DNS cancellation propagates", DnsCancellation);
            await DnsTestGroups();
            await RunAsync("selected DoH latency, uncached requests, failures and cancellation", DohLatency);
            await AuditRegressionTests();
            Run("a kernel upgrade without a reboot is detected from the module directories", KernelModulesMissing);
            if (args.Contains("--live-doh")) await RunAsync("live Cloudflare binary DoH and loopback", () => LiveDoh());
            if (args.Contains("--live-quad9")) await RunAsync("live Quad9 HTTP/2 binary DoH and loopback", () => LiveDoh("https://dns.quad9.net/dns-query"));
            if (args.Contains("--live-quad9-ecs")) await RunAsync("live Quad9 ECS HTTP/2 binary DoH and loopback", () => LiveDoh("https://dns11.quad9.net/dns-query"));
            if (args.Contains("--live-providers"))
                foreach (var provider in DohProviders.All)
                    await RunAsync("live provider binary DoH and loopback: " + provider, () => LiveDoh(DohProviders.GetEndpoint(provider)));
            Console.WriteLine($"PASS: {_passed} test groups.");
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

    private static async Task RunAsync(string name, Func<Task> test)
    {
        await test();
        _passed++;
        Console.WriteLine("PASS: " + name);
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private static bool Prepared(byte[] packet)
    {
        PacketChecksum.Prepare(packet);
        return true;
    }


    private static PacketProcessor Processor(params string[] domains)
    {
        var processor = new PacketProcessor();
        processor.UpdateTargets(domains, []);
        return processor;
    }

    private static void DnsRouting()
    {
        var processor = Processor("discord.com", UploadDomain);
        byte[] unrelated = UdpPacket(DnsQuestion("example.com", 1), "192.0.2.1", "1.1.1.1", 52000, 53);
        byte[] original = [.. unrelated];
        Check(processor.Process(unrelated, true).Action == PacketAction.Pass && unrelated.SequenceEqual(original), "Unselected DNS modified.");
        foreach (var pair in new[] { (Id: (ushort)11, Server: "1.1.1.1"), (Id: (ushort)12, Server: "8.8.8.8") })
        {
            byte[] dns = DnsQuestion(UploadDomain, pair.Id);
            byte[] query = UdpPacket(dns, "192.0.2.1", pair.Server, 52000, 53);
            original = [.. query];
            Check(processor.Process(query, true).Action == PacketAction.DnsQuery && query.SequenceEqual(original), "Captured query was modified.");
            byte[] reply = PacketProcessor.BuildDnsReply(query, Answer(dns));
            Check(new IPAddress(reply.AsSpan(12, 4)).ToString() == pair.Server && Read16(reply, 20) == 53, "Wrong original DNS server.");
            Check(new IPAddress(reply.AsSpan(16, 4)).ToString() == "192.0.2.1" && Read16(reply, 22) == 52000 && Read16(reply, 28) == pair.Id, "Wrong client endpoint or ID.");
            Check(Prepared(reply), "DNS checksum helper failed.");
            Check(Sum(reply.AsSpan(0, 20)) == 0xFFFF, "Invalid DNS IPv4 checksum.");
            var pseudo = new List<byte>(reply.AsSpan(12, 8).ToArray()) { 0, 17, (byte)((reply.Length - 20) >> 8), (byte)(reply.Length - 20) };
            pseudo.AddRange(reply.AsSpan(20).ToArray());
            Check(Sum([.. pseudo]) == 0xFFFF, "Invalid DNS UDP checksum.");
            var wrong = Answer(dns); wrong[1]++;
            try { PacketProcessor.BuildDnsReply(query, wrong); throw new Exception("Wrong transaction accepted."); }
            catch (ArgumentException) { }
        }
        byte[] spoof = UdpPacket(DnsQuestion("notdiscord.com", 13), "192.0.2.1", "1.1.1.1", 52000, 53);
        Check(processor.Process(spoof, true).Action == PacketAction.Pass, "Domain suffix boundary ignored.");
        byte[] sub = UdpPacket(DnsQuestion("api.discord.com", 14), "192.0.2.1", "1.1.1.1", 52000, 53);
        Check(processor.Process(sub, true).Action == PacketAction.DnsQuery, "Selected subdomain not matched.");
    }

    private static void UnmatchedDns()
    {
        var processor = Processor(UploadDomain);
        byte[] reply = UdpPacket(Answer(DnsQuestion(UploadDomain, 99)), "1.1.1.1", "192.0.2.1", 53, 52000);
        byte[] original = [.. reply];
        Check(processor.Process(reply, false).Action == PacketAction.Pass && reply.SequenceEqual(original), "Inbound DNS rewritten.");
    }

    private static void LearnedTargets()
    {
        var processor = Processor(UploadDomain);
        byte[] dns = DnsQuestion(UploadDomain, 42);
        byte[] query = UdpPacket(dns, "192.0.2.1", "1.1.1.1", 52000, 53);
        var decision = processor.Process(query, true);
        processor.LearnDnsResponse(dns, Answer(dns), decision.TargetVersion);
        byte[] quic = UdpPacket([1, 2, 3], "192.0.2.1", "203.0.113.20", 52000, 443);
        Check(processor.Process(quic, true).Action == PacketAction.Drop, "DNS-derived target not blocked for QUIC fallback.");
        processor.UpdateTargets([], []);
        Check(processor.Process(quic, true).Action == PacketAction.Pass, "Deselected target remains active.");
        processor.UpdateTargets([UploadDomain], []);
        decision = processor.Process(query, true);
        processor.UpdateTargets([], []);
        processor.UpdateTargets([UploadDomain], []);
        processor.LearnDnsResponse(dns, Answer(dns), decision.TargetVersion);
        Check(processor.Process(quic, true).Action == PacketAction.Pass, "Old target version reactivated a target.");
    }
    private static void QuicTargets()
    {
        var processor = Processor(UploadDomain);
        byte[] quic = UdpPacket([1, 2, 3], "192.0.2.1", "203.0.113.20", 52000, 443);
        byte[] original = [.. quic];
        Check(processor.Process(quic, true).Action == PacketAction.Pass && quic.SequenceEqual(original), "Unselected QUIC modified.");
        processor.UpdateTargets([UploadDomain], ["203.0.113.20/32"]);
        Check(processor.Process(quic, true).Action == PacketAction.Drop, "Resolved QUIC target ignored.");
        Check(processor.Process(quic, false).Action == PacketAction.Pass, "Inbound QUIC dropped.");
        processor.UpdateTargets([], ["203.0.113.20/33", "203.0.113.20/-1", "::1/128"]);
        Check(processor.Process(quic, true).Action == PacketAction.Pass, "Invalid CIDR broadened the filter.");
    }

    private static void TlsSelection()
    {
        var processor = Processor(UploadDomain);
        byte[] hello = ClientHello(UploadDomain);
        Check(PacketProcessor.TryReadSni(hello, out var host) && host == UploadDomain, "SNI not parsed.");
        byte[] packet = TcpPacket(hello);
        Check(processor.Process(packet, true).Action == PacketAction.Fragment, "Selected TLS not fragmented.");
        Check(processor.Process(TcpPacket(ClientHello("example.com")), true).Action == PacketAction.Pass, "Unselected TLS fragmented.");
        processor.UpdateTargets([UploadDomain], ["203.0.113.20/32"]);
        Check(processor.Process(TcpPacket(ClientHello("unrelated.example")), true).Action == PacketAction.Pass, "Shared IP fragmented an unselected hostname.");
        Check(processor.Process(TcpPacket(hello[..^1]), true).Action == PacketAction.Pass, "Incomplete TLS modified through CIDR fallback.");
        for (int length = 0; length < hello.Length; length++)
            Check(!PacketProcessor.TryReadSni(hello.AsSpan(0, length), out _), "Truncated ClientHello accepted.");
    }

    private static void SegmentedClientHello()
    {
        byte[] small = ClientHello(UploadDomain);
        byte[] large = new byte[small.Length + 2052];
        small.CopyTo(large, 0);
        Write16(large, small.Length, 21); // TLS padding extension.
        Write16(large, small.Length + 2, 2048);
        Write16(large, 3, (ushort)(large.Length - 5));
        int handshakeLength = large.Length - 9;
        large[6] = (byte)(handshakeLength >> 16);
        large[7] = (byte)(handshakeLength >> 8);
        large[8] = (byte)handshakeLength;
        Write16(large, 50, (ushort)(Read16(small, 50) + 2052));
        Check(PacketProcessor.TryReadSni(large, out var host) && host == UploadDomain, "Large ClientHello not parsed.");
        byte[] firstSegment = large[..1200];
        Check(PacketProcessor.TryReadSni(firstSegment, out host) && host == UploadDomain, "Complete SNI in first TCP segment ignored.");
        var processor = Processor(UploadDomain);
        byte[] packet = TcpPacket(firstSegment);
        Check(processor.Process(packet, true).Action == PacketAction.Fragment, "Segmented selected ClientHello bypass skipped.");
        var (head, tail) = PacketProcessor.SplitTcpPacket(packet);
        Check(head.AsSpan(40).ToArray().Concat(tail.AsSpan(40).ToArray()).SequenceEqual(firstSegment), "Segmented ClientHello corrupted by splitting.");
        var unrelated = Processor("example.com");
        byte[] original = [.. packet];
        Check(unrelated.Process(packet, true).Action == PacketAction.Pass && packet.SequenceEqual(original), "Unselected segmented ClientHello modified.");
        Check(processor.Process(TcpPacket(large[..(small.Length - 1)]), true).Action == PacketAction.Pass, "Truncated SNI modified.");
        Write16(firstSegment, 3, 20);
        Check(!PacketProcessor.TryReadSni(firstSegment, out _), "Invalid TLS record boundary accepted.");
    }

    private static void TcpFragments()
    {
        byte[] original = TcpPacket(ClientHello(UploadDomain));
        Write32(original, 24, uint.MaxValue - 1);
        original[33] = 0x19;
        var (head, tail) = PacketProcessor.SplitTcpPacket(original);
        Check(Read16(head, 2) == head.Length && Read16(tail, 2) == tail.Length, "Wrong IP length after split.");
        Check(Read32(tail, 24) == 0 && Read32(head, 24) == uint.MaxValue - 1, "TCP sequence wrap is wrong.");
        Check(head[33] == 0x10 && tail[33] == 0x19, "TCP flags lost or duplicated.");
        Check(head.AsSpan(40).ToArray().Concat(tail.AsSpan(40).ToArray()).SequenceEqual(original.AsSpan(40).ToArray()), "Fragment reassembly corrupted data.");
        foreach (byte[] fragment in new[] { head, tail })
        {
            Check(Prepared(fragment), "Native checksum helper failed.");
            Check(Sum(fragment.AsSpan(0, 20)) == 0xFFFF, "Invalid IPv4 checksum.");
            var pseudo = new List<byte>(fragment.AsSpan(12, 8).ToArray()) { 0, 6, (byte)((fragment.Length - 20) >> 8), (byte)(fragment.Length - 20) };
            pseudo.AddRange(fragment.AsSpan(20).ToArray());
            Check(Sum([.. pseudo]) == 0xFFFF, "Invalid TCP checksum.");
        }
    }



    private static void ParserBoundaries()
    {
        var processor = Processor(UploadDomain);
        var random = new Random(17);
        byte[][] seeds = [TcpPacket(ClientHello(UploadDomain)), UdpPacket(DnsQuestion(UploadDomain, 42), "192.0.2.1", "1.1.1.1", 52000, 53)];
        foreach (byte[] seed in seeds)
        {
            for (int length = 0; length < seed.Length; length++)
            {
                byte[] packet = seed[..length];
                if (length >= 4) Write16(packet, 2, (ushort)length);
                processor.Process(packet, true);
            }
            for (int i = 0; i < 2000; i++)
            {
                byte[] packet = [.. seed];
                packet[random.Next(packet.Length)] = (byte)random.Next(256);
                processor.Process(packet, (i & 1) != 0);
            }
        }
        byte[] fragmented = [.. seeds[0]];
        fragmented[6] = 0x20;
        Check(processor.Process(fragmented, true).Action == PacketAction.Pass, "IP fragment was parsed as a complete packet.");
        byte[] loop = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 12, 0, 1, 0, 1];
        Check(!PacketProcessor.TryReadDnsQuestion(loop, out _, out _), "DNS compression loop accepted.");
    }



    private static void LegacySettings()
    {
        string directory = Path.Combine(Path.GetTempPath(), "dapapa-migration-" + Guid.NewGuid());
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "settings.json");
        const string json = """
            {"Apps":[{"Id":"discord","Name":"Discord","Enabled":true,"Domain":"discord.com","Cidrs":["162.159.130.233/32"]},{"Id":"custom_saved","Name":"Saved","Domain":"saved.example","Category":"Özel","Enabled":true}],"ArchivedApps":[{"Id":"old","Domain":"old.example"}],"ExtraCidrs":["192.0.2.0/24"],"RunOnLogin":true,"AutoConnectOnLaunch":true,"StartMinimizedToTray":true,"MinimizeToTrayOnClose":false,"Language":"tr","EnableWinDivertAntiCensorship":false}
            """;
        try
        {
            File.WriteAllText(path, json);
            var service = new SettingsService(path);
            var settings = service.Load();
            string backup = Directory.GetFiles(directory, "*.bak").Single();
            Check(File.ReadAllText(backup) == json, "Original settings backup changed.");
            Check(settings.TargetListVersion == 1 && settings.Apps.Count == 0 && settings.GetEffectiveDomains().Count == 0, "Legacy targets survived migration.");
            Check(settings.RunOnLogin && settings.AutoConnectOnLaunch && settings.StartMinimizedToTray &&
                !settings.MinimizeToTrayOnClose && settings.Language == "tr", "Preferences were reset.");
            string saved = File.ReadAllText(path);
            Check(!saved.Contains("ArchivedApps") && !saved.Contains("Cidrs") && !saved.Contains("Category") &&
                !saved.Contains("EnableWinDivertAntiCensorship"), "Retired settings are still serialized.");
            Check(service.Load().Apps.Count == 0 && Directory.GetFiles(directory, "*.bak").Length == 1, "Empty settings were reinitialized or remigrated.");
            settings.Apps.Add(new ProtectedApp { Name = "Discord", Domain = "discord.com" });
            service.Save(settings);
            Check(service.Load().GetEffectiveDomains().SequenceEqual(["discord.com"]), "Hidden service domains were added.");
        }
        finally { Directory.Delete(directory, true); }
    }

    private static void LocalizedLabels()
    {
        foreach (AppLanguage language in Enum.GetValues<AppLanguage>())
        {
            Localization.Current = language;
            foreach (string key in new[] { "DnsResolveFailed", "LocalDnsStarted", "LocalDnsFailed", "ProtectionStartFailed", "EngineWorkerFailed", "SyncPartialFailure", "SyncIncompleteHeading", "SyncDnsCacheStatus", "SyncTargetsAppliedLive", "SyncTargetsCached", "AdapterLabel" })
                Check(Localization.T(key) != key, "Missing localization: " + key);
            Check(Localization.T("PingToDoh", "dns11.quad9.net").Contains("dns11.quad9.net") &&
                Localization.T("DohProbeFailed") != "DohProbeFailed", "DNS latency target or failure label missing.");
            Check(Localization.T("StatsDescription").Contains(language == AppLanguage.English ? "other apps" : "diğer uygulamalar"), "Statistics scope hidden.");
        }
    }

    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now = DateTimeOffset.Parse("2026-10-11T12:00:00Z");
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class Handler(Func<int, HttpResponseMessage> response) : HttpMessageHandler
    {
        public int Requests;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(response(++Requests));
    }

    private sealed class PendingHandler : HttpMessageHandler
    {
        public readonly TaskCompletionSource<HttpResponseMessage> Response = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _requests;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => ++_requests == 1 ? Response.Task.WaitAsync(cancellationToken)
                : Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
    }


    private static HttpResponseMessage DnsResponse(string address, int ttl) => WireResponse(Answer(DnsQuestion(UploadDomain, 0), address, (uint)ttl));

    private static async Task DnsCache()
    {
        var clock = new Clock();
        var handler = new Handler(count => count == 3 ? new(HttpStatusCode.ServiceUnavailable) : DnsResponse($"203.0.113.{count}", 60));
        using var client = new HttpClient(handler);
        var resolver = new DnsResolver(client, clock);
        Check((await resolver.ResolveIpv4AddressesAsync(UploadDomain))[0] == "203.0.113.1", "Initial DNS result wrong.");
        clock.Now = clock.Now.AddSeconds(59);
        Check((await resolver.ResolveIpv4AddressesAsync(UploadDomain))[0] == "203.0.113.1" && handler.Requests == 1, "TTL cache expired early.");
        clock.Now = clock.Now.AddSeconds(1);
        Check((await resolver.ResolveIpv4AddressesAsync(UploadDomain))[0] == "203.0.113.2" && handler.Requests == 2, "Expired TTL reused stale address.");
        clock.Now = clock.Now.AddSeconds(60);
        Check((await resolver.ResolveIpv4AddressesAsync(UploadDomain)).Count == 0, "DNS error returned expired address.");
        clock.Now = clock.Now.AddSeconds(30);
        Check((await resolver.ResolveIpv4AddressesAsync(UploadDomain))[0] == "203.0.113.4", "DNS error was never retried.");
        Check(resolver.GetNextRefreshUtc([UploadDomain]) == clock.Now.AddSeconds(60), "Wrong next refresh deadline.");
        resolver.ClearCache();
        await resolver.ResolveIpv4AddressesAsync(UploadDomain);
        Check(handler.Requests == 5, "Explicit refresh did not clear cache.");
    }

    private static async Task DnsCancellation()
    {
        using var client = new HttpClient(new Handler(_ => DnsResponse("203.0.113.1", 60)));
        var resolver = new DnsResolver(client);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        try { await resolver.ResolveIpv4AddressesAsync(UploadDomain, cancellation.Token); }
        catch (OperationCanceledException) { return; }
        throw new InvalidOperationException("DNS cancellation was swallowed.");
    }

    private static byte[] DnsQuestion(string domain, ushort id)
    {
        var dns = new List<byte>(new byte[] { (byte)(id >> 8), (byte)id, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 });
        foreach (string label in domain.Split('.')) { dns.Add((byte)label.Length); dns.AddRange(Encoding.ASCII.GetBytes(label)); }
        dns.AddRange(new byte[] { 0, 0, 1, 0, 1 });
        return [.. dns];
    }

    private static byte[] UdpPacket(byte[] payload, string source, string destination, ushort sourcePort, ushort destinationPort)
    {
        byte[] packet = new byte[28 + payload.Length];
        packet[0] = 0x45; packet[8] = 64; packet[9] = 17;
        Write16(packet, 2, (ushort)packet.Length);
        IPAddress.Parse(source).GetAddressBytes().CopyTo(packet, 12);
        IPAddress.Parse(destination).GetAddressBytes().CopyTo(packet, 16);
        Write16(packet, 20, sourcePort); Write16(packet, 22, destinationPort);
        Write16(packet, 24, (ushort)(packet.Length - 20));
        payload.CopyTo(packet, 28);
        return packet;
    }

    private static byte[] TcpPacket(byte[] payload)
    {
        byte[] packet = new byte[40 + payload.Length];
        packet[0] = 0x45; packet[8] = 64; packet[9] = 6; packet[32] = 0x50; packet[33] = 0x18;
        Write16(packet, 2, (ushort)packet.Length);
        IPAddress.Parse("192.0.2.1").GetAddressBytes().CopyTo(packet, 12);
        IPAddress.Parse("203.0.113.20").GetAddressBytes().CopyTo(packet, 16);
        Write16(packet, 20, 52000); Write16(packet, 22, 443);
        payload.CopyTo(packet, 40);
        return packet;
    }

    private static byte[] ClientHello(string host)
    {
        byte[] name = Encoding.ASCII.GetBytes(host);
        var body = new List<byte> { 3, 3 };
        body.AddRange(new byte[32]);
        body.AddRange(new byte[] { 0, 0, 2, 0x13, 1, 1, 0, 0, (byte)(name.Length + 9), 0, 0, 0,
            (byte)(name.Length + 5), 0, (byte)(name.Length + 3), 0, 0, (byte)name.Length });
        body.AddRange(name);
        var record = new List<byte> { 0x16, 3, 1, 0, (byte)(body.Count + 4), 1, 0, 0, (byte)body.Count };
        record.AddRange(body);
        return [.. record];
    }

    private static uint Sum(ReadOnlySpan<byte> bytes)
    {
        uint sum = 0;
        for (int i = 0; i < bytes.Length; i += 2) sum += (uint)(bytes[i] << 8) + (uint)(i + 1 < bytes.Length ? bytes[i + 1] : 0);
        while (sum >> 16 != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return sum;
    }

    private static ushort Read16(ReadOnlySpan<byte> bytes, int offset) => BinaryPrimitives.ReadUInt16BigEndian(bytes[offset..]);
    private static uint Read32(ReadOnlySpan<byte> bytes, int offset) => BinaryPrimitives.ReadUInt32BigEndian(bytes[offset..]);
    private static void Write16(Span<byte> bytes, int offset, ushort value) => BinaryPrimitives.WriteUInt16BigEndian(bytes[offset..], value);
    private static void Write32(Span<byte> bytes, int offset, uint value) => BinaryPrimitives.WriteUInt32BigEndian(bytes[offset..], value);
}
