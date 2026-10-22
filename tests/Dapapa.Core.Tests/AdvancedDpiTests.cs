using System.Text;
using System.Text.Json;
using Dapapa.Core.Models;
using Dapapa.Core;

internal static partial class Program
{
    private static void AdvancedDpiTests()
    {
        Run("split markers, protocol-specific offsets and eight-segment reassembly", SplitMarkers);
        Run("badseq, TTL, MD5, timestamps and ACK-free fake packets", AdvancedFakes);
        Run("AutoTTL flow matching, expiry, capacity and target invalidation", AutoTtlFlows);
        Run("fakedsplit/fakeddisorder retain real streams within the injection budget", FakeMix);
        Run("HTTP method-space, method-EOL and host-tab preserve body and stream length", AdvancedHttp);
        Run("advanced settings normalize limits, round-trip and retain Standard defaults", AdvancedDpiSettings);
    }

    private static byte[] TimestampPacket(byte[] original)
    {
        byte[] packet = new byte[original.Length + 12];
        original.AsSpan(0, 40).CopyTo(packet); original.AsSpan(40).CopyTo(packet.AsSpan(52));
        packet[32] = 0x80; packet[40] = 8; packet[41] = 10; packet[50] = packet[51] = 1;
        Write32(packet, 42, 700000); Write32(packet, 46, 9876); Write16(packet, 2, (ushort)packet.Length);
        return packet;
    }

    private static void SplitMarkers()
    {
        Check(TcpSplitPositions.IsValid("2,host,midsld,endhost,-1,method+2,sniext+1"), "Valid markers rejected.");
        foreach (string invalid in new[] { "", "0", "unknown", "host++1", "65536", "1,2,3,4,5,6,7,8", "2,,host" })
            Check(!TcpSplitPositions.IsValid(invalid), "Invalid marker accepted: " + invalid);
        var positions = TcpSplitPositions.Resolve("2,host,midsld,endhost,-1,method+2,sniext+1", 100, 30, "api.example.com", 0);
        Check(positions.SequenceEqual([2, 22, 30, 37, 45, 99]), "Marker offsets or TLS-only markers incorrect.");
        foreach (bool reverse in new[] { false, true })
        {
            var options = DpiOptions.Standard with { MultiSplit = true, SplitPositions = "2,host,midsld,endhost,-1,method+2,sniext+1", ReverseSegments = reverse };
            var processor = DpiProcessor(options);
            foreach (byte[] packet in new[] { TcpPacket(ClientHello("api.example.com")), HttpPacket("api.example.com", body: "body") })
            {
                Write32(packet, 24, uint.MaxValue - 3);
                var decision = processor.Process(packet, true);
                var injections = PacketProcessor.BuildInjections(packet, decision);
                Check(injections.Count is >= 5 and <= 8 && ReassembleReal(packet, injections).SequenceEqual(packet[40..]), "Multi-split changed the real stream.");
                uint first = unchecked(Read32(injections[0].Packet, 24) - Read32(packet, 24));
                Check(reverse ? first > 0 : first == 0, "Multidisorder wire order incorrect.");
                VerifyDpiChecksums(injections);
            }
        }
    }

    private static void AdvancedFakes()
    {
        byte[] packet = TimestampPacket(TcpPacket(ClientHello("example.com")));
        var options = DpiOptions.Standard with { FakeWrongChecksum = true, FakeWrongSequence = true, FakeLowTtl = true,
            FakeTtl = 3, FakeMd5Signature = true, FakeTimestamp = true, FakeDataNoAck = true, FakeRandomizeTls = true, FakeHostname = "google.com", FakeRepeats = 2 };
        var injections = PacketProcessor.BuildInjections(packet, DpiProcessor(options).Process(packet, true));
        var fakes = injections.Where(p => p.IsFake).ToArray();
        Check(fakes.Length == 12 && injections.Count == 14 && ReassembleReal(packet, injections).SequenceEqual(packet[52..]), "Fake variants/repeats changed real TLS.");
        Check(Read32(fakes[2].Packet, 24) == unchecked(Read32(packet, 24) + 0x80000000u) &&
            Read32(fakes[2].Packet, 28) == unchecked(Read32(packet, 28) - 66000u), "Badseq offset incorrect.");
        Check(fakes[4].Packet[8] == 3 && packet[8] == 64, "Fixed TTL changed real packets.");
        Check(PacketProcessor.TryReadHeaders(fakes[6].Packet, out int ip, out int tcp) && tcp == 52 &&
            fakes[6].Packet[ip + 20] == 19 && fakes[6].Packet[ip + 21] == 18, "MD5 option not inserted before existing options.");
        Check(Read32(fakes[8].Packet, 42) == 100000 && Read32(fakes[8].Packet, 46) == 9876, "TSval change corrupted TSecr.");
        Check((fakes[10].Packet[33] & 0x10) == 0 && (packet[33] & 0x10) != 0, "Datanoack changed real flags.");
        Check(!fakes[0].Packet.AsSpan(63, 32).SequenceEqual(packet.AsSpan(63, 32)) &&
            PacketProcessor.TryReadSni(fakes[0].Packet.AsSpan(52), out var hostname) && hostname.EndsWith("google.com"), "Fake random or hostname template invalid.");
        VerifyDpiChecksums(injections);
        var timestampOnly = DpiOptions.Standard with { TcpFragmentation = false, FakeTimestamp = true };
        byte[] noTimestamp = TcpPacket(ClientHello("example.com"));
        Check(PacketProcessor.BuildInjections(noTimestamp, DpiProcessor(timestampOnly).Process(noTimestamp, true)).All(p => !p.IsFake), "Timestamp invented when absent.");
        byte[] fullHeader = new byte[noTimestamp.Length + 40];
        noTimestamp.AsSpan(0, 40).CopyTo(fullHeader); noTimestamp.AsSpan(40).CopyTo(fullHeader.AsSpan(80));
        fullHeader[32] = 0xF0; Write16(fullHeader, 2, (ushort)fullHeader.Length);
        var md5Only = timestampOnly with { FakeTimestamp = false, FakeMd5Signature = true };
        Check(PacketProcessor.BuildInjections(fullHeader, DpiProcessor(md5Only).Process(fullHeader, true)).All(p => !p.IsFake), "MD5 overflowed TCP options.");
    }

    private static byte[] SynAck(byte ttl = 59, ushort clientPort = 52000)
    {
        byte[] packet = TcpPacket([]); packet[33] = 0x12; packet[8] = ttl;
        packet.AsSpan(12, 4).CopyTo(packet.AsSpan(16)); System.Net.IPAddress.Parse("203.0.113.20").GetAddressBytes().CopyTo(packet, 12);
        Write16(packet, 20, 443); Write16(packet, 22, clientPort); return packet;
    }

    private static void AutoTtlFlows()
    {
        var clock = new Clock(); var processor = new PacketProcessor(timeProvider: clock);
        processor.UpdateTargets(["example.com"], ["203.0.113.20/32"]);
        processor.UpdateOptions(DpiOptions.Standard with { TcpFragmentation = false, FakeAutoTtl = true, FakeLowTtl = true, FakeTtl = 2 });
        byte[] packet = TcpPacket(ClientHello("example.com"));
        Check(PacketProcessor.BuildInjections(packet, processor.Process(packet, true)).All(p => !p.IsFake), "AutoTTL used fixed fallback without a sample.");
        byte[] ack = SynAck(); var untouched = ack.ToArray();
        Check(processor.Process(ack, false).Action == PacketAction.Pass && ack.SequenceEqual(untouched), "SYN+ACK was modified.");
        var decision = processor.Process(packet, true);
        Check(decision.AutoTtl == 4 && PacketProcessor.BuildInjections(packet, decision).Single(p => p.IsFake).Packet[8] == 4, "AutoTTL did not use matching flow.");
        byte[] other = packet.ToArray(); Write16(other, 20, 52001);
        Check(processor.Process(other, true).AutoTtl == 0, "AutoTTL reused another client's sample.");
        clock.Now = clock.Now.AddSeconds(61);
        Check(processor.Process(packet, true).AutoTtl == 0, "Expired TTL sample reused.");
        Check(PacketProcessor.GuessFakeTtl(63) == 0 && PacketProcessor.GuessFakeTtl(0) == 0 && PacketProcessor.GuessFakeTtl(117) == 10 &&
            PacketProcessor.GuessFakeTtl(250) == 4, "Hop estimate boundaries incorrect.");
        processor.Process(ack, false); processor.UpdateTargets(["example.com"], ["203.0.113.20/32"]);
        Check(processor.HopSamplesCount == 0 && processor.Process(packet, true).AutoTtl == 0, "Target update retained old hop sample.");
        for (ushort port = 10000; port < 11100; port++) processor.Process(SynAck(clientPort: port), false);
        Check(processor.HopSamplesCount == 1024, "Hop cache exceeded capacity.");
        clock.Now = clock.Now.AddSeconds(61); processor.Process(ack, false);
        Check(processor.HopSamplesCount == 1 && processor.Process(packet, true).AutoTtl == 4, "Expired samples did not release capacity.");
        VerifyDpiChecksums(PacketProcessor.BuildInjections(packet, processor.Process(packet, true)));
    }

    private static void FakeMix()
    {
        byte[] packet = TimestampPacket(TcpPacket(ClientHello("example.com")));
        for (int bits = 0; bits < 128; bits++)
        {
            bool Bit(int n) => (bits & (1 << n)) != 0;
            var options = DpiOptions.Standard with { MultiSplit = true, SplitPositions = "1,2,3,4,host,midhost,-1", FakeMixSegments = true,
                ReverseSegments = Bit(0), FakeWrongChecksum = Bit(1), FakeWrongSequence = Bit(2), FakeLowTtl = Bit(3), FakeMd5Signature = Bit(4),
                FakeTimestamp = Bit(5), FakeDataNoAck = Bit(6), FakeRepeats = 6 };
            var processor = DpiProcessor(options);
            var injections = PacketProcessor.BuildInjections(packet, processor.Process(packet, true));
            Check(injections.Count <= 96 && injections.Count(i => !i.IsFake) == 8 && ReassembleReal(packet, injections).SequenceEqual(packet[52..]), "Fake mix dropped real bytes or exceeded budget.");
            VerifyDpiChecksums(injections);
            Check(processor.Process(TcpPacket(ClientHello("unselected.example")), true).Action == PacketAction.Pass, "Fake methods escaped target scope.");
        }
    }

    private static void AdvancedHttp()
    {
        byte[] packet = HttpPacket("example.com", body: "abc\r\nHost: body.example\r\n");
        foreach (var options in new[] {
            DpiOptions.Standard with { TcpFragmentation = false, HttpMethodSpace = true },
            DpiOptions.Standard with { TcpFragmentation = false, HttpMethodEol = true },
            DpiOptions.Standard with { TcpFragmentation = false, HttpHostTab = true } })
        {
            var injections = PacketProcessor.BuildInjections(packet, DpiProcessor(options).Process(packet, true));
            byte[] real = injections.Single().Packet; string text = Encoding.ASCII.GetString(real[40..]);
            Check(real.Length == packet.Length && text.EndsWith("abc\r\nHost: body.example\r\n"), "HTTP method changed length/body.");
            Check(options.HttpMethodSpace ? text.StartsWith("POST  /path") && text.Contains("Host:example.com\r\n") :
                options.HttpMethodEol ? text.StartsWith("\nPOST /path") && text.Contains("Host:example.com\r\n") : text.Contains("Host:\texample.com\r\n"), "HTTP spacing transformation incorrect.");
            VerifyDpiChecksums(injections);
        }
        var capped = DpiProcessor(DpiOptions.Standard with { MaxPayloadSize = 64 });
        Check(capped.Process(packet, true).Action == PacketAction.Pass, "Payload cutoff ignored.");
    }

    private static void AdvancedDpiSettings()
    {
        var options = new DpiOptions { MultiSplit = true, FakeWrongSequence = true, FakeAutoTtl = true, FakeMd5Signature = true, FakeTimestamp = true,
            FakeDataNoAck = true, FakeRandomizeTls = true, FakeMixSegments = true, FakeHostname = "bücher.de", FakeRepeats = 3, SplitPositions = "host+1,endhost-1" };
        var normalized = options.Normalize();
        Check(normalized.FakeHostname == "xn--bcher-kva.de" && JsonSerializer.Deserialize<DpiOptions>(JsonSerializer.Serialize(normalized)) == normalized, "Advanced options lost in serialization.");
        var invalid = options with { FakeTtl = 999, FakeRepeats = 999, TcpSplitSize = 0, MaxPayloadSize = -3, SplitPositions = "bad", FakeHostname = "*.bad" };
        var safe = invalid.Normalize();
        Check(safe.FakeTtl == 64 && safe.FakeRepeats == 6 && safe.TcpSplitSize == 1 && safe.MaxPayloadSize == 0 && safe.FakeHostname == "" &&
            TcpSplitPositions.IsValid(safe.SplitPositions), "Invalid settings can reach the packet emitter.");
        Check(!DpiOptions.Standard.HasFakeMethods && !DpiOptions.Standard.MultiSplit && DpiOptions.Standard.TcpSplitSize == 2, "Advanced defaults changed Standard.");
    }
}
