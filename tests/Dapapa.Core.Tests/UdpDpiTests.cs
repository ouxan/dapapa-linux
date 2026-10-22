using System.Text.Json;
using Dapapa.Core.Models;
using Dapapa.Core;

internal static partial class Program
{
    private static void UdpDpiTests()
    {
        Run("UDP protocol signatures, QUIC bounds and malformed parser fuzz", UdpProtocols);
        Run("UDP methods retain Standard, target, direction and DNS isolation", UdpIsolation);
        Run("UDP fakes, repeats, TTL and native invalid nonzero checksum", UdpFakes);
        Run("IPv4 UDP fragment offsets, ordering, reassembly and native checksums", UdpFragments);
        Run("QUIC-only UDP padding, original data preservation and MTU limits", UdpPadding);
        Run("UDP flow cutoff, expiry, capacity, target reset and option snapshots", UdpFlows);
        Run("UDP settings defaults, limits and serialization", UdpSettings);
    }

    private static DpiOptions UdpOptions => DpiOptions.Standard with { BlockQuic = false, UdpFakeWrongChecksum = true };
    private static byte[] QuicInitial(uint version = 1)
    {
        byte[] payload = new byte[1200];
        payload[0] = version == 1 ? (byte)0xC0 : (byte)0xD0; Write32(payload, 1, version);
        payload[5] = 8; payload[14] = 0; payload[15] = 0; Write16(payload, 16, 0x449E);
        return payload;
    }
    private static byte[] StunRequest()
    {
        byte[] payload = new byte[20]; Write16(payload, 0, 1); Write32(payload, 4, 0x2112A442); return payload;
    }
    private static byte[] DiscordDiscovery()
    {
        byte[] payload = new byte[74]; Write16(payload, 0, 1); Write16(payload, 2, 70); Write32(payload, 4, 123); return payload;
    }
    private static byte[] UdpDpiPacket(byte[]? payload = null, ushort port = 443, ushort clientPort = 52000) =>
        UdpPacket(payload ?? QuicInitial(), "192.0.2.1", "203.0.113.20", clientPort, port);

    private static void UdpProtocols()
    {
        Check(PacketProcessor.DetectUdpProtocol(QuicInitial()) == PacketProcessor.UdpProtocol.QuicInitial &&
            PacketProcessor.DetectUdpProtocol(QuicInitial(0x6B3343CF)) == PacketProcessor.UdpProtocol.QuicInitial, "QUIC v1/v2 not recognized.");
        Check(PacketProcessor.DetectUdpProtocol(StunRequest()) == PacketProcessor.UdpProtocol.Stun &&
            PacketProcessor.DetectUdpProtocol(DiscordDiscovery()) == PacketProcessor.UdpProtocol.DiscordDiscovery &&
            PacketProcessor.DetectUdpProtocol([1, 0, 0, 0, .. new byte[144]]) == PacketProcessor.UdpProtocol.WireGuard, "Known UDP protocol not recognized.");
        byte[] bad = QuicInitial(); bad[5] = 21;
        Check(PacketProcessor.DetectUdpProtocol(bad) == PacketProcessor.UdpProtocol.Unknown, "Oversize QUIC CID accepted.");
        bad = QuicInitial(); bad[15] = 0xFF;
        Check(PacketProcessor.DetectUdpProtocol(bad) == PacketProcessor.UdpProtocol.Unknown, "Oversize token accepted.");
        bad = QuicInitial(); Write16(bad, 16, 0x7FFF);
        Check(PacketProcessor.DetectUdpProtocol(bad) == PacketProcessor.UdpProtocol.Unknown, "Truncated QUIC packet accepted.");
        bad = StunRequest(); Write16(bad, 2, 4);
        Check(PacketProcessor.DetectUdpProtocol(bad) == PacketProcessor.UdpProtocol.Unknown, "STUN length mismatch accepted.");
        bad = DiscordDiscovery(); bad[8] = 1;
        Check(PacketProcessor.DetectUdpProtocol(bad) == PacketProcessor.UdpProtocol.Unknown, "Invalid voice discovery accepted.");
        var random = new Random(73);
        foreach (byte[] seed in new[] { QuicInitial(), StunRequest(), DiscordDiscovery() })
            for (int i = 0; i < 1000; i++)
            {
                byte[] payload = seed[..random.Next(seed.Length + 1)];
                if (payload.Length > 0) payload[random.Next(payload.Length)] = (byte)random.Next(256);
                _ = PacketProcessor.DetectUdpProtocol(payload);
            }
    }

    private static void UdpIsolation()
    {
        var processor = DpiProcessor(DpiOptions.Standard);
        Check(processor.Process(UdpDpiPacket(), true).Action == PacketAction.Drop && !DpiOptions.Standard.HasUdpMethods, "Standard behavior changed.");
        Check(processor.Process(UdpDpiPacket(StunRequest(), 3478), true).Action == PacketAction.Pass, "Standard changed STUN.");
        processor.UpdateOptions(UdpOptions);
        Check(processor.Process(UdpDpiPacket(), true).Action == PacketAction.Modify, "Selected QUIC ignored.");
        Check(processor.Process(UdpDpiPacket(), false).Action == PacketAction.Pass, "Inbound UDP modified.");
        var unselected = UdpPacket(QuicInitial(), "192.0.2.1", "198.51.100.10", 52000, 443);
        Check(processor.Process(unselected, true).Action == PacketAction.Pass, "Unselected IP changed.");
        Check(processor.Process(UdpDpiPacket(StunRequest(), 3478), true).Action == PacketAction.Pass, "Unselected protocol changed.");
        processor.UpdateOptions(UdpOptions with { UdpUnknown = true, UdpStun = true });
        Check(processor.Process(UdpDpiPacket(StunRequest(), 3478), true).Action == PacketAction.Modify, "Selected STUN ignored.");
        processor.UpdateOptions(UdpOptions with { UdpWireGuard = true, UdpDiscordDiscovery = true, UdpUnknown = true });
        foreach (var known in new[] { DiscordDiscovery(), (byte[])[1, 0, 0, 0, .. new byte[144]] })
            Check(processor.Process(UdpDpiPacket(known, 50000), true).Action == PacketAction.Modify, "Selected voice/WireGuard ignored.");
        Check(processor.Process(UdpDpiPacket([5, 6, 7], 5353), true).Action == PacketAction.Modify, "Unknown UDP opt-in ignored.");
        Check(processor.Process(UdpDpiPacket([5, 6, 7], 53), true).Action == PacketAction.Pass &&
            processor.Process(UdpDpiPacket([5, 6, 7], 52000, 53), true).Action == PacketAction.Pass, "UDP fake touched DNS.");
        Check(processor.Process(UdpDpiPacket(DnsQuestion("example.com", 4), 53), true).Action == PacketAction.DnsQuery, "Selected DNS routing lost.");
        byte[] fragmented = UdpDpiPacket(); Write16(fragmented, 6, 0x2000);
        Check(processor.Process(fragmented, true).Action == PacketAction.Pass, "Existing fragment modified.");
        byte[] reserved = UdpDpiPacket(); Write16(reserved, 6, 0x8000);
        Check(processor.Process(reserved, true).Action == PacketAction.Pass, "Reserved IPv4 flag modified.");
        byte[] large = UdpDpiPacket(new byte[1500], 9999);
        Check(processor.Process(large, true).Action == PacketAction.Pass, "Large UDP datagram modified.");
        processor.UpdateOptions(UdpOptions with { BlockQuic = true });
        Check(processor.Process(UdpDpiPacket(), true).Action == PacketAction.Drop, "QUIC block precedence lost.");
    }

    private static void VerifyUdpInjection(PacketInjection injection)
    {
        var packet = injection.Packet;
        PacketChecksum.Prepare(packet, invalidUdpChecksum: injection.InvalidUdpChecksum);
        Check(Sum(packet.AsSpan(0, 20)) == 0xFFFF, "UDP IP checksum invalid.");
        if ((Read16(packet, 6) & 0x3FFF) != 0) return;
        Check(PacketProcessor.TryReadHeaders(packet, out int ip, out _), "Bad generated UDP headers.");
        var pseudo = new List<byte>(packet.AsSpan(12, 8).ToArray()) { 0, 17, (byte)((packet.Length - ip) >> 8), (byte)(packet.Length - ip) };
        pseudo.AddRange(packet.AsSpan(ip).ToArray());
        Check((Sum([.. pseudo]) != 0xFFFF) == injection.InvalidUdpChecksum, "UDP checksum mismatch.");
        Check(!injection.InvalidUdpChecksum || Read16(packet, 26) != 0, "Fake used disabled UDP checksum.");
    }

    private static void UdpFakes()
    {
        byte[] original = UdpDpiPacket();
        var processor = DpiProcessor(UdpOptions with { UdpFakeLowTtl = true, UdpFakeTtl = 3, UdpFakeRepeats = 6 });
        var injections = PacketProcessor.BuildInjections(original, processor.Process(original, true));
        Check(injections.Count == 13 && injections.Count(i => i.IsFake) == 12, "Fake repeat budget incorrect.");
        Check(injections[^1].Packet.SequenceEqual(original) && injections.Take(12).All(i => i.Packet.Length == 92 && i.Packet.AsSpan(28).IndexOfAnyExcept((byte)0) < 0), "UDP fake changed real payload.");
        Check(injections.Take(6).All(i => i.InvalidUdpChecksum && i.Packet[8] == original[8]) &&
            injections.Skip(6).Take(6).All(i => !i.InvalidUdpChecksum && i.Packet[8] == 3), "Fake TTL/checksum types mixed.");
        foreach (var injection in injections) VerifyUdpInjection(injection);
    }

    private static void UdpFragments()
    {
        foreach (bool reverse in new[] { false, true })
            foreach (int split in new[] { 8, 16, 24, 1200 })
            {
                var options = UdpOptions with { UdpFakeWrongChecksum = false, UdpIpFragmentation = true, UdpFragmentSize = split, UdpReverseFragments = reverse };
                byte[] original = UdpDpiPacket(); Write16(original, 6, 0x4000);
                var injections = PacketProcessor.BuildInjections(original, DpiProcessor(options).Process(original, true));
                Check(injections.Count == 2 && (Read16(injections[0].Packet, 6) & 0x1FFF) == (reverse ? split / 8 : 0), "Fragment order incorrect.");
                foreach (var injection in injections) VerifyUdpInjection(injection);
                var sorted = injections.OrderBy(i => Read16(i.Packet, 6) & 0x1FFF).ToArray();
                Check(Read16(sorted[0].Packet, 4) != 0 && Read16(sorted[0].Packet, 4) == Read16(sorted[1].Packet, 4) &&
                    Read16(sorted[0].Packet, 6) == 0x2000 && Read16(sorted[1].Packet, 6) == split / 8, "Fragment IDs, flags or offsets invalid.");
                byte[] datagram = sorted.SelectMany(i => i.Packet[20..]).ToArray();
                Check(datagram[8..].SequenceEqual(original[28..]) && Read16(datagram, 4) == datagram.Length, "Fragment reassembly changed UDP payload.");
                var pseudo = new List<byte>(original.AsSpan(12, 8).ToArray()) { 0, 17, (byte)(datagram.Length >> 8), (byte)datagram.Length };
                pseudo.AddRange(datagram); Check(Sum([.. pseudo]) == 0xFFFF, "Fragment UDP checksum recalculated on incomplete data.");
            }
        byte[] odd = UdpDpiPacket([1, 2, 3, 4, 5], 9999);
        var oddOptions = UdpOptions with { UdpUnknown = true, UdpIpFragmentation = true };
        foreach (var injection in PacketProcessor.BuildInjections(odd, DpiProcessor(oddOptions).Process(odd, true))) VerifyUdpInjection(injection);
    }

    private static void UdpPadding()
    {
        for (int bits = 0; bits < 32; bits++)
        {
            bool Bit(int n) => (bits & (1 << n)) != 0;
            var mix = UdpOptions with { UdpFakeWrongChecksum = Bit(0), UdpFakeLowTtl = Bit(1), UdpIpFragmentation = Bit(2),
                UdpLengthPadding = Bit(3), UdpReverseFragments = Bit(4), UdpFakeRepeats = 6 };
            byte[] source = UdpDpiPacket();
            var combinedInjections = PacketProcessor.BuildInjections(source, DpiProcessor(mix).Process(source, true));
            Check(combinedInjections.Count <= 14, "UDP injection budget exceeded.");
            foreach (var injection in combinedInjections) VerifyUdpInjection(injection);
            var real = combinedInjections.Where(i => !i.IsFake).OrderBy(i => Read16(i.Packet, 6) & 0x1FFF).SelectMany(i => i.Packet[20..]).ToArray();
            Check(real.AsSpan(8, 1200).SequenceEqual(source.AsSpan(28)) && real.Length == 1208 + (Bit(3) ? 2 : 0), "UDP combination lost original bytes.");
        }
        var options = UdpOptions with { UdpFakeWrongChecksum = false, UdpLengthPadding = true, UdpPaddingSize = 64, UdpStun = true };
        byte[] original = UdpDpiPacket();
        var injections = PacketProcessor.BuildInjections(original, DpiProcessor(options).Process(original, true));
        Check(injections.Single().Packet.Length == original.Length + 64 && injections[0].Packet.AsSpan(28, original.Length - 28).SequenceEqual(original.AsSpan(28)) &&
            injections[0].Packet.AsSpan(original.Length).IndexOfAnyExcept((byte)0) < 0, "QUIC padding changed original bytes.");
        VerifyUdpInjection(injections[0]);
        byte[] stun = UdpDpiPacket(StunRequest(), 3478);
        Check(DpiProcessor(options).Process(stun, true).Action == PacketAction.Pass, "STUN padded.");
        byte[] largePayload = new byte[1450]; QuicInitial().CopyTo(largePayload, 0);
        Check(DpiProcessor(options).Process(UdpDpiPacket(largePayload), true).Action == PacketAction.Pass, "Padding exceeded MTU bound.");
        var combined = options with { UdpFakeWrongChecksum = true, UdpIpFragmentation = true, UdpReverseFragments = true };
        injections = PacketProcessor.BuildInjections(original, DpiProcessor(combined).Process(original, true));
        foreach (var injection in injections) VerifyUdpInjection(injection);
        byte[] restored = injections.Where(i => !i.IsFake).OrderBy(i => Read16(i.Packet, 6) & 0x1FFF).SelectMany(i => i.Packet[20..]).ToArray();
        Check(restored[8..(8 + 1200)].SequenceEqual(original[28..]) && restored.Length == 1272, "Padding/fragment combination lost original data.");
    }

    private static void UdpFlows()
    {
        var clock = new Clock();
        var processor = new PacketProcessor(timeProvider: clock);
        processor.UpdateTargets(["example.com"], ["203.0.113.20/32"]); processor.UpdateOptions(UdpOptions with { UdpPacketLimit = 2 });
        byte[] packet = UdpDpiPacket();
        var first = processor.Process(packet, true);
        Check(first.Action == PacketAction.Modify && processor.Process(packet, true).Action == PacketAction.Modify && processor.Process(packet, true).Action == PacketAction.Pass, "UDP cutoff ignored.");
        Check(processor.Process(UdpDpiPacket(clientPort: 52001), true).Action == PacketAction.Modify, "Different client port reused flow budget.");
        clock.Now = clock.Now.AddSeconds(61);
        Check(processor.Process(packet, true).Action == PacketAction.Modify, "Expired UDP flow did not restart.");
        processor.UpdateOptions(DpiOptions.Standard);
        Check(PacketProcessor.BuildInjections(packet, first).Count == 2 && processor.Process(packet, true).Action == PacketAction.Drop, "UDP snapshot or live Standard switch lost.");
        processor.UpdateTargets(["example.com"], ["203.0.113.20/32"]); processor.UpdateOptions(UdpOptions);
        Check(processor.UdpFlowsCount == 0, "Target update retained UDP flows.");
        for (ushort port = 10000; port < 11100; port++) processor.Process(UdpDpiPacket(clientPort: port), true);
        Check(processor.UdpFlowsCount == 1024 && processor.Process(UdpDpiPacket(clientPort: 12000), true).Action == PacketAction.Pass, "UDP cache capacity not enforced.");
        clock.Now = clock.Now.AddSeconds(61); processor.Process(packet, true);
        Check(processor.UdpFlowsCount == 1, "Expired UDP flows did not free capacity.");
        processor.UpdateTargets([], []);
        Check(processor.Process(packet, true).Action == PacketAction.Pass && new PacketProcessor().UdpFlowsCount == 0, "UDP target/session state leaked.");
    }

    private static void UdpSettings()
    {
        var old = JsonSerializer.Deserialize<DpiOptions>("{\"FakeWrongSequence\":true,\"TcpSplitSize\":5}")!;
        Check(!old.HasUdpMethods && old.FakeWrongSequence && old.TcpSplitSize == 5, "Old Custom options changed.");
        var options = UdpOptions with { UdpFakeLowTtl = true, UdpIpFragmentation = true, UdpLengthPadding = true, UdpReverseFragments = true,
            UdpStun = true, UdpWireGuard = true, UdpDiscordDiscovery = true, UdpUnknown = true };
        Check(JsonSerializer.Deserialize<DpiOptions>(JsonSerializer.Serialize(options)) == options, "UDP options did not round-trip.");
        var safe = (options with { UdpFakeTtl = 900, UdpFakeRepeats = 0, UdpFragmentSize = 19, UdpPaddingSize = 900, UdpPacketLimit = 0 }).Normalize();
        Check(safe.UdpFakeTtl == 64 && safe.UdpFakeRepeats == 1 && safe.UdpFragmentSize == 16 && safe.UdpPaddingSize == 64 && safe.UdpPacketLimit == 1, "UDP bounds not normalized.");
    }
}
