using System.Security.Cryptography;
using Dapapa.Core.Models;

namespace Dapapa.Core
{
    internal sealed partial class PacketProcessor
    {
        internal enum UdpProtocol { Unknown, QuicInitial, Stun, WireGuard, DiscordDiscovery }
        private readonly record struct UdpFlow(uint Client, uint Server, ushort ClientPort, ushort ServerPort, long Version);
        private sealed record UdpFlowState(int Count, DateTimeOffset Expires);
        private readonly object _udpGate = new();
        private readonly Dictionary<UdpFlow, UdpFlowState> _udpFlows = new();
        private static int _udpFragmentId = RandomNumberGenerator.GetInt32(65536);
        internal int UdpFlowsCount { get { lock (_udpGate) return _udpFlows.Count; } }

        private PacketDecision ProcessUdp(ReadOnlySpan<byte> packet, int ip, Targets targets, DpiOptions options)
        {
            if (!options.HasUdpMethods || ip != 20 || packet.Length > 1500 || (Read16(packet, 6) & 0x8000) != 0 || Read16(packet, ip) == 53 ||
                Read16(packet, ip + 2) == 53 || !IsIpTargeted(Read32(packet, 16), targets)) return new(PacketAction.Pass);
            var payload = packet[(ip + 8)..];
            if (payload.IsEmpty) return new(PacketAction.Pass);
            UdpProtocol protocol = DetectUdpProtocol(payload);
            bool selected = protocol switch
            {
                UdpProtocol.QuicInitial => options.UdpQuicInitial,
                UdpProtocol.Stun => options.UdpStun,
                UdpProtocol.WireGuard => options.UdpWireGuard,
                UdpProtocol.DiscordDiscovery => options.UdpDiscordDiscovery,
                _ => options.UdpUnknown
            };
            if (!selected || (!options.UdpFakeWrongChecksum && !options.UdpFakeLowTtl && !options.UdpIpFragmentation &&
                !(options.UdpLengthPadding && protocol == UdpProtocol.QuicInitial && packet.Length + options.UdpPaddingSize <= 1500)))
                return new(PacketAction.Pass);
            var now = _hopClock.GetUtcNow();
            var flow = new UdpFlow(Read32(packet, 12), Read32(packet, 16), Read16(packet, ip), Read16(packet, ip + 2), targets.Version);
            lock (_udpGate)
            {
                if (_udpFlows.TryGetValue(flow, out var state) && state.Expires > now)
                {
                    _udpFlows[flow] = state with { Count = Math.Min(20, state.Count + 1), Expires = now.AddSeconds(60) };
                    if (state.Count >= options.UdpPacketLimit) return new(PacketAction.Pass);
                }
                else
                {
                    foreach (var pair in _udpFlows.ToArray())
                        if (pair.Value.Expires <= now || pair.Key.Version != targets.Version) _udpFlows.Remove(pair.Key);
                    if (_udpFlows.Count >= 1024) return new(PacketAction.Pass);
                    _udpFlows[flow] = new(1, now.AddSeconds(60));
                }
            }
            return new(PacketAction.Modify, "UDP " + protocol, Options: options);
        }

        internal static UdpProtocol DetectUdpProtocol(ReadOnlySpan<byte> payload)
        {
            if (IsQuicInitial(payload)) return UdpProtocol.QuicInitial;
            if (payload.Length >= 20 && (payload[0] & 0xC0) == 0 && Read32(payload, 4) == 0x2112A442 &&
                Read16(payload, 2) % 4 == 0 && Read16(payload, 2) == payload.Length - 20)
            {
                int pos = 20;
                while (pos < payload.Length)
                {
                    if (pos + 4 > payload.Length) return UdpProtocol.Unknown;
                    pos += 4 + (Read16(payload, pos + 2) + 3) / 4 * 4;
                    if (pos > payload.Length) return UdpProtocol.Unknown;
                }
                return UdpProtocol.Stun;
            }
            if (payload.Length == 148 && payload[..4].SequenceEqual(new byte[] { 1, 0, 0, 0 })) return UdpProtocol.WireGuard;
            if (payload.Length == 74 && Read16(payload, 0) == 1 && Read16(payload, 2) == 70 &&
                payload[8..].IndexOfAnyExcept((byte)0) < 0) return UdpProtocol.DiscordDiscovery;
            return UdpProtocol.Unknown;
        }

        private static bool IsQuicInitial(ReadOnlySpan<byte> payload)
        {
            if (payload.Length < 1200 || (payload[0] & 0xC0) != 0xC0) return false;
            uint version = Read32(payload, 1);
            if (version != 1 && version != 0x6B3343CF) return false;
            if ((payload[0] & 0x30) != (version == 1 ? 0 : 0x10)) return false;
            int pos = 5;
            int dcid = payload[pos++];
            if (dcid > 20 || pos + dcid >= payload.Length) return false;
            pos += dcid;
            int scid = payload[pos++];
            if (scid > 20 || pos + scid >= payload.Length) return false;
            pos += scid;
            if (!TryReadQuicInteger(payload, ref pos, out ulong token) || token > (ulong)(payload.Length - pos)) return false;
            pos += (int)token;
            return TryReadQuicInteger(payload, ref pos, out ulong length) && length >= 20 && length <= (ulong)(payload.Length - pos);
        }

        private static bool TryReadQuicInteger(ReadOnlySpan<byte> payload, ref int pos, out ulong value)
        {
            value = 0;
            if (pos >= payload.Length) return false;
            int count = 1 << (payload[pos] >> 6);
            if (pos + count > payload.Length) return false;
            value = (ulong)(payload[pos++] & 0x3F);
            for (int i = 1; i < count; i++) value = value << 8 | payload[pos++];
            return true;
        }

        private static IReadOnlyList<PacketInjection> BuildUdpInjections(ReadOnlySpan<byte> original, PacketDecision decision)
        {
            if (decision.Action != PacketAction.Modify || decision.Options is not { } options ||
                !TryReadHeaders(original, out int ip, out _) || original[9] != 17 || ip != 20 || original.Length > 1500)
                return [new(original.ToArray())];
            var result = new List<PacketInjection>();
            void Fake(bool invalidChecksum, bool lowTtl, byte[] template)
            {
                if (lowTtl) template[8] = (byte)options.UdpFakeTtl;
                for (int repeat = 0; repeat < options.UdpFakeRepeats; repeat++)
                    result.Add(new(template.ToArray(), IsFake: true, InvalidUdpChecksum: invalidChecksum));
            }
            // A generic fake is intentionally not a valid QUIC/STUN/voice handshake.
            byte[] fake = new byte[ip + 8 + 64];
            original[..(ip + 8)].CopyTo(fake);
            Write16(fake, 2, (ushort)fake.Length); Write16(fake, ip + 4, 72);
            if (options.UdpFakeWrongChecksum) Fake(true, false, fake.ToArray());
            if (options.UdpFakeLowTtl) Fake(false, true, fake.ToArray());

            byte[] packet = original.ToArray();
            if (options.UdpLengthPadding && DetectUdpProtocol(original[(ip + 8)..]) == UdpProtocol.QuicInitial &&
                packet.Length + options.UdpPaddingSize <= 1500)
            {
                Array.Resize(ref packet, packet.Length + options.UdpPaddingSize);
                Write16(packet, 2, (ushort)packet.Length); Write16(packet, ip + 4, (ushort)(packet.Length - ip));
            }
            if (options.UdpIpFragmentation && options.UdpFragmentSize < packet.Length - ip)
            {
                SetUdpChecksum(packet, ip);
                ushort id = (ushort)Interlocked.Increment(ref _udpFragmentId);
                if (id == 0) id = (ushort)Interlocked.Increment(ref _udpFragmentId);
                int split = options.UdpFragmentSize;
                byte[] head = new byte[ip + split], tail = new byte[packet.Length - split];
                packet.AsSpan(0, ip + split).CopyTo(head);
                packet.AsSpan(0, ip).CopyTo(tail);
                packet.AsSpan(ip + split).CopyTo(tail.AsSpan(ip));
                Write16(head, 2, (ushort)head.Length); Write16(tail, 2, (ushort)tail.Length);
                Write16(head, 4, id); Write16(tail, 4, id);
                Write16(head, 6, 0x2000); Write16(tail, 6, (ushort)(split / 8));
                if (options.UdpReverseFragments) { result.Add(new(tail)); result.Add(new(head)); }
                else { result.Add(new(head)); result.Add(new(tail)); }
            }
            else result.Add(new(packet));
            return result;
        }

        private static void SetUdpChecksum(Span<byte> packet, int ip)
        {
            Write16(packet, ip + 6, 0);
            uint sum = 17 + (uint)(packet.Length - ip);
            for (int pos = 12; pos < 20; pos += 2) sum += Read16(packet, pos);
            for (int pos = ip; pos < packet.Length; pos += 2)
                sum += pos + 1 < packet.Length ? Read16(packet, pos) : (uint)packet[pos] << 8;
            while (sum >> 16 != 0) sum = (sum & 0xFFFF) + (sum >> 16);
            ushort checksum = (ushort)~sum;
            Write16(packet, ip + 6, checksum == 0 ? (ushort)0xFFFF : checksum);
        }
    }
}
