using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Dapapa.Core.Models;

namespace Dapapa.Core
{
    internal sealed partial class PacketProcessor
    {
        private readonly record struct HopFlow(uint Client, uint Server, ushort ClientPort, ushort ServerPort);
        private sealed record HopSample(byte Ttl, DateTimeOffset Expires, long TargetVersion);
        private readonly ConcurrentDictionary<HopFlow, HopSample> _hops = new();
        internal int HopSamplesCount => _hops.Count;

        private void ObserveHop(ReadOnlySpan<byte> packet, int ip, Targets targets)
        {
            if ((packet[ip + 13] & 0x17) != 0x12 || Read16(packet, ip) is not (80 or 443) || packet[8] == 0 ||
                !IsIpTargeted(Read32(packet, 12), targets)) return;
            var now = _hopClock.GetUtcNow();
            if (_hops.Count >= 1024)
                foreach (var pair in _hops)
                    if (pair.Value.Expires <= now || pair.Value.TargetVersion != targets.Version) _hops.TryRemove(pair.Key, out _);
            var flow = new HopFlow(Read32(packet, 16), Read32(packet, 12), Read16(packet, ip + 2), Read16(packet, ip));
            if (_hops.Count < 1024 || _hops.ContainsKey(flow)) _hops[flow] = new(packet[8], now.AddSeconds(60), targets.Version);
        }

        private byte GetAutoTtl(ReadOnlySpan<byte> packet, int ip, Targets targets)
        {
            var flow = new HopFlow(Read32(packet, 12), Read32(packet, 16), Read16(packet, ip), Read16(packet, ip + 2));
            return _hops.TryGetValue(flow, out var sample) && sample.TargetVersion == targets.Version && sample.Expires > _hopClock.GetUtcNow()
                ? GuessFakeTtl(sample.Ttl) : (byte)0;
        }

        internal static byte GuessFakeTtl(byte received)
        {
            int initial = received <= 64 ? 64 : received <= 128 ? 128 : 255;
            int hops = initial - received;
            return received == 0 || hops <= 1 ? (byte)0 : (byte)Math.Clamp(hops - 1, 1, 20);
        }

        internal static List<byte[]> SplitTcpPackets(ReadOnlySpan<byte> packet, IEnumerable<int> positions)
        {
            if (!TryReadHeaders(packet, out int ip, out int tcp) || packet[9] != 6) return [packet.ToArray()];
            int start = ip + tcp, length = packet.Length - start;
            var cuts = positions.Where(p => p > 0 && p < length).Distinct().Order().Take(7).Append(length);
            var result = new List<byte[]>();
            int offset = 0;
            foreach (int end in cuts)
            {
                byte[] segment = new byte[start + end - offset];
                packet[..start].CopyTo(segment);
                packet.Slice(start + offset, end - offset).CopyTo(segment.AsSpan(start));
                Write16(segment, 2, (ushort)segment.Length);
                Write32(segment, ip + 4, unchecked(Read32(packet, ip + 4) + (uint)offset));
                if (end != length) segment[ip + 13] &= 0xF6;
                result.Add(segment); offset = end;
            }
            return result;
        }

        private static List<PacketInjection> CombineInjections(List<byte[]> real, List<PacketInjection> fakes, int[] cuts, DpiOptions options)
        {
            var result = new List<PacketInjection>();
            int fakeBudget = 96 - real.Count;
            void Emit(PacketInjection injection)
            {
                for (int repeat = 0; repeat < options.FakeRepeats && fakeBudget > 0; repeat++, fakeBudget--) result.Add(injection);
            }
            if (options.FakeMixSegments && real.Count > 1)
            {
                var splitFakes = fakes.Select(fake => (Fake: fake, Parts: SplitTcpPackets(fake.Packet, cuts))).ToArray();
                for (int wire = 0; wire < real.Count; wire++)
                {
                    int index = options.ReverseSegments ? real.Count - wire - 1 : wire;
                    void Mix()
                    {
                        foreach (var fake in splitFakes)
                            if (index < fake.Parts.Count) Emit(new(fake.Parts[index], fake.Fake.InvalidTcpChecksum, true));
                    }
                    Mix(); result.Add(new(real[wire])); Mix();
                }
            }
            else
            {
                foreach (var fake in fakes) Emit(fake);
                result.AddRange(real.Select(packet => new PacketInjection(packet)));
            }
            return result;
        }

        private static List<PacketInjection> BuildFakes(ReadOnlySpan<byte> original, DpiOptions options, int hostOffset, int hostLength, byte autoTtl)
        {
            var result = new List<PacketInjection>();
            if (!options.HasFakeMethods || hostOffset < 0 || hostLength == 0 || !TryReadHeaders(original, out int ip, out int tcp)) return result;
            int start = ip + tcp;
            byte[] template = original.ToArray();
            var host = template.AsSpan(start + hostOffset, hostLength);
            if (options.FakeHostname.Length == 0)
            {
                byte letter = host[0] is (byte)'x' or (byte)'X' ? (byte)'y' : (byte)'x';
                for (int i = 0; i < host.Length; i++) if (host[i] != (byte)'.' && host[i] != (byte)'-') host[i] = letter;
            }
            else
            {
                byte[] name = Encoding.ASCII.GetBytes(options.FakeHostname);
                host.Fill((byte)'x');
                int count = Math.Min(name.Length, host.Length);
                name.AsSpan(name.Length - count).CopyTo(host[(host.Length - count)..]);
                if (name.Length < host.Length - 1) host[host.Length - name.Length - 1] = (byte)'.';
                if (host[0] == (byte)'.') host[0] = (byte)'x';
                if (host.SequenceEqual(original.Slice(start + hostOffset, hostLength))) host[0] = host[0] == (byte)'x' ? (byte)'y' : (byte)'x';
            }
            if (options.FakeRandomizeTls && Read16(original, ip + 2) == 443)
            {
                var payload = template.AsSpan(start);
                RandomNumberGenerator.Fill(payload.Slice(11, 32));
                int session = payload[43];
                if (44 + session <= payload.Length) RandomNumberGenerator.Fill(payload.Slice(44, session));
            }
            if (options.FakeWrongChecksum) result.Add(new(template.ToArray(), true, true));
            if (options.FakeWrongSequence)
            {
                byte[] fake = template.ToArray();
                // Half the sequence space keeps the fake outside normal receive windows.
                Write32(fake, ip + 4, unchecked(Read32(fake, ip + 4) + 0x80000000u));
                Write32(fake, ip + 8, unchecked(Read32(fake, ip + 8) - 66000u));
                result.Add(new(fake, IsFake: true));
            }
            if (options.FakeLowTtl || options.FakeAutoTtl)
            {
                byte ttl = options.FakeAutoTtl ? autoTtl : (byte)options.FakeTtl;
                if (ttl > 0) { byte[] fake = template.ToArray(); fake[8] = ttl; result.Add(new(fake, IsFake: true)); }
            }
            if (options.FakeMd5Signature && tcp <= 40 && template.Length <= 1480)
            {
                byte[] fake = new byte[template.Length + 20];
                template.AsSpan(0, ip + 20).CopyTo(fake);
                template.AsSpan(ip + 20).CopyTo(fake.AsSpan(ip + 40));
                fake[ip + 20] = 19; fake[ip + 21] = 18;
                RandomNumberGenerator.Fill(fake.AsSpan(ip + 22, 16));
                fake[ip + 38] = fake[ip + 39] = 1;
                fake[ip + 12] = (byte)(((tcp + 20) / 4 << 4) | (fake[ip + 12] & 15));
                Write16(fake, 2, (ushort)fake.Length);
                result.Add(new(fake, IsFake: true));
            }
            if (options.FakeTimestamp)
            {
                byte[] fake = template.ToArray();
                for (int pos = ip + 20; pos < ip + tcp;)
                {
                    byte type = fake[pos];
                    if (type == 0) break;
                    if (type == 1) { pos++; continue; }
                    if (pos + 2 > ip + tcp || fake[pos + 1] < 2 || pos + fake[pos + 1] > ip + tcp) break;
                    if (type == 8 && fake[pos + 1] == 10)
                    {
                        Write32(fake, pos + 2, unchecked(Read32(fake, pos + 2) - 600000u));
                        result.Add(new(fake, IsFake: true)); break;
                    }
                    pos += fake[pos + 1];
                }
            }
            if (options.FakeDataNoAck)
            {
                byte[] fake = template.ToArray(); fake[ip + 13] &= 0xEF;
                result.Add(new(fake, IsFake: true));
            }
            return result;
        }
    }
}
