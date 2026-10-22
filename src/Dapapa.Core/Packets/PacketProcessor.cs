using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Dapapa.Core.Models;

namespace Dapapa.Core
{
    internal enum PacketAction { Pass, Drop, DnsQuery, Fragment, Modify }
    internal readonly record struct PacketDecision(PacketAction Action, string Target = "", long TargetVersion = 0,
        DpiOptions? Options = null, int SplitPosition = 2, byte AutoTtl = 0);
    internal sealed record PacketInjection(byte[] Packet, bool InvalidTcpChecksum = false, bool IsFake = false, bool InvalidUdpChecksum = false);
    public readonly record struct ResolvedTargetIp(string Address, DateTimeOffset Expires);

    internal sealed partial class PacketProcessor(string? upstreamDnsHost = null, TimeProvider? timeProvider = null)
    {
        private readonly TimeProvider _hopClock = timeProvider ?? TimeProvider.System;
        private readonly object _targetGate = new();
        private sealed record Targets(HashSet<string> Domains, HashSet<uint> ExactIps,
            List<(uint Network, uint Mask)> Subnets, Dictionary<uint, DateTimeOffset> ResolvedIps, long Version,
            ConcurrentDictionary<uint, long>? learnedIps = null)
        {
            public readonly ConcurrentDictionary<uint, long> LearnedIps = learnedIps ?? new();
        }

        private volatile Targets _targets = new(new(StringComparer.OrdinalIgnoreCase), [], [], [], 0);

        private long _targetVersion;
        private volatile DpiOptions _options = DpiOptions.Standard;
        public int DomainsCount => _targets.Domains.Count;
        public long TargetVersion => _targets.Version;
        public void UpdateOptions(DpiOptions options) => _options = options.Normalize();

        public void UpdateTargets(IEnumerable<string> domains, IEnumerable<string> cidrs, IEnumerable<ResolvedTargetIp>? resolvedIps = null)
        {
            var names = domains.Select(DomainDnsResolver.CleanDomainName).Where(d => d.Length > 0)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var subnets = new List<(uint, uint)>();
            var exact = new HashSet<uint>();
            foreach (var cidr in cidrs)
            {
                var parts = cidr.Split('/');
                if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out var ip) ||
                    ip.AddressFamily != AddressFamily.InterNetwork) continue;
                int prefix = 32;
                if (parts.Length == 2 && (!int.TryParse(parts[1], out prefix) || prefix < 0 || prefix > 32)) continue;
                uint mask = prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);
                uint address = BinaryPrimitives.ReadUInt32BigEndian(ip.GetAddressBytes());
                if (prefix == 32) exact.Add(address);
                else subnets.Add((address & mask, mask));
            }
            var resolved = new Dictionary<uint, DateTimeOffset>();
            foreach (var entry in resolvedIps ?? [])
                if (IPAddress.TryParse(entry.Address, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    uint key = BinaryPrimitives.ReadUInt32BigEndian(ip.GetAddressBytes());
                    if (!resolved.TryGetValue(key, out var expiry) || entry.Expires > expiry) resolved[key] = entry.Expires;
                }
            lock (_targetGate)
            {
                var previous = _targets;
                bool sameDomains = previous.Domains.SetEquals(names);
                _targets = new(names, exact, subnets, resolved,
                    sameDomains ? previous.Version : Interlocked.Increment(ref _targetVersion), sameDomains ? previous.LearnedIps : null);
                _hops.Clear();
                lock (_udpGate) _udpFlows.Clear();
            }
        }

        internal static bool IsDomainTargeted(string domain, HashSet<string> targets)
        {
            if (targets.Contains(domain)) return true;
            foreach (string target in targets)
                if (domain.Length > target.Length && domain[domain.Length - target.Length - 1] == '.' &&
                    domain.EndsWith(target, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private bool IsIpTargeted(uint ip, Targets targets)
        {
            if (targets.ExactIps.Contains(ip)) return true;
            foreach (var subnet in targets.Subnets)
                if ((ip & subnet.Mask) == subnet.Network) return true;
            if (targets.ResolvedIps.TryGetValue(ip, out var expiry) && expiry > _hopClock.GetUtcNow()) return true;
            return targets.LearnedIps.TryGetValue(ip, out long expires) && expires > Environment.TickCount64;
        }

        internal bool TrySendDnsResponse(byte[] query, long targetVersion, Func<bool> send)
        {
            lock (_targetGate)
            {
                var targets = _targets;
                return targets.Version == targetVersion && DnsWire.TryReadQuestion(query, out var question) &&
                    IsDomainTargeted(question.Name, targets.Domains) && send();
            }
        }

        public PacketDecision Process(Span<byte> packet, bool outbound)
        {
            if (!TryReadHeaders(packet, out int ipLength, out int transportLength)) return new(PacketAction.Pass);
            var targets = _targets;
            var options = _options;
            uint destination = Read32(packet, 16);
            ushort destinationPort = Read16(packet, ipLength + 2);

            if (packet[9] == 17)
            {
                if (outbound && destinationPort == 443 && options.BlockQuic && IsIpTargeted(destination, targets))
                    return new(PacketAction.Drop);
                if (outbound && destinationPort == 53)
                {
                    var dns = packet[(ipLength + 8)..];
                    if (DnsWire.TryReadMessage(dns, out var question, out _) && question.Class == 1 &&
                        !question.Name.Equals(upstreamDnsHost, StringComparison.OrdinalIgnoreCase) &&
                        (dns[2] & 0x80) == 0 && IsDomainTargeted(question.Name, targets.Domains))
                        return new(PacketAction.DnsQuery, question.Name, targets.Version);
                }
                return outbound ? ProcessUdp(packet, ipLength, targets, options) : new(PacketAction.Pass);
            }
            if (!outbound) { ObserveHop(packet, ipLength, targets); return new(PacketAction.Pass); }
            if ((packet[ipLength + 13] & 0x26) != 0) return new(PacketAction.Pass);
            var payload = packet[(ipLength + transportLength)..];
            if (options.MaxPayloadSize > 0 && payload.Length > options.MaxPayloadSize) return new(PacketAction.Pass);
            string host;
            int hostOffset;
            if (destinationPort == 443)
            {
                if (!TryReadSni(payload, out host, out hostOffset)) return new(PacketAction.Pass);
            }
            else if (destinationPort == 80)
            {
                if (!TryReadHttpHost(payload, out var header)) return new(PacketAction.Pass);
                host = header.Host;
                hostOffset = header.HostOffset;
            }
            else return new(PacketAction.Pass);

            if (!IsDomainTargeted(host, targets.Domains)) return new(PacketAction.Pass);
            int split = options.SplitAtHostname ? hostOffset + host.Length / 2 : options.TcpSplitSize;
            byte autoTtl = options.FakeAutoTtl ? GetAutoTtl(packet, ipLength, targets) : (byte)0;
            if (options.TcpFragmentation)
                return new(PacketAction.Fragment, host, Options: options, SplitPosition: split, AutoTtl: autoTtl);
            return options.HasFakeMethods || (destinationPort == 80 && options.HasHttpMethods)
                ? new(PacketAction.Modify, host, Options: options, AutoTtl: autoTtl) : new(PacketAction.Pass);
        }

        public void LearnDnsResponse(byte[] query, byte[] reply, long targetVersion)
        {
            var targets = _targets;
            if (targets.Version != targetVersion || !DnsWire.IsResponseFor(query, reply) ||
                !DnsWire.TryReadQuestion(query, out var question) || !IsDomainTargeted(question.Name, targets.Domains)) return;
            long now = Environment.TickCount64;
            foreach (var pair in targets.LearnedIps)
                if (pair.Value <= now) targets.LearnedIps.TryRemove(pair.Key, out _);
            foreach (var (ip, ttl) in DnsWire.ReadIpv4Answers(reply))
                if (ttl > 0) targets.LearnedIps[BinaryPrimitives.ReadUInt32BigEndian(IPAddress.Parse(ip).GetAddressBytes())] = now + (long)ttl * 1000;
        }

        internal static byte[] BuildDnsReply(ReadOnlySpan<byte> original, byte[] reply)
        {
            if (!TryReadHeaders(original, out int ipLength, out _) || original[9] != 17 || Read16(original, ipLength + 2) != 53 ||
                !DnsWire.IsResponseFor(original[(ipLength + 8)..], reply)) throw new ArgumentException("Mismatched DNS reply.");
            reply = DnsWire.LimitUdpResponse(original[(ipLength + 8)..], reply, 65535 - ipLength - 8);
            byte[] packet = new byte[ipLength + 8 + reply.Length];
            original[..ipLength].CopyTo(packet);
            original.Slice(16, 4).CopyTo(packet.AsSpan(12));
            original.Slice(12, 4).CopyTo(packet.AsSpan(16));
            packet[8] = 64;
            Write16(packet, 2, (ushort)packet.Length);
            Write16(packet, ipLength, 53);
            Write16(packet, ipLength + 2, Read16(original, ipLength));
            Write16(packet, ipLength + 4, (ushort)(8 + reply.Length));
            reply.CopyTo(packet, ipLength + 8);
            return packet;
        }
        internal static bool TryReadHeaders(ReadOnlySpan<byte> packet, out int ipLength, out int transportLength)
        {
            ipLength = transportLength = 0;
            if (packet.Length < 20 || packet[0] >> 4 != 4 || Read16(packet, 2) != packet.Length ||
                (Read16(packet, 6) & 0x3FFF) != 0) return false;
            ipLength = (packet[0] & 0x0F) * 4;
            if (ipLength < 20 || ipLength > packet.Length) return false;
            if (packet[9] == 17)
            {
                transportLength = 8;
                return ipLength + 8 <= packet.Length && Read16(packet, ipLength + 4) == packet.Length - ipLength;
            }
            if (packet[9] != 6 || ipLength + 20 > packet.Length) return false;
            transportLength = (packet[ipLength + 12] >> 4) * 4;
            return transportLength >= 20 && ipLength + transportLength <= packet.Length;
        }

        internal static bool TryReadDnsQuestion(ReadOnlySpan<byte> dns, out string domain, out int end)
        {
            bool valid = DnsWire.TryReadQuestion(dns, out var question) && question.Class == 1;
            domain = valid ? question.Name.ToLowerInvariant() : string.Empty;
            end = valid ? question.End : 12;
            return valid;
        }
        internal static bool TryReadSni(ReadOnlySpan<byte> payload, out string host)
            => TryReadSni(payload, out host, out _);

        internal static bool TryReadSni(ReadOnlySpan<byte> payload, out string host, out int hostOffset)
        {
            host = string.Empty;
            hostOffset = -1;
            if (payload.Length < 44 || payload[0] != 0x16 || payload[1] != 3 || payload[5] != 1) return false;
            int recordEnd = 5 + Read16(payload, 3);
            int handshakeEnd = 9 + (payload[6] << 16 | payload[7] << 8 | payload[8]);
            if (handshakeEnd > recordEnd || handshakeEnd < 44) return false;
            var hello = payload[..Math.Min(handshakeEnd, payload.Length)];
            int pos = 43;
            pos += 1 + hello[pos];
            if (pos + 2 > hello.Length) return false;
            pos += 2 + Read16(hello, pos);
            if (pos >= hello.Length) return false;
            pos += 1 + hello[pos];
            if (pos + 2 > hello.Length) return false;
            int end = pos + 2 + Read16(hello, pos);
            pos += 2;
            if (end != handshakeEnd) return false;
            while (pos + 4 <= Math.Min(end, hello.Length))
            {
                int type = Read16(hello, pos), length = Read16(hello, pos + 2);
                pos += 4;
                if (pos + length > end || pos + length > hello.Length) return false;
                if (type == 0)
                {
                    if (length < 5 || Read16(hello, pos) != length - 2 || hello[pos + 2] != 0) return false;
                    int nameLength = Read16(hello, pos + 3);
                    if (nameLength is < 1 or > 253 || nameLength + 5 != length) return false;
                    var name = hello.Slice(pos + 5, nameLength);
                    if (!IsHostName(name)) return false;
                    host = Encoding.ASCII.GetString(name).ToLowerInvariant();
                    hostOffset = pos + 5;
                    return true;
                }
                pos += length;
            }
            return false;
        }

        private static bool IsHostName(ReadOnlySpan<byte> name)
        {
            foreach (byte value in name)
                if (!(value is >= (byte)'a' and <= (byte)'z' or >= (byte)'A' and <= (byte)'Z' or
                    >= (byte)'0' and <= (byte)'9' or (byte)'.' or (byte)'-' or (byte)'_')) return false;
            return true;
        }

        private readonly record struct HttpHostHeader(string Host, int NameOffset, int ValueOffset, int ValueLength, int HostOffset);

        private static bool TryReadHttpHost(ReadOnlySpan<byte> payload, out HttpHostHeader header)
        {
            header = default;
            string text = Encoding.ASCII.GetString(payload[..Math.Min(payload.Length, 8192)]);
            if (!(text.StartsWith("GET ") || text.StartsWith("POST ") || text.StartsWith("HEAD ")) ||
                !text.Contains("\r\n\r\n")) return false;
            int requestEnd = text.IndexOf("\r\n", StringComparison.Ordinal);
            string[] request = text[..requestEnd].Split(' ');
            if (request.Length != 3 || request[1].Length == 0 || request[2] is not ("HTTP/1.0" or "HTTP/1.1")) return false;
            int pos = requestEnd + 2;
            bool found = false;
            while (pos < text.Length)
            {
                int end = text.IndexOf("\r\n", pos, StringComparison.Ordinal);
                if (end < 0) return false;
                string line = text[pos..end];
                if (line.Length == 0) break;
                if (line[0] is ' ' or '\t') return false;
                if (line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
                {
                    if (found) return false;
                    string value = line[5..].Trim(' ', '\t');
                    string hostname = value;
                    int colon = value.IndexOf(':');
                    if (colon >= 0)
                    {
                        if (!ushort.TryParse(value[(colon + 1)..], out ushort port) || port == 0) return false;
                        hostname = value[..colon];
                    }
                    if (!DomainName.TryNormalize(hostname, out string host)) return false;
                    int start = pos + 5;
                    while (start < end && text[start] is ' ' or '\t') start++;
                    header = new(host, pos, pos + 5, end - pos - 5, start);
                    found = true;
                }
                pos = end + 2;
            }
            return found;
        }

        internal static IReadOnlyList<PacketInjection> BuildInjections(ReadOnlySpan<byte> original, PacketDecision decision)
        {
            if (original.Length >= 20 && original[9] == 17) return BuildUdpInjections(original, decision);
            if (decision.Options is not { } options || decision.Action is not (PacketAction.Fragment or PacketAction.Modify) ||
                !TryReadHeaders(original, out int ipLength, out int tcpLength) || original[9] != 6)
                return [new(original.ToArray())];
            byte[] packet = original.ToArray();
            int payloadOffset = ipLength + tcpLength;
            var payload = packet.AsSpan(payloadOffset);
            int hostOffset = -1, hostLength = 0;
            if (Read16(packet, ipLength + 2) == 443 && TryReadSni(payload, out string sni, out hostOffset)) hostLength = sni.Length;
            else if (Read16(packet, ipLength + 2) == 80 && TryReadHttpHost(payload, out var header))
            {
                hostOffset = header.HostOffset; hostLength = header.Host.Length;
                if (options.HttpHostHeaderCase) "hOsT"u8.CopyTo(payload.Slice(header.NameOffset, 4));
                if (options.HttpHostDomainCase)
                    for (int i = 0; i < hostLength; i++)
                    {
                        byte value = payload[hostOffset + i];
                        if (value is >= (byte)'A' and <= (byte)'Z') value += 32;
                        if ((i & 1) == 0 && value is >= (byte)'a' and <= (byte)'z') value -= 32;
                        payload[hostOffset + i] = value;
                    }
                bool donated = false;
                if ((options.HttpMethodSpace || options.HttpMethodEol) && header.ValueLength > 0 && payload[header.ValueOffset] is (byte)' ' or (byte)'\t')
                {
                    int insert = options.HttpMethodSpace ? payload.IndexOf((byte)' ') : 0;
                    byte[] changed = new byte[payload.Length];
                    payload[..insert].CopyTo(changed);
                    changed[insert] = options.HttpMethodSpace ? (byte)' ' : (byte)'\n';
                    payload.Slice(insert, header.ValueOffset - insert).CopyTo(changed.AsSpan(insert + 1));
                    payload[(header.ValueOffset + 1)..].CopyTo(changed.AsSpan(header.ValueOffset + 1));
                    changed.CopyTo(payload); donated = true;
                }
                if (!donated && options.HttpHostRemoveSpace && header.ValueLength > 0 && payload[header.ValueOffset] == (byte)' ')
                {
                    // Move optional whitespace to the end of the value, preserving TCP stream length.
                    payload.Slice(header.ValueOffset + 1, header.ValueLength - 1).CopyTo(payload.Slice(header.ValueOffset));
                    payload[header.ValueOffset + header.ValueLength - 1] = (byte)' ';
                    hostOffset--;
                }
                else if (!donated && !options.HttpHostRemoveSpace && options.HttpHostTab && header.ValueLength > 0 && payload[header.ValueOffset] == (byte)' ')
                    payload[header.ValueOffset] = (byte)'\t';
            }
            int fakeHostOffset = hostOffset;
            if (Read16(original, ipLength + 2) == 80 && TryReadHttpHost(original[payloadOffset..], out var originalHeader)) fakeHostOffset = originalHeader.HostOffset;
            var fakes = BuildFakes(original, options, fakeHostOffset, hostLength, decision.AutoTtl);
            int[] cuts = [];
            List<byte[]> parts;
            if (options.TcpFragmentation)
            {
                cuts = options.MultiSplit ? TcpSplitPositions.Resolve(options.SplitPositions, payload.Length, hostOffset, decision.Target,
                    Read16(packet, ipLength + 2) == 80 ? 1 : 0) : [decision.SplitPosition];
                parts = SplitTcpPackets(packet, cuts);
                if (options.ReverseSegments) parts.Reverse();
            }
            else parts = [packet];
            return CombineInjections(parts, fakes, cuts, options);
        }

        internal static (byte[] Head, byte[] Tail) SplitTcpPacket(ReadOnlySpan<byte> packet, int split = 2)
        {
            if (!TryReadHeaders(packet, out int ipLength, out int tcpLength) || packet[9] != 6)
                throw new ArgumentException("Invalid TCP packet.", nameof(packet));
            int payloadOffset = ipLength + tcpLength;
            if (split <= 0 || split >= packet.Length - payloadOffset) throw new ArgumentOutOfRangeException(nameof(split));
            byte[] head = packet[..(payloadOffset + split)].ToArray();
            byte[] tail = new byte[packet.Length - split];
            packet[..payloadOffset].CopyTo(tail);
            packet[(payloadOffset + split)..].CopyTo(tail.AsSpan(payloadOffset));
            Write16(head, 2, (ushort)head.Length);
            Write16(tail, 2, (ushort)tail.Length);
            Write32(tail, ipLength + 4, unchecked(Read32(packet, ipLength + 4) + (uint)split));
            head[ipLength + 13] &= 0xF6; // Keep FIN and PSH on the final segment.
            return (head, tail);
        }

        private static ushort Read16(ReadOnlySpan<byte> bytes, int offset) => BinaryPrimitives.ReadUInt16BigEndian(bytes[offset..]);
        private static uint Read32(ReadOnlySpan<byte> bytes, int offset) => BinaryPrimitives.ReadUInt32BigEndian(bytes[offset..]);
        private static void Write16(Span<byte> bytes, int offset, ushort value) => BinaryPrimitives.WriteUInt16BigEndian(bytes[offset..], value);
        private static void Write32(Span<byte> bytes, int offset, uint value) => BinaryPrimitives.WriteUInt32BigEndian(bytes[offset..], value);
    }
}
