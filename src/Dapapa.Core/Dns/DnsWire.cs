using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace Dapapa.Core
{
    internal readonly record struct DnsQuestion(string Name, ushort Type, ushort Class, int End);
    internal readonly record struct DnsRecord(ushort Type, ushort Class, uint Ttl, int TtlOffset, int DataOffset, int Length, int Section);

    internal static class DnsWire
    {
        public static ushort Read16(ReadOnlySpan<byte> data, int offset) => BinaryPrimitives.ReadUInt16BigEndian(data[offset..]);
        public static uint Read32(ReadOnlySpan<byte> data, int offset) => BinaryPrimitives.ReadUInt32BigEndian(data[offset..]);
        public static void Write16(Span<byte> data, int offset, ushort value) => BinaryPrimitives.WriteUInt16BigEndian(data[offset..], value);
        public static void Write32(Span<byte> data, int offset, uint value) => BinaryPrimitives.WriteUInt32BigEndian(data[offset..], value);

        public static byte[] CreateQuery(string domain, ushort type = 1, ushort id = 0)
        {
            domain = DomainDnsResolver.CleanDomainName(domain);
            if (domain.Length is < 1 or > 253) throw new ArgumentException("Invalid DNS name.", nameof(domain));
            var data = new List<byte>(new byte[] { (byte)(id >> 8), (byte)id, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 });
            foreach (string label in domain.Split('.'))
            {
                if (label.Length is < 1 or > 63 || !IsHostName(Encoding.UTF8.GetBytes(label)))
                    throw new ArgumentException("Invalid DNS label.", nameof(domain));
                data.Add((byte)label.Length);
                data.AddRange(Encoding.ASCII.GetBytes(label));
            }
            data.AddRange(new byte[] { 0, (byte)(type >> 8), (byte)type, 0, 1 });
            return [.. data];
        }

        public static bool TryReadQuestion(ReadOnlySpan<byte> data, out DnsQuestion question)
        {
            question = default;
            int offset = 12;
            if (data.Length < 12 || (data[2] & 0x78) != 0 || Read16(data, 4) != 1 ||
                !TryReadName(data, ref offset, out string name) || name.Length == 0 || offset + 4 > data.Length) return false;
            question = new(name, Read16(data, offset), Read16(data, offset + 2), offset + 4);
            return true;
        }

        public static bool TryReadMessage(ReadOnlySpan<byte> data, out DnsQuestion question, out List<DnsRecord> records)
        {
            question = default;
            records = [];
            if (data.Length > 65535 || !TryReadQuestion(data, out question)) return false;
            int offset = question.End;
            for (int section = 0; section < 3; section++)
            {
                int count = Read16(data, 6 + section * 2);
                for (int i = 0; i < count; i++)
                {
                    if (!TryReadName(data, ref offset, out _) || offset + 10 > data.Length) return false;
                    ushort type = Read16(data, offset), recordClass = Read16(data, offset + 2);
                    uint ttl = Read32(data, offset + 4);
                    int length = Read16(data, offset + 8), start = offset + 10;
                    if (start + length > data.Length) return false;
                    if (type == 1 && recordClass == 1 && length != 4 || type == 28 && recordClass == 1 && length != 16) return false;
                    if (type == 5)
                    {
                        int nameOffset = start;
                        if (!TryReadName(data, ref nameOffset, out _) || nameOffset != start + length) return false;
                    }
                    records.Add(new(type, recordClass, ttl, offset + 4, start, length, section));
                    offset = start + length;
                }
            }
            return offset == data.Length;
        }

        public static bool IsResponseFor(ReadOnlySpan<byte> query, ReadOnlySpan<byte> response)
        {
            return TryReadQuestion(query, out var expected) && (query[2] & 0x80) == 0 &&
                TryReadMessage(response, out var actual, out _) && (response[2] & 0x80) != 0 &&
                Read16(query, 0) == Read16(response, 0) && expected.Type == actual.Type && expected.Class == actual.Class &&
                expected.Name.Equals(actual.Name, StringComparison.OrdinalIgnoreCase);
        }

        public static byte[] ErrorResponse(ReadOnlySpan<byte> query, int code, bool truncated = false)
        {
            bool valid = TryReadQuestion(query, out var question);
            byte[] reply = new byte[valid ? question.End : 12];
            query[..Math.Min(query.Length, reply.Length)].CopyTo(reply);
            ushort flags = (ushort)(0x8080 | (query.Length >= 4 ? Read16(query, 2) & 0x0110 : 0) | (code & 15));
            if (truncated) flags |= 0x0200;
            Write16(reply, 2, flags);
            Write16(reply, 4, valid ? (ushort)1 : (ushort)0);
            reply.AsSpan(6, 6).Clear();
            return reply;
        }

        public static byte[] LimitUdpResponse(ReadOnlySpan<byte> query, byte[] response, int maximum = 65507)
        {
            int limit = 512;
            if (TryReadMessage(query, out _, out var records))
                foreach (var record in records)
                    if (record.Type == 41) limit = Math.Max(512, (int)record.Class);
            return response.Length <= Math.Min(limit, maximum) ? response : ErrorResponse(query, response[3] & 15, true);
        }

        /// <summary>A successful, complete reply without an IPv4 answer: the name exists but has no A record (NODATA).</summary>
        public static bool IsNoIpv4Answer(ReadOnlySpan<byte> response) =>
            TryReadMessage(response, out _, out var records) && (response[3] & 15) == 0 && (response[2] & 2) == 0
            && !records.Any(r => r.Section == 0 && r.Type == 1 && r.Class == 1);

        public static List<(string Ip, uint Ttl)> ReadIpv4Answers(ReadOnlySpan<byte> response)
        {
            if (!TryReadMessage(response, out _, out var records) || (response[3] & 15) != 0 || (response[2] & 2) != 0) return [];
            var result = new List<(string, uint)>();
            uint minimum = records.Where(r => r.Section == 0 && r.Class == 1 && r.Type is 1 or 5)
                .Select(r => r.Ttl).DefaultIfEmpty(0u).Min();
            foreach (var record in records)
                if (record.Section == 0 && record.Type == 1 && record.Class == 1)
                    result.Add((new IPAddress(response.Slice(record.DataOffset, 4)).ToString(), Math.Min(record.Ttl, minimum)));
            return result;
        }

        private static bool TryReadName(ReadOnlySpan<byte> data, ref int offset, out string name)
        {
            name = string.Empty;
            int position = offset;
            bool jumped = false;
            var labels = new List<string>();
            for (int step = 0; step < 128 && position < data.Length; step++)
            {
                int start = position, length = data[position++];
                if (length == 0)
                {
                    if (!jumped) offset = position;
                    name = string.Join('.', labels);
                    return name.Length <= 253;
                }
                if ((length & 0xC0) == 0xC0)
                {
                    if (position >= data.Length) return false;
                    int pointer = ((length & 0x3F) << 8) | data[position++];
                    if (pointer < 12 || pointer >= start) return false;
                    if (!jumped) offset = position;
                    jumped = true;
                    position = pointer;
                    continue;
                }
                if (length > 63 || position + length > data.Length || !IsHostName(data.Slice(position, length))) return false;
                labels.Add(Encoding.ASCII.GetString(data.Slice(position, length)));
                position += length;
            }
            return false;
        }

        private static bool IsHostName(ReadOnlySpan<byte> name)
        {
            foreach (byte value in name)
                if (!(value is >= (byte)'a' and <= (byte)'z' or >= (byte)'A' and <= (byte)'Z' or
                    >= (byte)'0' and <= (byte)'9' or (byte)'-' or (byte)'_')) return false;
            return true;
        }
    }
}
