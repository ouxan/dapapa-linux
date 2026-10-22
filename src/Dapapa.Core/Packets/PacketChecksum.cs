using System.Buffers.Binary;

namespace Dapapa.Core
{
    internal static class PacketChecksum
    {
        /// <summary>
        /// Recomputes IPv4 and transport checksums before injection, then corrupts them for fakes that must be rejected.
        /// UDP fragments keep the full-datagram checksum written by the processor.
        /// </summary>
        public static void Prepare(Span<byte> packet, bool invalidTcpChecksum = false, bool invalidUdpChecksum = false)
        {
            if (packet.Length < 20 || packet[0] >> 4 != 4) throw new ArgumentException("Invalid IPv4 packet.", nameof(packet));
            int ipLength = (packet[0] & 0x0F) * 4;
            if (ipLength < 20 || ipLength > packet.Length) throw new ArgumentException("Invalid IPv4 header.", nameof(packet));
            BinaryPrimitives.WriteUInt16BigEndian(packet[10..], 0);
            BinaryPrimitives.WriteUInt16BigEndian(packet[10..], Fold(Sum(packet[..ipLength], 0)));

            bool fragment = (BinaryPrimitives.ReadUInt16BigEndian(packet[6..]) & 0x3FFF) != 0;
            byte protocol = packet[9];
            if (protocol == 6 && !fragment && packet.Length >= ipLength + 20)
                WriteTransportChecksum(packet, ipLength, 16);
            else if (protocol == 17 && !fragment && packet.Length >= ipLength + 8)
                WriteTransportChecksum(packet, ipLength, 6);

            if (invalidUdpChecksum)
            {
                if (protocol != 17 || fragment) throw new ArgumentException("Invalid fake UDP packet.", nameof(packet));
                ushort checksum = BinaryPrimitives.ReadUInt16BigEndian(packet[(ipLength + 6)..]);
                BinaryPrimitives.WriteUInt16BigEndian(packet[(ipLength + 6)..], (ushort)(checksum == 1 ? 2 : checksum ^ 1));
            }
            if (invalidTcpChecksum)
            {
                if (protocol != 6 || fragment) throw new ArgumentException("Invalid fake TCP packet.", nameof(packet));
                packet[ipLength + 16] ^= 0x01;
            }
        }

        public static bool IsValid(ReadOnlySpan<byte> packet)
        {
            if (packet.Length < 20 || packet[0] >> 4 != 4) return false;
            int ipLength = (packet[0] & 0x0F) * 4;
            if (ipLength < 20 || ipLength > packet.Length || Fold(Sum(packet[..ipLength], 0)) != 0) return false;
            if ((BinaryPrimitives.ReadUInt16BigEndian(packet[6..]) & 0x3FFF) != 0) return true;
            if (packet[9] == 17 && packet.Length >= ipLength + 8 && BinaryPrimitives.ReadUInt16BigEndian(packet[(ipLength + 6)..]) == 0)
                return true;
            return packet[9] is not (6 or 17) || Fold(Sum(packet[ipLength..], PseudoHeader(packet, ipLength))) == 0;
        }

        private static void WriteTransportChecksum(Span<byte> packet, int ipLength, int offset)
        {
            BinaryPrimitives.WriteUInt16BigEndian(packet[(ipLength + offset)..], 0);
            ushort checksum = Fold(Sum(packet[ipLength..], PseudoHeader(packet, ipLength)));
            if (checksum == 0 && packet[9] == 17) checksum = 0xFFFF;
            BinaryPrimitives.WriteUInt16BigEndian(packet[(ipLength + offset)..], checksum);
        }

        private static uint PseudoHeader(ReadOnlySpan<byte> packet, int ipLength)
        {
            uint sum = (uint)packet[9] + (uint)(packet.Length - ipLength);
            for (int i = 12; i < 20; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(packet[i..]);
            return sum;
        }

        private static uint Sum(ReadOnlySpan<byte> data, uint sum)
        {
            int i = 0;
            for (; i + 1 < data.Length; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(data[i..]);
            if (i < data.Length) sum += (uint)data[i] << 8;
            return sum;
        }

        private static ushort Fold(uint sum)
        {
            while (sum >> 16 != 0) sum = (sum & 0xFFFF) + (sum >> 16);
            return (ushort)~sum;
        }
    }
}
