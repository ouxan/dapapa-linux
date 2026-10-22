namespace Dapapa.Helper.Native
{
    /// <summary>
    /// Sends complete IPv4 packets through a raw socket. Packets carry the bypass mark so the capture rules skip them,
    /// and IP_NODEFRAG keeps conntrack from reassembling deliberately fragmented datagrams.
    /// </summary>
    internal sealed unsafe class RawSender : IDisposable
    {
        private readonly int _fd;

        public RawSender(uint bypassMark)
        {
            _fd = LibC.socket(LibC.AF_INET, LibC.SOCK_RAW | LibC.SOCK_CLOEXEC, LibC.IPPROTO_RAW);
            if (_fd < 0) throw LibC.LastError("socket(AF_INET, SOCK_RAW)");
            try
            {
                LibC.SetOption(_fd, LibC.SOL_SOCKET, LibC.SO_MARK, unchecked((int)bypassMark));
                LibC.SetOption(_fd, LibC.SOL_IP, LibC.IP_NODEFRAG, 1);
            }
            catch
            {
                LibC.close(_fd);
                throw;
            }
        }

        public void Send(ReadOnlySpan<byte> packet)
        {
            if (packet.Length < 20) throw new ArgumentException("Invalid IPv4 packet.", nameof(packet));
            var destination = new LibC.SockAddrIn
            {
                Family = LibC.AF_INET,
                Address = (uint)(packet[16] | packet[17] << 8 | packet[18] << 16 | packet[19] << 24)
            };
            fixed (byte* data = packet)
            {
                nint sent = LibC.sendto(_fd, data, (nuint)packet.Length, 0, &destination, (uint)sizeof(LibC.SockAddrIn));
                if (sent < 0) throw LibC.LastError("sendto(raw)");
                if (sent != packet.Length) throw new IOException("Incomplete packet injection.");
            }
        }

        public void Dispose() => LibC.close(_fd);
    }
}
