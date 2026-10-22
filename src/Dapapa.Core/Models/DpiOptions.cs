using Dapapa.Core;
using System.Text.Json.Serialization;

namespace Dapapa.Core.Models
{
    public enum DpiMode { Standard, Custom }

    public sealed record DpiOptions
    {
        public static DpiOptions Standard { get; } = new();
        public bool TcpFragmentation { get; init; } = true;
        public bool ReverseSegments { get; init; } = true;
        public bool SplitAtHostname { get; init; }
        public bool HttpHostHeaderCase { get; init; }
        public bool HttpHostDomainCase { get; init; }
        public bool HttpHostRemoveSpace { get; init; }
        public bool FakeWrongChecksum { get; init; }
        public bool MultiSplit { get; init; }
        public string SplitPositions { get; init; } = "2,host,midsld,endhost";
        public int TcpSplitSize { get; init; } = 2;
        public bool FakeWrongSequence { get; init; }
        public bool FakeLowTtl { get; init; }
        public bool FakeAutoTtl { get; init; }
        public int FakeTtl { get; init; } = 2;
        public bool FakeMd5Signature { get; init; }
        public bool FakeTimestamp { get; init; }
        public bool FakeDataNoAck { get; init; }
        public bool FakeRandomizeTls { get; init; }
        public string FakeHostname { get; init; } = "";
        public int FakeRepeats { get; init; } = 1;
        public bool FakeMixSegments { get; init; }
        public int MaxPayloadSize { get; init; }
        public bool HttpMethodSpace { get; init; }
        public bool HttpMethodEol { get; init; }
        public bool HttpHostTab { get; init; }
        public bool BlockQuic { get; init; } = true;
        public bool UdpFakeWrongChecksum { get; init; }
        public bool UdpFakeLowTtl { get; init; }
        public int UdpFakeTtl { get; init; } = 2;
        public int UdpFakeRepeats { get; init; } = 1;
        public bool UdpIpFragmentation { get; init; }
        public int UdpFragmentSize { get; init; } = 8;
        public bool UdpReverseFragments { get; init; }
        public bool UdpLengthPadding { get; init; }
        public int UdpPaddingSize { get; init; } = 2;
        public int UdpPacketLimit { get; init; } = 3;
        public bool UdpQuicInitial { get; init; } = true;
        public bool UdpStun { get; init; }
        public bool UdpWireGuard { get; init; }
        public bool UdpDiscordDiscovery { get; init; }
        public bool UdpUnknown { get; init; }
        [JsonIgnore] public bool HasUdpMethods => UdpFakeWrongChecksum || UdpFakeLowTtl || UdpIpFragmentation || UdpLengthPadding;
        [JsonIgnore] public bool HasHttpMethods => HttpHostHeaderCase || HttpHostDomainCase || HttpHostRemoveSpace || HttpMethodSpace || HttpMethodEol || HttpHostTab;
        [JsonIgnore] public bool HasFakeMethods => FakeWrongChecksum || FakeWrongSequence || FakeLowTtl || FakeAutoTtl || FakeMd5Signature || FakeTimestamp || FakeDataNoAck;
        [JsonIgnore] public bool HasTrafficMethods => TcpFragmentation || HasHttpMethods || HasFakeMethods || BlockQuic || HasUdpMethods;
        public DpiOptions Normalize() => this with
        {
            TcpSplitSize = Math.Clamp(TcpSplitSize, 1, 1024), FakeTtl = Math.Clamp(FakeTtl, 1, 64),
            FakeRepeats = Math.Clamp(FakeRepeats, 1, 6), MaxPayloadSize = Math.Clamp(MaxPayloadSize, 0, 65535),
            UdpFakeTtl = Math.Clamp(UdpFakeTtl, 1, 64), UdpFakeRepeats = Math.Clamp(UdpFakeRepeats, 1, 6),
            UdpFragmentSize = Math.Clamp(UdpFragmentSize / 8 * 8, 8, 1440), UdpPaddingSize = Math.Clamp(UdpPaddingSize, 1, 64),
            UdpPacketLimit = Math.Clamp(UdpPacketLimit, 1, 20),
            SplitPositions = TcpSplitPositions.IsValid(SplitPositions) ? SplitPositions : "2,host,midsld,endhost",
            FakeHostname = string.IsNullOrWhiteSpace(FakeHostname) ? "" : DomainName.TryNormalize(FakeHostname, out var host) ? host : ""
        };
    }
}
