namespace Dapapa.Core
{
    public sealed class TrafficStatisticsService
    {
        internal readonly record struct AdapterSample(string Id, string Name, long Received, long Sent, bool Up);
        private readonly Func<AdapterSample?> _read;
        private readonly TimeProvider _clock;
        private AdapterSample? _previous;
        private long _sampleTimestamp;
        private long? _connectionTimestamp;
        private string _adapterName = "";

        public TrafficStatisticsService() : this(ReadAdapter, TimeProvider.System) { }
        internal TrafficStatisticsService(Func<AdapterSample?> read, TimeProvider clock) { _read = read; _clock = clock; }
        public double DownloadSpeedBytesPerSec { get; private set; }
        public double UploadSpeedBytesPerSec { get; private set; }
        public long SessionDownloadedBytes { get; private set; }
        public long SessionUploadedBytes { get; private set; }
        public long SessionTotalBytes => SessionDownloadedBytes + SessionUploadedBytes;
        public bool IsAdapterUp { get; private set; }
        public string AdapterName => string.IsNullOrWhiteSpace(_adapterName) ? Localization.T("NetworkAdapter") : _adapterName;
        public TimeSpan Uptime => _connectionTimestamp is long start ? _clock.GetElapsedTime(start) : TimeSpan.Zero;

        /// <summary>
        /// Picks the adapter of the most specific IPv4 route towards 1.1.1.1 (no traffic is sent) and reads its kernel
        /// counters. Policy routing tables are not consulted; the main table is used.
        /// </summary>
        private static AdapterSample? ReadAdapter()
        {
            try
            {
                string? name = null;
                int bestPrefix = -1, bestMetric = int.MaxValue;
                foreach (string line in File.ReadLines("/proc/net/route").Skip(1))
                {
                    string[] f = line.Split('	', StringSplitOptions.RemoveEmptyEntries);
                    if (f.Length < 8 || (Convert.ToInt32(f[3], 16) & 1) == 0) continue;
                    uint destination = Convert.ToUInt32(f[1], 16), mask = Convert.ToUInt32(f[7], 16);
                    if ((0x01010101u & mask) != destination) continue;
                    int prefix = System.Numerics.BitOperations.PopCount(mask), metric = int.Parse(f[6]);
                    if (prefix > bestPrefix || prefix == bestPrefix && metric < bestMetric)
                        (name, bestPrefix, bestMetric) = (f[0], prefix, metric);
                }
                if (name == null) return null;
                string sys = Path.Combine("/sys/class/net", name);
                string state = File.ReadAllText(Path.Combine(sys, "operstate")).Trim();
                bool up = state == "up" || state == "unknown" && File.ReadAllText(Path.Combine(sys, "carrier")).Trim() == "1";
                return new(name + "#" + File.ReadAllText(Path.Combine(sys, "ifindex")).Trim(), name,
                    long.Parse(File.ReadAllText(Path.Combine(sys, "statistics", "rx_bytes"))),
                    long.Parse(File.ReadAllText(Path.Combine(sys, "statistics", "tx_bytes"))), up);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException or OverflowException) { return null; }
        }

        public void StartSession()
        {
            _connectionTimestamp = _clock.GetTimestamp();
            SessionDownloadedBytes = SessionUploadedBytes = 0;
            _previous = null;
            Update(false);
        }

        public void StopSession()
        {
            _connectionTimestamp = null;
            DownloadSpeedBytesPerSec = UploadSpeedBytesPerSec = 0;
        }

        public void Reset()
        {
            SessionDownloadedBytes = SessionUploadedBytes = 0;
            DownloadSpeedBytesPerSec = UploadSpeedBytesPerSec = 0;
            if (_connectionTimestamp != null) StartSession();
            else _previous = null;
        }

        public void Update(bool isConnected)
        {
            var current = _read();
            long timestamp = _clock.GetTimestamp();
            IsAdapterUp = current is { Up: true };
            if (current == null || !current.Value.Up)
            {
                _previous = null;
                DownloadSpeedBytesPerSec = UploadSpeedBytesPerSec = 0;
                return;
            }
            _adapterName = current.Value.Name;
            var sample = current.Value;
            if (_previous is not { } previous || previous.Id != sample.Id ||
                sample.Received < previous.Received || sample.Sent < previous.Sent)
            {
                _previous = sample;
                _sampleTimestamp = timestamp;
                DownloadSpeedBytesPerSec = UploadSpeedBytesPerSec = 0;
                return;
            }
            double elapsed = _clock.GetElapsedTime(_sampleTimestamp, timestamp).TotalSeconds;
            if (elapsed <= 0.4) return;
            long received = sample.Received - previous.Received, sent = sample.Sent - previous.Sent;
            DownloadSpeedBytesPerSec = received / elapsed;
            UploadSpeedBytesPerSec = sent / elapsed;
            if (isConnected)
            {
                SessionDownloadedBytes += received;
                SessionUploadedBytes += sent;
            }
            _previous = sample;
            _sampleTimestamp = timestamp;
        }
        public static string FormatSpeed(double bytesPerSec)
        {
            if (bytesPerSec < 1024) return bytesPerSec.ToString("0", Localization.Culture) + " B/s";
            if (bytesPerSec < 1024 * 1024) return (bytesPerSec / 1024.0).ToString("0.0", Localization.Culture) + " KB/s";
            return (bytesPerSec / (1024.0 * 1024.0)).ToString("0.00", Localization.Culture) + " MB/s";
        }

        public static string FormatBytes(long bytes)
        {
            if (bytes < 1024) return bytes.ToString(Localization.Culture) + " B";
            if (bytes < 1024 * 1024) return (bytes / 1024.0).ToString("0.0", Localization.Culture) + " KB";
            if (bytes < 1024L * 1024 * 1024) return (bytes / (1024.0 * 1024.0)).ToString("0.0", Localization.Culture) + " MB";
            return (bytes / (1024.0 * 1024.0 * 1024.0)).ToString("0.00", Localization.Culture) + " GB";
        }

        public static string FormatDuration(TimeSpan span)
        {
            return span.TotalHours >= 1
                ? $"{(int)span.TotalHours:D2}:{span.Minutes:D2}:{span.Seconds:D2}"
                : $"{span.Minutes:D2}:{span.Seconds:D2}";
        }

    }
}
