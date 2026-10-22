using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using Dapapa.Core.Models;
using Dapapa.Core;

internal static partial class Program
{
    private static async Task AuditRegressionTests()
    {
        Run("resolved IP TTL expires without a UI refresh and exact matches allocate nothing", ResolvedIpExpiry);
        Run("adapter switches, disconnects and counter resets retain accurate totals", AdapterSwitches);
        await RunAsync("target removal rejects pending loopback DNS replies", RemovedTargetReply);
        await RunAsync("IP refresh preserves pending selected DNS and learned subdomain IPs", UnchangedDomainsReply);
        await RunAsync("background logs drain, rotate and remain bounded", LogRotation);
    }

    private static void ResolvedIpExpiry()
    {
        var clock = new Clock();
        var processor = new PacketProcessor(timeProvider: clock);
        processor.UpdateTargets(["example.com"], [], [new("203.0.113.20", clock.Now.AddSeconds(10))]);
        byte[] selected = UdpDpiPacket([1]);
        Check(processor.Process(selected, true).Action == PacketAction.Drop, "Unexpired resolved IP was not targeted.");
        clock.Now = clock.Now.AddSeconds(11);
        Check(processor.Process(selected, true).Action == PacketAction.Pass, "Expired resolved IP survived without a UI refresh.");
        processor.UpdateTargets(["example.com"], Enumerable.Range(0, 2000).Select(i => $"10.0.{i / 256}.{i % 256}/32"));
        for (int i = 0; i < 10000; i++) processor.Process(selected, true);
        long before = GC.GetAllocatedBytesForCurrentThread();
        var timer = Stopwatch.StartNew();
        for (int i = 0; i < 100000; i++) Check(processor.Process(selected, true).Action == PacketAction.Pass, "Unselected IP changed.");
        timer.Stop();
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Check(allocated < 1024, "Unmatched UDP hot path allocates per packet.");
        Console.WriteLine($"PERF: 100000 unmatched packets, 2000 exact targets: {timer.Elapsed.TotalMilliseconds:F1} ms, {allocated} allocated bytes; managed processor only.");
        processor.UpdateTargets(["example.com"], ["203.0.113.0/24"]);
        Check(processor.Process(selected, true).Action == PacketAction.Drop, "CIDR support regressed.");
    }

    private sealed class TrafficClock : TimeProvider
    {
        public long Timestamp;
        public override long GetTimestamp() => Timestamp;
        public override long TimestampFrequency => 1000;
        public void Advance() => Timestamp += 1000;
    }
    private static void AdapterSwitches()
    {
        var clock = new TrafficClock();
        TrafficStatisticsService.AdapterSample? sample = new("wifi", "Wi-Fi", 1000, 100, true);
        var stats = new TrafficStatisticsService(() => sample, clock);
        stats.StartSession(); clock.Advance(); sample = new("wifi", "Wi-Fi", 1200, 150, true); stats.Update(true);
        Check(stats.SessionDownloadedBytes == 200 && stats.DownloadSpeedBytesPerSec == 200, "Initial adapter sample wrong.");
        clock.Advance(); sample = new("ethernet", "Ethernet", 900000, 800000, true); stats.Update(true);
        Check(stats.SessionDownloadedBytes == 200 && stats.DownloadSpeedBytesPerSec == 0, "Adapter switch created a traffic spike.");
        clock.Advance(); sample = new("ethernet", "Ethernet", 900300, 800020, true); stats.Update(true);
        Check(stats.SessionDownloadedBytes == 500 && stats.SessionUploadedBytes == 70, "Completed adapter totals were lost.");
        clock.Advance(); sample = null; stats.Update(true); clock.Advance(); sample = new("ethernet", "Ethernet", 999999, 999999, true); stats.Update(true);
        Check(stats.SessionDownloadedBytes == 500 && stats.DownloadSpeedBytesPerSec == 0, "Reconnect compared different baselines.");
        clock.Advance(); sample = new("ethernet", "Ethernet", 1, 1, true); stats.Update(true);
        Check(stats.SessionDownloadedBytes == 500 && stats.Uptime.TotalSeconds == 6, "Counter reset or monotonic uptime failed.");
        stats.Reset(); Check(stats.SessionTotalBytes == 0 && stats.Uptime == TimeSpan.Zero, "Session reset failed.");
    }

    private static async Task RemovedTargetReply()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var handler = new WireHandler(async (query, _) => { started.TrySetResult(); await release.Task; return WireResponse(Answer(query)); });
        using var http = new HttpClient(handler);
        await using var dns = new LocalDnsService(new DohDnsClient(http), 0);
        dns.UpdateTargets([UploadDomain, "keep.example"]); await dns.StartAsync();
        var processor = Processor(UploadDomain, "keep.example");
        int answered = 0;
        dns.Answered += (query, reply) => { Interlocked.Increment(ref answered); processor.LearnDnsResponse(query, reply, processor.TargetVersion); };
        using var socket = new UdpClient(); socket.Connect(dns.Endpoint);
        await socket.SendAsync(DnsWire.CreateQuery(UploadDomain));
        await started.Task.WaitAsync(TimeSpan.FromSeconds(2));
        processor.UpdateTargets(["keep.example"], []); dns.UpdateTargets(["keep.example"]);
        release.TrySetResult();
        using (var quiet = new CancellationTokenSource(TimeSpan.FromMilliseconds(300)))
        {
            bool late = false;
            try { await socket.ReceiveAsync(quiet.Token); late = true; } catch (OperationCanceledException) { }
            Check(!late && answered == 0, "A removed target received or learned from a late reply.");
        }
        byte[] packet = UdpPacket(DnsWire.CreateQuery(UploadDomain), "192.0.2.1", "1.1.1.1", 52000, 53);
        Check(processor.DomainsCount == 1 && processor.Process(packet, true).Action == PacketAction.Pass, "A removed target restored its selection.");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        await socket.SendAsync(DnsWire.CreateQuery("keep.example"), timeout.Token);
        Check(DnsWire.TryReadQuestion((await socket.ReceiveAsync(timeout.Token)).Buffer, out var question) && question.Name == "keep.example", "Remaining target stopped working.");
    }

    private static async Task UnchangedDomainsReply()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var handler = new WireHandler(async (query, _) => { started.TrySetResult(); await release.Task; return WireResponse(Answer(query)); });
        using var http = new HttpClient(handler);
        await using var dns = new LocalDnsService(new DohDnsClient(http), 0);
        dns.UpdateTargets(["example.com"]); await dns.StartAsync();
        var processor = Processor("example.com");
        dns.Answered += (query, reply) => processor.LearnDnsResponse(query, reply, processor.TargetVersion);
        using var socket = new UdpClient(); socket.Connect(dns.Endpoint);
        await socket.SendAsync(DnsWire.CreateQuery("api.example.com"));
        await started.Task.WaitAsync(TimeSpan.FromSeconds(2));
        processor.UpdateTargets(["example.com"], [], [new("192.0.2.44", DateTimeOffset.UtcNow.AddSeconds(30))]);
        dns.UpdateTargets(["example.com"]);
        release.TrySetResult();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        await socket.ReceiveAsync(timeout.Token);
        processor.UpdateTargets(["example.com"], [], [new("192.0.2.45", DateTimeOffset.UtcNow.AddSeconds(30))]);
        Check(processor.Process(UdpDpiPacket([1]), true).Action == PacketAction.Drop,
            "IP-only refresh erased an unexpired subdomain address learned from selected DNS.");
    }

    private static async Task LogRotation()
    {
        string directory = Path.Combine(Path.GetTempPath(), "dapapa-log-test-" + Guid.NewGuid());
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "app.log");
        try
        {
            for (int batch = 0; batch < 7; batch++)
            {
                await using var log = new LogFileWriter(path, 4096);
                for (int i = 0; i < 12; i++) log.Write("batch=" + batch + " " + new string('x', 80));
            }
            var files = Directory.GetFiles(directory);
            Check(files.Length <= 4 && files.Length > 1 && files.All(f => new FileInfo(f).Length <= 4096), "Log rotation did not bound file count and sizes.");
            Check(File.ReadAllText(path).Contains("batch=6"), "Shutdown failed to drain the latest entries.");
        }
        finally { Directory.Delete(directory, true); }
    }
}
