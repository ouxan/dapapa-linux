using System.IO;
using System.Net.Http;
using System.Text.Json;
using Dapapa.Core.Models;
using Dapapa.Core;

internal static partial class Program
{
    private static async Task DomainGroupTestGroups()
    {
        Run("multiline domain lists normalize atomically, reject bad lines and enforce limits", DomainListInputs);
        Run("related domains stay in one group, share selection and persist without remigration", DomainGroups);
        Run("group member changes invalidate learned DNS and preserve overlapping groups", GroupTargetChanges);
        await RunAsync("bulk IP resolution stays within eight requests without queue overflow", BulkResolution);
        await RunAsync("cancelled bulk IP resolution drains outstanding requests", BulkResolutionCancellation);
    }

    private static void DomainListInputs()
    {
        Check(DomainList.TryParse(" EXAMPLE.COM.\r\n\nhttps://API.other.net/path\r\nexample.com\nbücher.de", out var domains, out var error), error);
        Check(domains.SequenceEqual(["example.com", "api.other.net", "xn--bcher-kva.de"]), "List normalization or deduplication changed order.");
        Check(!DomainList.TryParse("example.com\n*.bad.net\nvalid.net", out var invalid, out error) && invalid.Length == 0 && error.Contains("2"),
            "Invalid list partially accepted or missing line number.");
        Check(!DomainList.TryParse("\n \r\n", out _, out _), "Empty list accepted.");
        string limit = string.Join('\n', Enumerable.Range(0, 500).Select(i => $"domain{i}.example"));
        Check(DomainList.TryParse(limit, out domains, out _) && domains.Length == 500, "Valid list limit rejected.");
        Check(!DomainList.TryParse(limit + "\nextra.example", out domains, out _) && domains.Length == 0, "Oversized list partially accepted.");
    }

    private static void DomainGroups()
    {
        var root = new ProtectedApp { Domain = "example.com", Name = "Example" };
        var settings = new AppSettings { TargetListVersion = 1, Apps = [root] };
        string? changed = null;
        root.PropertyChanged += (_, e) => changed = e.PropertyName;
        var choices = new List<DiscoveryChoice> {
            new(new("cdn.other.net", [DiscoveryReason.Resource])) { Selected = true },
            new(new("unselected.other.net", [DiscoveryReason.Resource])) };
        root.AddRelatedDomains(DiscoveryChoice.SelectedDomains(choices, root.GetDomains()));
        Check(settings.Apps.Count == 1 && root.RelatedDomains.SequenceEqual(["cdn.other.net"]), "Discovery created separate list entries.");
        Check(changed == nameof(ProtectedApp.SubtitleText) && root.SubtitleText.Contains("1"), "Grouped subtitle did not notify the UI.");
        root.AddRelatedDomains(["CDN.other.net", "api.other.net"]);
        Check(settings.GetEffectiveDomains().SequenceEqual(["example.com", "cdn.other.net", "api.other.net"]), "Group member targets are missing or duplicated.");
        root.Enabled = false;
        Check(settings.GetEffectiveDomains().Count == 0, "Disabling root left related domains active.");
        root.Enabled = true;
        root.SetDomains(["example.com", "api.other.net"]);
        Check(!settings.GetEffectiveDomains().Contains("cdn.other.net"), "Removed group member remained selected.");
        var independent = new ProtectedApp { Domain = "another.example", RelatedDomains = ["api.other.net"] };
        settings.Apps.Add(independent);
        root.Enabled = false;
        Check(settings.GetEffectiveDomains().SequenceEqual(["another.example", "api.other.net"]), "Shared member depends on another group's selection.");
        settings.Apps.Remove(root);
        Check(settings.GetEffectiveDomains().Contains("api.other.net"), "Deleting one group removed another group's member.");

        string directory = Path.Combine(Path.GetTempPath(), "dapapa-groups-" + Guid.NewGuid());
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "settings.json");
        try
        {
            const string old = "{\"TargetListVersion\":1,\"Apps\":[{\"Id\":\"saved\",\"Name\":\"Saved\",\"Domain\":\"saved.example\",\"Enabled\":false}],\"Language\":\"tr\"}";
            File.WriteAllText(path, old);
            var store = new SettingsService(path);
            var preserved = store.Load();
            Check(preserved.Apps.Count == 1 && !preserved.Apps[0].Enabled && preserved.Apps[0].RelatedDomains.Count == 0 &&
                Directory.GetFiles(directory, "*.bak").Length == 0 && File.ReadAllText(path) == old, "1.0.11 records were reset or guessed into groups.");
            preserved.Apps[0].AddRelatedDomains(["cdn.saved.net", "api.saved.net"]);
            preserved.Apps[0].Enabled = true;
            store.Save(preserved);
            Check(store.Load().GetEffectiveDomains().SequenceEqual(["saved.example", "cdn.saved.net", "api.saved.net"]), "Group domains did not persist.");
            var roundtrip = JsonSerializer.Deserialize<AppSettings>(JsonSerializer.Serialize(settings))!;
            roundtrip.NormalizeTargets();
            Check(roundtrip.GetEffectiveDomains().SequenceEqual(settings.GetEffectiveDomains()), "Independent group roundtrip changed targets.");
        }
        finally { Directory.Delete(directory, true); }
    }

    private static void GroupTargetChanges()
    {
        var root = new ProtectedApp { Domain = "root.example", RelatedDomains = ["cdn.other.net"] };
        var settings = new AppSettings { TargetListVersion = 1, Apps = [root] };
        var processor = new PacketProcessor();
        processor.UpdateTargets(settings.GetEffectiveDomains(), []);
        byte[] query = DnsQuestion("cdn.other.net", 42);
        var packet = UdpPacket(query, "192.0.2.1", "1.1.1.1", 52000, 53);
        var decision = processor.Process(packet, true);
        Check(decision.Action == PacketAction.DnsQuery, "Group member DNS was not selected.");
        Check(processor.Process(TcpPacket(ClientHello("api.cdn.other.net")), true).Action == PacketAction.Fragment,
            "Group member subdomain was not selected for TCP.");
        root.SetDomains(["root.example"]);
        processor.UpdateTargets(settings.GetEffectiveDomains(), []);
        processor.LearnDnsResponse(query, Answer(query), decision.TargetVersion);
        Check(processor.Process(packet, true).Action == PacketAction.Pass &&
            processor.Process(UdpPacket([1, 2], "192.0.2.1", "203.0.113.20", 52000, 443), true).Action == PacketAction.Pass,
            "Late DNS reactivated a removed group member.");
        root.AddRelatedDomains(["cdn.other.net"]);
        processor.UpdateTargets(settings.GetEffectiveDomains(), []);
        Check(processor.Process(packet, true).Action == PacketAction.DnsQuery, "Live group addition was ignored.");
        root.Enabled = false;
        processor.UpdateTargets(settings.GetEffectiveDomains(), []);
        Check(processor.Process(packet, true).Action == PacketAction.Pass, "Group disable did not remove members.");
    }

    private static async Task BulkResolution()
    {
        int active = 0, peak = 0, requests = 0;
        var handler = new WireHandler(async (query, token) =>
        {
            Interlocked.Increment(ref requests);
            int current = Interlocked.Increment(ref active);
            int observed;
            do { observed = Volatile.Read(ref peak); } while (current > observed && Interlocked.CompareExchange(ref peak, current, observed) != observed);
            try { await Task.Delay(3, token); return WireResponse(Answer(query)); }
            finally { Interlocked.Decrement(ref active); }
        });
        using var client = new HttpClient(handler);
        var resolver = new DnsResolver(client);
        string[] domains = Enumerable.Range(0, 120).Select(i => $"domain{i}.example").ToArray();
        var results = await DomainDnsResolver.ResolveAllAsync(domains, resolver);
        Check(results.Count == 120 && results.Values.All(ips => ips.Count == 1) && requests == 120 && peak is > 1 and <= 8,
            "Bulk resolution overflowed the DoH queue or exceeded concurrency.");
        await DomainDnsResolver.ResolveAllAsync(domains, resolver);
        Check(requests == 120, "Bulk resolution ignored TTL cache.");
        await DomainDnsResolver.ResolveAllAsync(domains, resolver, force: true);
        Check(requests == 240 && peak <= 8, "Forced list refresh did not bypass cache within the concurrency limit.");
    }

    private static async Task BulkResolutionCancellation()
    {
        int requests = 0, active = 0;
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var client = new HttpClient(new WireHandler(async (query, token) =>
        {
            Interlocked.Increment(ref active);
            if (Interlocked.Increment(ref requests) == 8) ready.TrySetResult();
            try { await Task.Delay(Timeout.Infinite, token); return WireResponse(Answer(query)); }
            finally { Interlocked.Decrement(ref active); }
        }));
        using var cancellation = new CancellationTokenSource();
        var pending = DomainDnsResolver.ResolveAllAsync(Enumerable.Range(0, 100).Select(i => $"pending{i}.example"), new DnsResolver(client), ct: cancellation.Token);
        await ready.Task.WaitAsync(TimeSpan.FromSeconds(2));
        cancellation.Cancel();
        try { await pending; throw new Exception("Cancelled domain list completed normally."); }
        catch (OperationCanceledException) { }
        Check(active == 0 && requests == 8, "Bulk cancellation left work alive or queued all domains.");
    }
}
