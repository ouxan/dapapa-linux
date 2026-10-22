using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using Dapapa.Core.Models;
using Dapapa.Core;

internal static partial class Program
{
    private static void ProviderSettings()
    {
        string directory = Path.Combine(Path.GetTempPath(), "dapapa-providers-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            string path = Path.Combine(directory, "settings.json");
            File.WriteAllText(path, "{\"TargetListVersion\":1,\"Language\":\"tr\",\"AutoConnectOnLaunch\":true," +
                "\"DpiMode\":1,\"CustomDpi\":{\"UdpFakeWrongChecksum\":true,\"BlockQuic\":false}," +
                "\"Apps\":[{\"Id\":\"keep\",\"Domain\":\"example.com\",\"Name\":\"Keep\",\"RelatedDomains\":[\"cdn.other.net\"]}]}");
            var store = new SettingsService(path);
            var settings = store.Load();
            Check(settings.DohProvider == DohProvider.Quad9Ecs && settings.GetDohEndpoint() == DohDnsClient.Quad9EcsEndpoint, "Legacy default changed.");
            Check(DohProviders.All.Count == 5 && DohProviders.All.Select(DohProviders.GetEndpoint).Distinct().Count() == 5, "Duplicate/missing preset.");
            foreach (var provider in DohProviders.All)
            {
                settings.DohProvider = provider; store.Save(settings); settings = store.Load();
                Check(settings.DohProvider == provider && settings.GetDohEndpoint() == DohProviders.GetEndpoint(provider), "Provider did not persist.");
                Check(settings.Apps.Count == 1 && settings.Apps[0].Id == "keep" && settings.Apps[0].RelatedDomains.SequenceEqual(["cdn.other.net"]) &&
                    settings.Language == "tr" && settings.AutoConnectOnLaunch && settings.CustomDpi.UdpFakeWrongChecksum && !settings.CustomDpi.BlockQuic &&
                    settings.DpiMode == DpiMode.Custom, "Provider selection altered existing preferences.");
                Check(DohDnsClient.ParseEndpoint(settings.GetDohEndpoint()).Scheme == "https", "Preset is not valid HTTPS.");
                foreach (var language in Enum.GetValues<AppLanguage>())
                {
                    Localization.Current = language;
                    Check(Localization.T(DohProviders.GetLabelKey(provider)) != DohProviders.GetLabelKey(provider) &&
                        Localization.T(DohProviders.GetDescriptionKey(provider)) != DohProviders.GetDescriptionKey(provider), "Provider label/description missing.");
                }
            }
            settings.DohProvider = (DohProvider)999; settings.NormalizeTargets();
            Check(settings.DohProvider == DohProvider.Quad9Ecs && settings.Apps.Count == 1, "Invalid provider failed safe normalization.");
            Check(!Directory.EnumerateFiles(directory, "*.bak").Any(), "Provider addition caused migration.");
            Check(!JsonSerializer.Serialize(settings).Contains("CustomDoh"), "Removed custom URL settings returned.");
        }
        finally { Directory.Delete(directory, true); }
    }

    private static async Task ProviderRouting()
    {
        foreach (var provider in DohProviders.All)
        {
            string endpoint = DohProviders.GetEndpoint(provider);
            var queryHandler = new WireHandler((query, _) => Task.FromResult(WireResponse(Answer(query, "203.0.113.21"))), endpoint);
            var refreshHandler = new WireHandler((query, _) => Task.FromResult(WireResponse(Answer(query, "203.0.113.22"))));
            using var queryHttp = new HttpClient(queryHandler);
            using var refreshHttp = new HttpClient(refreshHandler);
            var queryClient = new DohDnsClient(queryHttp, endpoint: endpoint);
            var refresh = new DnsResolver(new DohDnsClient(refreshHttp));
            await using var local = new LocalDnsService(queryClient, 0);
            local.UpdateTargets(["example.com"]); await local.StartAsync();
            byte[] first = DnsWire.CreateQuery("example.com");
            byte[] reply = await UdpQuery(local.Endpoint, first);
            Check(DnsWire.IsResponseFor(first, reply) && DnsWire.ReadIpv4Answers(reply).Single().Ip == "203.0.113.21", "Preset query went to the wrong provider.");
            Check((await refresh.ResolveIpv4AddressesAsync("example.com")).Single() == "203.0.113.22", "Refresh shared query results.");
            refresh.ClearCache(); await refresh.ResolveIpv4AddressesAsync("example.com");
            byte[] second = DnsWire.CreateQuery("example.com");
            byte[] secondReply = await UdpQuery(local.Endpoint, second);
            Check(DnsWire.IsResponseFor(second, secondReply) && queryHandler.Requests == 1 && refreshHandler.Requests == 2,
                "Refresh invalidated selected provider cache or failed to refresh independently.");
            var probeHandler = new WireHandler((query, _) => Task.FromResult(WireResponse(Answer(query))), endpoint);
            using var latency = new LatencyAndEndpointService(new HttpClient(probeHandler));
            Check(await latency.MeasureDohAsync(endpoint) >= 0 && probeHandler.Requests == 1, "Latency used another provider.");
            Check(queryClient.PendingCount == 0 && DomainDnsResolver.Client.Endpoint.AbsoluteUri == DohDnsClient.CloudflareEndpoint,
                "Preset changed the production IP-refresh endpoint.");
        }
    }

    private static async Task ProviderFailures()
    {
        foreach (var provider in DohProviders.All)
        {
            string endpoint = DohProviders.GetEndpoint(provider);
            foreach (bool timeout in new[] { false, true })
            {
                var handler = new WireHandler(async (query, ct) =>
                {
                    if (timeout) await Task.Delay(Timeout.Infinite, ct);
                    return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
                }, endpoint);
                using var http = new HttpClient(handler);
                var client = new DohDnsClient(http, timeout: TimeSpan.FromMilliseconds(60), endpoint: endpoint);
                await using var local = new LocalDnsService(client, 0);
                local.UpdateTargets(["example.com"]); await local.StartAsync();
                byte[] query = DnsWire.CreateQuery("example.com");
                byte[] reply = await UdpQuery(local.Endpoint, query);
                Check(DnsWire.IsResponseFor(query, reply) && (reply[3] & 15) == 2 && handler.Requests == 1 && client.CachedCount == 0,
                    "Failed provider request was cached, fell back or returned success.");
            }
        }
    }

    private static async Task<int> ProbeProviders()
    {
        var results = new List<object>();
        int failed = 0;
        foreach (var provider in DohProviders.All)
        {
            string endpoint = DohProviders.GetEndpoint(provider);
            using var http = DomainDnsResolver.CreateHttpClient();
            var client = new DohDnsClient(http, endpoint: endpoint);
            string? error = null;
            client.Log += message => error = message;
            foreach (string domain in new[] { "example.com", "discord.com", UploadDomain })
            {
                error = null;
                var timer = System.Diagnostics.Stopwatch.StartNew();
                byte[] query = DnsWire.CreateQuery(domain);
                byte[] reply = await client.ResolveAsync(query);
                bool ok = DnsWire.IsResponseFor(query, reply) && (reply[3] & 15) == 0 && DnsWire.ReadIpv4Answers(reply).Count > 0;
                if (!ok) failed++;
                results.Add(new { Provider = provider.ToString(), Endpoint = endpoint, Domain = domain, Success = ok,
                    ElapsedMilliseconds = timer.ElapsedMilliseconds, Rcode = reply[3] & 15, Error = error });
                Console.WriteLine($"PROBE: {provider}: {domain}: {(ok ? "PASS" : "FAIL")} ({timer.ElapsedMilliseconds} ms){(error == null ? "" : "; " + error)}");
            }
        }
        Console.WriteLine("PROBEJSON:" + JsonSerializer.Serialize(results));
        return failed == 0 ? 0 : 1;
    }
}
