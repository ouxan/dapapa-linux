using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using Dapapa.Core;

internal static partial class Program
{
    private sealed class WireHandler(Func<byte[], CancellationToken, Task<HttpResponseMessage>> respond, string endpoint = DohDnsClient.CloudflareEndpoint) : HttpMessageHandler
    {
        public int Requests;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Check(request.Method == HttpMethod.Post && request.RequestUri?.AbsoluteUri == endpoint, "Wrong DoH transport.");
            Check(request.Version == HttpVersion.Version20 && request.VersionPolicy == HttpVersionPolicy.RequestVersionOrLower,
                "DoH must negotiate HTTP/2 while allowing local HTTP/1.1 servers.");
            Check(request.Content?.Headers.ContentType?.MediaType == "application/dns-message" &&
                request.Headers.Accept.Any(a => a.MediaType == "application/dns-message"), "Wrong DoH media type.");
            Interlocked.Increment(ref Requests);
            return await respond(await request.Content!.ReadAsByteArrayAsync(cancellationToken), cancellationToken);
        }
    }

    private static HttpResponseMessage WireResponse(byte[] data)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(data) };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
        return response;
    }

    private static byte[] Answer(byte[] query, string ip = "203.0.113.20", uint ttl = 60, int count = 1)
    {
        Check(DnsWire.TryReadQuestion(query, out var question), "Invalid test query.");
        var data = query[..question.End].ToList();
        data[2] |= 0x80; data[3] = 0x80;
        data[6] = (byte)(count >> 8); data[7] = (byte)count;
        data[8] = data[9] = data[10] = data[11] = 0;
        for (int i = 0; i < count; ++i)
        {
            data.AddRange(new byte[] { 0xC0, 12, 0, 1, 0, 1, (byte)(ttl >> 24), (byte)(ttl >> 16), (byte)(ttl >> 8), (byte)ttl, 0, 4 });
            data.AddRange(IPAddress.Parse(ip).GetAddressBytes());
        }
        return [.. data];
    }

    private static byte[] WithEdns(byte[] query, ushort size = 1232, bool dnssec = false)
    {
        byte[] data = [.. query, 0, 0, 41, (byte)(size >> 8), (byte)size, 0, 0, dnssec ? (byte)0x80 : (byte)0, 0, 0, 0];
        Write16(data, 10, 1);
        return data;
    }

    private static byte[] CnameAnswer(byte[] query)
    {
        var data = DnsWire.ErrorResponse(query, 0).ToList();
        data[7] = 2;
        byte[] alias = DnsWire.CreateQuery("cdn.example")[12..^4];
        data.AddRange(new byte[] { 0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 20, 0, (byte)alias.Length });
        int aliasOffset = data.Count;
        data.AddRange(alias);
        data.AddRange(new byte[] { (byte)(0xC0 | aliasOffset >> 8), (byte)aliasOffset, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 20 });
        return [.. data];
    }

    private static byte[] NxDomain(byte[] query)
    {
        var data = DnsWire.ErrorResponse(query, 3).ToList();
        data[9] = 1;
        data.AddRange(new byte[] { 0xC0, 12, 0, 6, 0, 1, 0, 0, 0, 30, 0, 22, 0, 0 });
        data.AddRange(new byte[20]);
        return [.. data];
    }

    private static async Task DnsTestGroups()
    {
        await RunAsync("binary DoH cache keys, TTL, CNAME and HTTP Age", WireCache);
        await RunAsync("DoH coalescing, independent cancellation and invalidation", Coalescing);
        await RunAsync("DoH errors, malformed replies, mismatch and timeout", WireErrors);
        await RunAsync("eight active requests, queue capacity and 512 cache entries", Capacity);
        await RunAsync("a name without an IPv4 address is cached quietly; NXDOMAIN still fails", NoIpv4Answer);
        await RunAsync("real loopback DNS, same IDs, NXDOMAIN and live selection", LoopbackDns);
        await RunAsync("UDP limits and EDNS truncation", UdpLimits);
        await RunAsync("local port conflict prevents protection startup", PortConflict);
        await RunAsync("disconnect cancels DNS, drains work and forbids late replies", DisconnectDns);
        Run("DNS wire parser malformed-message fuzz", WireFuzz);
        await RunAsync("custom DoH routing, provider cache separation and no fallback", CustomDoh);
        Run("default Quad9 ECS provider, legacy settings and URL validation", DohSettings);
        Run("DoH provider settings persist without changing targets or DPI", ProviderSettings);
        await RunAsync("all provider presets route loopback queries with independent refresh caches", ProviderRouting);
        await RunAsync("provider errors and timeouts return SERVFAIL without fallback", ProviderFailures);
        await RunAsync("provider replacement drains pending DNS before reusing the port", ReplaceProvider);
        await RunAsync("real local HTTPS DoH and certificate validation", LocalHttpsDoh);
    }

    private static async Task WireCache()
    {
        var clock = new Clock();
        var cnameHandler = new WireHandler((q, _) => Task.FromResult(WireResponse(CnameAnswer(q))));
        using var http = new HttpClient(cnameHandler);
        var client = new DohDnsClient(http, clock);
        byte[] query = DnsWire.CreateQuery(UploadDomain, id: 7);
        byte[] first = await client.ResolveAsync(query);
        Check(DnsWire.ReadIpv4Answers(first).Single().Ttl == 20, "CNAME lifetime was ignored.");
        clock.Now = clock.Now.AddSeconds(7);
        byte[] secondQuery = [.. query]; Write16(secondQuery, 0, 99);
        byte[] second = await client.ResolveAsync(secondQuery);
        DnsWire.TryReadMessage(second, out _, out var records);
        Check(Read16(second, 0) == 99 && records[0].Ttl == 13 && records[1].Ttl == 53 && client.CachedCount == 1, "Cached IDs or remaining TTL wrong.");
        Check(client.GetExpiry(query) == clock.Now.AddSeconds(13), "Wrong CNAME expiry.");
        clock.Now = clock.Now.AddSeconds(13);
        await client.ResolveAsync(query);
        Check(cnameHandler.Requests == 2, "Expired CNAME answer was reused.");
        var handler = new WireHandler((q, _) => Task.FromResult(WireResponse(Answer(q))));
        using var keyHttp = new HttpClient(handler);
        var keys = new DohDnsClient(keyHttp);
        await keys.ResolveAsync(query);
        await keys.ResolveAsync(secondQuery);
        await keys.ResolveAsync(DnsWire.CreateQuery(UploadDomain, 28));
        await keys.ResolveAsync(WithEdns(query));
        await keys.ResolveAsync(WithEdns(query, dnssec: true));
        byte[] cd = [.. query]; cd[3] |= 0x10;
        await keys.ResolveAsync(cd);
        byte[] caseQuery = [.. query]; caseQuery[13] = (byte)'D';
        await keys.ResolveAsync(caseQuery);
        Check(handler.Requests == 6, "Cache omitted query bytes or included transaction IDs.");
        var resolver = new DnsResolver(keys);
        await resolver.ResolveIpv4AddressesAsync(UploadDomain);
        Check(handler.Requests == 6, "IP refresh does not share packet-query cache.");
        using var ageHttp = new HttpClient(new WireHandler((q, _) =>
        {
            var response = WireResponse(Answer(q)); response.Headers.Age = TimeSpan.FromSeconds(10); return Task.FromResult(response);
        }));
        var aged = new DohDnsClient(ageHttp, clock);
        Check(DnsWire.ReadIpv4Answers(await aged.ResolveAsync(query)).Single().Ttl == 50, "HTTP cache Age ignored.");
    }

    private static async Task Coalescing()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var handler = new WireHandler(async (q, ct) => { started.TrySetResult(); await release.Task.WaitAsync(ct); return WireResponse(Answer(q)); });
        using var http = new HttpClient(handler);
        var client = new DohDnsClient(http);
        byte[] query = DnsWire.CreateQuery(UploadDomain, id: 1);
        using var cancellation = new CancellationTokenSource();
        Task<byte[]> first = client.ResolveAsync(query, cancellation.Token);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(2));
        byte[] other = [.. query]; Write16(other, 0, 2);
        Task<byte[]> second = client.ResolveAsync(other);
        cancellation.Cancel();
        try { await first; throw new Exception("Caller cancellation swallowed."); } catch (OperationCanceledException) { }
        Check(!second.IsCompleted && handler.Requests == 1, "One caller canceled a shared query.");
        client.ClearCache();
        release.SetResult();
        Check(Read16(await second, 0) == 2 && client.CachedCount == 0, "Old request filled the refreshed cache.");
        await client.ResolveAsync(query);
        Check(handler.Requests == 2 && client.CachedCount == 1 && client.PendingCount == 0, "Invalidation or drain failed.");
    }

    private static async Task WireErrors()
    {
        byte[] query = DnsWire.CreateQuery(UploadDomain, id: 25);
        Func<byte[], HttpResponseMessage>[] errors =
        [
            q => new HttpResponseMessage(HttpStatusCode.Forbidden),
            q => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("HTML") },
            q => WireResponse(Answer(q)[..^1]),
            q => { byte[] reply = Answer(q); reply[1]++; return WireResponse(reply); },
            q => WireResponse(Answer(DnsWire.CreateQuery("other.example", id: 25))),
            q => WireResponse(new byte[65536]),
            q => { byte[] reply = Answer(q); reply[q.Length + 1] = 255; return WireResponse(reply); }
        ];
        foreach (var error in errors)
        {
            using var http = new HttpClient(new WireHandler((q, _) => Task.FromResult(error(q))));
            var client = new DohDnsClient(http);
            byte[] reply = await client.ResolveAsync(query);
            Check(DnsWire.IsResponseFor(query, reply) && (reply[3] & 15) == 2 && client.CachedCount == 0, "DoH failure was accepted as success.");
        }
        using var slow = new HttpClient(new WireHandler(async (q, ct) => { await Task.Delay(Timeout.Infinite, ct); return WireResponse(Answer(q)); }));
        var timed = new DohDnsClient(slow, timeout: TimeSpan.FromMilliseconds(50));
        Check(((await timed.ResolveAsync(query))[3] & 15) == 2 && timed.PendingCount == 0, "Timeout did not SERVFAIL or drain.");
    }

    private static async Task Capacity()
    {
        int active = 0, maximum = 0;
        var eightStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancellation = new CancellationTokenSource();
        var handler = new WireHandler(async (q, ct) =>
        {
            int count = Interlocked.Increment(ref active);
            lock (eightStarted) maximum = Math.Max(maximum, count);
            if (count == 8) eightStarted.TrySetResult();
            try { await Task.Delay(Timeout.Infinite, ct); return WireResponse(Answer(q)); }
            finally { Interlocked.Decrement(ref active); }
        });
        using var http = new HttpClient(handler);
        var client = new DohDnsClient(http);
        var tasks = Enumerable.Range(0, 72).Select(i => client.ResolveAsync(DnsWire.CreateQuery($"q{i}.discord.com"), cancellation.Token)).ToArray();
        await eightStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        byte[] overflow = await client.ResolveAsync(DnsWire.CreateQuery("overflow.discord.com"));
        Check(maximum == 8 && handler.Requests == 8 && client.PendingCount == 72 && (overflow[3] & 15) == 2, "Concurrency or queue bound violated.");
        cancellation.Cancel();
        foreach (var task in tasks) try { await task; } catch (OperationCanceledException) { }
        Check(client.PendingCount == 0 && active == 0, "Canceled queue did not drain.");
        using var cacheHttp = new HttpClient(new WireHandler((q, _) => Task.FromResult(WireResponse(Answer(q)))));
        var cached = new DohDnsClient(cacheHttp);
        for (int i = 0; i < 513; ++i) await cached.ResolveAsync(DnsWire.CreateQuery($"q{i}.discord.com"));
        Check(cached.CachedCount == 512, "Cache capacity violated.");
    }

    private static async Task<byte[]> UdpQuery(IPEndPoint endpoint, byte[] query)
    {
        using var socket = new UdpClient(AddressFamily.InterNetwork);
        socket.Connect(endpoint);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        await socket.SendAsync(query, timeout.Token);
        return (await socket.ReceiveAsync(timeout.Token)).Buffer;
    }

    private static async Task LoopbackDns()
    {
        var handler = new WireHandler((q, _) =>
        {
            DnsWire.TryReadQuestion(q, out var question);
            return Task.FromResult(WireResponse(question.Name.StartsWith("missing.") ? NxDomain(q) : CnameAnswer(q)));
        });
        using var http = new HttpClient(handler);
        var client = new DohDnsClient(http);
        await using var dns = new LocalDnsService(client, 0);
        dns.UpdateTargets(["discord.com"]);
        await dns.StartAsync();
        Check(dns.Endpoint.Address.Equals(IPAddress.Loopback) && dns.IsRunning, "DNS is not restricted to IPv4 loopback.");
        byte[] query = DnsWire.CreateQuery("api.discord.com", id: 42);
        var replies = await Task.WhenAll(UdpQuery(dns.Endpoint, query), UdpQuery(dns.Endpoint, query));
        Check(replies.All(r => DnsWire.IsResponseFor(query, r)) && handler.Requests == 1, "Two clients sharing an ID collided.");
        byte[] unrelated = await UdpQuery(dns.Endpoint, DnsWire.CreateQuery("notdiscord.com", id: 42));
        Check((unrelated[3] & 15) == 5 && handler.Requests == 1, "Unselected DNS escaped to DoH.");
        byte[] missing = DnsWire.CreateQuery("missing.discord.com", id: 42);
        byte[] nx = await UdpQuery(dns.Endpoint, missing);
        Check(DnsWire.IsResponseFor(missing, nx) && (nx[3] & 15) == 3 && Read16(nx, 8) == 1, "NXDOMAIN authority was lost.");
        await UdpQuery(dns.Endpoint, missing);
        Check(handler.Requests == 3, "NXDOMAIN was cached as a positive answer.");
        dns.UpdateTargets([]);
        Check(((await UdpQuery(dns.Endpoint, query))[3] & 15) == 5, "Live deselection ignored.");
        dns.UpdateTargets(["discord.com"]);
        byte[] reselected = await UdpQuery(dns.Endpoint, query);
        Check(DnsWire.IsResponseFor(query, reselected), "Live reselection failed.");
    }

    private static async Task UdpLimits()
    {
        using var http = new HttpClient(new WireHandler((q, _) => Task.FromResult(WireResponse(Answer(q, count: 40)))));
        await using var dns = new LocalDnsService(new DohDnsClient(http), 0);
        dns.UpdateTargets(["discord.com"]); await dns.StartAsync();
        byte[] query = DnsWire.CreateQuery("discord.com", id: 10);
        byte[] small = await UdpQuery(dns.Endpoint, query);
        Check(DnsWire.IsResponseFor(query, small) && small.Length <= 512 && (small[2] & 2) != 0 && Read16(small, 6) == 0, "Oversized reply was not truncated cleanly.");
        byte[] edns = WithEdns(query);
        byte[] large = await UdpQuery(dns.Endpoint, edns);
        Check(DnsWire.IsResponseFor(edns, large) && large.Length > 512 && large.Length <= 1232 && (large[2] & 2) == 0 && Read16(large, 6) == 40, "EDNS size ignored.");
        byte[] tiny = WithEdns(query, 128);
        Check(((await UdpQuery(dns.Endpoint, tiny))[2] & 2) != 0, "EDNS minimum size invalid.");
    }

    private static async Task PortConflict()
    {
        using var http = new HttpClient(new WireHandler((q, _) => Task.FromResult(WireResponse(Answer(q)))));
        await using var occupied = new LocalDnsService(new DohDnsClient(http));
        occupied.UpdateTargets(["discord.com"]);
        try { await occupied.StartAsync(); }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AddressAlreadyInUse)
        {
            // An existing application listener also provides the required port conflict.
        }
        await using var second = new LocalDnsService(new DohDnsClient(http));
        second.UpdateTargets(["discord.com"]);
        try { await second.StartAsync(); throw new Exception("A second local DNS bound an occupied port."); }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AddressAlreadyInUse) { }
        Check(!second.IsRunning, "Local DNS reported running after a bind failure.");
    }

    private static async Task DisconnectDns()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var handler = new WireHandler(async (q, ct) => { started.TrySetResult(); await Task.Delay(Timeout.Infinite, ct); return WireResponse(Answer(q)); });
        using var http = new HttpClient(handler);
        var client = new DohDnsClient(http);
        await using var dns = new LocalDnsService(client, 0);
        dns.UpdateTargets([UploadDomain]); await dns.StartAsync();
        var endpoint = dns.Endpoint;
        using var socket = new UdpClient();
        socket.Connect(endpoint);
        await socket.SendAsync(DnsQuestion(UploadDomain, 42));
        await started.Task.WaitAsync(TimeSpan.FromSeconds(2));
        await dns.StopAsync().WaitAsync(TimeSpan.FromSeconds(2));
        using (var quiet = new CancellationTokenSource(TimeSpan.FromMilliseconds(200)))
        {
            bool late = false;
            try { await socket.ReceiveAsync(quiet.Token); late = true; } catch (OperationCanceledException) { }
            Check(!late && client.PendingCount == 0 && !dns.IsRunning, "Disconnected session sent a late reply or kept DNS work alive.");
        }
        await using var next = new LocalDnsService(client, endpoint.Port);
        next.UpdateTargets(["discord.com"]); await next.StartAsync();
        Check(next.IsRunning, "Disconnected DNS port was not released.");
    }

    private static void WireFuzz()
    {
        byte[] query = WithEdns(DnsWire.CreateQuery(UploadDomain));
        byte[][] seeds = [query, Answer(query), CnameAnswer(query), NxDomain(query)];
        var random = new Random(53);
        foreach (var seed in seeds)
        {
            for (int length = 0; length < seed.Length; ++length)
                Check(!DnsWire.TryReadMessage(seed.AsSpan(0, length), out _, out _), "Incomplete DNS accepted.");
            for (int i = 0; i < 2000; ++i)
            {
                byte[] data = [.. seed]; data[random.Next(data.Length)] = (byte)random.Next(256);
                DnsWire.TryReadMessage(data, out _, out _);
                DnsWire.IsResponseFor(query, data);
                DnsWire.ReadIpv4Answers(data);
            }
        }
    }

    private static async Task LiveDoh(string? endpoint = null)
    {
        using var http = DomainDnsResolver.CreateHttpClient();
        var client = new DohDnsClient(http, endpoint: endpoint);
        client.Log += Console.WriteLine;
        if (endpoint != null)
        {
            byte[] query = DnsWire.CreateQuery("discord.com", id: 105);
            using var request = new HttpRequestMessage(HttpMethod.Post, client.Endpoint)
            {
                Version = HttpVersion.Version20,
                VersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
                Content = new ByteArrayContent(query)
            };
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(4));
            using var response = await http.SendAsync(request, timeout.Token);
            response.EnsureSuccessStatusCode();
            Check(response.Version >= HttpVersion.Version20, "Live Quad9 did not negotiate HTTP/2.");
            byte[] reply = await response.Content.ReadAsByteArrayAsync(timeout.Token);
            Check(response.Content.Headers.ContentType?.MediaType == "application/dns-message" &&
                DnsWire.IsResponseFor(query, reply), "Invalid live HTTP/2 DNS reply.");
            Console.WriteLine($"LIVE: {client.Endpoint.Host}: HTTP/{response.Version}");
        }
        await using var dns = new LocalDnsService(client, 0);
        dns.UpdateTargets(["discord.com", UploadDomain]); await dns.StartAsync();
        foreach (string name in new[] { "discord.com", UploadDomain })
        {
            byte[] query = DnsWire.CreateQuery(name, id: 103);
            using var socket = new UdpClient(AddressFamily.InterNetwork);
            socket.Connect(dns.Endpoint);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(6));
            await socket.SendAsync(query, timeout.Token);
            byte[] reply = (await socket.ReceiveAsync(timeout.Token)).Buffer;
            Check(DnsWire.IsResponseFor(query, reply) && DnsWire.ReadIpv4Answers(reply).Count > 0, "Live binary DNS failed: " + name);
            Console.WriteLine($"LIVE: {name}: {string.Join(", ", DnsWire.ReadIpv4Answers(reply).Select(a => a.Ip))}");
        }
        using var latency = new LatencyAndEndpointService();
        long elapsed = await latency.MeasureDohAsync(endpoint);
        Check(elapsed >= 0, "Live selected-provider DoH latency failed.");
        Console.WriteLine($"LIVE: {client.Endpoint.Host}: DNS query latency {elapsed} ms");
    }

    private static byte[] NoData(byte[] query, uint soaTtl)
    {
        byte[] reply = NxDomain(query);
        reply[3] &= 0xF0;
        Write32(reply, query.Length + 6, soaTtl);
        return reply;
    }

    private static async Task NoIpv4Answer()
    {
        var clock = new Clock();
        uint soaTtl = 30;
        var handler = new WireHandler((q, _) =>
        {
            Check(DnsWire.TryReadQuestion(q, out var question), "Invalid resolver query.");
            return Task.FromResult(WireResponse(question.Name.StartsWith("missing.") ? NxDomain(q) : NoData(q, soaTtl)));
        });
        using var http = new HttpClient(handler);
        var resolver = new DnsResolver(new DohDnsClient(http, clock), clock);
        var log = new List<string>();
        resolver.Log += log.Add;

        Check(DnsWire.IsNoIpv4Answer(NoData(DnsWire.CreateQuery("discordapp.net"), 30)), "NODATA reply was not recognised.");
        Check(!DnsWire.IsNoIpv4Answer(NxDomain(DnsWire.CreateQuery("missing.example"))), "NXDOMAIN was treated as NODATA.");
        Check((await resolver.ResolveIpv4AddressesAsync("discordapp.net")).Count == 0 && log.Count == 0, "NODATA was logged as a failure.");
        Check(resolver.GetNextRefreshUtc(["discordapp.net"]) == clock.Now + DnsResolver.NoAddressRefresh, "Short negative TTL was not raised to the minimum refresh.");
        clock.Now = clock.Now.AddSeconds(20);
        await resolver.ResolveIpv4AddressesAsync("discordapp.net");
        Check(handler.Requests == 1 && log.Count == 0, "Cached NODATA was requested again.");

        soaTtl = 1800;
        resolver.ClearCache();
        await resolver.ResolveIpv4AddressesAsync("discordapp.net");
        Check(resolver.GetNextRefreshUtc(["discordapp.net"]) == clock.Now.AddSeconds(1800) && log.Count == 0, "Long negative TTL was not kept.");

        Check((await resolver.ResolveIpv4AddressesAsync("missing.example")).Count == 0 && log.Count == 1, "NXDOMAIN was not logged.");
        Check(resolver.GetNextRefreshUtc(["missing.example"]) == clock.Now.AddSeconds(30), "NXDOMAIN retry delay changed.");
    }
}
