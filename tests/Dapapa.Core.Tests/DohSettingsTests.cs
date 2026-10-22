using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Dapapa.Core.Models;
using Dapapa.Core;

internal static partial class Program
{
    private static async Task CustomDoh()
    {
        const string endpoint = "https://127.0.0.1:8443/dns-query";
        var customHandler = new WireHandler((q, _) => Task.FromResult(WireResponse(Answer(q, "203.0.113.21"))), endpoint);
        var cloudflareHandler = new WireHandler((q, _) => Task.FromResult(WireResponse(Answer(q, "203.0.113.22"))));
        using var customHttp = new HttpClient(customHandler);
        using var cloudflareHttp = new HttpClient(cloudflareHandler);
        var custom = new DohDnsClient(customHttp, endpoint: endpoint);
        var cloudflare = new DohDnsClient(cloudflareHttp);
        await using var dns = new LocalDnsService(custom, 0);
        dns.UpdateTargets([UploadDomain]); await dns.StartAsync();
        byte[] query = DnsWire.CreateQuery(UploadDomain);
        Check(DnsWire.ReadIpv4Answers(await UdpQuery(dns.Endpoint, query)).Single().Ip == "203.0.113.21", "Custom query went to Cloudflare.");
        var refresh = new DnsResolver(cloudflare);
        Check((await refresh.ResolveIpv4AddressesAsync(UploadDomain)).Single() == "203.0.113.22", "IP refresh used the custom DNS cache.");
        refresh.ClearCache(); await refresh.ResolveIpv4AddressesAsync(UploadDomain);
        await UdpQuery(dns.Endpoint, query);
        Check(cloudflareHandler.Requests == 2 && customHandler.Requests == 1, "Forced IP refresh reused its cache or invalidated custom DNS.");
        Check(DomainDnsResolver.Client.Endpoint.AbsoluteUri == DohDnsClient.CloudflareEndpoint, "Production IP resolver was changed.");
        using var failedHttp = new HttpClient(new WireHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)), endpoint));
        var failed = new DohDnsClient(failedHttp, endpoint: endpoint);
        Check(((await failed.ResolveAsync(query))[3] & 15) == 2 && cloudflareHandler.Requests == 2, "Custom DNS silently fell back to Cloudflare.");
    }

    private static void DohSettings()
    {
        var legacy = JsonSerializer.Deserialize<AppSettings>("{\"Language\":\"tr\",\"AutoConnectOnLaunch\":true,\"UseCustomDoh\":true,\"CustomDohEndpoint\":\"https://127.0.0.1:8443/dns-query\"}")!;
        Check(legacy.GetDohEndpoint() == DohDnsClient.Quad9EcsEndpoint && legacy.AutoConnectOnLaunch, "Legacy settings changed the fixed provider or lost preferences.");
        var reloaded = JsonSerializer.Deserialize<AppSettings>(JsonSerializer.Serialize(legacy))!;
        Check(reloaded.GetDohEndpoint() == DohDnsClient.Quad9EcsEndpoint && reloaded.Language == "tr", "Fixed DoH provider or language changed.");
        Check(!JsonSerializer.Serialize(reloaded).Contains("CustomDoh"), "Removed custom DNS settings were persisted.");
        foreach (string endpoint in new[] { "", "localhost:8443", "http://127.0.0.1:8443/dns-query", "https://user:secret@localhost/dns-query", "https://localhost/dns-query#fragment" })
        {
            try { DohDnsClient.ParseEndpoint(endpoint); throw new Exception("Invalid DoH endpoint accepted: " + endpoint); }
            catch (ArgumentException) { }
        }
        foreach (AppLanguage language in Enum.GetValues<AppLanguage>())
        {
            Localization.Current = language;
            foreach (string key in new[] { "DohHint", "InvalidDohEndpoint", "DohProviderActive" })
                Check(Localization.T(key) != key, "Missing DoH localization: " + key);
        }
        var processor = new PacketProcessor("dns.example.com");
        processor.UpdateTargets(["example.com"], []);
        byte[] bootstrap = UdpPacket(DnsWire.CreateQuery("dns.example.com"), "192.0.2.1", "1.1.1.1", 52000, 53);
        byte[] original = [.. bootstrap];
        Check(processor.Process(bootstrap, true).Action == PacketAction.Pass && bootstrap.SequenceEqual(original), "DoH host lookup recursively entered its own resolver.");
        byte[] selected = UdpPacket(DnsWire.CreateQuery("www.example.com"), "192.0.2.1", "1.1.1.1", 52000, 53);
        Check(processor.Process(selected, true).Action == PacketAction.DnsQuery, "Bootstrap exception broadened beyond the DoH host.");
    }

    private static async Task ReplaceProvider()
    {
        const string endpoint = "https://127.0.0.1:8443/dns-query";
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var oldHttp = new HttpClient(new WireHandler(async (q, ct) =>
        {
            started.TrySetResult(); await Task.Delay(Timeout.Infinite, ct); return WireResponse(Answer(q));
        }));
        var oldClient = new DohDnsClient(oldHttp);
        await using var oldDns = new LocalDnsService(oldClient, 0);
        oldDns.UpdateTargets([UploadDomain]); await oldDns.StartAsync();
        var bound = oldDns.Endpoint;
        using var socket = new UdpClient(AddressFamily.InterNetwork);
        socket.Connect(bound);
        byte[] query = DnsWire.CreateQuery(UploadDomain);
        await socket.SendAsync(query);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(2));
        await oldDns.StopAsync().WaitAsync(TimeSpan.FromSeconds(2));
        Check(oldClient.PendingCount == 0, "Old provider was not drained.");
        using var nextHttp = new HttpClient(new WireHandler((q, _) => Task.FromResult(WireResponse(Answer(q, "203.0.113.23"))), endpoint));
        await using var nextDns = new LocalDnsService(new DohDnsClient(nextHttp, endpoint: endpoint), bound.Port);
        nextDns.UpdateTargets([UploadDomain]); await nextDns.StartAsync();
        byte[] reply = await UdpQuery(nextDns.Endpoint, query);
        Check(DnsWire.ReadIpv4Answers(reply).Single().Ip == "203.0.113.23", "Replacement provider reused an old reply.");
    }

    private static async Task LocalHttpsDoh()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder(); names.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(names.Build());
        using var generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(10));
        // Reload the certificate from PKCS#12 so the TLS server gets a usable private key; no certificate store is changed.
        using var certificate = X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx), null);
        foreach (bool trustCertificate in new[] { true, false })
        {
            var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
            try
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                string endpoint = $"https://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/dns-query";
                var server = Task.Run(async () =>
                {
                    using var connection = await listener.AcceptTcpClientAsync(timeout.Token);
                    using var stream = new SslStream(connection.GetStream());
                    try
                    {
                        await stream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = certificate }, timeout.Token);
                        if (!trustCertificate) return;
                        var header = new List<byte>(); byte[] single = new byte[1];
                        while (header.Count < 8192)
                        {
                            await stream.ReadExactlyAsync(single, timeout.Token); header.Add(single[0]);
                            if (header.Count >= 4 && header.TakeLast(4).SequenceEqual(new byte[] { 13, 10, 13, 10 })) break;
                        }
                        string text = Encoding.ASCII.GetString(header.ToArray());
                        Check(text.StartsWith("POST /dns-query HTTP/1.1") && text.Contains("application/dns-message"), "Local HTTPS received a wrong DoH request.");
                        string length = text.Split("\r\n").Single(line => line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase));
                        int size = int.Parse(length.Split(':')[1]);
                        Check(size is > 12 and <= 65535, "Invalid HTTPS query length.");
                        byte[] query = new byte[size]; await stream.ReadExactlyAsync(query, timeout.Token);
                        byte[] reply = Answer(query, "203.0.113.24");
                        byte[] headers = Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {reply.Length}\r\nConnection: close\r\n\r\n");
                        await stream.WriteAsync(headers, timeout.Token); await stream.WriteAsync(reply, timeout.Token); await stream.FlushAsync(timeout.Token);
                    }
                    catch (Exception ex) when (!trustCertificate && ex is AuthenticationException or System.IO.IOException) { }
                });
                using var http = trustCertificate ? new HttpClient(new HttpClientHandler
                {
                    // Trust only this test certificate; production clients use the system trust store.
                    ServerCertificateCustomValidationCallback = (_, peer, _, _) => peer?.Thumbprint == certificate.Thumbprint
                }) : DomainDnsResolver.CreateHttpClient();
                var client = new DohDnsClient(http, endpoint: endpoint);
                string? error = null; client.Log += line => error = line;
                byte[] result = await client.ResolveAsync(DnsWire.CreateQuery(UploadDomain), timeout.Token);
                await server.WaitAsync(timeout.Token);
                if (trustCertificate) Check(DnsWire.ReadIpv4Answers(result).SingleOrDefault().Ip == "203.0.113.24", "Real local HTTPS DoH failed: " + error);
                else Check((result[3] & 15) == 2 && client.CachedCount == 0, "Production accepted an untrusted HTTPS certificate.");
            }
            finally { listener.Stop(); }
        }
    }
}
