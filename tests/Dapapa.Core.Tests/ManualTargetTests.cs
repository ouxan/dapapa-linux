using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using Dapapa.Core.Models;
using Dapapa.Core;

internal static partial class Program
{
    private static async Task ManualTargetTestGroups()
    {
        Run("domain and URL normalization, IDN, malformed inputs and duplicates", DomainInputs);
        Run("backup failure cannot reset settings and empty installations remain empty", MigrationFailure);
        Run("discovery candidates remain inactive until individually selected", DiscoverySelection);
        await RunAsync("discovery resources, CSP, HTML base and redirects", DiscoverySources);
        await RunAsync("discovery failure, partial results and HTTPS redirect boundaries", DiscoveryFailures);
        await RunAsync("discovery size and candidate limits, malformed HTML and timeout", DiscoveryLimits);
        await RunAsync("cancelled discovery cannot return late results", DiscoveryCancellation);
    }

    private static void DomainInputs()
    {
        foreach (var pair in new[] { (" EXAMPLE.COM. ", "example.com"), ("https://Example.com:8443/a?q=x#frag", "example.com"),
            ("http://api.example.com/path", "api.example.com"), ("bücher.de", "xn--bcher-kva.de") })
            Check(DomainName.TryNormalize(pair.Item1, out var actual) && actual == pair.Item2, "Normalization failed: " + pair.Item1);
        foreach (string invalid in new[] { "", "localhost", "192.0.2.1", "https://[::1]/", "*.example.com", "foo..com", "-foo.com",
            "foo-.com", "https://user:secret@example.com", "ftp://example.com", "bad domain.com", "a_b.com", "example.com/path", "example.com:53", "https://example.com\\bad" })
            Check(!DomainName.TryNormalize(invalid, out _), "Invalid domain accepted: " + invalid);
        var settings = new AppSettings { TargetListVersion = 1, Apps = [new() { Domain = "EXAMPLE.COM." },
            new() { Domain = "example.com" }, new() { Domain = "invalid" }] };
        settings.NormalizeTargets();
        Check(settings.Apps.Count == 1 && settings.Apps[0].Name == "example.com", "Invalid or duplicate saved domain retained.");
        settings.Apps.Add(new() { Name = "Discord", Domain = "different.example" });
        Check(settings.GetEffectiveDomains().SequenceEqual(["example.com", "different.example"]), "Display name caused hidden service expansion.");
    }

    private static void MigrationFailure()
    {
        string directory = Path.Combine(Path.GetTempPath(), "dapapa-settings-" + Guid.NewGuid());
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "settings.json");
        try
        {
            const string original = "{\"Apps\":[{\"Domain\":\"saved.example\"}],\"Language\":\"tr\"}";
            File.WriteAllText(path, original);
            var fail = new SettingsService(path, (_, _) => throw new IOException("Injected backup failure"));
            try { fail.Load(); throw new Exception("Failed backup reset settings."); }
            catch (IOException) { }
            Check(File.ReadAllText(path) == original, "Backup failure changed original settings.");
            var failingReplace = new SettingsService(path, replace: (_, _) => throw new IOException("Injected replace failure"));
            try { failingReplace.Load(); throw new Exception("Failed settings replacement unexpectedly succeeded."); }
            catch (IOException) { }
            Check(File.ReadAllText(path) == original, "Failed atomic replacement changed original settings.");
            Check(Directory.GetFiles(directory, "*.bak").Length == 1 && Directory.GetFiles(directory, "*.tmp").Length == 0,
                "Failed replacement lost backup or left temporary files.");
            string freshPath = Path.Combine(directory, "new.json");
            var fresh = new SettingsService(freshPath);
            var settings = fresh.Load();
            Check(settings.TargetListVersion == 1 && settings.Apps.Count == 0, "Fresh installation has preset targets.");
            Check(fresh.Load().Apps.Count == 0, "Empty list acquired defaults on reload.");
            settings.Apps.Add(new() { Domain = "saved.example", Name = "Saved", Enabled = false });
            fresh.Save(settings);
            var reload = fresh.Load();
            Check(reload.Apps.Count == 1 && !reload.Apps[0].Enabled && reload.Apps[0].Name == "Saved", "Manual target selection did not persist.");
        }
        finally { Directory.Delete(directory, true); }
    }

    private static void DiscoverySelection()
    {
        var choices = new List<DiscoveryChoice> {
            new(new("cdn.other.net", [DiscoveryReason.Resource])),
            new(new("api.other.net", [DiscoveryReason.Policy])),
            new(new("api.saved.net", [DiscoveryReason.Redirect])) };
        Check(DiscoveryChoice.SelectedDomains(choices, []).Length == 0, "Suggestions were selected automatically.");
        choices[0].Selected = true;
        choices[2].Selected = true;
        Check(DiscoveryChoice.SelectedDomains(choices, ["saved.net"]).SequenceEqual(["cdn.other.net"]), "Unselected or already covered candidate added.");
    }

    private sealed class DiscoveryHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        public readonly List<Uri> Requests = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            Requests.Add(request.RequestUri!);
            return send(request, token);
        }
    }
    private static HttpResponseMessage Html(string html, string? policy = null)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(html, Encoding.UTF8, "text/html") };
        if (policy != null) response.Headers.TryAddWithoutValidation("Content-Security-Policy", policy);
        return response;
    }
    private static HttpResponseMessage Redirect(string url)
    {
        var response = new HttpResponseMessage(HttpStatusCode.Found);
        response.Headers.Location = new Uri(url, UriKind.RelativeOrAbsolute);
        return response;
    }
    private static async Task DiscoverySources()
    {
        var handler = new DiscoveryHandler((request, _) => Task.FromResult(request.RequestUri!.Host == "example.com"
            ? Redirect("https://www.example.com/home")
            : Html("""
                <base href="https://assets.other.net/base/">
                <script src="script.js"></script><img src="//images.other.net/i.png">
                <video poster="https://posters.other.net/x"><source src="https://media.other.net/a"></video>
                <link rel="stylesheet" href="https://styles.other.net/main.css">
                <link rel="preconnect" href="https://api.other.net"><link rel="canonical" href="https://ignore.other.net">
                <a href="https://ignore.other.net/link">Ignore</a>
                <script src="https://api.example.com/already.js"></script>
                <script src="https://api.other.net/source.js"></script>
                <meta http-equiv="Content-Security-Policy" content="connect-src https://socket.other.net wss://ws.other.net; img-src https://images.other.net">
                """, "default-src 'self'; connect-src https://api.other.net wss://ws.other.net https://*.wild.net https: data:; report-uri https://report.other.net")));
        using var service = new RelatedDomainDiscoveryService(new HttpClient(handler));
        var result = await service.DiscoverAsync("example.com", CancellationToken.None);
        Check(result.Completed && result.Error == null, "Valid discovery failed: " + result.Error);
        Check(result.Candidates.Select(c => c.Domain).Order().SequenceEqual(new[] { "api.other.net", "assets.other.net", "images.other.net",
            "media.other.net", "posters.other.net", "socket.other.net", "styles.other.net", "ws.other.net" }.Order()), "Wrong resource or policy domain set.");
        Check(result.Candidates.Single(c => c.Domain == "api.other.net").Reasons.Count == 2, "Candidate reasons were not combined.");
        Check(handler.Requests.Count == 2 && handler.Requests.All(u => u.Host.EndsWith("example.com")), "External resources were fetched.");
        var external = new DiscoveryHandler((request, _) => Task.FromResult(request.RequestUri!.Host == "example.com"
            ? Redirect("https://redirect.other.net/") : Html("<p>ok")));
        using var redirected = new RelatedDomainDiscoveryService(new HttpClient(external));
        var redirectResult = await redirected.DiscoverAsync("example.com", CancellationToken.None);
        Check(redirectResult.Candidates.Single().Domain == "redirect.other.net" &&
            redirectResult.Candidates.Single().Reasons.Single() == DiscoveryReason.Redirect, "Cross-domain redirect was not recorded.");
    }

    private static async Task DiscoveryFailures()
    {
        foreach (var status in new[] { HttpStatusCode.Forbidden, HttpStatusCode.NotFound, HttpStatusCode.ServiceUnavailable })
        {
            using var service = new RelatedDomainDiscoveryService(new HttpClient(new DiscoveryHandler((_, _) =>
                Task.FromResult(new HttpResponseMessage(status)))));
            var result = await service.DiscoverAsync("example.com", CancellationToken.None);
            Check(!result.Completed && result.Error != null, "HTTP failure reported as success.");
        }
        var handler = new DiscoveryHandler((request, _) => Task.FromResult(request.RequestUri!.Host == "example.com"
            ? Redirect("https://redirect.other.net/") : new HttpResponseMessage(HttpStatusCode.Forbidden)));
        using var partial = new RelatedDomainDiscoveryService(new HttpClient(handler));
        var partialResult = await partial.DiscoverAsync("example.com", CancellationToken.None);
        Check(!partialResult.Completed && partialResult.Candidates.Single().Domain == "redirect.other.net", "Partial suggestions lost or reported complete.");
        foreach (string location in new[] { "http://other.net/", "https://user:password@other.net/", "https://192.0.2.1/" })
        {
            var redirect = new DiscoveryHandler((_, _) => Task.FromResult(Redirect(location)));
            using var service = new RelatedDomainDiscoveryService(new HttpClient(redirect));
            Check(!(await service.DiscoverAsync("example.com", CancellationToken.None)).Completed && redirect.Requests.Count == 1,
                "Invalid redirect followed.");
        }
        using var notHtml = new RelatedDomainDiscoveryService(new HttpClient(new DiscoveryHandler((_, _) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}", Encoding.UTF8, "application/json") }))));
        Check(!(await notHtml.DiscoverAsync("example.com", CancellationToken.None)).Completed, "Non-HTML response accepted.");
        using var dnsError = new RelatedDomainDiscoveryService(new HttpClient(new DiscoveryHandler((_, _) =>
            throw new HttpRequestException("Injected DNS/TLS failure"))));
        Check(!(await dnsError.DiscoverAsync("example.com", CancellationToken.None)).Completed, "Transport failure ignored.");
    }

    private static async Task DiscoveryLimits()
    {
        var redirects = new DiscoveryHandler((request, _) => Task.FromResult(Redirect("https://example.com/" + Guid.NewGuid())));
        using var loop = new RelatedDomainDiscoveryService(new HttpClient(redirects));
        Check(!(await loop.DiscoverAsync("example.com", CancellationToken.None)).Completed && redirects.Requests.Count == 6, "Redirect limit ignored.");
        string many = string.Join("", Enumerable.Range(0, 110).Select(i => $"<img src='https://host{i}.other.net/image'>"));
        using var capped = new RelatedDomainDiscoveryService(new HttpClient(new DiscoveryHandler((_, _) => Task.FromResult(Html(many)))));
        var cappedResult = await capped.DiscoverAsync("example.com", CancellationToken.None);
        Check(!cappedResult.Completed && cappedResult.Candidates.Count == 100, "Candidate limit ignored.");
        using var huge = new RelatedDomainDiscoveryService(new HttpClient(new DiscoveryHandler((_, _) =>
            Task.FromResult(Html(new string('x', RelatedDomainDiscoveryService.MaxHtmlBytes + 1))))));
        Check(!(await huge.DiscoverAsync("example.com", CancellationToken.None)).Completed, "Oversized HTML accepted.");
        using var broken = new RelatedDomainDiscoveryService(new HttpClient(new DiscoveryHandler((_, _) =>
            Task.FromResult(Html("<img src='https://image.other.net/x'><broken <script src='https://script.other.net/y'>")))));
        var brokenResult = await broken.DiscoverAsync("example.com", CancellationToken.None);
        Check(brokenResult.Completed && brokenResult.Candidates.Any(c => c.Domain == "image.other.net"), "HTML error recovery failed.");
        using var timeout = new RelatedDomainDiscoveryService(new HttpClient(new DiscoveryHandler(async (_, token) =>
        {
            await Task.Delay(Timeout.Infinite, token);
            return Html("");
        })), TimeSpan.FromMilliseconds(30));
        Check(!(await timeout.DiscoverAsync("example.com", CancellationToken.None)).Completed, "Timeout reported success.");
    }

    private static async Task DiscoveryCancellation()
    {
        var completion = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        var requested = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var service = new RelatedDomainDiscoveryService(new HttpClient(new DiscoveryHandler((_, _) =>
        {
            requested.TrySetResult();
            return completion.Task;
        })));
        using var cancellation = new CancellationTokenSource();
        var pending = service.DiscoverAsync("example.com", cancellation.Token);
        await requested.Task;
        cancellation.Cancel();
        completion.SetResult(Html("<script src='https://late.other.net/a.js'></script>"));
        try { await pending; throw new Exception("Cancelled discovery returned late suggestions."); }
        catch (OperationCanceledException) { }
    }
}
