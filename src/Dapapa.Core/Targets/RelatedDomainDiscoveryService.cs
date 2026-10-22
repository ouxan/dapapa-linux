using System.IO;
using System.Net;
using System.Net.Http;
using AngleSharp.Html.Parser;

namespace Dapapa.Core
{
    internal enum DiscoveryReason { Resource, Redirect, Policy }
    internal sealed record RelatedDomainCandidate(string Domain, IReadOnlyList<DiscoveryReason> Reasons);
    internal sealed record DiscoveryResult(IReadOnlyList<RelatedDomainCandidate> Candidates, bool Completed,
        string? ErrorKey, object[]? ErrorArguments = null)
    {
        public string? Error => ErrorKey == null ? null : Localization.T(ErrorKey, ErrorArguments ?? []);
    }

    internal sealed class RelatedDomainDiscoveryService : IDisposable
    {
        internal const int MaxHtmlBytes = 2 * 1024 * 1024;
        internal const int MaxCandidates = 100;
        private readonly HttpClient _http;
        private readonly TimeSpan _timeout;

        public RelatedDomainDiscoveryService() : this(new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = false, UseCookies = false, AutomaticDecompression = DecompressionMethods.All
        }) { Timeout = Timeout.InfiniteTimeSpan }) { }

        internal RelatedDomainDiscoveryService(HttpClient http, TimeSpan? timeout = null)
        {
            _http = http;
            _timeout = timeout ?? TimeSpan.FromSeconds(15);
        }

        public async Task<DiscoveryResult> DiscoverAsync(string domain, CancellationToken cancellationToken)
        {
            domain = DomainName.Normalize(domain);
            var found = new Dictionary<string, HashSet<DiscoveryReason>>(StringComparer.OrdinalIgnoreCase);
            bool truncated = false;
            void Add(Uri? uri, DiscoveryReason reason)
            {
                if (uri == null || uri.UserInfo.Length != 0 ||
                    uri.Scheme is not ("http" or "https" or "ws" or "wss") ||
                    !DomainName.TryNormalize(uri.Host, out string host) ||
                    (host.Equals(domain, StringComparison.OrdinalIgnoreCase) || host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))) return;
                if (!found.TryGetValue(host, out var reasons))
                {
                    if (found.Count == MaxCandidates) { truncated = true; return; }
                    found.Add(host, reasons = []);
                }
                reasons.Add(reason);
            }
            void Policies(IEnumerable<string> policies)
            {
                foreach (string policy in policies)
                    foreach (string directive in policy.Split(';'))
                    {
                        string[] parts = directive.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length == 0 || parts[0].ToLowerInvariant() is not ("default-src" or "connect-src" or "script-src" or
                            "script-src-elem" or "style-src" or "style-src-elem" or "img-src" or "font-src" or
                            "media-src" or "frame-src" or "child-src" or "worker-src" or "manifest-src")) continue;
                        foreach (string source in parts.Skip(1))
                            if (!source.Contains('*') && Uri.TryCreate(source, UriKind.Absolute, out var uri)) Add(uri, DiscoveryReason.Policy);
                    }
            }
            DiscoveryResult Result(bool completed, string? errorKey, params object[] arguments) => new(found.OrderBy(p => p.Key)
                .Select(p => new RelatedDomainCandidate(p.Key, p.Value.Order().ToArray())).ToArray(), completed, errorKey, arguments);

            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(_timeout);
            var token = deadline.Token;
            try
            {
                var uri = new Uri("https://" + domain + "/");
                for (int redirects = 0; ; redirects++)
                {
                    using var request = new HttpRequestMessage(HttpMethod.Get, uri);
                    request.Headers.UserAgent.ParseAdd("dapapa/" + typeof(RelatedDomainDiscoveryService).Assembly.GetName().Version!.ToString(3));
                    using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
                    if (response.StatusCode is HttpStatusCode.MovedPermanently or HttpStatusCode.Found or
                        HttpStatusCode.SeeOther or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect)
                    {
                        if (redirects == 5) return Result(false, "DiscoveryRedirectLimit");
                        if (response.Headers.Location == null || !Uri.TryCreate(uri, response.Headers.Location, out var next) ||
                            next.Scheme != "https" || next.UserInfo.Length != 0 || !DomainName.TryNormalize(next.Host, out _))
                            return Result(false, "DiscoveryInvalidRedirect");
                        Add(next, DiscoveryReason.Redirect);
                        uri = next;
                        continue;
                    }
                    if (!response.IsSuccessStatusCode) return Result(false, "DiscoveryHttpFailure", (int)response.StatusCode);
                    if (response.Content.Headers.ContentType?.MediaType is not ("text/html" or "application/xhtml+xml"))
                        return Result(false, "DiscoveryNotHtml");
                    if (response.Content.Headers.ContentLength > MaxHtmlBytes)
                        return Result(false, "DiscoverySizeLimit");
                    using var stream = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
                    using var buffer = new MemoryStream();
                    byte[] chunk = new byte[16384];
                    int count;
                    while ((count = await stream.ReadAsync(chunk, token).ConfigureAwait(false)) > 0)
                    {
                        if (buffer.Length + count > MaxHtmlBytes) return Result(false, "DiscoverySizeLimit");
                        buffer.Write(chunk, 0, count);
                    }
                    token.ThrowIfCancellationRequested();
                    buffer.Position = 0;
                    using var reader = new StreamReader(buffer, GetEncoding(response.Content.Headers.ContentType?.CharSet));
                    string html = await reader.ReadToEndAsync(token).ConfigureAwait(false);
                    using var document = await new HtmlParser().ParseDocumentAsync(html, token).ConfigureAwait(false);
                    var baseUri = uri;
                    string? baseValue = document.QuerySelector("base[href]")?.GetAttribute("href");
                    if (Uri.TryCreate(uri, baseValue, out var htmlBase) && htmlBase.Scheme is "http" or "https" && htmlBase.UserInfo.Length == 0)
                        baseUri = htmlBase;
                    foreach (var element in document.QuerySelectorAll("script[src],img[src],iframe[src],audio[src],video[src],source[src],track[src],embed[src],input[type=image][src]"))
                        if (Uri.TryCreate(baseUri, element.GetAttribute("src"), out var resource)) Add(resource, DiscoveryReason.Resource);
                    foreach (var element in document.QuerySelectorAll("video[poster],object[data]"))
                        if (Uri.TryCreate(baseUri, element.GetAttribute(element.LocalName == "video" ? "poster" : "data"), out var resource))
                            Add(resource, DiscoveryReason.Resource);
                    foreach (var element in document.QuerySelectorAll("link[href]"))
                    {
                        var relations = (element.GetAttribute("rel") ?? "").Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                        if (relations.Any(r => r.ToLowerInvariant() is "stylesheet" or "preload" or "modulepreload" or "preconnect" or "dns-prefetch" or "icon" or "manifest") &&
                            Uri.TryCreate(baseUri, element.GetAttribute("href"), out var resource)) Add(resource, DiscoveryReason.Resource);
                    }
                    if (response.Headers.TryGetValues("Content-Security-Policy", out var values)) Policies(values);
                    Policies(document.QuerySelectorAll("meta[http-equiv]").Where(e =>
                        string.Equals(e.GetAttribute("http-equiv"), "Content-Security-Policy", StringComparison.OrdinalIgnoreCase))
                        .Select(e => e.GetAttribute("content") ?? ""));
                    token.ThrowIfCancellationRequested();
                    return Result(!truncated, truncated ? "DiscoveryCandidateLimit" : null);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (OperationCanceledException) { return Result(false, "DiscoveryTimeout"); }
            catch (HttpRequestException ex)
            {
                return ex.StatusCode.HasValue ? Result(false, "DiscoveryHttpFailure", (int)ex.StatusCode.Value)
                    : Result(false, "DiscoveryConnectionFailure");
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidDataException or ArgumentException)
            {
                return Result(false, "DiscoveryReadFailure");
            }
        }

        private static System.Text.Encoding GetEncoding(string? charset)
        {
            try { return charset == null ? System.Text.Encoding.UTF8 : System.Text.Encoding.GetEncoding(charset.Trim('"')); }
            catch (ArgumentException) { return System.Text.Encoding.UTF8; }
        }
        public void Dispose() => _http.Dispose();
    }
}
