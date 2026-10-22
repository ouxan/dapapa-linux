using System.Collections.Concurrent;
using System.Net;

namespace Dapapa.Core
{
    public static class DomainDnsResolver
    {
        internal static readonly DohDnsClient Client = new(CreateHttpClient());
        internal static HttpClient CreateHttpClient() => new(new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.All,
            AllowAutoRedirect = false,
            UseCookies = false
        }) { Timeout = Timeout.InfiniteTimeSpan };
        private static readonly DnsResolver Resolver = new(Client);
        public static event Action<string>? Log;

        static DomainDnsResolver()
        {
            Client.Log += message => Log?.Invoke(message);
            Resolver.Log += message => Log?.Invoke(message);
        }

        public static string CleanDomainName(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain)) return string.Empty;
            var clean = domain.Trim().ToLowerInvariant();
            if (clean.StartsWith("https://")) clean = clean[8..];
            if (clean.StartsWith("http://")) clean = clean[7..];
            int slash = clean.IndexOf('/');
            if (slash >= 0) clean = clean[..slash];
            int colon = clean.IndexOf(':');
            if (colon >= 0) clean = clean[..colon];
            return clean.TrimEnd('.');
        }

        public static void ClearCache() => Resolver.ClearCache();
        public static DateTimeOffset GetNextRefreshUtc(IEnumerable<string> domains) => Resolver.GetNextRefreshUtc(domains);
        public static DateTimeOffset GetExpiryUtc(string domain) => Resolver.GetNextRefreshUtc([CleanDomainName(domain)]);
        public static Task<List<string>> ResolveIpv4AddressesAsync(string domain, CancellationToken ct = default)
            => Resolver.ResolveIpv4AddressesAsync(CleanDomainName(domain), ct);

        public static Task<Dictionary<string, List<string>>> ResolveAllAsync(
            IEnumerable<string> domains, bool force = false, CancellationToken ct = default)
            => ResolveAllAsync(domains, Resolver, force, ct);

        internal static async Task<Dictionary<string, List<string>>> ResolveAllAsync(
            IEnumerable<string> domains, DnsResolver resolver, bool force = false, CancellationToken ct = default)
        {
            var names = domains.Select(CleanDomainName).Where(d => d.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            if (force) resolver.ClearCache();
            var results = new ConcurrentDictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            await Parallel.ForEachAsync(names, new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = ct },
                async (name, token) => results[name] = await resolver.ResolveIpv4AddressesAsync(name, token).ConfigureAwait(false)).ConfigureAwait(false);
            return names.ToDictionary(name => name, name => results[name], StringComparer.OrdinalIgnoreCase);
        }
    }

    internal sealed class DnsResolver
    {
        private sealed record RefreshState(DateTimeOffset Expires, bool Failed);
        internal static readonly TimeSpan NoAddressRefresh = TimeSpan.FromMinutes(5);
        private readonly DohDnsClient _client;
        private readonly TimeProvider _time;
        private readonly ConcurrentDictionary<string, RefreshState> _refresh = new(StringComparer.OrdinalIgnoreCase);
        private readonly object _gate = new();
        private long _epoch;
        public event Action<string>? Log;

        public DnsResolver(HttpClient client, TimeProvider? timeProvider = null) : this(new DohDnsClient(client, timeProvider), timeProvider) { }
        public DnsResolver(DohDnsClient client, TimeProvider? timeProvider = null)
        {
            _client = client;
            _time = timeProvider ?? TimeProvider.System;
        }

        public void ClearCache() { lock (_gate) { ++_epoch; _refresh.Clear(); _client.ClearCache(); } }
        public DateTimeOffset GetNextRefreshUtc(IEnumerable<string> domains) => domains
            .Select(d => _refresh.TryGetValue(d, out var state) ? state.Expires : _time.GetUtcNow())
            .DefaultIfEmpty(DateTimeOffset.MaxValue).Min();

        public async Task<List<string>> ResolveIpv4AddressesAsync(string domain, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            long epoch;
            lock (_gate)
            {
                epoch = _epoch;
                if (_refresh.TryGetValue(domain, out var failed) && failed.Failed && failed.Expires > _time.GetUtcNow()) return [];
            }
            try
            {
                byte[] query = DnsWire.CreateQuery(domain);
                byte[] reply = await _client.ResolveAsync(query, ct).ConfigureAwait(false);
                var addresses = DnsWire.ReadIpv4Answers(reply).Select(a => a.Ip).Distinct().ToList();
                if (addresses.Count == 0 && !DnsWire.IsNoIpv4Answer(reply)) throw new HttpRequestException("No IPv4 address returned.");
                var expires = _client.GetExpiry(query);
                // A name without an A record (discordapp.net) is a valid answer, not a failure to log and retry every 30 s.
                if (addresses.Count == 0 && expires < _time.GetUtcNow() + NoAddressRefresh) expires = _time.GetUtcNow() + NoAddressRefresh;
                lock (_gate)
                    if (epoch == _epoch) _refresh[domain] = new(expires, false);
                return addresses;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) when (ex is HttpRequestException or InvalidDataException or ArgumentException)
            {
                lock (_gate)
                    if (epoch == _epoch) _refresh[domain] = new(_time.GetUtcNow().AddSeconds(30), true);
                Log?.Invoke(Localization.T("DnsResolveFailed", domain, ex.Message));
                return [];
            }
        }
    }
}
