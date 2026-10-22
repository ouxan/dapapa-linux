using System.Diagnostics;
using System.Net.Http;

namespace Dapapa.Core
{
    public class LatencyAndEndpointService : IDisposable
    {
        private readonly HttpClient _http;

        public LatencyAndEndpointService() : this(DomainDnsResolver.CreateHttpClient()) { }
        internal LatencyAndEndpointService(HttpClient http) => _http = http;

        public async Task<long> MeasureDohAsync(string? endpoint, int timeoutMs = 4000, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                // A fresh client avoids measuring the application's DNS cache as network latency.
                var client = new DohDnsClient(_http, timeout: TimeSpan.FromMilliseconds(timeoutMs), endpoint: endpoint ?? DohDnsClient.Quad9EcsEndpoint);
                var stopwatch = Stopwatch.StartNew();
                byte[] reply = await client.ResolveAsync(DnsWire.CreateQuery("example.com"), ct).ConfigureAwait(false);
                return (reply[3] & 15) == 0 && DnsWire.ReadIpv4Answers(reply).Count > 0 ? stopwatch.ElapsedMilliseconds : -1;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch { }
            return -1;
        }

        public void Dispose() => _http.Dispose();
    }
}
