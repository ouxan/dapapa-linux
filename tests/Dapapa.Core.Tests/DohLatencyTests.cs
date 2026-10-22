using System.Net;
using System.Net.Http;
using Dapapa.Core;

internal static partial class Program
{
    private static async Task DohLatency()
    {
        const string endpoint = "https://dns11.quad9.net/dns-query";
        var handler = new WireHandler(async (query, ct) =>
        {
            await Task.Delay(40, ct);
            return WireResponse(Answer(query));
        }, endpoint);
        using var latency = new LatencyAndEndpointService(new HttpClient(handler));
        for (int i = 0; i < 2; ++i)
            Check(await latency.MeasureDohAsync(endpoint) >= 30, "DNS latency measured a cache hit or the wrong provider.");
        Check(handler.Requests == 2, "DNS latency reused the application cache.");

        using var failed = new LatencyAndEndpointService(new HttpClient(new WireHandler(
            (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)), endpoint)));
        Check(await failed.MeasureDohAsync(endpoint) == -1, "Failed DoH returned a successful latency.");

        using var timedOut = new LatencyAndEndpointService(new HttpClient(new WireHandler(async (query, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            return WireResponse(Answer(query));
        }, endpoint)));
        Check(await timedOut.MeasureDohAsync(endpoint, 80) == -1, "Timed out DoH returned a successful latency.");
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(80));
        try
        {
            await timedOut.MeasureDohAsync(endpoint, ct: cancellation.Token);
            throw new Exception("Cancelled latency probe completed normally.");
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }

        var defaultHandler = new WireHandler((query, _) => Task.FromResult(WireResponse(Answer(query))), endpoint);
        using var defaultLatency = new LatencyAndEndpointService(new HttpClient(defaultHandler));
        Check(await defaultLatency.MeasureDohAsync(null) >= 0 && defaultHandler.Requests == 1,
            "Default provider latency did not use the selected default endpoint.");
    }
}
