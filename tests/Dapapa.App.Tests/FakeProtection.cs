using Dapapa.App.Services;
using Dapapa.Core.Ipc;
using Dapapa.Core.Models;

/// <summary>In-memory stand-in for the helper that records every request the window makes.</summary>
internal sealed class FakeProtection : IProtectionService
{
    public int Starts, Updates, Stops, Refreshes;
    public bool Disposed;
    public IReadOnlyList<string> Domains = [];
    public DpiOptions? Options;
    public DohProvider Provider;
    public IReadOnlyList<string>? LastUpdateDomains;
    public DpiOptions? LastUpdateOptions;
    public DohProvider? LastUpdateProvider;
    public Exception? FailStart, FailUpdate, FailRefresh;
    public int IpsPerDomain = 1;
    public readonly List<string> Calls = [];

    public HelperStatus? Status { get; private set; }
    public bool IsRunning => Status?.State == ProtectionState.Running;
    public event Action<HelperStatus>? StatusChanged;
    public event Action<string>? Log;
    public event Action? ConnectionLost;

    public async Task StartAsync(IReadOnlyList<string> domains, DpiOptions options, DohProvider provider, CancellationToken ct = default)
    {
        await Task.Yield();
        Starts++;
        Calls.Add("start");
        if (FailStart != null) throw FailStart;
        (Domains, Options, Provider) = (domains, options, provider);
        Publish(new HelperStatus(ProtectionState.Running) { ActiveDomains = domains.Count, Provider = provider });
    }

    public async Task UpdateAsync(IReadOnlyList<string>? domains, DpiOptions? options, DohProvider? provider, CancellationToken ct = default)
    {
        await Task.Yield();
        Updates++;
        Calls.Add("update");
        (LastUpdateDomains, LastUpdateOptions, LastUpdateProvider) = (domains, options, provider);
        if (FailUpdate != null) throw FailUpdate;
        if (!IsRunning) throw new HelperException("Protection is not running.");
        Domains = domains ?? Domains;
        Options = options ?? Options;
        Provider = provider ?? Provider;
        Publish(Status! with { ActiveDomains = Domains.Count, Provider = Provider });
    }

    public async Task StopAsync(CancellationToken ct = default)
    {
        await Task.Yield();
        Stops++;
        Calls.Add("stop");
        Publish(new HelperStatus(ProtectionState.Stopped));
    }

    public async Task<RefreshResult> RefreshAsync(bool force, CancellationToken ct = default)
    {
        await Task.Yield();
        Refreshes++;
        Calls.Add(force ? "refresh-force" : "refresh");
        if (FailRefresh != null) throw FailRefresh;
        if (!IsRunning) throw new HelperException("Protection is not running.");
        return new RefreshResult(Domains.ToDictionary(d => d, d => d.StartsWith("unresolved.") ? 0 : IpsPerDomain), true);
    }

    public Task PollAsync(CancellationToken ct = default) => Task.CompletedTask;

    /// <summary>Simulates the helper reporting a failed session, as after a queue error.</summary>
    public void Drop() => Publish(new HelperStatus(ProtectionState.Failed) { Error = "queue failed" });

    public void SetCounters(long packets, long dnsReplies) => Publish(Status! with { BypassedPackets = packets, DnsReplies = dnsReplies });

    public void RaiseLog(string text) => Log?.Invoke(text);

    public void LoseConnection()
    {
        Status = null;
        ConnectionLost?.Invoke();
    }

    private void Publish(HelperStatus status)
    {
        Status = status;
        StatusChanged?.Invoke(status);
    }

    public ValueTask DisposeAsync()
    {
        Disposed = true;
        return ValueTask.CompletedTask;
    }
}
