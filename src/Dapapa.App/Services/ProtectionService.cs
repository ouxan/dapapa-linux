using Avalonia.Threading;
using Dapapa.Core.Ipc;
using Dapapa.Core.Models;

namespace Dapapa.App.Services
{
    /// <summary>What the window needs from the privileged helper. Events are raised on the UI thread.</summary>
    public interface IProtectionService : IAsyncDisposable
    {
        HelperStatus? Status { get; }
        bool IsRunning { get; }
        event Action<HelperStatus>? StatusChanged;
        event Action<string>? Log;
        event Action? ConnectionLost;
        Task StartAsync(IReadOnlyList<string> domains, DpiOptions options, DohProvider provider, CancellationToken ct = default);
        Task UpdateAsync(IReadOnlyList<string>? domains, DpiOptions? options, DohProvider? provider, CancellationToken ct = default);
        Task StopAsync(CancellationToken ct = default);
        Task<RefreshResult> RefreshAsync(bool force, CancellationToken ct = default);
        Task PollAsync(CancellationToken ct = default);
    }

    /// <summary>
    /// Talks to dapapa-helper over its Unix socket. The connection is opened on first use and kept for the
    /// lifetime of the window, because the helper stops protection shortly after its owning connection closes.
    /// </summary>
    public sealed class HelperProtectionService(string? socketPath = null) : IProtectionService
    {
        private readonly SemaphoreSlim _connectGate = new(1, 1);
        private HelperClient? _client;

        public HelperStatus? Status { get; private set; }
        public bool IsRunning => _client != null && Status?.State == ProtectionState.Running;
        public event Action<HelperStatus>? StatusChanged;
        public event Action<string>? Log;
        public event Action? ConnectionLost;

        public async Task StartAsync(IReadOnlyList<string> domains, DpiOptions options, DohProvider provider, CancellationToken ct = default) =>
            Apply(await SendAsync(new HelperRequest(0, HelperCommand.Start) { Domains = domains, Options = options, Provider = provider }, ct));

        public async Task UpdateAsync(IReadOnlyList<string>? domains, DpiOptions? options, DohProvider? provider, CancellationToken ct = default) =>
            Apply(await SendAsync(new HelperRequest(0, HelperCommand.Update) { Domains = domains, Options = options, Provider = provider }, ct));

        public async Task StopAsync(CancellationToken ct = default)
        {
            if (_client == null) return;
            Apply(await SendAsync(new HelperRequest(0, HelperCommand.Stop), ct));
        }

        public async Task<RefreshResult> RefreshAsync(bool force, CancellationToken ct = default)
        {
            var response = await SendAsync(new HelperRequest(0, HelperCommand.Refresh) { Force = force }, ct);
            Apply(response);
            return response.Refresh ?? new RefreshResult(new Dictionary<string, int>(), false);
        }

        public async Task PollAsync(CancellationToken ct = default)
        {
            if (_client == null) return;
            Apply(await SendAsync(new HelperRequest(0, HelperCommand.Status), ct));
        }

        private async Task<HelperResponse> SendAsync(HelperRequest request, CancellationToken ct)
        {
            var client = await ConnectAsync(ct);
            return await client.SendAsync(request, ct);
        }

        private async Task<HelperClient> ConnectAsync(CancellationToken ct)
        {
            await _connectGate.WaitAsync(ct);
            try
            {
                if (_client != null) return _client;
                var client = await HelperClient.ConnectAsync(socketPath, ct);
                client.EventReceived += OnEvent;
                client.Disconnected += _ => Dispatcher.UIThread.Post(() => OnDisconnected(client));
                _client = client;
                return client;
            }
            finally { _connectGate.Release(); }
        }

        private void OnEvent(HelperEvent helperEvent) => Dispatcher.UIThread.Post(() =>
        {
            if (helperEvent.Kind == HelperEventKind.Log && helperEvent.Text != null) Log?.Invoke(helperEvent.Text);
            else if (helperEvent.Status != null) SetStatus(helperEvent.Status);
        });

        private void OnDisconnected(HelperClient client)
        {
            if (!ReferenceEquals(_client, client)) return;
            _client = null;
            _ = client.DisposeAsync().AsTask();
            Status = null;
            ConnectionLost?.Invoke();
        }

        private void Apply(HelperResponse response)
        {
            if (response.Status == null) return;
            if (Dispatcher.UIThread.CheckAccess()) SetStatus(response.Status);
            else Dispatcher.UIThread.Post(() => SetStatus(response.Status));
        }

        private void SetStatus(HelperStatus status)
        {
            Status = status;
            StatusChanged?.Invoke(status);
        }

        public async ValueTask DisposeAsync()
        {
            var client = Interlocked.Exchange(ref _client, null);
            if (client != null) await client.DisposeAsync();
            _connectGate.Dispose();
        }
    }
}
