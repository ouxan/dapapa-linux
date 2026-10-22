using System.Net;
using System.Net.Sockets;

namespace Dapapa.Core
{
    internal sealed class LocalDnsService(DohDnsClient client, int port = 5300) : IAsyncDisposable
    {
        private readonly object _gate = new();
        private readonly HashSet<Task> _requests = new();
        private readonly CancellationTokenSource _cancellation = new();
        private sealed record TargetSelection(HashSet<string> Domains, CancellationTokenSource Cancellation);
        private TargetSelection _targets = new(new(StringComparer.OrdinalIgnoreCase), new());
        private UdpClient? _socket;
        private Task? _listener;
        private Task? _stop;
        public event Action<string>? Log;
        public event Action<Exception>? Failed;
        /// <summary>Raised with (query, reply) for each selected query just before the reply is sent.</summary>
        public event Action<byte[], byte[]>? Answered;
        public bool IsRunning => !_cancellation.IsCancellationRequested && _listener is { IsCompleted: false };
        public IPEndPoint Endpoint => (IPEndPoint)(_socket?.Client.LocalEndPoint ?? throw new InvalidOperationException("Local DNS is not running."));

        public void UpdateTargets(IEnumerable<string> domains)
        {
            var names = domains.Select(DomainDnsResolver.CleanDomainName).Where(d => d.Length > 0)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            lock (_gate)
            {
                if (_stop != null || _targets.Domains.SetEquals(names)) return;
                var previous = _targets;
                _targets = new(names, new());
                previous.Cancellation.Cancel();
                previous.Cancellation.Dispose();
            }
        }

        public Task StartAsync()
        {
            lock (_gate)
            {
                if (_listener != null || _stop != null) throw new InvalidOperationException("Local DNS session already used.");
                var socket = new UdpClient(AddressFamily.InterNetwork);
                try
                {
                    socket.ExclusiveAddressUse = true;
                    socket.Client.Bind(new IPEndPoint(IPAddress.Loopback, port));
                    _socket = socket;
                    _listener = Task.Run(ListenAsync);
                }
                catch { socket.Dispose(); throw; }
                return Task.CompletedTask;
            }
        }

        private async Task ListenAsync()
        {
            try
            {
                while (!_cancellation.IsCancellationRequested)
                {
                    var received = await _socket!.ReceiveAsync(_cancellation.Token).ConfigureAwait(false);
                    Task? task = null;
                    lock (_gate)
                    {
                        if (_cancellation.IsCancellationRequested) break;
                        if (_requests.Count < 72)
                        {
                            task = Task.Run(() => AnswerAsync(received));
                            _requests.Add(task);
                        }
                    }
                    if (task == null)
                        await _socket.SendAsync(DnsWire.ErrorResponse(received.Buffer, 2), received.RemoteEndPoint, _cancellation.Token).ConfigureAwait(false);
                    else _ = task.ContinueWith(completed => { lock (_gate) _requests.Remove(completed); }, TaskScheduler.Default);
                }
            }
            catch (Exception ex) when (_cancellation.IsCancellationRequested && ex is OperationCanceledException or ObjectDisposedException or SocketException) { }
            catch (Exception ex)
            {
                Log?.Invoke(Localization.T("LocalDnsFailed", ex.Message));
                Failed?.Invoke(ex);
            }
        }

        private async Task AnswerAsync(UdpReceiveResult received)
        {
            TargetSelection selection;
            CancellationTokenSource cancellation;
            lock (_gate)
            {
                selection = _targets;
                cancellation = CancellationTokenSource.CreateLinkedTokenSource(_cancellation.Token, selection.Cancellation.Token);
            }
            using var requestCancellation = cancellation;
            try
            {
                byte[] query = received.Buffer;
                if (query.Length < 2) return;
                byte[] reply;
                bool selected = false;
                if (!DnsWire.TryReadMessage(query, out var question, out _) || (query[2] & 0x80) != 0)
                    reply = DnsWire.ErrorResponse(query, 1);
                else if (question.Class != 1 || !PacketProcessor.IsDomainTargeted(question.Name, selection.Domains))
                    reply = DnsWire.ErrorResponse(query, 5);
                else
                {
                    reply = await client.ResolveAsync(query, cancellation.Token).ConfigureAwait(false);
                    selected = true;
                }
                reply = DnsWire.LimitUdpResponse(query, reply);
                ValueTask<int> sending;
                lock (_gate)
                {
                    if (!ReferenceEquals(selection, _targets) || cancellation.IsCancellationRequested) return;
                    if (selected) Answered?.Invoke(query, reply);
                    sending = _socket!.SendAsync(reply, received.RemoteEndPoint, cancellation.Token);
                }
                await sending.ConfigureAwait(false);
            }
            catch (Exception ex) when (cancellation.IsCancellationRequested && ex is OperationCanceledException or ObjectDisposedException or SocketException) { }
            catch (Exception ex) { Log?.Invoke(Localization.T("LocalDnsFailed", ex.Message)); }
        }

        public Task StopAsync()
        {
            lock (_gate) return _stop ??= Task.Run(async () =>
            {
                _cancellation.Cancel();
                if (_listener != null) await _listener.ConfigureAwait(false);
                Task[] pending;
                lock (_gate) pending = [.. _requests];
                await Task.WhenAll(pending).ConfigureAwait(false);
                _socket?.Dispose();
                lock (_gate) _targets.Cancellation.Dispose();
            });
        }

        public async ValueTask DisposeAsync() => await StopAsync().ConfigureAwait(false);
    }
}
