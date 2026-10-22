using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Text;

namespace Dapapa.Core.Ipc
{
    /// <summary>Connection to the privileged helper. Protection started through a client is tied to that connection's lease.</summary>
    public sealed class HelperClient : IAsyncDisposable
    {
        private readonly Socket _socket;
        private readonly StreamReader _reader;
        private readonly StreamWriter _writer;
        private readonly SemaphoreSlim _writeGate = new(1, 1);
        private readonly ConcurrentDictionary<long, TaskCompletionSource<HelperResponse>> _pending = new();
        private readonly CancellationTokenSource _closed = new();
        private readonly Task _readLoop;
        private long _nextId;

        public event Action<HelperEvent>? EventReceived;
        public event Action<Exception?>? Disconnected;

        private HelperClient(Socket socket)
        {
            _socket = socket;
            var stream = new NetworkStream(socket, ownsSocket: false);
            _reader = new StreamReader(stream, new UTF8Encoding(false));
            _writer = new StreamWriter(stream, new UTF8Encoding(false)) { AutoFlush = true, NewLine = "\n" };
            _readLoop = Task.Run(ReadLoopAsync);
        }

        public static async Task<HelperClient> ConnectAsync(string? socketPath = null, CancellationToken cancellationToken = default)
        {
            var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            try
            {
                await socket.ConnectAsync(new UnixDomainSocketEndPoint(socketPath ?? HelperProtocol.DefaultSocketPath), cancellationToken)
                    .ConfigureAwait(false);
                var client = new HelperClient(socket);
                var hello = await client.SendAsync(new HelperRequest(0, HelperCommand.Hello) { Protocol = HelperProtocol.Version },
                    cancellationToken).ConfigureAwait(false);
                if (hello.Protocol != HelperProtocol.Version)
                {
                    await client.DisposeAsync().ConfigureAwait(false);
                    throw new InvalidOperationException($"Unsupported helper protocol {hello.Protocol}.");
                }
                return client;
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        /// <summary>Sends a request and returns the successful response; helper errors are thrown as <see cref="HelperException"/>.</summary>
        public async Task<HelperResponse> SendAsync(HelperRequest request, CancellationToken cancellationToken = default)
        {
            long id = Interlocked.Increment(ref _nextId);
            var completion = new TaskCompletionSource<HelperResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
            _pending[id] = completion;
            try
            {
                string line = HelperProtocol.Serialize(new HelperMessage { Request = request with { Id = id } });
                await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
                try { await _writer.WriteLineAsync(line.AsMemory(), cancellationToken).ConfigureAwait(false); }
                finally { _writeGate.Release(); }
                var response = await completion.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                return response.Ok ? response : throw new HelperException(response.Error ?? "Helper request failed.");
            }
            finally { _pending.TryRemove(id, out _); }
        }

        private async Task ReadLoopAsync()
        {
            Exception? failure = null;
            try
            {
                while (!_closed.IsCancellationRequested)
                {
                    string? line = await _reader.ReadLineAsync(_closed.Token).ConfigureAwait(false);
                    if (line == null) break;
                    if (line.Length > HelperProtocol.MaxMessageBytes) throw new InvalidDataException("Oversized helper message.");
                    var message = HelperProtocol.Deserialize(line);
                    if (message.Response is { } response && _pending.TryGetValue(response.Id, out var completion))
                        completion.TrySetResult(response);
                    else if (message.Event is { } helperEvent)
                        EventReceived?.Invoke(helperEvent);
                }
            }
            catch (OperationCanceledException) when (_closed.IsCancellationRequested) { }
            catch (Exception ex) { failure = ex; }
            var error = new IOException("Helper connection closed.", failure);
            foreach (var pending in _pending.Values) pending.TrySetException(error);
            if (!_closed.IsCancellationRequested) Disconnected?.Invoke(failure);
        }

        public async ValueTask DisposeAsync()
        {
            _closed.Cancel();
            try { _socket.Shutdown(SocketShutdown.Both); } catch (SocketException) { }
            _socket.Dispose();
            try { await _readLoop.ConfigureAwait(false); } catch { }
            _writeGate.Dispose();
        }
    }

    public sealed class HelperException(string message) : Exception(message);
}
