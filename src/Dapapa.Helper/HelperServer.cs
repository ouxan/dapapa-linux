using System.Buffers.Binary;
using System.Net.Sockets;
using System.Text;
using System.Threading.Channels;
using Dapapa.Core;
using Dapapa.Core.Ipc;

namespace Dapapa.Helper
{
    /// <summary>
    /// Unix socket front end for <see cref="ProtectionEngine"/>. Access is controlled by the socket file's group and
    /// mode; protection is leased to the connection that last started or updated it and stops when that client is gone.
    /// </summary>
    internal sealed class HelperServer(ProtectionEngine engine, TimeSpan leaseGrace)
    {
        private sealed class Connection(Socket socket, int uid, int pid)
        {
            public readonly Socket Socket = socket;
            public readonly int Uid = uid;
            public readonly int Pid = pid;
            public readonly Channel<string> Outgoing = Channel.CreateBounded<string>(new BoundedChannelOptions(256)
                { FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true });
        }

        private readonly object _gate = new();
        private readonly HashSet<Connection> _connections = new();
        private Connection? _owner;
        private CancellationTokenSource? _leaseTimer;

        public async Task RunAsync(Socket listener, CancellationToken cancellationToken)
        {
            engine.Log += line => Broadcast(new HelperEvent(HelperEventKind.Log) { Text = line });
            engine.StatusChanged += status => Broadcast(new HelperEvent(HelperEventKind.Status) { Status = status });
            var clients = new List<Task>();
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    var socket = await listener.AcceptAsync(cancellationToken).ConfigureAwait(false);
                    clients.Add(Task.Run(() => ServeAsync(socket, cancellationToken), CancellationToken.None));
                    clients.RemoveAll(task => task.IsCompleted);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
            await Task.WhenAll(clients).ConfigureAwait(false);
        }

        private async Task ServeAsync(Socket socket, CancellationToken cancellationToken)
        {
            var (pid, uid) = ReadPeer(socket);
            var connection = new Connection(socket, uid, pid);
            lock (_gate) _connections.Add(connection);
            Console.WriteLine($"Client connected: uid={uid} pid={pid}");
            using var closed = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var stream = new NetworkStream(socket, ownsSocket: true);
            var input = new BufferedStream(stream, 16 * 1024);
            var writer = Task.Run(() => WriteLoopAsync(connection, stream, closed.Token));
            try
            {
                bool greeted = false;
                while (!closed.IsCancellationRequested)
                {
                    string? line = await ReadLineAsync(input, closed.Token).ConfigureAwait(false);
                    if (line == null) break;
                    HelperResponse response;
                    try
                    {
                        var request = HelperProtocol.Deserialize(line).Request ?? throw new InvalidDataException("Missing request.");
                        if (!greeted && request.Command != HelperCommand.Hello) throw new InvalidDataException("Hello is required first.");
                        greeted = true;
                        response = await HandleAsync(connection, request, closed.Token).ConfigureAwait(false);
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        response = new HelperResponse(TryReadId(line), false) { Error = ex.Message };
                    }
                    Send(connection, new HelperMessage { Response = response });
                }
            }
            catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or InvalidDataException) { }
            finally
            {
                connection.Outgoing.Writer.TryComplete();
                closed.Cancel();
                try { await writer.ConfigureAwait(false); } catch { }
                await stream.DisposeAsync().ConfigureAwait(false);
                OnDisconnected(connection);
                Console.WriteLine($"Client disconnected: uid={uid} pid={pid}");
            }
        }

        private async Task<HelperResponse> HandleAsync(Connection connection, HelperRequest request, CancellationToken cancellationToken)
        {
            switch (request.Command)
            {
                case HelperCommand.Hello:
                    return new HelperResponse(request.Id, true) { Protocol = HelperProtocol.Version, Status = engine.Status };
                case HelperCommand.Status:
                    return new HelperResponse(request.Id, true) { Status = engine.Status };
                case HelperCommand.Start:
                    if (request.Domains == null || request.Options == null || request.Provider == null)
                        throw new InvalidDataException("Start requires domains, options and provider.");
                    Claim(connection);
                    await engine.StartAsync(request.Domains, request.Options, request.Provider.Value).ConfigureAwait(false);
                    return new HelperResponse(request.Id, true) { Status = engine.Status };
                case HelperCommand.Update:
                    Claim(connection);
                    await engine.UpdateAsync(request.Domains, request.Options, request.Provider).ConfigureAwait(false);
                    return new HelperResponse(request.Id, true) { Status = engine.Status };
                case HelperCommand.Stop:
                    lock (_gate) { _owner = null; CancelLease(); }
                    await engine.StopAsync(closeConnections: true).ConfigureAwait(false);
                    return new HelperResponse(request.Id, true) { Status = engine.Status };
                case HelperCommand.Refresh:
                    var refresh = await engine.RefreshAsync(request.Force, cancellationToken).ConfigureAwait(false);
                    return new HelperResponse(request.Id, true) { Refresh = refresh, Status = engine.Status };
                default:
                    throw new InvalidDataException("Unknown command.");
            }
        }

        private void Claim(Connection connection)
        {
            lock (_gate)
            {
                _owner = connection;
                CancelLease();
            }
        }

        private void OnDisconnected(Connection connection)
        {
            lock (_gate)
            {
                _connections.Remove(connection);
                if (!ReferenceEquals(_owner, connection)) return;
                _owner = null;
                CancelLease();
                var timer = _leaseTimer = new CancellationTokenSource();
                _ = Task.Run(async () =>
                {
                    try { await Task.Delay(leaseGrace, timer.Token).ConfigureAwait(false); }
                    catch (OperationCanceledException) { return; }
                    lock (_gate) if (!ReferenceEquals(_leaseTimer, timer) || _owner != null) return;
                    Console.WriteLine("Owning client did not return; stopping protection.");
                    await engine.StopAsync(closeConnections: true).ConfigureAwait(false);
                });
            }
        }

        private void CancelLease()
        {
            _leaseTimer?.Cancel();
            _leaseTimer = null;
        }

        private void Broadcast(HelperEvent helperEvent)
        {
            if (helperEvent.Kind == HelperEventKind.Log) Console.WriteLine(helperEvent.Text);
            string line = HelperProtocol.Serialize(new HelperMessage { Event = helperEvent });
            lock (_gate)
                foreach (var connection in _connections) connection.Outgoing.Writer.TryWrite(line);
        }

        private static void Send(Connection connection, HelperMessage message) =>
            connection.Outgoing.Writer.TryWrite(HelperProtocol.Serialize(message));

        private static async Task WriteLoopAsync(Connection connection, NetworkStream stream, CancellationToken cancellationToken)
        {
            await foreach (string line in connection.Outgoing.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                byte[] data = Encoding.UTF8.GetBytes(line + "\n");
                await stream.WriteAsync(data, cancellationToken).ConfigureAwait(false);
            }
        }

        /// <summary>Reads one newline-terminated UTF-8 line, rejecting lines above the protocol limit before buffering them.</summary>
        private static async Task<string?> ReadLineAsync(Stream stream, CancellationToken cancellationToken)
        {
            var buffer = new MemoryStream();
            byte[] one = new byte[1];
            while (true)
            {
                int read = await stream.ReadAsync(one, cancellationToken).ConfigureAwait(false);
                if (read == 0) return buffer.Length == 0 ? null : throw new InvalidDataException("Truncated message.");
                if (one[0] == (byte)'\n') return Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
                if (buffer.Length >= HelperProtocol.MaxMessageBytes) throw new InvalidDataException("Oversized message.");
                buffer.WriteByte(one[0]);
            }
        }

        private static long TryReadId(string line)
        {
            try { return HelperProtocol.Deserialize(line).Request?.Id ?? 0; }
            catch { return 0; }
        }

        private static (int Pid, int Uid) ReadPeer(Socket socket)
        {
            byte[] credentials = new byte[12];
            socket.GetRawSocketOption(Native.LibC.SOL_SOCKET, Native.LibC.SO_PEERCRED, credentials);
            return (BinaryPrimitives.ReadInt32LittleEndian(credentials), BinaryPrimitives.ReadInt32LittleEndian(credentials.AsSpan(4)));
        }
    }
}
