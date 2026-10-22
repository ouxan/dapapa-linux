using System.Net.Sockets;
using Dapapa.Core;

namespace Dapapa.App.Services
{
    /// <summary>
    /// Keeps one GUI per user session. The first instance listens on a socket in the runtime directory; later
    /// launches ask it to show its window and exit.
    /// </summary>
    public sealed class SingleInstance : IDisposable
    {
        private readonly Socket _listener;
        private readonly string _path;
        private readonly CancellationTokenSource _stop = new();

        public event Action? ShowRequested;

        private SingleInstance(Socket listener, string path)
        {
            _listener = listener;
            _path = path;
            _ = AcceptLoopAsync();
        }

        public static string SocketPath
        {
            get
            {
                string? runtime = Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR");
                string directory = !string.IsNullOrEmpty(runtime) && Path.IsPathRooted(runtime)
                    ? Path.Combine(runtime, "dapapa")
                    : Path.Combine(XdgPaths.StateHome, "dapapa");
                return Path.Combine(directory, "app.sock");
            }
        }

        /// <summary>Returns the owner for this session, or null after signalling an already running instance.</summary>
        public static SingleInstance? TryAcquire(bool showExisting, string? path = null)
        {
            path ??= SocketPath;
            if (TrySignal(path, showExisting)) return null;
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.SetUnixFileMode(Path.GetDirectoryName(path)!, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            // Nothing answered, so a socket file left here belongs to an instance that is gone.
            File.Delete(path);
            var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            try
            {
                listener.Bind(new UnixDomainSocketEndPoint(path));
                listener.Listen(4);
                return new SingleInstance(listener, path);
            }
            catch (SocketException) when (TrySignal(path, showExisting))
            {
                listener.Dispose();
                return null;
            }
            catch
            {
                listener.Dispose();
                throw;
            }
        }

        private static bool TrySignal(string path, bool show)
        {
            if (!File.Exists(path)) return false;
            using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            try
            {
                socket.Connect(new UnixDomainSocketEndPoint(path));
                socket.Send(show ? "show\n"u8 : "ping\n"u8);
                return true;
            }
            catch (SocketException) { return false; }
        }

        private async Task AcceptLoopAsync()
        {
            while (!_stop.IsCancellationRequested)
            {
                Socket connection;
                try { connection = await _listener.AcceptAsync(_stop.Token); }
                catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException) { return; }
                using (connection)
                {
                    var buffer = new byte[16];
                    try
                    {
                        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
                        timeout.CancelAfter(TimeSpan.FromSeconds(2));
                        int read = await connection.ReceiveAsync(buffer, SocketFlags.None, timeout.Token);
                        if (read >= 4 && buffer.AsSpan(0, 4).SequenceEqual("show"u8)) ShowRequested?.Invoke();
                    }
                    catch (Exception ex) when (ex is OperationCanceledException or SocketException) { }
                }
            }
        }

        public void Dispose()
        {
            _stop.Cancel();
            _listener.Dispose();
            try { File.Delete(_path); } catch (IOException) { }
            _stop.Dispose();
        }
    }
}
