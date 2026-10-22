using Tmds.DBus.Protocol;

namespace Dapapa.App.Services
{
    /// <summary>Short status messages, the counterpart of the Windows tray balloons.</summary>
    public interface INotifier
    {
        void Show(string title, string text);
    }

    /// <summary>
    /// Desktop notifications through <c>org.freedesktop.Notifications</c> (dunst, mako or swaync on Hyprland). Each message
    /// replaces the previous one, so "Connecting..." and "Done" share one bubble. Without a notification server nothing is
    /// shown and the app keeps working.
    /// </summary>
    public sealed class DesktopNotifier(string? address = null) : INotifier, IDisposable
    {
        private const string Service = "org.freedesktop.Notifications";
        private const string ObjectPath = "/org/freedesktop/Notifications";
        private const int TimeoutMs = 3000; // the Windows app shows its balloons for 3 s
        // dunst does not search the hicolor theme by default, so the packaged image is passed as a file when present.
        private static readonly string AppIcon = File.Exists("/usr/share/pixmaps/dapapa.png") ? "file:///usr/share/pixmaps/dapapa.png" : "dapapa";
        private readonly string _address = address ?? DBusAddress.Session ?? string.Empty;
        private readonly SemaphoreSlim _gate = new(1, 1);
        private DBusConnection? _connection;
        private uint _lastId;
        private volatile bool _disposed;

        public void Show(string title, string text) => _ = ShowAsync(title, text);

        /// <summary>Sends one notification; returns false when no notification server could be reached.</summary>
        internal async Task<bool> ShowAsync(string title, string text)
        {
            await _gate.WaitAsync().ConfigureAwait(false);
            try
            {
                if (_disposed || _address.Length == 0) return false;
                if (_connection == null)
                {
                    var connection = new DBusConnection(_address);
                    try { await connection.ConnectAsync().ConfigureAwait(false); }
                    catch { connection.Dispose(); throw; }
                    Volatile.Write(ref _connection, connection);
                    if (_disposed) { connection.Dispose(); return false; }
                }
                _lastId = await _connection.CallMethodAsync(CreateNotify(_connection, title, text, _lastId),
                    static (Message reply, object? _) => reply.GetBodyReader().ReadUInt32()).ConfigureAwait(false);
                return true;
            }
            catch (Exception ex) when (ex is DBusExceptionBase or IOException or System.Net.Sockets.SocketException or ObjectDisposedException)
            {
                // Connect again on the next message; the server may start later, for example after a panel restart.
                _connection?.Dispose();
                _connection = null;
                _lastId = 0;
                return false;
            }
            finally { _gate.Release(); }
        }

        private static MessageBuffer CreateNotify(DBusConnection connection, string title, string text, uint replaces)
        {
            using var writer = connection.GetMessageWriter();
            writer.WriteMethodCallHeader(Service, ObjectPath, Service, "Notify", "susssasa{sv}i");
            writer.WriteString("dapapa");
            writer.WriteUInt32(replaces);
            writer.WriteString(AppIcon);
            writer.WriteString(title);
            writer.WriteString(text);
            writer.WriteArray(Array.Empty<string>());
            var hints = writer.WriteDictionaryStart();
            writer.WriteDictionaryEntryStart();
            writer.WriteString("desktop-entry");
            writer.WriteVariantString("dapapa");
            writer.WriteDictionaryEnd(hints);
            writer.WriteInt32(TimeoutMs);
            return writer.CreateMessage();
        }

        /// <summary>Closes the connection without waiting for a pending message, so exiting never blocks on D-Bus.</summary>
        public void Dispose()
        {
            _disposed = true;
            Volatile.Read(ref _connection)?.Dispose();
        }
    }
}
