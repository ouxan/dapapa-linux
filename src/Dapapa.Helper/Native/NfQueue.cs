using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Dapapa.Helper.Native
{
    /// <summary>Verdict for a queued packet. <see cref="Mark"/> is OR-ed into the existing packet mark when non-zero.</summary>
    internal readonly record struct QueueVerdict(bool Accept, uint Mark = 0)
    {
        public static readonly QueueVerdict Pass = new(true);
        public static readonly QueueVerdict Drop = new(false);
    }

    /// <summary>Handles one queued IPv4 packet. Runs on the queue thread; must not block.</summary>
    internal delegate QueueVerdict QueuedPacketHandler(Span<byte> packet, bool outbound);

    /// <summary>
    /// Consumes a netfilter queue through libnetfilter_queue. The queue is configured fail-open so that a slow or
    /// missing consumer lets traffic through instead of dropping it.
    /// </summary>
    internal sealed unsafe partial class NfQueue : IDisposable
    {
        private const string Library = "libnetfilter_queue.so.1";
        private const byte NFQNL_COPY_PACKET = 2;
        private const uint NFQA_CFG_F_FAIL_OPEN = 1;
        private const uint NF_DROP = 0;
        private const uint NF_ACCEPT = 1;
        private const byte NF_INET_LOCAL_OUT = 3;

        private readonly IntPtr _handle;
        private readonly IntPtr _queue;
        private readonly int _fd;
        private readonly GCHandle _self;
        private readonly QueuedPacketHandler _handler;
        private Thread? _thread;
        private volatile bool _stopping;
        private Exception? _failure;

        public event Action<Exception>? Failed;
        public long HandlerErrors;

        public NfQueue(ushort queueNumber, QueuedPacketHandler handler, uint maxLength = 4096)
        {
            _handler = handler;
            _handle = nfq_open();
            if (_handle == IntPtr.Zero) throw LibC.LastError("nfq_open");
            _self = GCHandle.Alloc(this);
            try
            {
                _queue = nfq_create_queue(_handle, queueNumber, &OnPacket, GCHandle.ToIntPtr(_self));
                if (_queue == IntPtr.Zero) throw LibC.LastError($"nfq_create_queue({queueNumber})");
                if (nfq_set_mode(_queue, NFQNL_COPY_PACKET, 0xFFFF) < 0) throw LibC.LastError("nfq_set_mode");
                if (nfq_set_queue_maxlen(_queue, maxLength) < 0) throw LibC.LastError("nfq_set_queue_maxlen");
                if (nfq_set_queue_flags(_queue, NFQA_CFG_F_FAIL_OPEN, NFQA_CFG_F_FAIL_OPEN) < 0) throw LibC.LastError("nfq_set_queue_flags");
                _fd = nfq_fd(_handle);
                LibC.SetOption(_fd, LibC.SOL_NETLINK, LibC.NETLINK_NO_ENOBUFS, 1);
                try { LibC.SetOption(_fd, LibC.SOL_SOCKET, LibC.SO_RCVBUFFORCE, 8 * 1024 * 1024); } catch (IOException) { }
                var timeout = new LibC.TimeVal { Microseconds = 200_000 };
                if (LibC.setsockopt(_fd, LibC.SOL_SOCKET, LibC.SO_RCVTIMEO, &timeout, (uint)sizeof(LibC.TimeVal)) != 0)
                    throw LibC.LastError("setsockopt(SO_RCVTIMEO)");
            }
            catch
            {
                if (_queue != IntPtr.Zero) nfq_destroy_queue(_queue);
                nfq_close(_handle);
                _self.Free();
                throw;
            }
        }

        public bool IsRunning => _thread is { IsAlive: true } && !_stopping;

        public void Start()
        {
            _thread = new Thread(ReceiveLoop) { IsBackground = true, Name = "dapapa-nfqueue" };
            _thread.Start();
        }

        private void ReceiveLoop()
        {
            byte[] buffer = new byte[256 * 1024];
            try
            {
                fixed (byte* data = buffer)
                {
                    while (!_stopping)
                    {
                        nint received = LibC.recv(_fd, data, (nuint)buffer.Length, 0);
                        if (received < 0)
                        {
                            int errno = Marshal.GetLastPInvokeError();
                            if (errno is LibC.EINTR or LibC.EAGAIN or LibC.ENOBUFS) continue;
                            throw LibC.LastError("recv(nfqueue)");
                        }
                        if (received == 0) continue;
                        nfq_handle_packet(_handle, data, (int)received);
                        if (_failure != null) throw _failure;
                    }
                }
            }
            catch (Exception ex) when (!_stopping)
            {
                _stopping = true;
                Failed?.Invoke(ex);
            }
        }

        [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
        private static int OnPacket(IntPtr queue, IntPtr message, IntPtr data, IntPtr state)
        {
            var self = (NfQueue)GCHandle.FromIntPtr(state).Target!;
            byte* header = nfq_get_msg_packet_hdr(data);
            if (header == null) return 0;
            uint id = BinaryPrimitives.ReadUInt32BigEndian(new ReadOnlySpan<byte>(header, 4));
            bool outbound = header[6] == NF_INET_LOCAL_OUT;
            var verdict = QueueVerdict.Pass;
            try
            {
                byte* payload;
                int length = nfq_get_payload(data, &payload);
                if (length > 0) verdict = self._handler(new Span<byte>(payload, length), outbound);
            }
            catch (Exception)
            {
                // Fail open: a handler error must never black-hole traffic.
                Interlocked.Increment(ref self.HandlerErrors);
                verdict = QueueVerdict.Pass;
            }
            int result = verdict.Mark != 0
                ? nfq_set_verdict2(queue, id, verdict.Accept ? NF_ACCEPT : NF_DROP, nfq_get_nfmark(data) | verdict.Mark, 0, null)
                : nfq_set_verdict(queue, id, verdict.Accept ? NF_ACCEPT : NF_DROP, 0, null);
            if (result < 0) self._failure ??= LibC.LastError("nfq_set_verdict");
            return 0;
        }

        public void Dispose()
        {
            _stopping = true;
            if (_thread != null && _thread != Thread.CurrentThread) _thread.Join();
            nfq_destroy_queue(_queue);
            nfq_close(_handle);
            _self.Free();
        }

        [LibraryImport(Library, SetLastError = true)] private static partial IntPtr nfq_open();
        [LibraryImport(Library)] private static partial int nfq_close(IntPtr handle);
        [LibraryImport(Library, SetLastError = true)]
        private static partial IntPtr nfq_create_queue(IntPtr handle, ushort number,
            delegate* unmanaged[Cdecl]<IntPtr, IntPtr, IntPtr, IntPtr, int> callback, IntPtr data);
        [LibraryImport(Library)] private static partial int nfq_destroy_queue(IntPtr queue);
        [LibraryImport(Library, SetLastError = true)] private static partial int nfq_set_mode(IntPtr queue, byte mode, uint range);
        [LibraryImport(Library, SetLastError = true)] private static partial int nfq_set_queue_maxlen(IntPtr queue, uint length);
        [LibraryImport(Library, SetLastError = true)] private static partial int nfq_set_queue_flags(IntPtr queue, uint mask, uint flags);
        [LibraryImport(Library)] private static partial int nfq_fd(IntPtr handle);
        [LibraryImport(Library)] private static partial int nfq_handle_packet(IntPtr handle, byte* buffer, int length);
        [LibraryImport(Library)] private static partial byte* nfq_get_msg_packet_hdr(IntPtr data);
        [LibraryImport(Library)] private static partial int nfq_get_payload(IntPtr data, byte** payload);
        [LibraryImport(Library)] private static partial uint nfq_get_nfmark(IntPtr data);
        [LibraryImport(Library, SetLastError = true)]
        private static partial int nfq_set_verdict(IntPtr queue, uint id, uint verdict, uint length, byte* buffer);
        [LibraryImport(Library, SetLastError = true)]
        private static partial int nfq_set_verdict2(IntPtr queue, uint id, uint verdict, uint mark, uint length, byte* buffer);
    }
}
