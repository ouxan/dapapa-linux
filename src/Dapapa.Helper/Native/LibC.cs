using System.Runtime.InteropServices;

namespace Dapapa.Helper.Native
{
    internal static partial class LibC
    {
        public const int AF_INET = 2;
        public const int SOCK_RAW = 3;
        public const int SOCK_CLOEXEC = 0x80000;
        public const int IPPROTO_RAW = 255;
        public const int SOL_IP = 0;
        public const int SOL_SOCKET = 1;
        public const int SOL_NETLINK = 270;
        public const int IP_NODEFRAG = 22;
        public const int SO_RCVTIMEO = 20;
        public const int SO_RCVBUFFORCE = 33;
        public const int SO_MARK = 36;
        public const int SO_PEERCRED = 17;
        public const int NETLINK_NO_ENOBUFS = 5;
        public const int EINTR = 4;
        public const int EAGAIN = 11;
        public const int ENOBUFS = 105;

        [StructLayout(LayoutKind.Sequential)]
        public struct SockAddrIn
        {
            public ushort Family;
            public ushort Port;
            public uint Address;
            public ulong Zero;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TimeVal
        {
            public long Seconds;
            public long Microseconds;
        }

        [LibraryImport("libc", SetLastError = true)]
        public static partial int socket(int domain, int type, int protocol);

        [LibraryImport("libc", SetLastError = true)]
        public static unsafe partial int setsockopt(int fd, int level, int name, void* value, uint length);

        [LibraryImport("libc", SetLastError = true)]
        public static unsafe partial nint sendto(int fd, byte* buffer, nuint length, int flags, SockAddrIn* address, uint addressLength);

        [LibraryImport("libc", SetLastError = true)]
        public static unsafe partial nint recv(int fd, byte* buffer, nuint length, int flags);

        [LibraryImport("libc", SetLastError = true)]
        public static partial int close(int fd);

        [LibraryImport("libc")]
        public static partial uint geteuid();

        public static unsafe void SetOption(int fd, int level, int name, int value)
        {
            if (setsockopt(fd, level, name, &value, sizeof(int)) != 0) throw LastError($"setsockopt({level},{name})");
        }

        public static Exception LastError(string operation)
        {
            int errno = Marshal.GetLastPInvokeError();
            return new IOException($"{operation} failed: {Marshal.GetPInvokeErrorMessage(errno)} (errno {errno})");
        }
    }
}
