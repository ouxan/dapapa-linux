using System.Diagnostics;
using System.Net;

namespace Dapapa.Helper.Firewall
{
    /// <summary>An IPv4 TCP or UDP flow the helper rewrote, identified the way the local socket sees it.</summary>
    internal readonly record struct ProtectedFlow(bool Tcp, ushort SourcePort, uint Destination, ushort DestinationPort)
    {
        /// <summary>Reads the flow of an outbound IPv4 TCP/UDP packet; false for anything else.</summary>
        public static bool TryRead(ReadOnlySpan<byte> packet, out ProtectedFlow flow)
        {
            flow = default;
            if (packet.Length < 20 || packet[0] >> 4 != 4) return false;
            int header = (packet[0] & 0x0F) * 4;
            byte protocol = packet[9];
            if (protocol is not (6 or 17) || packet.Length < header + 4) return false;
            flow = new ProtectedFlow(protocol == 6,
                (ushort)(packet[header] << 8 | packet[header + 1]),
                (uint)(packet[16] << 24 | packet[17] << 16 | packet[18] << 8 | packet[19]),
                (ushort)(packet[header + 2] << 8 | packet[header + 3]));
            return true;
        }

        public override string ToString() =>
            $"{(Tcp ? "tcp" : "udp")} :{SourcePort} -> {new IPAddress(new[] { (byte)(Destination >> 24), (byte)(Destination >> 16), (byte)(Destination >> 8), (byte)Destination })}:{DestinationPort}";
    }

    /// <summary>
    /// Closes local sockets of flows that only worked through the helper, so stopping protection takes effect at once
    /// instead of when applications reconnect. Uses the kernel's socket-destroy interface through iproute2's ss
    /// (CONFIG_INET_DIAG_DESTROY, enabled in Arch's kernels); without it the sockets simply stay open.
    /// </summary>
    internal sealed class ConnectionCloser(string ssPath = "ss")
    {
        private const int FlowsPerCall = 48;

        public int Close(IEnumerable<ProtectedFlow> flows, Action<string> log)
        {
            int closed = 0;
            foreach (var group in flows.Distinct().GroupBy(flow => flow.Tcp))
                foreach (var chunk in group.Chunk(FlowsPerCall))
                    closed += Run(BuildArguments(group.Key, chunk), log);
            return closed;
        }

        /// <summary>ss arguments that destroy exactly the given sockets: matched by local port and remote address.</summary>
        internal static List<string> BuildArguments(bool tcp, IReadOnlyList<ProtectedFlow> flows)
        {
            var args = new List<string> { "-K", "-n", "-H", tcp ? "-t" : "-u", "-a" };
            for (int i = 0; i < flows.Count; i++)
            {
                var flow = flows[i];
                if (i > 0) args.Add("or");
                var address = new IPAddress(new[] { (byte)(flow.Destination >> 24), (byte)(flow.Destination >> 16),
                    (byte)(flow.Destination >> 8), (byte)flow.Destination });
                args.AddRange(["(", "dst", $"{address}:{flow.DestinationPort}", "and", "sport", "=", $":{flow.SourcePort}", ")"]);
            }
            return args;
        }

        private int Run(List<string> arguments, Action<string> log)
        {
            var start = new ProcessStartInfo(ssPath) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
            foreach (string argument in arguments) start.ArgumentList.Add(argument);
            try
            {
                using var process = Process.Start(start) ?? throw new InvalidOperationException("ss did not start.");
                var output = process.StandardOutput.ReadToEndAsync();
                var errors = process.StandardError.ReadToEndAsync();
                if (!process.WaitForExit(5000))
                {
                    process.Kill();
                    return 0;
                }
                string error = errors.Result.Trim();
                if (error.Length > 0) log("ss: " + error);
                return output.Result.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length;
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
            {
                log("ss: " + ex.Message);
                return 0;
            }
        }
    }
}
