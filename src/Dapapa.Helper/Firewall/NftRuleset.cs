using System.Diagnostics;
using System.Globalization;
using System.Text;
using Dapapa.Core.Models;

namespace Dapapa.Helper.Firewall
{
    /// <summary>
    /// Owns the <c>ip dapapa</c> nftables table. Rules are generated from validated options only and replaced atomically;
    /// no other table is read or modified.
    /// </summary>
    internal sealed class NftRuleset(ushort queueNumber, uint bypassMark, uint dnsMark, int localDnsPort, string nftPath = "nft")
    {
        public const string TableName = "dapapa";

        internal string Build(DpiOptions options)
        {
            options = options.Normalize();
            string queue = $"queue num {queueNumber} bypass";
            string bypass = $"meta mark & {Hex(bypassMark)} == {Hex(bypassMark)} accept";
            var output = new List<string>
            {
                bypass,
                "oifname \"lo\" accept",
                $"udp dport 53 {queue}"
            };
            if (options.TcpFragmentation || options.HasFakeMethods || options.HasHttpMethods)
            {
                output.Add($"tcp dport 443 @ih,0,16 0x1603 {queue}");
                output.Add($"tcp dport 80 @ih,0,32 {{ 0x47455420, 0x504f5354, 0x48454144 }} {queue}");
            }
            if (options.BlockQuic) output.Add($"udp dport 443 {queue}");
            if (options.HasUdpMethods)
            {
                const string udp = "udp dport != 53 udp sport != 53 ip length <= 1500";
                if (options.UdpUnknown) output.Add($"{udp} {queue}");
                else
                {
                    if (options.UdpQuicInitial) output.Add($"{udp} udp length >= 1208 @ih,0,8 & 0xc0 == 0xc0 {queue}");
                    if (options.UdpStun) output.Add($"{udp} udp length >= 28 @ih,32,32 0x2112a442 {queue}");
                    if (options.UdpWireGuard) output.Add($"{udp} udp length 156 @ih,0,32 0x01000000 {queue}");
                    if (options.UdpDiscordDiscovery) output.Add($"{udp} udp length 82 @ih,0,32 0x00010046 {queue}");
                }
            }

            var text = new StringBuilder();
            // Declaring then deleting the table makes the whole file one atomic replacement, whether or not it existed.
            text.AppendLine($"table ip {TableName}");
            text.AppendLine($"delete table ip {TableName}");
            text.AppendLine($"table ip {TableName} {{");
            AppendChain(text, "capture_out", "filter hook output priority raw; policy accept;", output);
            if (options.FakeAutoTtl)
                AppendChain(text, "capture_in", "filter hook input priority raw; policy accept;",
                    [$"tcp sport {{ 80, 443 }} tcp flags & (syn | ack | fin | rst) == (syn | ack) {queue}"]);
            AppendChain(text, "dns_redirect", "nat hook output priority dstnat; policy accept;",
                [$"meta mark & {Hex(dnsMark)} == {Hex(dnsMark)} udp dport 53 dnat to 127.0.0.1:{localDnsPort}"]);
            text.AppendLine("}");
            return text.ToString();
        }

        public void Apply(DpiOptions options) => Run("-f -", Build(options));

        /// <summary>Removes the table if present. Safe to call repeatedly, including after a crash.</summary>
        public void Remove() => Run("-f -", $"table ip {TableName}\ndelete table ip {TableName}\n");

        private void Run(string arguments, string input)
        {
            var info = new ProcessStartInfo(nftPath, arguments)
            {
                RedirectStandardInput = true,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false
            };
            using var process = Process.Start(info) ?? throw new IOException("Unable to start nft.");
            process.StandardInput.Write(input);
            process.StandardInput.Close();
            string error = process.StandardError.ReadToEnd();
            process.StandardOutput.ReadToEnd();
            if (!process.WaitForExit(10_000))
            {
                process.Kill();
                throw new TimeoutException("nft timed out.");
            }
            if (process.ExitCode != 0) throw new IOException($"nft failed ({process.ExitCode}): {error.Trim()}");
        }

        private static void AppendChain(StringBuilder text, string name, string hook, IEnumerable<string> rules)
        {
            text.AppendLine($"    chain {name} {{");
            text.AppendLine($"        type {hook}");
            foreach (string rule in rules) text.AppendLine("        " + rule);
            text.AppendLine("    }");
        }

        private static string Hex(uint value) => "0x" + value.ToString("x8", CultureInfo.InvariantCulture);
    }
}
