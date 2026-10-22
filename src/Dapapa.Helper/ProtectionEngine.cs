using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using Dapapa.Core;
using Dapapa.Core.Ipc;
using Dapapa.Core.Models;
using Dapapa.Helper.Firewall;
using Dapapa.Helper.Native;

namespace Dapapa.Helper
{
    internal sealed record HelperConfig
    {
        public ushort QueueNumber { get; init; } = 2701;
        public uint BypassMark { get; init; } = 0x10000000;
        public uint DnsMark { get; init; } = 0x20000000;
        public int LocalDnsPort { get; init; } = 5300;
        public string NftPath { get; init; } = "nft";
        public string SsPath { get; init; } = "ss";
        /// <summary>Test-only: replaces every DoH endpoint, including the Cloudflare target resolver.</summary>
        public string? DohEndpointOverride { get; init; }
        /// <summary>Test-only: an additional trusted root certificate for DoH connections.</summary>
        public X509Certificate2? ExtraTrustedRoot { get; init; }
    }

    /// <summary>
    /// One protection session at a time: local DNS, the packet queue, raw injection, the nftables table and the
    /// Cloudflare target-IP refresh. Start installs rules last; stop removes them first so traffic never depends on a
    /// stopped consumer.
    /// </summary>
    internal sealed class ProtectionEngine : IAsyncDisposable
    {
        private sealed class Session
        {
            public required HttpClient QueryHttp;
            public required HttpClient TargetHttp;
            public required LocalDnsService Dns;
            public required PacketProcessor Processor;
            public required DnsResolver Resolver;
            public required RawSender Raw;
            public required NfQueue Queue;
            public required DohProvider Provider;
            public required DpiOptions Options;
            public IReadOnlyList<string> Domains = [];
            public readonly CancellationTokenSource Cancellation = new();
            public readonly SemaphoreSlim RefreshGate = new(1, 1);
            public readonly SemaphoreSlim Wake = new(0, 1);
            public Task? RefreshLoop;
            public long LastActivityLog;
            /// <summary>Flows the helper rewrote, with the target they were rewritten for; closed on stop.</summary>
            public readonly System.Collections.Concurrent.ConcurrentDictionary<ProtectedFlow, string> Flows = new();
        }

        private const int MaxTrackedFlows = 8192;

        private readonly HelperConfig _config;
        private readonly NftRuleset _nft;
        private readonly ConnectionCloser _closer;
        private readonly SemaphoreSlim _gate = new(1, 1);
        private Session? _session;
        private ProtectionState _state = ProtectionState.Stopped;
        private string? _error;
        private long _bypassed;
        private long _dnsReplies;
        private string? _lastTarget;
        private DateTimeOffset? _lastBypassed;

        public event Action<string>? Log;
        public event Action<HelperStatus>? StatusChanged;

        public ProtectionEngine(HelperConfig config)
        {
            _config = config;
            _nft = new NftRuleset(config.QueueNumber, config.BypassMark, config.DnsMark, config.LocalDnsPort, config.NftPath);
            _closer = new ConnectionCloser(config.SsPath);
        }

        public HelperStatus Status
        {
            get
            {
                var session = _session;
                return new HelperStatus(_state)
                {
                    Error = _error,
                    ActiveDomains = session?.Processor.DomainsCount ?? 0,
                    BypassedPackets = Interlocked.Read(ref _bypassed),
                    DnsReplies = Interlocked.Read(ref _dnsReplies),
                    LastTarget = _lastTarget,
                    LastBypassed = _lastBypassed,
                    Provider = session?.Provider ?? DohProvider.Quad9Ecs,
                    HelperVersion = typeof(ProtectionEngine).Assembly.GetName().Version?.ToString(3) ?? ""
                };
            }
        }

        /// <summary>Removes rules left behind by a previous helper process.</summary>
        public void CleanupStaleRules()
        {
            try { _nft.Remove(); }
            catch (Exception ex) { Log?.Invoke(Localization.T("GenericError", ex.Message)); }
        }

        public async Task StartAsync(IReadOnlyList<string> domains, DpiOptions options, DohProvider provider)
        {
            domains = ValidateDomains(domains);
            if (!Enum.IsDefined(provider)) throw new ArgumentException("Unknown DoH provider.");
            await _gate.WaitAsync().ConfigureAwait(false);
            try
            {
                if (_session != null) await StopCoreAsync(ProtectionState.Stopped, null).ConfigureAwait(false);
                await StartCoreAsync(domains, options.Normalize(), provider).ConfigureAwait(false);
            }
            finally { _gate.Release(); }
        }

        public async Task UpdateAsync(IReadOnlyList<string>? domains, DpiOptions? options, DohProvider? provider)
        {
            if (domains != null) domains = ValidateDomains(domains);
            await _gate.WaitAsync().ConfigureAwait(false);
            try
            {
                var session = _session ?? throw new InvalidOperationException("Protection is not running.");
                var nextDomains = domains ?? session.Domains;
                var nextOptions = options?.Normalize() ?? session.Options;
                var nextProvider = provider ?? session.Provider;
                if (nextProvider != session.Provider)
                {
                    // A provider change replaces the DoH client and local resolver, so the session restarts.
                    await StopCoreAsync(ProtectionState.Stopped, null).ConfigureAwait(false);
                    await StartCoreAsync(nextDomains, nextOptions, nextProvider).ConfigureAwait(false);
                    return;
                }
                if (options != null && _nft.Build(nextOptions) != _nft.Build(session.Options)) _nft.Apply(nextOptions);
                session.Options = nextOptions;
                session.Processor.UpdateOptions(nextOptions);
                if (domains != null && !domains.SequenceEqual(session.Domains, StringComparer.OrdinalIgnoreCase))
                {
                    session.Domains = domains;
                    session.Dns.UpdateTargets(domains);
                    session.Processor.UpdateTargets(domains, []);
                    WakeRefresh(session);
                    Log?.Invoke(Localization.T("EngineUpdated", session.Processor.DomainsCount));
                    CloseUntargetedFlows(session, domains);
                }
                PublishStatus();
            }
            finally { _gate.Release(); }
        }

        /// <param name="closeConnections">
        /// Also closes the local sockets of connections the helper rewrote, so they stop working now instead of when the
        /// application reconnects. Used when the user stops protection or the controlling client goes away.
        /// </param>
        public async Task StopAsync(bool closeConnections = false)
        {
            await _gate.WaitAsync().ConfigureAwait(false);
            try { await StopCoreAsync(ProtectionState.Stopped, null, closeConnections).ConfigureAwait(false); }
            finally { _gate.Release(); }
        }

        /// <summary>Resolves every target through Cloudflare now and applies the result before returning it.</summary>
        public async Task<RefreshResult> RefreshAsync(bool force, CancellationToken cancellationToken)
        {
            var session = _session ?? throw new InvalidOperationException("Protection is not running.");
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, session.Cancellation.Token);
            var result = await RefreshTargetsAsync(session, force, linked.Token).ConfigureAwait(false);
            if (force && result.Applied) SystemDnsCache.Flush(message => Log?.Invoke(message));
            return result;
        }

        private async Task StartCoreAsync(IReadOnlyList<string> domains, DpiOptions options, DohProvider provider)
        {
            SetState(ProtectionState.Starting, null);
            Session? session = null;
            HttpClient? queryHttp = null, targetHttp = null;
            LocalDnsService? dns = null;
            RawSender? raw = null;
            NfQueue? queue = null;
            try
            {
                _nft.Remove();
                string queryEndpoint = _config.DohEndpointOverride ?? DohProviders.GetEndpoint(provider);
                string targetEndpoint = _config.DohEndpointOverride ?? DohDnsClient.CloudflareEndpoint;
                queryHttp = CreateHttpClient();
                targetHttp = CreateHttpClient();
                var queryClient = new DohDnsClient(queryHttp, endpoint: queryEndpoint);
                queryClient.Log += message => Log?.Invoke(message);
                var resolver = new DnsResolver(new DohDnsClient(targetHttp, endpoint: targetEndpoint));
                resolver.Log += message => Log?.Invoke(message);
                var processor = new PacketProcessor(queryClient.Endpoint.Host);
                processor.UpdateTargets(domains, []);
                processor.UpdateOptions(options);

                dns = new LocalDnsService(queryClient, _config.LocalDnsPort);
                dns.Log += message => Log?.Invoke(message);
                dns.UpdateTargets(domains);
                await dns.StartAsync().ConfigureAwait(false);
                Log?.Invoke(Localization.T("LocalDnsStarted", dns.Endpoint));
                Log?.Invoke(Localization.T("DohProviderActive", queryClient.Endpoint.GetLeftPart(UriPartial.Path)));

                raw = new RawSender(_config.BypassMark);
                var current = new Session
                {
                    QueryHttp = queryHttp, TargetHttp = targetHttp, Dns = dns, Processor = processor, Resolver = resolver,
                    Raw = raw, Queue = null!, Provider = provider, Options = options, Domains = domains
                };
                dns.Answered += (query, reply) =>
                {
                    processor.LearnDnsResponse(query, reply, processor.TargetVersion);
                    Interlocked.Increment(ref _dnsReplies);
                };
                queue = new NfQueue(_config.QueueNumber, (packet, outbound) => Handle(current, packet, outbound));
                current.Queue = queue;
                session = current;
                queue.Failed += error => _ = Task.Run(() => FailAsync(current, error));
                dns.Failed += error => _ = Task.Run(() => FailAsync(current, error));
                queue.Start();

                _nft.Apply(options);
                _session = session;
                session.RefreshLoop = Task.Run(() => RefreshLoopAsync(session));
                SetState(ProtectionState.Running, null);
                Log?.Invoke(Localization.T("EngineStarted", processor.DomainsCount));
            }
            catch (Exception ex)
            {
                try { _nft.Remove(); } catch (Exception cleanup) { Log?.Invoke(Localization.T("GenericError", cleanup.Message)); }
                queue?.Dispose();
                raw?.Dispose();
                if (dns != null) await dns.StopAsync().ConfigureAwait(false);
                queryHttp?.Dispose();
                targetHttp?.Dispose();
                _session = null;
                Log?.Invoke(Localization.T("GenericError", ex.Message));
                if (!KernelModules.RunningKernelMissing())
                {
                    SetState(ProtectionState.Failed, ex.Message);
                    throw;
                }
                string message = Localization.T("KernelUpdatedRestart");
                SetState(ProtectionState.Failed, message);
                Log?.Invoke(Localization.T("GenericError", message));
                throw new InvalidOperationException(message, ex);
            }
        }

        private async Task StopCoreAsync(ProtectionState finalState, string? error, bool closeConnections = false)
        {
            var session = _session;
            if (session == null)
            {
                SetState(finalState, error);
                return;
            }
            SetState(ProtectionState.Stopping, null);
            _session = null;
            var failures = new List<Exception>();
            try { _nft.Remove(); } catch (Exception ex) { failures.Add(ex); }
            // After the rules are gone a reconnect goes out unmodified, so only rewritten flows are closed.
            if (closeConnections) CloseFlows(session.Flows.Keys);
            session.Cancellation.Cancel();
            try { session.Queue.Dispose(); } catch (Exception ex) { failures.Add(ex); }
            try { if (session.RefreshLoop != null) await session.RefreshLoop.ConfigureAwait(false); } catch (OperationCanceledException) { }
            try { await session.Dns.StopAsync().ConfigureAwait(false); } catch (Exception ex) { failures.Add(ex); }
            session.Raw.Dispose();
            session.QueryHttp.Dispose();
            session.TargetHttp.Dispose();
            SystemDnsCache.Flush(message => Log?.Invoke(message));
            foreach (var failure in failures) Log?.Invoke(Localization.T("GenericError", failure.Message));
            SetState(finalState, error ?? (failures.Count > 0 ? failures[0].Message : null));
            Log?.Invoke(Localization.T("EngineStopped"));
        }

        private async Task FailAsync(Session session, Exception error)
        {
            Log?.Invoke(Localization.T("EngineWorkerFailed", error.Message));
            await _gate.WaitAsync().ConfigureAwait(false);
            try
            {
                if (ReferenceEquals(_session, session)) await StopCoreAsync(ProtectionState.Failed, error.Message).ConfigureAwait(false);
            }
            finally { _gate.Release(); }
        }

        private QueueVerdict Handle(Session session, Span<byte> packet, bool outbound)
        {
            var decision = session.Processor.Process(packet, outbound);
            switch (decision.Action)
            {
                case PacketAction.Pass: return QueueVerdict.Pass;
                case PacketAction.Drop: return QueueVerdict.Drop;
                case PacketAction.DnsQuery: return new QueueVerdict(true, _config.DnsMark);
            }
            var injections = PacketProcessor.BuildInjections(packet, decision);
            bool modified = injections.Count > 1 || !injections[0].Packet.AsSpan().SequenceEqual(packet);
            if (!modified) return QueueVerdict.Pass;
            int realSent = 0;
            try
            {
                foreach (var injection in injections)
                {
                    PacketChecksum.Prepare(injection.Packet, injection.InvalidTcpChecksum, injection.InvalidUdpChecksum);
                    session.Raw.Send(injection.Packet);
                    if (!injection.IsFake) realSent++;
                }
            }
            catch (Exception ex)
            {
                Log?.Invoke(Localization.T("GenericError", ex.Message));
                // Nothing real left the host yet: let the original through. Otherwise drop it; TCP retransmits the rest.
                return realSent == 0 ? QueueVerdict.Pass : QueueVerdict.Drop;
            }
            Interlocked.Increment(ref _bypassed);
            if (outbound && session.Flows.Count < MaxTrackedFlows && ProtectedFlow.TryRead(packet, out var flow))
                session.Flows[flow] = decision.Target;
            _lastTarget = decision.Target;
            _lastBypassed = DateTimeOffset.Now;
            long tick = Environment.TickCount64;
            if (tick - session.LastActivityLog >= 1000)
            {
                session.LastActivityLog = tick;
                Log?.Invoke(Localization.T("EngineActivity", Interlocked.Read(ref _bypassed)));
            }
            return QueueVerdict.Drop;
        }

        private void CloseUntargetedFlows(Session session, IReadOnlyList<string> domains)
        {
            var targets = new HashSet<string>(domains, StringComparer.OrdinalIgnoreCase);
            var removed = new List<ProtectedFlow>();
            foreach (var (flow, target) in session.Flows)
                if (target.Length > 0 && !PacketProcessor.IsDomainTargeted(target, targets) && session.Flows.TryRemove(flow, out _))
                    removed.Add(flow);
            CloseFlows(removed);
        }

        private void CloseFlows(ICollection<ProtectedFlow> flows)
        {
            if (flows.Count == 0) return;
            int closed = _closer.Close(flows, message => Log?.Invoke(message));
            Log?.Invoke(Localization.T("ConnectionsClosed", closed));
        }

        private async Task RefreshLoopAsync(Session session)
        {
            var token = session.Cancellation.Token;
            while (!token.IsCancellationRequested)
            {
                try { await RefreshTargetsAsync(session, false, token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { return; }
                catch (Exception ex) { Log?.Invoke(Localization.T("GenericError", ex.Message)); }
                var next = session.Resolver.GetNextRefreshUtc(session.Domains);
                var delay = next - DateTimeOffset.UtcNow;
                if (delay < TimeSpan.FromSeconds(5)) delay = TimeSpan.FromSeconds(5);
                if (delay > TimeSpan.FromHours(1)) delay = TimeSpan.FromHours(1);
                try { await session.Wake.WaitAsync(delay, token).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
            }
        }

        private static async Task<RefreshResult> RefreshTargetsAsync(Session session, bool force, CancellationToken token)
        {
            await session.RefreshGate.WaitAsync(token).ConfigureAwait(false);
            try
            {
                var domains = session.Domains;
                var resolved = await DomainDnsResolver.ResolveAllAsync(domains, session.Resolver, force, token).ConfigureAwait(false);
                token.ThrowIfCancellationRequested();
                if (!ReferenceEquals(domains, session.Domains)) return new RefreshResult(new Dictionary<string, int>(), false);
                var ips = resolved.SelectMany(pair => pair.Value.Select(ip =>
                    new ResolvedTargetIp(ip, session.Resolver.GetNextRefreshUtc([pair.Key])))).ToArray();
                session.Processor.UpdateTargets(domains, [], ips);
                return new RefreshResult(resolved.ToDictionary(pair => pair.Key, pair => pair.Value.Count, StringComparer.OrdinalIgnoreCase), true);
            }
            finally { session.RefreshGate.Release(); }
        }

        private static void WakeRefresh(Session session)
        {
            try { session.Wake.Release(); } catch (SemaphoreFullException) { }
        }

        private HttpClient CreateHttpClient()
        {
            var handler = new SocketsHttpHandler
            {
                AutomaticDecompression = DecompressionMethods.All,
                AllowAutoRedirect = false,
                UseCookies = false,
                // The helper's own DoH connections carry the bypass mark so they are never captured.
                ConnectCallback = async (context, cancellationToken) =>
                {
                    var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                    try
                    {
                        socket.SetRawSocketOption(LibC.SOL_SOCKET, LibC.SO_MARK, BitConverter.GetBytes(_config.BypassMark));
                        await socket.ConnectAsync(context.DnsEndPoint, cancellationToken).ConfigureAwait(false);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch
                    {
                        socket.Dispose();
                        throw;
                    }
                }
            };
            if (_config.ExtraTrustedRoot is { } root)
                handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, chain, errors) =>
                {
                    if (errors == SslPolicyErrors.None) return true;
                    if (certificate == null || chain == null || (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != 0) return false;
                    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                    chain.ChainPolicy.CustomTrustStore.Add(root);
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    return chain.Build(new X509Certificate2(certificate));
                };
            return new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        }

        private static IReadOnlyList<string> ValidateDomains(IReadOnlyList<string> domains)
        {
            if (domains.Count == 0) throw new ArgumentException(Localization.T("NoActiveTargets"));
            if (domains.Count > HelperProtocol.MaxDomains) throw new ArgumentException("Too many target domains.");
            var normalized = new List<string>(domains.Count);
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string domain in domains)
            {
                if (!DomainName.TryNormalize(domain, out string name)) throw new ArgumentException(Localization.T("InvalidDomain", domain));
                if (seen.Add(name)) normalized.Add(name);
            }
            return normalized;
        }

        private void SetState(ProtectionState state, string? error)
        {
            _state = state;
            _error = error;
            PublishStatus();
        }

        private void PublishStatus() => StatusChanged?.Invoke(Status);

        public async ValueTask DisposeAsync()
        {
            await StopAsync().ConfigureAwait(false);
            _gate.Dispose();
        }
    }
}
