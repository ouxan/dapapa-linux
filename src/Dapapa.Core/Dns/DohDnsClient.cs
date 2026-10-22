using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;

namespace Dapapa.Core
{
    internal sealed class DohDnsClient(HttpClient client, TimeProvider? timeProvider = null, TimeSpan? timeout = null, string? endpoint = null)
    {
        internal const string CloudflareEndpoint = "https://1.1.1.1/dns-query";
        internal const string Quad9EcsEndpoint = "https://dns11.quad9.net/dns-query";
        public Uri Endpoint { get; } = ParseEndpoint(endpoint);

        internal static Uri ParseEndpoint(string? endpoint)
        {
            if (!Uri.TryCreate(endpoint ?? CloudflareEndpoint, UriKind.Absolute, out var uri) ||
                uri.Scheme != Uri.UriSchemeHttps || uri.Host.Length == 0 || uri.UserInfo.Length != 0 || uri.Fragment.Length != 0)
                throw new ArgumentException(Localization.T("InvalidDohEndpoint"));
            return uri;
        }
        private sealed record CacheEntry(byte[] Message, List<DnsRecord> Records, DateTimeOffset Created, DateTimeOffset Expires);
        private sealed class Operation(byte[] query, long epoch)
        {
            public readonly byte[] Query = query;
            public readonly long Epoch = epoch;
            public readonly CancellationTokenSource Cancellation = new();
            public readonly TaskCompletionSource<byte[]> Completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
            public int Waiters;
        }

        private readonly object _gate = new();
        private readonly Dictionary<string, CacheEntry> _cache = new();
        private readonly Dictionary<(long Epoch, string Key), Operation> _operations = new();
        private readonly SemaphoreSlim _slots = new(8, 8);
        private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
        private readonly TimeSpan _timeout = timeout ?? TimeSpan.FromSeconds(4);
        private long _epoch;
        public event Action<string>? Log;
        internal int CachedCount { get { lock (_gate) return _cache.Count; } }
        internal int PendingCount { get { lock (_gate) return _operations.Count; } }

        public void ClearCache() { lock (_gate) { ++_epoch; _cache.Clear(); } }

        public DateTimeOffset GetExpiry(byte[] query)
        {
            string key = Key(query);
            lock (_gate) return _cache.TryGetValue(key, out var entry) ? entry.Expires : _time.GetUtcNow();
        }

        public async Task<byte[]> ResolveAsync(byte[] query, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!DnsWire.TryReadMessage(query, out _, out _) || (query[2] & 0x80) != 0)
                throw new InvalidDataException("Invalid DNS query.");
            string key = Key(query);
            Operation operation;
            lock (_gate)
            {
                var now = _time.GetUtcNow();
                if (_cache.TryGetValue(key, out var cached))
                {
                    if (cached.Expires > now) return CopyResponse(cached, query, now);
                    _cache.Remove(key);
                }
                var operationKey = (_epoch, key);
                if (!_operations.TryGetValue(operationKey, out operation!))
                {
                    if (_operations.Count >= 72) return DnsWire.ErrorResponse(query, 2);
                    operation = new((byte[])query.Clone(), _epoch);
                    _operations.Add(operationKey, operation);
                    operation.Cancellation.CancelAfter(_timeout);
                    _ = Task.Run(() => FetchAsync(operation, key));
                }
                ++operation.Waiters;
            }
            try
            {
                byte[] reply = (byte[])(await operation.Completion.Task.WaitAsync(cancellationToken).ConfigureAwait(false)).Clone();
                DnsWire.Write16(reply, 0, DnsWire.Read16(query, 0));
                return reply;
            }
            finally
            {
                bool drain = false;
                lock (_gate)
                {
                    if (--operation.Waiters == 0 && !operation.Completion.Task.IsCompleted)
                    {
                        operation.Cancellation.Cancel();
                        drain = true;
                    }
                }
                if (drain)
                    try { await operation.Completion.Task.ConfigureAwait(false); } catch (OperationCanceledException) { }
            }
        }

        private async Task FetchAsync(Operation operation, string key)
        {
            bool entered = false;
            byte[]? reply = null;
            bool cancelled = false;
            try
            {
                await _slots.WaitAsync(operation.Cancellation.Token).ConfigureAwait(false);
                entered = true;
                using var request = new HttpRequestMessage(HttpMethod.Post, Endpoint)
                {
                    Version = System.Net.HttpVersion.Version20,
                    VersionPolicy = HttpVersionPolicy.RequestVersionOrLower
                };
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));
                request.Content = new ByteArrayContent(operation.Query);
                request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, operation.Cancellation.Token).ConfigureAwait(false);
                response.EnsureSuccessStatusCode();
                if (response.Content.Headers.ContentType?.MediaType != "application/dns-message")
                    throw new InvalidDataException("Unexpected DoH content type.");
                using var stream = await response.Content.ReadAsStreamAsync(operation.Cancellation.Token).ConfigureAwait(false);
                using var buffer = new MemoryStream();
                byte[] chunk = new byte[4096];
                int count;
                while ((count = await stream.ReadAsync(chunk, operation.Cancellation.Token).ConfigureAwait(false)) > 0)
                {
                    if (buffer.Length + count > 65535) throw new InvalidDataException("Oversized DNS response.");
                    buffer.Write(chunk, 0, count);
                }
                reply = buffer.ToArray();
                if (!DnsWire.IsResponseFor(operation.Query, reply)) throw new InvalidDataException("DNS response does not match the query.");
                DnsWire.TryReadMessage(reply, out _, out var records);
                uint age = (uint)Math.Clamp(response.Headers.Age?.TotalSeconds ?? 0, 0, uint.MaxValue);
                var ttls = new List<DnsRecord>();
                foreach (var record in records)
                {
                    if (record.Type == 41) continue;
                    uint ttl = record.Ttl > age ? record.Ttl - age : 0;
                    DnsWire.Write32(reply, record.TtlOffset, ttl);
                    ttls.Add(record with { Ttl = ttl });
                }
                uint minimum = ttls.Select(r => r.Ttl).DefaultIfEmpty(0u).Min();
                var now = _time.GetUtcNow();
                lock (_gate)
                {
                    if (operation.Epoch == _epoch && (reply[3] & 15) == 0 && (reply[2] & 2) == 0 && minimum > 0 && !operation.Cancellation.IsCancellationRequested)
                    {
                        if (_cache.Count >= 512) _cache.Remove(_cache.MinBy(pair => pair.Value.Created).Key);
                        _cache[key] = new(reply, ttls, now, now.AddSeconds(minimum));
                    }
                }
            }
            catch (OperationCanceledException) when (operation.Cancellation.IsCancellationRequested && operation.Waiters == 0) { cancelled = true; }
            catch (Exception ex)
            {
                DnsWire.TryReadQuestion(operation.Query, out var question);
                Log?.Invoke(Localization.T("DnsResolveFailed", question.Name, ex.Message));
                reply = DnsWire.ErrorResponse(operation.Query, 2);
            }
            finally
            {
                if (entered) _slots.Release();
                lock (_gate)
                {
                    _operations.Remove((operation.Epoch, key));
                    if (cancelled) operation.Completion.TrySetCanceled();
                    else operation.Completion.TrySetResult(reply ?? DnsWire.ErrorResponse(operation.Query, 2));
                    operation.Cancellation.Dispose();
                }
            }
        }

        private static string Key(byte[] query) => Convert.ToHexString(SHA256.HashData(query.AsSpan(2)));
        private static byte[] CopyResponse(CacheEntry entry, byte[] query, DateTimeOffset now)
        {
            byte[] reply = (byte[])entry.Message.Clone();
            uint elapsed = (uint)Math.Clamp((now - entry.Created).TotalSeconds, 0, uint.MaxValue);
            foreach (var record in entry.Records)
                DnsWire.Write32(reply, record.TtlOffset, record.Ttl > elapsed ? record.Ttl - elapsed : 0);
            DnsWire.Write16(reply, 0, DnsWire.Read16(query, 0));
            return reply;
        }
    }
}
