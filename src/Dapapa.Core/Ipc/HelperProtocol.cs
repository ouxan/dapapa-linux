using System.Text.Json;
using System.Text.Json.Serialization;
using Dapapa.Core.Models;

namespace Dapapa.Core.Ipc
{
    /// <summary>
    /// Newline-delimited JSON protocol between unprivileged clients and the privileged helper.
    /// Each line is one <see cref="HelperMessage"/>; requests carry an id that the matching response repeats.
    /// </summary>
    public static class HelperProtocol
    {
        public const int Version = 1;
        public const int MaxMessageBytes = 1024 * 1024;
        public const int MaxDomains = 20000;
        public const string DefaultSocketPath = "/run/dapapa/helper.sock";

        public static readonly JsonSerializerOptions JsonOptions = new()
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Converters = { new JsonStringEnumConverter() }
        };

        public static string Serialize(HelperMessage message) => JsonSerializer.Serialize(message, JsonOptions);

        public static HelperMessage Deserialize(string line) =>
            JsonSerializer.Deserialize<HelperMessage>(line, JsonOptions) ?? throw new InvalidDataException("Empty helper message.");
    }

    public enum HelperCommand { Hello, Start, Update, Stop, Status, Refresh }

    public enum ProtectionState { Stopped, Starting, Running, Stopping, Failed }

    public sealed record HelperMessage
    {
        public HelperRequest? Request { get; init; }
        public HelperResponse? Response { get; init; }
        public HelperEvent? Event { get; init; }
    }

    public sealed record HelperRequest(long Id, HelperCommand Command)
    {
        public int Protocol { get; init; }
        public IReadOnlyList<string>? Domains { get; init; }
        public DpiOptions? Options { get; init; }
        public DohProvider? Provider { get; init; }
        public bool Force { get; init; }
    }

    public sealed record HelperResponse(long Id, bool Ok)
    {
        public string? Error { get; init; }
        public int Protocol { get; init; }
        public HelperStatus? Status { get; init; }
        public RefreshResult? Refresh { get; init; }
    }

    public sealed record HelperEvent(HelperEventKind Kind)
    {
        public string? Text { get; init; }
        public HelperStatus? Status { get; init; }
    }

    public enum HelperEventKind { Log, Status }

    public sealed record HelperStatus(ProtectionState State)
    {
        public string? Error { get; init; }
        public int ActiveDomains { get; init; }
        public long BypassedPackets { get; init; }
        public long DnsReplies { get; init; }
        public string? LastTarget { get; init; }
        public DateTimeOffset? LastBypassed { get; init; }
        public DohProvider Provider { get; init; }
        public string HelperVersion { get; init; } = "";
    }

    /// <summary>Per-domain IPv4 counts from a Cloudflare target refresh; zero means the domain could not be resolved.</summary>
    public sealed record RefreshResult(IReadOnlyDictionary<string, int> Domains, bool Applied);
}
