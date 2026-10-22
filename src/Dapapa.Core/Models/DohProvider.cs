using Dapapa.Core;

namespace Dapapa.Core.Models
{
    public enum DohProvider { Quad9Ecs, Quad9, Cloudflare, Google, AdGuard }

    public static class DohProviders
    {
        public static IReadOnlyList<DohProvider> All { get; } = Array.AsReadOnly(Enum.GetValues<DohProvider>());
        public static string GetEndpoint(DohProvider provider) => provider switch
        {
            DohProvider.Quad9 => "https://dns.quad9.net/dns-query",
            DohProvider.Cloudflare => DohDnsClient.CloudflareEndpoint,
            DohProvider.Google => "https://dns.google/dns-query",
            DohProvider.AdGuard => "https://dns.adguard-dns.com/dns-query",
            _ => DohDnsClient.Quad9EcsEndpoint
        };
        public static string GetLabelKey(DohProvider provider) => "DohProvider" + provider;
        public static string GetDescriptionKey(DohProvider provider) => provider switch
        {
            DohProvider.Quad9Ecs => "DohQuad9EcsDescription",
            DohProvider.Quad9 => "DohQuad9Description",
            DohProvider.AdGuard => "DohAdGuardDescription",
            _ => "DohUnfilteredDescription"
        };
    }
}
