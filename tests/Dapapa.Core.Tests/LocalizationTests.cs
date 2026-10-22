using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using Dapapa.Core.Models;
using Dapapa.Core;

internal static partial class Program
{
    private static async Task LocalizationTestGroups()
    {
        Run("all translation entries have valid matching formats and used keys exist", TranslationCoverage);
        Run("selected language controls numeric formats, counters and group summaries", LocalizedFormats);
        Run("language change notifications only fire on changes", LanguageNotifications);
        await RunAsync("discovery HTTP and network failures follow the current language", LocalizedDiscoveryFailures);
    }

    private static void TranslationCoverage()
    {
        foreach (var (key, pair) in Localization.Entries)
        {
            Check(!string.IsNullOrWhiteSpace(pair.En) && !string.IsNullOrWhiteSpace(pair.Tr), "Empty translation: " + key);
            var en = CompositeFormat.Parse(pair.En);
            var tr = CompositeFormat.Parse(pair.Tr);
            Check(en.MinimumArgumentCount == tr.MinimumArgumentCount, "Translation format mismatch: " + key);
            string Indices(string text) => string.Join(",", Regex.Matches(text, @"(?<!\{)\{(\d+)(?:[,}:])")
                .Select(m => m.Groups[1].Value).Distinct().Order());
            Check(Indices(pair.En) == Indices(pair.Tr), "Translation loses an argument: " + key);
        }
        string root = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(root, "dapapa-linux.slnx"))) root = Path.GetDirectoryName(root) ?? throw new DirectoryNotFoundException("Repository root not found.");
        var files = Directory.EnumerateFiles(Path.Combine(root, "src"), "*.cs", SearchOption.AllDirectories)
            .Where(file => !file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}"));
        foreach (string file in files)
            foreach (Match match in Regex.Matches(File.ReadAllText(file), "Localization\\.T\\(\"([^\"]+)\"\\s*[,)]"))
                Check(Localization.Entries.ContainsKey(match.Groups[1].Value), "Missing translation in " + file + ": " + match.Groups[1].Value);
        foreach (var reason in Enum.GetValues<DiscoveryReason>())
            Check(Localization.Entries.ContainsKey("DiscoveryReason" + reason), "Missing discovery reason: " + reason);
    }

    private static void LocalizedFormats()
    {
        var language = Localization.Current;
        var culture = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("fr-FR");
            var group = new ProtectedApp { Domain = "example.com" };
            group.AddRelatedDomains(["cdn.other.net"]);
            Localization.Current = AppLanguage.English;
            Check(TrafficStatisticsService.FormatBytes(1536) == "1.5 KB", "English bytes depend on OS culture.");
            Check(TrafficStatisticsService.FormatSpeed(1536) == "1.5 KB/s", "English speed depends on OS culture.");
            Check(Localization.T("PacketsCount", 1234) == "1,234 packets", "English packet formatting incorrect.");
            Check(Localization.T("QueryCount", 1) == "1 query", "English singular query incorrect.");
            Check(group.SubtitleText == "example.com + 1 domain", "English singular group incorrect.");
            group.AddRelatedDomains(["assets.other.net"]);
            Check(group.SubtitleText == "example.com + 2 domains", "English plural group incorrect.");
            Check(Localization.T("DiscoveryFoundSingle", 1).StartsWith("1 suggestion found."), "Singular discovery incorrect.");
            Check(Localization.T("SyncPartialFailureSingle", 1).StartsWith("1 domain could"), "Singular IP failure incorrect.");
            var traffic = new TrafficStatisticsService();
            Check(traffic.AdapterName == "Network adapter", "English adapter fallback incorrect.");
            Localization.Current = AppLanguage.Turkish;
            Check(TrafficStatisticsService.FormatBytes(1536) == "1,5 KB", "Turkish bytes depend on OS culture.");
            Check(TrafficStatisticsService.FormatSpeed(1536) == "1,5 KB/s", "Turkish speed depends on OS culture.");
            Check(Localization.T("PacketsCount", 1234) == "1.234 paket", "Turkish packet formatting incorrect.");
            Check(Localization.T("QueriesCount", 0) == "0 sorgu", "Turkish DNS count incorrect.");
            Check(traffic.AdapterName == "Ağ adaptörü", "Adapter fallback does not follow language changes.");
            Check(Localization.T("IdleSpeed", 0) == "0,0 KB/s", "Idle speed ignores language.");
        }
        finally { CultureInfo.CurrentCulture = culture; Localization.Current = language; }
    }

    private static void LanguageNotifications()
    {
        var language = Localization.Current;
        int changes = 0;
        void Changed() => changes++;
        Localization.Changed += Changed;
        try
        {
            Localization.Current = language;
            Check(changes == 0, "Unchanged language causes refresh.");
            Localization.Current = language == AppLanguage.English ? AppLanguage.Turkish : AppLanguage.English;
            Check(changes == 1, "Language change not delivered.");
            Localization.Current = language;
            Check(changes == 2, "Language restoration not delivered.");
        }
        finally { Localization.Changed -= Changed; Localization.Current = language; }
    }

    private sealed class LocalizationHttpHandler(bool failConnection) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            failConnection ? Task.FromException<HttpResponseMessage>(new HttpRequestException("English native transport error")) :
                Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden));
    }

    private static async Task LocalizedDiscoveryFailures()
    {
        var language = Localization.Current;
        try
        {
            using var http = new HttpClient(new LocalizationHttpHandler(false));
            using var service = new RelatedDomainDiscoveryService(http);
            Localization.Current = AppLanguage.English;
            var result = await service.DiscoverAsync("example.com", CancellationToken.None);
            Check(!result.Completed && result.Error == "The page returned HTTP 403.", "403 is not a localized failure.");
            Localization.Current = AppLanguage.Turkish;
            Check(result.Error == "Sayfa HTTP 403 yanıtı verdi.", "Stored discovery error does not follow the language.");
            using var failedHttp = new HttpClient(new LocalizationHttpHandler(true));
            using var failedService = new RelatedDomainDiscoveryService(failedHttp);
            var failed = await failedService.DiscoverAsync("example.com", CancellationToken.None);
            Check(!failed.Completed && failed.Error == Localization.T("DiscoveryConnectionFailure"), "Raw English network error shown.");
            Localization.Current = AppLanguage.English;
            Check(failed.Error == Localization.T("DiscoveryConnectionFailure"), "Connection failure language is stale.");
        }
        finally { Localization.Current = language; }
    }
}
