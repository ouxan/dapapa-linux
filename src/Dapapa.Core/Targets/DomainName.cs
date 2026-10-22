using System.Globalization;
using System.Net;

namespace Dapapa.Core
{
    internal static class DomainName
    {
        public static string Normalize(string value) => TryNormalize(value, out var domain)
            ? domain : throw new ArgumentException(Localization.T("InvalidDomain"));

        public static bool TryNormalize(string? value, out string domain)
        {
            domain = "";
            if (string.IsNullOrWhiteSpace(value)) return false;
            string input = value.Trim();
            if (input.Any(char.IsWhiteSpace) || input.Contains('*') || input.Contains('\\')) return false;
            bool url = input.Contains("://", StringComparison.Ordinal);
            if (!url && input.IndexOfAny(['/', '?', '#', ':', '@']) >= 0) return false;
            if (url)
            {
                if (!Uri.TryCreate(input, UriKind.Absolute, out var uri) ||
                    (uri.Scheme != "https" && uri.Scheme != "http") || uri.UserInfo.Length != 0) return false;
                input = uri.Host;
            }
            input = input.TrimEnd('.');
            try { input = new IdnMapping().GetAscii(input).ToLowerInvariant(); }
            catch (ArgumentException) { return false; }
            if (input.Length > 253 || !input.Contains('.') || IPAddress.TryParse(input, out _) ||
                Uri.CheckHostName(input) != UriHostNameType.Dns) return false;
            if (!input.Split('.').All(label => label.Length is > 0 and <= 63 &&
                char.IsAsciiLetterOrDigit(label[0]) && char.IsAsciiLetterOrDigit(label[^1]) &&
                label.All(c => char.IsAsciiLetterOrDigit(c) || c == '-'))) return false;
            domain = input;
            return true;
        }
    }
}
