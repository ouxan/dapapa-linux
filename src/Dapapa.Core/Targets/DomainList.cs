namespace Dapapa.Core
{
    internal static class DomainList
    {
        internal const int MaxDomains = 500;
        public static bool TryParse(string input, out string[] domains, out string error)
        {
            var parsed = new List<string>();
            var unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string[] lines = input.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
            for (int i = 0; i < lines.Length; i++)
            {
                if (string.IsNullOrWhiteSpace(lines[i])) continue;
                if (!DomainName.TryNormalize(lines[i], out var domain))
                {
                    domains = [];
                    error = Localization.T("InvalidDomainLine", i + 1);
                    return false;
                }
                if (unique.Add(domain)) parsed.Add(domain);
                if (parsed.Count > MaxDomains)
                {
                    domains = [];
                    error = Localization.T("DomainListLimit", MaxDomains);
                    return false;
                }
            }
            domains = parsed.ToArray();
            error = domains.Length == 0 ? Localization.T("InvalidDomain") : "";
            return domains.Length > 0;
        }
    }
}
