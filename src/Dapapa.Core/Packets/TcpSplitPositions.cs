using System.Globalization;
using System.Text.RegularExpressions;

namespace Dapapa.Core
{
    internal static class TcpSplitPositions
    {
        private static readonly Regex Marker = new("^(host|midhost|endhost|sld|midsld|endsld|sniext|method)([+-][0-9]{1,5})?$",
            RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
        public static bool IsValid(string? expression)
        {
            if (string.IsNullOrWhiteSpace(expression) || expression.Length > 160) return false;
            string[] parts = expression.Split(',');
            return parts.Length <= 7 && parts.All(part =>
                (int.TryParse(part.Trim(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out int value) && value is >= -65535 and <= 65535 && value != 0) ||
                Marker.IsMatch(part.Trim()));
        }

        public static int[] Resolve(string expression, int payloadLength, int hostOffset, string hostname, int methodLength)
        {
            if (!IsValid(expression)) return [];
            int lastDot = hostname.LastIndexOf('.');
            int sld = lastDot < 0 ? 0 : hostname.LastIndexOf('.', Math.Max(0, lastDot - 1)) + 1;
            int endSld = lastDot < 0 ? hostname.Length : lastDot;
            var positions = new SortedSet<int>();
            foreach (string part in expression.Split(',').Select(p => p.Trim()))
            {
                int position;
                if (int.TryParse(part, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out int value))
                    position = value < 0 ? payloadLength + value : value;
                else
                {
                    var match = Marker.Match(part);
                    int? marker = match.Groups[1].Value switch
                    {
                        "host" => hostOffset, "midhost" => hostOffset + hostname.Length / 2, "endhost" => hostOffset + hostname.Length,
                        "sld" => hostOffset + sld, "midsld" => hostOffset + sld + (endSld - sld) / 2, "endsld" => hostOffset + endSld,
                        "sniext" => methodLength == 0 ? hostOffset - 9 : null,
                        "method" => methodLength > 0 ? 0 : null, _ => null
                    };
                    if (marker == null) continue;
                    int offset = match.Groups[2].Success ? int.Parse(match.Groups[2].Value, CultureInfo.InvariantCulture) : 0;
                    position = marker.Value + offset;
                }
                if (position > 0 && position < payloadLength) positions.Add(position);
            }
            return positions.ToArray();
        }
    }
}
