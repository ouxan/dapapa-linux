using System.ComponentModel;

namespace Dapapa.Core
{
    /// <summary>A related-domain candidate shown to the user; nothing is selected until the user opts in.</summary>
    internal sealed class DiscoveryChoice(RelatedDomainCandidate candidate) : INotifyPropertyChanged
    {
        public string Domain => candidate.Domain;
        public string ReasonText => string.Join(", ", candidate.Reasons.Select(r => Localization.T("DiscoveryReason" + r)));
        public bool Selected { get; set; }
        public event PropertyChangedEventHandler? PropertyChanged;
        public void RefreshLocalization() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(ReasonText)));

        public static string[] SelectedDomains(IEnumerable<DiscoveryChoice> choices, IEnumerable<string> existing) =>
            choices.Where(c => c.Selected && !existing.Any(d =>
                c.Domain.Equals(d, StringComparison.OrdinalIgnoreCase) || c.Domain.EndsWith("." + d, StringComparison.OrdinalIgnoreCase)))
            .Select(c => c.Domain).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }
}
