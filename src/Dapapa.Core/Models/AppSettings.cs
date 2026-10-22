using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text.Json.Serialization;
using Dapapa.Core;

namespace Dapapa.Core.Models
{
    public class ProtectedApp : INotifyPropertyChanged
    {
        private bool _enabled = true;
        private string _name = "";
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string Name { get => _name; set { _name = value; OnPropertyChanged(); } }
        public string Domain { get; set; } = "";
        public List<string> RelatedDomains { get; set; } = [];
        public bool Enabled
        {
            get => _enabled;
            set { _enabled = value; OnPropertyChanged(); }
        }
        [JsonIgnore] public string SubtitleText => RelatedDomains.Count == 0 ? Domain :
            Localization.T(RelatedDomains.Count == 1 ? "DomainGroupSummarySingle" : "DomainGroupSummary", Domain, RelatedDomains.Count);
        [JsonIgnore] public string ActionLabel => Localization.T("TargetActions");
        public void RefreshLocalization()
        {
            OnPropertyChanged(nameof(ActionLabel));
            OnPropertyChanged(nameof(SubtitleText));
        }
        public IEnumerable<string> GetDomains() => new[] { Domain }.Concat(RelatedDomains ?? []);
        public void SetDomains(IEnumerable<string> domains)
        {
            var normalized = domains.Select(DomainName.Normalize).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            if (normalized.Length == 0 || normalized.Length > DomainList.MaxDomains)
                throw new ArgumentException(Localization.T("DomainListLimit", DomainList.MaxDomains));
            Domain = normalized[0];
            RelatedDomains = normalized.Skip(1).ToList();
            OnPropertyChanged(nameof(Domain));
            OnPropertyChanged(nameof(SubtitleText));
        }
        public void AddRelatedDomains(IEnumerable<string> domains) => SetDomains(GetDomains().Concat(domains));
        public ProtectedApp Copy() => new() { Id = Id, Name = Name, Domain = Domain,
            RelatedDomains = [.. RelatedDomains], Enabled = Enabled };
        public void Apply(ProtectedApp source)
        {
            Name = source.Name;
            Domain = source.Domain;
            RelatedDomains = [.. source.RelatedDomains];
            Enabled = source.Enabled;
            OnPropertyChanged(nameof(Domain));
            OnPropertyChanged(nameof(SubtitleText));
        }
        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged([CallerMemberName] string? name = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    public class AppSettings
    {
        public const int CurrentTargetListVersion = 1;
        public int TargetListVersion { get; set; }
        public List<ProtectedApp> Apps { get; set; } = [];
        public bool RunOnLogin { get; set; }
        public bool MinimizeToTrayOnClose { get; set; } = true;
        public bool StartMinimizedToTray { get; set; }
        public bool AutoConnectOnLaunch { get; set; }
        public bool EnableConnectionWatchdog { get; set; } = true;
        public string Language { get; set; } = "en";
        public DpiMode DpiMode { get; set; }
        public DpiOptions CustomDpi { get; set; } = new();
        public DohProvider DohProvider { get; set; }
        public DpiOptions GetDpiOptions() => DpiMode == DpiMode.Custom ? CustomDpi ?? DpiOptions.Standard : DpiOptions.Standard;
        public string GetDohEndpoint() => DohProviders.GetEndpoint(DohProvider);
        public AppSettings Copy()
        {
            var copy = (AppSettings)MemberwiseClone();
            copy.Apps = Apps.Select(a => a.Copy()).ToList();
            return copy;
        }
        public List<string> GetEffectiveDomains() => Apps.Where(a => a.Enabled)
            .SelectMany(a => a.GetDomains()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        public void NormalizeTargets()
        {
            if (!Enum.IsDefined(DpiMode)) DpiMode = DpiMode.Standard;
            if (!Enum.IsDefined(DohProvider)) DohProvider = DohProvider.Quad9Ecs;
            CustomDpi = (CustomDpi ?? new()).Normalize();
            Apps ??= [];
            var domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var ids = new HashSet<string>(StringComparer.Ordinal);
            Apps = Apps.Where(a => a != null && DomainName.TryNormalize(a.Domain, out _) &&
                domains.Add(DomainName.Normalize(a.Domain))).ToList();
            foreach (var app in Apps)
            {
                app.Domain = DomainName.Normalize(app.Domain);
                app.RelatedDomains = (app.RelatedDomains ?? []).Where(d => DomainName.TryNormalize(d, out _))
                    .Select(DomainName.Normalize).Where(d => !d.Equals(app.Domain, StringComparison.OrdinalIgnoreCase))
                    .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                if (string.IsNullOrWhiteSpace(app.Name)) app.Name = app.Domain;
                if (string.IsNullOrWhiteSpace(app.Id) || !ids.Add(app.Id))
                {
                    app.Id = Guid.NewGuid().ToString("N");
                    ids.Add(app.Id);
                }
            }
        }
    }
}
