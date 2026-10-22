using Avalonia.Data.Converters;

namespace Dapapa.App.Styles
{
    /// <summary>
    /// The Windows app lays text out with Segoe UI's Windows metrics (1.33 × font size per line). Selawik shares
    /// those metrics, but Avalonia uses its tighter hhea line height (1.20 ×), so lines are set explicitly.
    /// </summary>
    public static class TextMetrics
    {
        public const double LineHeightRatio = 2724.0 / 2048.0;

        public static readonly IValueConverter LineHeight =
            new FuncValueConverter<double, double>(size => Math.Round(size * LineHeightRatio, 2));
    }
}
