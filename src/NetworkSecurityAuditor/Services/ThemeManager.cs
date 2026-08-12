using System.ComponentModel;
using System.Windows;

namespace NetworkSecurityAuditor.Services;

internal static class ThemeManager
{
    internal static readonly Uri HighContrastResourceUri =
        new("/NetworkSecurityAuditor;component/Theme/HighContrast.xaml", UriKind.Relative);

    private static Application? _application;

    internal static event EventHandler? SystemContrastChanged;

    internal static void Initialize(Application application)
    {
        ArgumentNullException.ThrowIfNull(application);
        if (ReferenceEquals(_application, application))
            return;

        Shutdown();
        _application = application;
        Apply(application.Resources, SystemParameters.HighContrast);
        SystemParameters.StaticPropertyChanged += OnSystemParameterChanged;
    }

    internal static void Shutdown()
    {
        SystemParameters.StaticPropertyChanged -= OnSystemParameterChanged;
        _application = null;
    }

    internal static void Apply(ResourceDictionary resources, bool highContrast)
    {
        ArgumentNullException.ThrowIfNull(resources);
        var existing = resources.MergedDictionaries
            .Where(IsHighContrastDictionary)
            .ToList();

        if (highContrast)
        {
            if (existing.Count == 0)
                resources.MergedDictionaries.Add(CreateHighContrastDictionary());
            else
                foreach (var duplicate in existing.Skip(1))
                    resources.MergedDictionaries.Remove(duplicate);
            return;
        }

        foreach (var dictionary in existing)
            resources.MergedDictionaries.Remove(dictionary);
    }

    internal static ResourceDictionary CreateHighContrastDictionary() =>
        new() { Source = HighContrastResourceUri };

    private static bool IsHighContrastDictionary(ResourceDictionary dictionary) =>
        dictionary.Source is not null &&
        dictionary.Source.OriginalString.Equals(
            HighContrastResourceUri.OriginalString,
            StringComparison.OrdinalIgnoreCase);

    private static void OnSystemParameterChanged(object? sender, PropertyChangedEventArgs e)
    {
        if ((!string.IsNullOrEmpty(e.PropertyName) && e.PropertyName != nameof(SystemParameters.HighContrast)) || _application is null)
            return;

        var application = _application;
        application.Dispatcher.BeginInvoke(() =>
        {
            if (!ReferenceEquals(_application, application))
                return;

            Apply(application.Resources, SystemParameters.HighContrast);
            SystemContrastChanged?.Invoke(null, EventArgs.Empty);
        });
    }
}
