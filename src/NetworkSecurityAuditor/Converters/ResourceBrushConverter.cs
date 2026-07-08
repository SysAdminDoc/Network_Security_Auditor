using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace NetworkSecurityAuditor.Converters;

public sealed class ResourceBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is string key && !string.IsNullOrWhiteSpace(key))
        {
            return Application.Current.TryFindResource(key) as Brush ?? Brushes.Transparent;
        }

        return Brushes.Transparent;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return Binding.DoNothing;
    }
}
