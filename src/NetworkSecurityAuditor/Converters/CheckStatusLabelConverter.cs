using System.Globalization;
using System.Windows.Data;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Converters;

public sealed class CheckStatusLabelConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is CheckStatus status
            ? status switch
            {
                CheckStatus.NotAssessed => "Not assessed",
                CheckStatus.NA => "N/A",
                _ => status.ToString()
            }
            : value;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        Binding.DoNothing;
}
