using System.Globalization;
using System.Windows.Data;
using NetworkSecurityAuditor.Localization;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Converters;

public sealed class CheckStatusLabelConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is CheckStatus status
            ? status switch
            {
                CheckStatus.NotAssessed => UiText.StatusNotAssessed,
                CheckStatus.NA => UiText.StatusNotApplicable,
                CheckStatus.Pass => UiText.StatusPass,
                CheckStatus.Partial => UiText.StatusPartial,
                CheckStatus.Fail => UiText.StatusFail,
                _ => UiText.Unknown
            }
            : value;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        Binding.DoNothing;
}
