using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using PcCheck.Core;

namespace PcCheck.App.Views;

public sealed class SeverityBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        Application.Current.FindResource(value switch
        {
            Severity.Critical => "CriticalBrush",
            Severity.High => "HighBrush",
            Severity.Medium => "MediumBrush",
            Severity.Low => "LowBrush",
            _ => "InfoBrush",
        });

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class VerdictBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        Application.Current.FindResource(value switch
        {
            Verdict.HardwareReplace => "CriticalBrush",
            Verdict.Format => "HighBrush",
            // Not the accent: with the orange brand, accent sits too close to Format's color.
            Verdict.Cleanup => "CleanupBrush",
            _ => "OkBrush",
        });

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class NullToCollapsedConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture) =>
        value is null || value as string == "" ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class CountToVisibilityConverter : IValueConverter
{
    // parameter "empty" shows the element only when the count is zero.
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var any = value is int n && n > 0;
        if (parameter as string == "empty") any = !any;
        return any ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}
