using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using PcCheck.App.ViewModels;
using PcCheck.Core;

namespace PcCheck.App;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        StateChanged += (_, _) => OnStateChanged();
        SourceInitialized += (_, _) => RoundCorners();
    }

    private void OnMinimize(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void OnMaximize(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    private void OnClose(object sender, RoutedEventArgs e) => Close();

    // x:Static text is read when a view loads, so a new window is the simplest way to show every string in the new language.
    private void OnSwitchLanguage(object sender, RoutedEventArgs e)
    {
        Lang.Set(Lang.IsKorean ? "en" : "ko");
        App.ApplyLanguageFont();
        var next = new MainWindow
        {
            DataContext = new MainViewModel(),
            WindowStartupLocation = WindowStartupLocation.Manual,
            Left = RestoreBounds.Left, Top = RestoreBounds.Top, Width = RestoreBounds.Width, Height = RestoreBounds.Height,
        };
        Application.Current.MainWindow = next;
        next.Show();
        if (WindowState == WindowState.Maximized) next.WindowState = WindowState.Maximized;
        Close();
    }

    private void OnStateChanged()
    {
        var maximized = WindowState == WindowState.Maximized;
        // A maximized WindowChrome window extends past the screen by the resize border; pull the content back in.
        var b = SystemParameters.WindowResizeBorderThickness;
        Root.Margin = maximized ? new Thickness(b.Left + 1, b.Top + 1, b.Right + 1, b.Bottom + 1) : new Thickness(0);
        MaxButton.Content = maximized ? "\uE923" : "\uE922";
        MaxButton.ToolTip = maximized ? Strings.Win_Restore : Strings.Win_Maximize;
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

    // Windows 11 rounds normal windows but not custom-chrome ones unless asked; Windows 10 ignores the call.
    private void RoundCorners()
    {
        const int DWMWA_WINDOW_CORNER_PREFERENCE = 33, DWMWCP_ROUND = 2;
        var pref = DWMWCP_ROUND;
        _ = DwmSetWindowAttribute(new WindowInteropHelper(this).Handle, DWMWA_WINDOW_CORNER_PREFERENCE, ref pref, sizeof(int));
    }
}
