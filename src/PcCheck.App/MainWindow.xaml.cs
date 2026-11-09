using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

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

    private void OnStateChanged()
    {
        var maximized = WindowState == WindowState.Maximized;
        // A maximized WindowChrome window extends past the screen by the resize border; pull the content back in.
        var b = SystemParameters.WindowResizeBorderThickness;
        Root.Margin = maximized ? new Thickness(b.Left + 1, b.Top + 1, b.Right + 1, b.Bottom + 1) : new Thickness(0);
        MaxButton.Content = maximized ? "\uE923" : "\uE922";
        MaxButton.ToolTip = maximized ? "이전 크기로" : "최대화";
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
