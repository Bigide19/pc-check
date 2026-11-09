using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using Path = System.Windows.Shapes.Path;

namespace PcCheck.App.Views;

public enum LeakDropMode { Progress, Clean, Leaking, Fixed }

// Brand drop that doubles as a status mark: fills up while scanning, drips while something leaks, plugged after fixes.
public partial class LeakDrop : UserControl
{
    public static readonly DependencyProperty ModeProperty = DependencyProperty.Register(
        nameof(Mode), typeof(LeakDropMode), typeof(LeakDrop), new PropertyMetadata(LeakDropMode.Clean, (d, _) => ((LeakDrop)d).Render()));

    public static readonly DependencyProperty ValueProperty = DependencyProperty.Register(
        nameof(Value), typeof(double), typeof(LeakDrop), new PropertyMetadata(0.0, (d, _) => ((LeakDrop)d).Render()));

    public static readonly DependencyProperty CountProperty = DependencyProperty.Register(
        nameof(Count), typeof(int), typeof(LeakDrop), new PropertyMetadata(0, (d, _) => ((LeakDrop)d).Render()));

    public LeakDropMode Mode { get => (LeakDropMode)GetValue(ModeProperty); set => SetValue(ModeProperty, value); }
    public double Value { get => (double)GetValue(ValueProperty); set => SetValue(ValueProperty, value); }
    public int Count { get => (int)GetValue(CountProperty); set => SetValue(CountProperty, value); }

    private bool _dripping;

    public LeakDrop()
    {
        InitializeComponent();
        Render();
    }

    private void Render()
    {
        var mode = Mode;
        var progress = mode == LeakDropMode.Progress;
        Root.Height = progress ? 100 : 136;
        Back.Fill = (Brush)FindResource(progress ? "AccentSoftBrush" : "BrandBrush");
        Tank.Visibility = Outline.Visibility = progress ? Visibility.Visible : Visibility.Collapsed;
        Check.Visibility = mode is LeakDropMode.Clean or LeakDropMode.Fixed ? Visibility.Visible : Visibility.Collapsed;
        Plug.Visibility = mode == LeakDropMode.Fixed ? Visibility.Visible : Visibility.Collapsed;
        CountText.Visibility = mode == LeakDropMode.Leaking ? Visibility.Visible : Visibility.Collapsed;
        CountText.Text = Count > 99 ? "99+" : Count.ToString();

        if (progress)
        {
            var target = 96 * (1 - Math.Clamp(Value, 0, 1));
            LevelShift.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(target, TimeSpan.FromMilliseconds(300)));
        }
        SetDripping(mode == LeakDropMode.Leaking);

        AutomationProperties.SetName(this, mode switch
        {
            LeakDropMode.Progress => string.Format(Strings.Drop_Progress, Math.Round(Math.Clamp(Value, 0, 1) * 100)),
            LeakDropMode.Leaking => Count == 1 ? Strings.Drop_LeakOne : string.Format(Strings.Drop_Leaks, Count),
            LeakDropMode.Fixed => Strings.Drop_Fixed,
            _ => Strings.Drop_NoLeak,
        });
    }

    private void SetDripping(bool on)
    {
        if (on == _dripping) return;
        _dripping = on;
        // Respect the Windows "show animations" setting: show still drips instead.
        var animate = on && SystemParameters.ClientAreaAnimation;
        Drip(Drip1, on, animate, TimeSpan.Zero);
        Drip(Drip2, on, animate, TimeSpan.FromMilliseconds(550));
    }

    private static void Drip(Path drip, bool on, bool animate, TimeSpan delay)
    {
        var shift = (TranslateTransform)drip.RenderTransform;
        shift.BeginAnimation(TranslateTransform.YProperty, null);
        drip.BeginAnimation(OpacityProperty, null);
        if (!on) { drip.Opacity = 0; return; }
        if (!animate)
        {
            drip.Opacity = 1;
            shift.Y = delay == TimeSpan.Zero ? 0 : 18;
            return;
        }

        var period = TimeSpan.FromMilliseconds(1600);
        shift.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(0, 26, period)
        {
            BeginTime = delay, RepeatBehavior = RepeatBehavior.Forever, EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseIn },
        });
        var fade = new DoubleAnimationUsingKeyFrames { BeginTime = delay, Duration = period, RepeatBehavior = RepeatBehavior.Forever };
        fade.KeyFrames.Add(new LinearDoubleKeyFrame(0, KeyTime.FromPercent(0)));
        fade.KeyFrames.Add(new LinearDoubleKeyFrame(1, KeyTime.FromPercent(0.15)));
        fade.KeyFrames.Add(new LinearDoubleKeyFrame(0, KeyTime.FromPercent(1)));
        drip.BeginAnimation(OpacityProperty, fade);
    }
}
