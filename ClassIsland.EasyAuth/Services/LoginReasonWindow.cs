using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;

namespace ClassIsland.EasyAuth.Services;

/// <summary>
/// 独立的「本次登录原因」输入框。不走 ClassIsland 的对话框服务，
/// 就是一个普通 Avalonia Window：Show() 非模态，关掉/超时都不影响认证结果。
///
/// 可见性取舍：ClassIsland 主窗口通常全屏且置顶，弹窗不置顶会被完全遮住，
/// 所以这里设 Topmost；但**不调用 Activate()**，不抢键盘焦点、不打断用户。
/// </summary>
public sealed class LoginReasonWindow : Window
{
    private readonly LoginReasonContext _ctx;
    private readonly TextBox _input = new()
    {
        Watermark = "例如：调课 / 临时借用 / 演示",
        MaxLength = LoginReasonService.MaxReasonLength,
        AcceptsReturn = false
    };
    private readonly DispatcherTimer _timer = new()
    {
        Interval = TimeSpan.FromSeconds(LoginReasonService.AutoCloseSeconds)
    };

    private bool _inputTouched;
    private bool _recorded;

    public LoginReasonWindow(LoginReasonContext ctx)
    {
        _ctx = ctx;
        Title = "EasyAuth · 本次登录原因";
        Width = 460;
        SizeToContent = SizeToContent.Height;
        CanResize = false;
        ShowInTaskbar = false;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        Topmost = true;

        var root = new StackPanel { Margin = new Thickness(16), Spacing = 8 };
        root.Children.Add(new TextBlock
        {
            Text = "已通过 U 盘验证，记一下本次登录原因？",
            FontWeight = FontWeight.SemiBold,
            TextWrapping = TextWrapping.Wrap
        });
        root.Children.Add(new TextBlock
        {
            Text = "仅写入本机 audit.log 用于排查；可以直接忽略，" +
                   $"{LoginReasonService.AutoCloseSeconds} 秒未点输入框会自动关闭。",
            TextWrapping = TextWrapping.Wrap,
            Opacity = 0.75
        });

        // 点击（或键盘聚焦）输入框即视为"打算填写"，取消自动关闭，
        // 让用户从容写完再提交或手动关掉。
        _input.GotFocus += (_, _) =>
        {
            _inputTouched = true;
            _timer.Stop();
        };
        root.Children.Add(_input);

        var row = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Spacing = 8
        };
        var skip = new Button { Content = "忽略" };
        skip.Click += (_, _) => CloseWith("dismissed");
        var submit = new Button { Content = "记录原因" };
        submit.Click += (_, _) => CloseWith("provided");
        row.Children.Add(skip);
        row.Children.Add(submit);
        root.Children.Add(row);
        Content = root;

        _timer.Tick += (_, _) =>
        {
            _timer.Stop();
            if (!_inputTouched)
            {
                CloseWith("timeout");
            }
        };
        // 无论提交、忽略、超时还是 Alt+F4，都只记录一次
        Closed += (_, _) => Finish("dismissed");
        Opened += (_, _) => _timer.Start();
    }

    /// <summary>由按钮或超时调用：指定结果并关闭窗口。</summary>
    public void CloseWith(string outcome)
    {
        Finish(outcome);
        Close();
    }

    private void Finish(string outcome)
    {
        if (_recorded)
        {
            return;
        }
        _recorded = true;
        _timer.Stop();
        LoginReasonService.Record(_ctx, _input.Text, outcome);
    }
}
