using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Controls.Primitives;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Styling;
using ClassIsland.Core.Abstractions.Controls;
using ClassIsland.Core.Attributes;
using ClassIsland.EasyAuth.Services;

namespace ClassIsland.EasyAuth.Settings;

/// <summary>
/// 插件设置页：ClassIsland 设置窗口 →「U盘密钥」。
///
/// 为什么单独开一页：
///   临时密码、完整性检测这些「应急与自检」是**插件级**配置（写在 security.json，
///   与具体哪一支 U 盘凭据无关）。原先它们塞在凭据编辑界面的「安全与应急」折叠区里，
///   既难找，又必须先存在一个 U 盘凭据才进得去——而临时密码恰恰是「U 盘丢了/坏了」
///   时用的应急通道，此时恰恰最可能没有可编辑的凭据。
///
/// ⚠ 手动注册：宿主**不会**自动发现插件的设置页。
/// 必须在 Plugin.Initialize 里显式调用 services.AddSettingsPage&lt;EasyAuthSettingsPage&gt;()，
/// 否则这一页根本不会出现在设置窗口里。详见 Plugin.cs。
/// </summary>
[SettingsPageInfo(PageId, "U盘密钥", "\uec8b", "\uec8b")]
public class EasyAuthSettingsPage : SettingsPageBase
{
    /// <summary>设置页 ID。与插件 id 同前缀，避免和其它插件撞 id（撞了 AddSettingsPage 会直接抛异常）。</summary>
    public const string PageId = "cn.amengbro.easyauth.settings";

    private readonly StackPanel _root = new() { Margin = new Thickness(18, 14, 18, 18), Spacing = 6 };

    // —— 检测器开关 ——
    private readonly CheckBox _chkTamper = new() { Content = "完整性检测（只记录差异，不重启、不回滚）" };
    private readonly CheckBox _chkTempEnabled = new() { Content = "启用一次性临时密码" };

    // —— 一次性临时密码 ——
    private readonly TextBlock _tempStatus = new() { TextWrapping = TextWrapping.Wrap, FontSize = 12 };
    private readonly TextBox _tempPlain = new()
    {
        IsReadOnly = true,
        IsVisible = false,
        FontFamily = new FontFamily("Consolas"),
        FontSize = 22,
        LetterSpacing = 3,
        TextAlignment = TextAlignment.Center,
        HorizontalAlignment = HorizontalAlignment.Stretch
    };
    private readonly Button _genTempButton = new() { Content = "生成临时密码" };
    private readonly Button _revokeTempButton = new() { Content = "撤销" };
    private readonly Button _copyTempButton = new() { Content = "复制", IsVisible = false };

    // —— 完整性检测 ——
    private readonly TextBlock _integrityStatus = new() { TextWrapping = TextWrapping.Wrap, FontSize = 12 };
    private readonly Button _rebaselineButton = new() { Content = "重建完整性基线" };

    // —— 审计日志 ——
    private readonly Button _auditButton = new() { Content = "查看审计日志（最近 15 条）" };
    private readonly TextBlock _auditView = new()
    {
        TextWrapping = TextWrapping.Wrap,
        FontFamily = new FontFamily("Consolas"),
        FontSize = 11,
        IsVisible = false
    };

    private bool _suppressChange;

    public EasyAuthSettingsPage()
    {
        BuildUi();
        Content = new ScrollViewer
        {
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
            Content = _root
        };

        Loaded += OnLoaded;

        _chkTamper.IsCheckedChanged += (_, _) =>
        {
            if (_suppressChange) return;
            SecurityConfigStore.Mutate(PluginPaths.PluginDirectory, cfg =>
            {
                cfg.EnableTamperDetection = _chkTamper.IsChecked == true;
                return cfg;
            });
            RefreshIntegrityUi();
        };

        _chkTempEnabled.IsCheckedChanged += (_, _) =>
        {
            if (_suppressChange) return;
            SecurityConfigStore.Mutate(PluginPaths.PluginDirectory, cfg =>
            {
                cfg.EnableTempPassword = _chkTempEnabled.IsChecked == true;
                return cfg;
            });
            RefreshTempUi();
        };

        _genTempButton.Click += async (_, _) => await GenerateTempPasswordAsync();
        _revokeTempButton.Click += (_, _) => RevokeTempPassword();
        _copyTempButton.Click += async (_, _) => await CopyPlaintextAsync();
        _rebaselineButton.Click += (_, _) => Rebaseline();
        _auditButton.Click += (_, _) => ToggleAuditView();
    }

    /// <summary>搭界面。全部用代码构建，避免为插件引入 Avalonia XAML 编译链。</summary>
    private void BuildUi()
    {
        _root.Children.Add(new TextBlock
        {
            Text = "U盘密钥 · 安全与应急",
            FontSize = 20,
            FontWeight = FontWeight.SemiBold,
            Margin = new Thickness(0, 0, 0, 4)
        });
        _root.Children.Add(new TextBlock
        {
            Text = "这里的配置是插件级的，对所有 U 盘凭据生效。",
            FontSize = 11,
            TextWrapping = TextWrapping.Wrap,
            Opacity = 0.7,
            Margin = new Thickness(0, 0, 0, 8)
        });

        // —— 检测器开关 ——
        _root.Children.Add(SectionTitle("检测器开关"));
        _root.Children.Add(_chkTamper);
        _root.Children.Add(_chkTempEnabled);
        _root.Children.Add(new TextBlock
        {
            Text = "每个通道各自独立可开关，互不牵连。下列开关为预留项，本版尚未接线（保持关闭）：" +
                   "静默重启、自动换回、应急恢复码。",
            FontSize = 11,
            TextWrapping = TextWrapping.Wrap,
            Opacity = 0.7,
            Margin = new Thickness(0, 2, 0, 4)
        });

        // —— 一次性临时密码 ——
        _root.Children.Add(SectionTitle("一次性临时密码"));
        _root.Children.Add(_tempStatus);
        _root.Children.Add(_tempPlain);

        var tempRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        tempRow.Children.Add(_genTempButton);
        tempRow.Children.Add(_revokeTempButton);
        tempRow.Children.Add(_copyTempButton);
        _root.Children.Add(tempRow);

        _root.Children.Add(new TextBlock
        {
            Text = "明文只显示这一次，本机只保存哈希；用一次即作废，没有有效期。" +
                   "应急通道，不是防破解机制——同一账户下能写插件配置目录的人可以自行撤销或重建。",
            FontSize = 11,
            TextWrapping = TextWrapping.Wrap,
            Opacity = 0.7,
            Margin = new Thickness(0, 2, 0, 4)
        });

        // —— 完整性检测 ——
        _root.Children.Add(SectionTitle("完整性检测"));
        _root.Children.Add(_integrityStatus);
        _root.Children.Add(_rebaselineButton);
        _root.Children.Add(new TextBlock
        {
            Text = "只记录 Credentials.json 的内容差异，不重启 ClassIsland、不回滚文件。" +
                   "宿主每次保存凭据也会产生差异，插件无法判定来源；确认是你自己改的后再点重建基线。",
            FontSize = 11,
            TextWrapping = TextWrapping.Wrap,
            Opacity = 0.7,
            Margin = new Thickness(0, 2, 0, 4)
        });

        // —— 审计日志 ——
        _root.Children.Add(SectionTitle("审计日志"));
        _root.Children.Add(_auditButton);
        _root.Children.Add(_auditView);
    }

    private static TextBlock SectionTitle(string text) => new()
    {
        Text = text,
        FontWeight = FontWeight.SemiBold,
        FontSize = 14,
        Margin = new Thickness(0, 10, 0, 2)
    };

    private void OnLoaded(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        ApplyTheme();
        RefreshAll();
    }

    /// <summary>把配置与运行状态同步到界面。</summary>
    private void RefreshAll()
    {
        var dir = PluginPaths.PluginDirectory;
        var cfg = SecurityConfigStore.Load(dir);
        _suppressChange = true;
        _chkTamper.IsChecked = cfg.EnableTamperDetection;
        _chkTempEnabled.IsChecked = cfg.EnableTempPassword;
        _suppressChange = false;
        RefreshTempUi();
        RefreshIntegrityUi();
    }

    private void RefreshTempUi()
    {
        var dir = PluginPaths.PluginDirectory;
        var cfg = SecurityConfigStore.Load(dir);
        _tempStatus.Text = TempPasswordService.Describe(dir);
        // 通道关闭时不允许生成
        _genTempButton.IsEnabled = cfg.EnableTempPassword;
        _revokeTempButton.IsEnabled = cfg.EnableTempPassword && cfg.HasActiveTempPassword();
    }

    private void RefreshIntegrityUi()
    {
        _integrityStatus.Text = IntegrityMonitor.Describe(PluginPaths.PluginDirectory);
    }

    private async Task GenerateTempPasswordAsync()
    {
        var dir = PluginPaths.PluginDirectory;
        // PBKDF2 十万次迭代，放线程池避免卡住 UI
        var issue = await Task.Run(() => TempPasswordService.Create(dir));
        if (issue == null)
        {
            _tempStatus.Text = "生成失败：无法写入 security.json，请检查插件配置目录权限。";
            return;
        }
        // 明文只在此处显示一次；不写盘、不进日志、不进审计
        _tempPlain.Text = issue.Plaintext;
        _tempPlain.IsVisible = true;
        _copyTempButton.IsVisible = true;
        RefreshTempUi();
    }

    private void RevokeTempPassword()
    {
        TempPasswordService.Revoke(PluginPaths.PluginDirectory);
        _tempPlain.Text = "";
        _tempPlain.IsVisible = false;
        _copyTempButton.IsVisible = false;
        RefreshTempUi();
    }

    private async Task CopyPlaintextAsync()
    {
        var text = _tempPlain.Text;
        if (string.IsNullOrEmpty(text)) return;
        try
        {
            var top = TopLevel.GetTopLevel(this);
            var clipboard = top?.Clipboard;
            if (clipboard == null)
            {
                _tempStatus.Text = "剪贴板不可用，请手动选中并复制上面的密码。";
                return;
            }
            await clipboard.SetTextAsync(text);
            _tempStatus.Text = "已复制到剪贴板。明文只显示这一次，请立刻记下并清空剪贴板。";
        }
        catch (Exception ex)
        {
            _tempStatus.Text = $"复制失败：{ex.GetType().Name}，请手动选中并复制。";
        }
    }

    private void Rebaseline()
    {
        var ok = IntegrityMonitor.Rebaseline(PluginPaths.PluginDirectory);
        RefreshIntegrityUi();
        _integrityStatus.Text = ok
            ? "已重建完整性基线，后续以当前凭据文件为准。"
            : "重建失败：找不到凭据文件，或没有读取权限。";
    }

    private void ToggleAuditView()
    {
        if (_auditView.IsVisible)
        {
            _auditView.IsVisible = false;
            _auditButton.Content = "查看审计日志（最近 15 条）";
            return;
        }
        _auditView.Text = AuditLogService.ReadTail(PluginPaths.PluginDirectory);
        _auditView.IsVisible = true;
        _auditButton.Content = "收起审计日志";
    }

    /// <summary>
    /// 主题适配：优先用宿主主题里的资源键，取不到再按明暗回退，
    /// 保证在浅色/深色主题下文字都读得出来。
    /// </summary>
    private void ApplyTheme()
    {
        var app = Application.Current;
        if (app == null) return;
        var variant = app.RequestedThemeVariant ?? ThemeVariant.Default;
        var isDark = variant == ThemeVariant.Dark;

        var foreground = ResolveBrush(app, variant, "MaterialDesignBody",
            isDark ? Color.FromRgb(0xEC, 0xEC, 0xEC) : Color.FromRgb(0x1A, 0x1A, 0x1A));
        var background = ResolveBrush(app, variant, "MaterialDesignPaper",
            isDark ? Color.FromRgb(0x20, 0x20, 0x20) : Color.FromRgb(0xFC, 0xFC, 0xFC));

        if (foreground != null)
        {
            TextElement.SetForeground(this, foreground);
        }
        if (background != null)
        {
            Background = background;
        }
    }

    private static IBrush? ResolveBrush(Application app, ThemeVariant variant, string key, Color fallback)
    {
        try
        {
            if (app.TryFindResource(key, variant, out var res))
            {
                if (res is IBrush brush) return brush;
                if (res is Color color) return new SolidColorBrush(color);
            }
        }
        catch
        {
            // 资源不存在或主题还没加载完，走回退色
        }
        return new SolidColorBrush(fallback);
    }
}
