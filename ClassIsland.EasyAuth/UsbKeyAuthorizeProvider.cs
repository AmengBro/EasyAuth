using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Templates;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using ClassIsland.Core.Abstractions.Controls;
using ClassIsland.Core.Attributes;
using ClassIsland.EasyAuth.Models;
using ClassIsland.EasyAuth.Services;

namespace ClassIsland.EasyAuth;

/// <summary>
/// U盘密钥认证提供方。
/// 认证态：分区下拉框 -> 验证 -> 进度条 + 逐项状态 -> 通过后按钮变"进入"。
/// 编辑态：分层开关复选框 -> 读取设备信息 -> 保存配对。
/// </summary>
[AuthorizeProviderInfo("easyauth.usbkey", "U盘密钥", "\uec8b")]
public class UsbKeyAuthorizeProvider : AuthorizeProviderControlBase<UsbKeyAuthSettings>
{
    private readonly ComboBox _volumeBox = new() { MinWidth = 240, HorizontalAlignment = HorizontalAlignment.Stretch };
    private readonly Button _refreshButton = new() { Content = "刷新", Width = 64, Margin = new Thickness(8, 0, 0, 0) };
    private readonly Button _actionButton = new() { Content = "验证", HorizontalAlignment = HorizontalAlignment.Stretch };
    private readonly ProgressBar _progress = new() { IsIndeterminate = true, IsVisible = false, Height = 4, Margin = new Thickness(0, 6, 0, 0) };
    private readonly TextBlock _status = new() { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 0) };

    private readonly StackPanel _editPanel = new();
    private readonly CheckBox _chkSn = new() { Content = "磁盘序列号绑定（防换盘克隆）", Margin = new Thickness(0, 2, 0, 0) };
    private readonly CheckBox _chkVolume = new() { Content = "卷标识绑定（防同盘另一分区）", Margin = new Thickness(0, 2, 0, 0) };
    private readonly CheckBox _chkToken = new() { Content = "token 校验（防复制密钥文件）", Margin = new Thickness(0, 2, 0, 0) };
    private readonly CheckBox _chkCounter = new() { Content = "克隆计数（防过期克隆盘）", Margin = new Thickness(0, 2, 0, 0) };
    private readonly CheckBox _chkBrand = new() { Content = "品牌提示（仅提示，不参与判定）", Margin = new Thickness(0, 2, 0, 0) };
    private readonly Button _readButton = new() { Content = "读取", Margin = new Thickness(0, 8, 0, 0) };
    private readonly TextBlock _deviceInfo = new() { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 0) };
    private readonly Button _saveButton = new() { Content = "保存配对", HorizontalAlignment = HorizontalAlignment.Stretch };

    private bool _verified;
    private bool _busy;
    private bool _uiModeApplied;

    public UsbKeyAuthorizeProvider()
    {
        var root = new StackPanel { Margin = new Thickness(10), Spacing = 4 };
        root.Children.Add(new TextBlock
        {
            Text = "通过 EasyAuth 验证",
            FontWeight = FontWeight.SemiBold
        });

        var pickRow = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto") };
        pickRow.Children.Add(_volumeBox);
        Grid.SetColumn(_refreshButton, 1);
        pickRow.Children.Add(_refreshButton);
        root.Children.Add(pickRow);

        // —— 编辑态专属区 ——
        _editPanel.Children.Add(new TextBlock
        {
            Text = "启用哪些验证方式",
            FontWeight = FontWeight.SemiBold,
            Margin = new Thickness(0, 8, 0, 0)
        });
        _editPanel.Children.Add(_chkSn);
        _editPanel.Children.Add(_chkVolume);
        _editPanel.Children.Add(_chkToken);
        _editPanel.Children.Add(_chkCounter);
        _editPanel.Children.Add(_chkBrand);
        _editPanel.Children.Add(_readButton);
        _editPanel.Children.Add(_deviceInfo);
        _editPanel.Children.Add(_saveButton);
        root.Children.Add(_editPanel);

        // —— 认证态专属区 ——
        root.Children.Add(_actionButton);
        root.Children.Add(_progress);
        root.Children.Add(_status);

        Content = root;

        Loaded += OnLoaded;
        _refreshButton.Click += async (_, _) => await RefreshVolumesAsync();
        _readButton.Click += async (_, _) => await ReadDeviceAsync();
        _saveButton.Click += async (_, _) => await PairAsync();
        _actionButton.Click += async (_, _) => await OnActionClickedAsync();
    }

    /// <summary>设置与界面模式（IsEditingMode 在 GetInstance 时赋值，Loaded 时读取最稳）</summary>
    private void ApplyMode()
    {
        if (_uiModeApplied)
        {
            return;
        }
        _uiModeApplied = true;
        var editing = IsEditingMode;
        _editPanel.IsVisible = editing;
        _actionButton.IsVisible = !editing;
        _progress.IsVisible = false;

        if (editing)
        {
            _chkSn.IsChecked = Settings.EnableSnBinding;
            _chkVolume.IsChecked = Settings.EnableVolumeGuidBinding;
            _chkToken.IsChecked = Settings.EnableTokenCheck;
            _chkCounter.IsChecked = Settings.EnableCloneCounter;
            _chkBrand.IsChecked = Settings.EnableBrandHint;
            SetStatus(IsPaired() ? $"当前配对盘 SN：{Settings.PairedDiskSerial}" : "尚未配对：请选择分区后点「读取」，确认设备信息无误再点「保存配对」。", false);
        }
        else
        {
            SetStatus("请选择用于验证的分区，然后点「验证」。", false);
        }
    }

    private void OnLoaded(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        ApplyMode();
        _ = RefreshVolumesAsync();
    }

    private bool IsPaired()
    {
        return !string.IsNullOrWhiteSpace(Settings.PairedDiskSerial)
               && !string.IsNullOrWhiteSpace(Settings.TokenHash);
    }

    private VolumeInfo? SelectedVolume => _volumeBox.SelectedItem as VolumeInfo;

    private async Task RefreshVolumesAsync()
    {
        if (_busy)
        {
            return;
        }
        _busy = true;
        try
        {
            SetStatus("正在枚举分区…", false);
            var volumes = await Task.Run(DiskInfoService.EnumerateVolumes);

            _volumeBox.ItemTemplate = new FuncDataTemplate<VolumeInfo>((v, _) =>
                new TextBlock
                {
                    Text = v == null
                        ? ""
                        : $"{v.DriveLetter}:\\ {Describe(v)}"
                });
            _volumeBox.ItemsSource = volumes;

            // 预选已配对的分区（按卷 GUID 匹配，兼容盘符漂移）
            var preset = volumes.FirstOrDefault(v =>
                !string.IsNullOrEmpty(Settings.PairedVolumeGuid) &&
                string.Equals(v.VolumeGuid, Settings.PairedVolumeGuid, StringComparison.OrdinalIgnoreCase));
            if (preset != null)
            {
                _volumeBox.SelectedItem = preset;
            }

            if (volumes.Count == 0)
            {
                SetStatus("未找到带盘符的分区，请插入 U 盘后点「刷新」。", true);
            }
            else
            {
                SetStatus(preset != null
                    ? $"已预选配对分区 {preset.DriveLetter}:\\，点「验证」开始。"
                    : $"共 {volumes.Count} 个分区，请选择用于验证的分区。", false);
            }
        }
        finally
        {
            _busy = false;
        }
    }

    private static string Describe(VolumeInfo v)
    {
        var label = string.IsNullOrWhiteSpace(v.VolumeLabel) ? "" : $"[{v.VolumeLabel}] ";
        var model = string.IsNullOrWhiteSpace(v.DiskModel) ? "未知设备" : v.DiskModel;
        var serial = v.InfoComplete ? "" : "（序列号读取失败）";
        return $"{label}{model}{serial}";
    }

    private void SetStatus(string text, bool isError)
    {
        _status.Text = text;
        _status.Foreground = isError ? Brushes.Firebrick : Brushes.DimGray;
    }

    private void SetStatusOk(string text)
    {
        _status.Text = text;
        _status.Foreground = new SolidColorBrush(Color.FromRgb(0x0F, 0x6C, 0x3C));
    }

    /// <summary>认证态主按钮：验证 / 进入</summary>
    private async Task OnActionClickedAsync()
    {
        if (IsEditingMode)
        {
            return;
        }
        if (_verified)
        {
            CompleteAuthorize();
            return;
        }
        await VerifyAsync();
    }

    private async Task VerifyAsync()
    {
        if (_busy)
        {
            return;
        }
        if (SelectedVolume == null)
        {
            SetStatus("请先选择用于验证的分区。", true);
            return;
        }
        if (!IsPaired())
        {
            SetStatus("本机尚未完成配对，请由管理员在凭据编辑界面完成配对。", true);
            return;
        }

        _busy = true;
        _verified = false;
        _actionButton.Content = "验证中…";
        _actionButton.IsEnabled = false;
        _progress.IsVisible = true;
        try
        {
            var letter = SelectedVolume!.DriveLetter;
            SetStatus("正在读取分区信息…", false);

            // 重新解析分区，避免列表过期（换盘/盘符变化）
            var fresh = (await Task.Run(DiskInfoService.EnumerateVolumes))
                .FirstOrDefault(v => string.Equals(v.DriveLetter, letter, StringComparison.OrdinalIgnoreCase));
            if (fresh == null)
            {
                SetStatus($"分区 {letter}:\\ 已不可用，请重新选择。", true);
                return;
            }

            var machineGuid = await Task.Run(DiskInfoService.GetMachineGuid);
            var stateDir = AppContext.BaseDirectory;
            var state = await Task.Run(() => PluginStateStore.Load(stateDir));
            // 计数基线按卷隔离：其他盘的配对/认证不会影响本盘
            var expected = state.GetCounter(fresh.VolumeGuid);

            var result = await Task.Run(async () => await AuthVerifier.VerifyAsync(
                Settings, fresh, machineGuid, expected,
                report: step => Dispatcher.UIThread.Post(() => SetStatus($"正在验证：{step}…", false)),
                yieldAsync: () => Task.Delay(20)));

            _progress.IsVisible = false;

            if (result.Success)
            {
                _verified = true;
                _actionButton.Content = "进入";
                _actionButton.IsEnabled = true;
                var warn = result.CounterWriteBackWarning ? "（计数回写失败，防克隆计数已降级）" : "";
                SetStatusOk($"验证通过{warn}，点「进入」继续。");
                await Task.Run(() =>
                {
                    state.SetCounter(fresh.VolumeGuid, result.NewCounter);
                    PluginStateStore.Save(stateDir, state);
                });
            }
            else
            {
                _actionButton.Content = "验证";
                _actionButton.IsEnabled = true;
                SetStatus($"✗ {result.FailedStep}：{result.FailureReason}", true);
            }
        }
        finally
        {
            _busy = false;
            if (!_verified)
            {
                _actionButton.Content = "验证";
                _actionButton.IsEnabled = true;
            }
        }
    }

    /// <summary>编辑态：读取所选分区的设备信息</summary>
    private async Task ReadDeviceAsync()
    {
        if (SelectedVolume == null)
        {
            SetStatus("请先选择要配对的分区。", true);
            return;
        }
        SetStatus("正在读取设备信息…", false);
        var letter = SelectedVolume!.DriveLetter;
        var fresh = (await Task.Run(DiskInfoService.EnumerateVolumes))
            .FirstOrDefault(v => string.Equals(v.DriveLetter, letter, StringComparison.OrdinalIgnoreCase));
        if (fresh == null)
        {
            SetStatus($"分区 {letter}:\\ 已不可用，请重新选择。", true);
            return;
        }

        _volumeBox.SelectedItem = fresh;
        var kvState = KeyVaultService.KeyVaultExists(fresh.VolumeGuid) ? "已存在 key.bin（重新配对会覆盖旧密钥）" : "尚无 key.bin（首次配对将创建）";
        _deviceInfo.Text =
            $"分区：{fresh.DriveLetter}:\\ {Describe(fresh)}\n" +
            $"磁盘序列号：{(fresh.DiskSerialNumber ?? "读取失败")}\n" +
            $"卷标识：{fresh.VolumeGuid}\n" +
            $"密钥文件：{kvState}";
        SetStatus(fresh.InfoComplete
            ? "设备信息已读取，确认无误后点「保存配对」。"
            : "⚠ 该分区序列号读取失败，无法配对（请换一个分区或检查磁盘）。", !fresh.InfoComplete);
    }

    /// <summary>编辑态：执行配对</summary>
    private async Task PairAsync()
    {
        var volume = SelectedVolume;
        if (volume == null)
        {
            SetStatus("请先选择要配对的分区。", true);
            return;
        }
        Settings.EnableSnBinding = _chkSn.IsChecked ?? true;
        Settings.EnableVolumeGuidBinding = _chkVolume.IsChecked ?? true;
        Settings.EnableTokenCheck = _chkToken.IsChecked ?? true;
        Settings.EnableCloneCounter = _chkCounter.IsChecked ?? true;
        Settings.EnableBrandHint = _chkBrand.IsChecked ?? false;

        if (!Settings.HasAnyHardBinding)
        {
            SetStatus("请至少启用一种硬绑定（磁盘序列号 / 卷标识 / token）。", true);
            return;
        }

        SetStatus("正在配对…", false);
        var machineGuid = await Task.Run(DiskInfoService.GetMachineGuid);
        var stateDir = AppContext.BaseDirectory;
        string? pairError = null;
        var ok = await Task.Run(() => AuthVerifier.Pair(Settings, volume, machineGuid, out pairError));
        if (!ok)
        {
            SetStatus($"配对失败：{pairError}", true);
            return;
        }

        // 配对后重置【本卷】的存活计数（其他盘的计数不受影响）
        await Task.Run(() =>
        {
            var state = PluginStateStore.Load(stateDir);
            state.SetCounter(volume.VolumeGuid, 0);
            PluginStateStore.Save(stateDir, state);
        });

        _deviceInfo.Text =
            $"分区：{volume.DriveLetter}:\\ {Describe(volume)}\n" +
            $"磁盘序列号：{Settings.PairedDiskSerial}\n" +
            $"卷标识：{Settings.PairedVolumeGuid}\n" +
            $"密钥文件：已创建 .EasyAuth\\key.bin（隐藏+系统属性）";
        SetStatusOk("配对成功。点「确定」保存凭据后即可用该 U 盘解锁。");
    }

    /// <summary>凭据保存前的完整性校验（编辑模式）</summary>
    public override bool ValidateAuthorizeSettings()
    {
        if (!Settings.HasAnyHardBinding)
        {
            return false;
        }
        return IsPaired();
    }
}