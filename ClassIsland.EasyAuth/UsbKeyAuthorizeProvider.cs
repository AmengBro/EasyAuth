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
/// 认证态：分区下拉框 -> 验证 -> 进度条 + 逐项状态 -> 通过后按钮变"继续"。
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
    private readonly TextBlock _multiHint = new();
    private readonly TextBlock _userHint = new();
    private readonly CheckBox _chkMulti = new() { Content = "多分区同时校验（实验性 · 下拉框显示设备名，按设备校验其全部分区）", Margin = new Thickness(0, 2, 0, 0) };
    private readonly CheckBox _chkSn = new() { Content = "磁盘序列号绑定（防换盘克隆）", Margin = new Thickness(0, 2, 0, 0) };
    private readonly CheckBox _chkVolume = new() { Content = "卷标识绑定（防同盘另一分区）", Margin = new Thickness(0, 2, 0, 0) };
    private readonly CheckBox _chkToken = new() { Content = "token 校验（防复制密钥文件）", Margin = new Thickness(0, 2, 0, 0) };
    private readonly CheckBox _chkCounter = new() { Content = "克隆计数（防过期克隆盘）", Margin = new Thickness(0, 2, 0, 0) };
    private readonly CheckBox _chkBrand = new() { Content = "品牌提示（仅提示，不参与判定）", Margin = new Thickness(0, 2, 0, 0) };
    private readonly CheckBox _chkUser = new() { Content = "Windows 账户绑定（实验性 · DPAPI，需重新配对）", Margin = new Thickness(0, 2, 0, 0) };
    private readonly Button _readButton = new() { Content = "读取", Margin = new Thickness(0, 8, 0, 0) };
    private readonly Button _auditButton = new() { Content = "查看审计日志", Margin = new Thickness(8, 0, 0, 0) };
    private readonly TextBlock _deviceInfo = new() { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 0) };
    private readonly Button _saveButton = new() { Content = "保存配对", HorizontalAlignment = HorizontalAlignment.Stretch };

    private bool _verified;
    private bool _busy;
    private bool _uiModeApplied;
    private bool _suppressMultiChange;
    private int _instanceId;
    private static int _instanceCounter;
    private bool _loadedOnce;

    /// <summary>
    /// 当前是否为多分区（设备）模式。
    /// 只读 Settings（纯数据），不读 Avalonia 控件——本属性会在 Task.Run 的
    /// 线程池线程里被访问，读控件会抛 "Call from invalid thread"。
    /// 复选框勾选变化时已同步写回 Settings.MultiPartitionMode。
    /// </summary>
    private bool MultiMode => Settings.MultiPartitionMode;

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
            Text = "模式与验证方式",
            FontWeight = FontWeight.SemiBold,
            Margin = new Thickness(0, 8, 0, 0)
        });
        _editPanel.Children.Add(_chkMulti);
        _multiHint = new TextBlock
        {
            Text = "⚠ 实验性功能：多分区模式要求每个分区都单独配对，漏掉任一个都将无法解锁。" +
                   "首次使用建议先在单分区模式下验证通过，再切换到此模式。",
            Foreground = new SolidColorBrush(Color.FromRgb(0xB2, 0x6A, 0x00)),
            TextWrapping = TextWrapping.Wrap,
            FontSize = 11,
            Margin = new Thickness(0, 2, 0, 4),
            IsVisible = false
        };
        _editPanel.Children.Add(_multiHint);
        _editPanel.Children.Add(_chkSn);
        _editPanel.Children.Add(_chkVolume);
        _editPanel.Children.Add(_chkToken);
        _editPanel.Children.Add(_chkCounter);
        _editPanel.Children.Add(_chkBrand);
        _editPanel.Children.Add(_chkUser);
        _userHint = new TextBlock
        {
            Text = "⚠ 实验性功能：账户绑定把密钥再包一层当前 Windows 账户的 DPAPI 密文。" +
                   "仅在教师使用独占账户时有额外保护；多账号共用时无增益，且启用后必须重新配对。",
            Foreground = new SolidColorBrush(Color.FromRgb(0xB2, 0x6A, 0x00)),
            TextWrapping = TextWrapping.Wrap,
            FontSize = 11,
            Margin = new Thickness(0, 2, 0, 4),
            IsVisible = false
        };
        _editPanel.Children.Add(_userHint);
        var readRow = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto") };
        readRow.Children.Add(_readButton);
        Grid.SetColumn(_auditButton, 1);
        readRow.Children.Add(_auditButton);
        _editPanel.Children.Add(readRow);
        _editPanel.Children.Add(_deviceInfo);
        _editPanel.Children.Add(_saveButton);
        root.Children.Add(_editPanel);

        // —— 认证态专属区 ——
        root.Children.Add(_actionButton);
        root.Children.Add(_progress);
        root.Children.Add(_status);

        Content = root;

        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
        _refreshButton.Click += async (_, _) => await RefreshVolumesAsync();
        _readButton.Click += async (_, _) => await ReadDeviceAsync();
        _saveButton.Click += async (_, _) => await PairAsync();
        _actionButton.Click += async (_, _) => await OnActionClickedAsync();
        _auditButton.Click += (_, _) => _deviceInfo.Text = "审计日志（最近 15 条）：\n" +
            AuditLogService.ReadTail(PluginPaths.PluginDirectory);
        _volumeBox.SelectionChanged += async (_, _) => await RememberSelectedVolumeAsync();
        _chkMulti.IsCheckedChanged += async (_, _) =>
        {
            // 实验性功能提示条跟随开关显隐
            _multiHint.IsVisible = _chkMulti.IsChecked == true;
            if (_suppressMultiChange)
            {
                return;
            }
            Settings.MultiPartitionMode = _chkMulti.IsChecked ?? false;
            await RefreshVolumesAsync();
        };
        _chkUser.IsCheckedChanged += (_, _) =>
        {
            _userHint.IsVisible = _chkUser.IsChecked == true;
        };
    }

    /// <summary>记住本次选择的分区，下次打开界面自动预选（体验偏好）</summary>
    private async Task RememberSelectedVolumeAsync()
    {
        // 设备模式下记住该设备第一个分区，用于下次反查回设备
        var v = SelectedVolume
                ?? SelectedGroup?.Volumes.FirstOrDefault();
        if (v == null || string.IsNullOrEmpty(v.VolumeGuid))
        {
            return;
        }
        var stateDir = PluginPaths.PluginDirectory;
        await Task.Run(() =>
        {
            var st = PluginStateStore.Load(stateDir);
            if (string.Equals(st.LastVolumeGuid, v.VolumeGuid, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
            st.LastVolumeGuid = v.VolumeGuid;
            PluginStateStore.Save(stateDir, st);
        });
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
            _suppressMultiChange = true;
            _chkMulti.IsChecked = Settings.MultiPartitionMode;
            _suppressMultiChange = false;
            _chkSn.IsChecked = Settings.EnableSnBinding;
            _chkVolume.IsChecked = Settings.EnableVolumeGuidBinding;
            _chkToken.IsChecked = Settings.EnableTokenCheck;
            _chkCounter.IsChecked = Settings.EnableCloneCounter;
            _chkBrand.IsChecked = Settings.EnableBrandHint;
            _chkUser.IsChecked = Settings.EnableUserBinding;
            // 已有配置时同步提示条的显隐
            _multiHint.IsVisible = _chkMulti.IsChecked == true;
            _userHint.IsVisible = _chkUser.IsChecked == true;
            SetStatus(IsPaired() ? $"当前配对盘 SN：{Settings.PairedDiskSerial}" : "尚未配对：请选择分区后点「读取」，确认设备信息无误再点「保存配对」。", false);
        }
        else
        {
            SetStatus("请选择用于验证的分区，然后点「验证」。", false);
        }
    }

    private void OnLoaded(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        // Avalonia 的 ListBox 在窗口高度变化时会回收容器，导致同一个实例的
        // Unloaded/Loaded 重放。此时若重新枚举分区，会把用户刚选中的项清空、
        // 也会覆盖刚设置的「配对成功」提示——正是多分区模式点击保存配对后
        // 下拉框直接清空、绿字提示消失的直接原因。
        // 因此只在首次加载时枚举；后续重放仅记录日志。
        if (_loadedOnce)
        {
            AuditLogService.Write(PluginPaths.PluginDirectory, "CTRL-RELOADED",
                detail: $"instance={_instanceId}（同一实例重复 Loaded，跳过重新枚举以保留选择）");
            return;
        }
        _loadedOnce = true;
        _instanceId = ++_instanceCounter;
        AuditLogService.Write(PluginPaths.PluginDirectory, "CTRL-LOADED",
            detail: $"instance={_instanceId} editing={IsEditingMode} multi={Settings.MultiPartitionMode} " +
                    $"paired={IsPaired()} authVols={Settings.AuthorizedVolumeGuids?.Count ?? -1}");
        RecoverSettingsFromState();
        ApplyMode();
        _ = RefreshVolumesAsync();
    }

    /// <summary>
    /// 从插件状态恢复凭据设置。
    /// 场景：配对成功后凭据尚未「确定」保存，控件因故被重建——新实例的 Settings
    /// 来自磁盘上未更新的 JSON，配对信息全丢，表现为下拉框清空、校验失败。
    /// 配对事实同时写在插件 state.json 里，可据此还原。
    /// </summary>
    private void RecoverSettingsFromState()
    {
        // 仅在「本凭据完全空白」时从本机配对记录恢复。
        // 多凭据场景下（同时添加多个 U 盘密钥），若某凭据已经做出过选择，
        // 绝不能拿别的凭据/全局记录覆盖它。
        if (IsPaired() || IsEditingMode == false)
        {
            return;
        }
        if (!string.IsNullOrEmpty(Settings.SelectedVolumeGuid))
        {
            return;
        }
        try
        {
            var state = PluginStateStore.Load(PluginPaths.PluginDirectory);
            if (state.Pairings.Count == 0)
            {
                return;
            }
            var guid = !string.IsNullOrEmpty(state.LastVolumeGuid) && state.Pairings.ContainsKey(state.LastVolumeGuid)
                ? state.LastVolumeGuid
                : state.Pairings.Keys.FirstOrDefault();
            if (guid == null)
            {
                return;
            }
            var rec = state.Pairings[guid];
            Settings.PairedVolumeGuid = guid;
            Settings.PairedDiskSerial = rec.DiskSerial;
            Settings.TokenHash = rec.TokenHash;
            Settings.BrandHint = rec.BrandHint;
            Settings.MultiPartitionMode = rec.MultiPartitionMode;
            Settings.AuthorizedVolumeGuids ??= new List<string>();
            if (Settings.AuthorizedVolumeGuids.Count == 0)
            {
                Settings.AuthorizedVolumeGuids.Add(guid);
            }
            AuditLogService.Write(PluginPaths.PluginDirectory, "CTRL-RECOVER",
                detail: $"instance={_instanceId} vol={guid} multi={rec.MultiPartitionMode}");
        }
        catch
        {
            // 恢复失败不影响主流程
        }
    }

    private void OnUnloaded(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        AuditLogService.Write(PluginPaths.PluginDirectory, "CTRL-UNLOADED",
            detail: $"instance={_instanceId}");
    }

    private bool IsPaired()
    {
        return !string.IsNullOrWhiteSpace(Settings.PairedDiskSerial)
               && !string.IsNullOrWhiteSpace(Settings.TokenHash);
    }

    private VolumeInfo? SelectedVolume => _volumeBox.SelectedItem as VolumeInfo;
    private DiskGroupInfo? SelectedGroup => _volumeBox.SelectedItem as DiskGroupInfo;

    private async Task RefreshVolumesAsync()
    {
        if (_busy)
        {
            return;
        }
        _busy = true;
        try
        {
            SetStatus(MultiMode ? "正在枚举设备…" : "正在枚举分区…", false);
            if (MultiMode)
            {
                await RefreshDeviceGroupsAsync();
                return;
            }
            var volumes = await Task.Run(DiskInfoService.EnumerateVolumes);

            // 刷新会重建 ItemsSource 导致选中项丢失：先记住刷新前的选择，之后按优先级恢复
            var prevGuid = SelectedVolume?.VolumeGuid;
            var prevLetter = SelectedVolume?.DriveLetter;

            _volumeBox.ItemTemplate = new FuncDataTemplate<VolumeInfo>((v, _) =>
                new TextBlock
                {
                    Text = v == null
                        ? ""
                        : $"{v.DriveLetter}:\\ {Describe(v)}"
                });
            _volumeBox.ItemsSource = volumes;
            _volumeBox.SelectedItem = null;

            // 恢复优先级：刷新前的选择 -> 已配对的分区 -> 上次选择的分区
            var target = volumes.FirstOrDefault(v => prevGuid != null &&
                string.Equals(v.VolumeGuid, prevGuid, StringComparison.OrdinalIgnoreCase))
                ?? volumes.FirstOrDefault(v => prevLetter != null &&
                    string.Equals(v.DriveLetter, prevLetter, StringComparison.OrdinalIgnoreCase))
                ?? volumes.FirstOrDefault(v => !string.IsNullOrEmpty(Settings.PairedVolumeGuid) &&
                    string.Equals(v.VolumeGuid, Settings.PairedVolumeGuid, StringComparison.OrdinalIgnoreCase));
            if (target == null)
            {
                var state = await Task.Run(() => PluginStateStore.Load(PluginPaths.PluginDirectory));
                if (!string.IsNullOrEmpty(state.LastVolumeGuid))
                {
                    target = volumes.FirstOrDefault(v =>
                        string.Equals(v.VolumeGuid, state.LastVolumeGuid, StringComparison.OrdinalIgnoreCase));
                }
            }
            if (target != null)
            {
                _volumeBox.SelectedItem = target;
            }

            if (volumes.Count == 0)
            {
                SetStatus("未找到带盘符的分区，请插入 U 盘后点「刷新」。", true);
            }
            else if (target == null)
            {
                SetStatus($"共 {volumes.Count} 个分区，请选择用于验证的分区。", false);
            }
            else if (IsEditingMode)
            {
                SetStatus($"已选中 {target.DriveLetter}:\\，点「读取」查看设备信息，「保存配对」写入密钥。", false);
            }
            else
            {
                SetStatus($"已选中 {target.DriveLetter}:\\，点「验证」开始。", false);
            }
        }
        finally
        {
            _busy = false;
        }
    }

    /// <summary>设备（多分区）模式：下拉框列设备，选中即校验其全部合格分区</summary>
    private async Task RefreshDeviceGroupsAsync()
    {
        var groups = await Task.Run(DiskInfoService.EnumerateDiskGroups);

        var prevSerial = SelectedGroup?.DiskSerial;
        _volumeBox.ItemTemplate = new FuncDataTemplate<DiskGroupInfo>((g, _) =>
            new TextBlock { Text = g == null ? "" : g.DisplayName });
        _volumeBox.ItemsSource = groups;
        _volumeBox.SelectedItem = null;

        DiskGroupInfo? target = null;
        if (prevSerial != null)
        {
            target = groups.FirstOrDefault(g =>
                string.Equals(g.DiskSerial, prevSerial, StringComparison.OrdinalIgnoreCase));
        }
        if (target == null && !string.IsNullOrEmpty(Settings.PairedVolumeGuid))
        {
            target = groups.FirstOrDefault(g => g.Volumes.Any(v =>
                string.Equals(v.VolumeGuid, Settings.PairedVolumeGuid, StringComparison.OrdinalIgnoreCase)));
        }
        if (target == null)
        {
            var state = await Task.Run(() => PluginStateStore.Load(PluginPaths.PluginDirectory));
            if (!string.IsNullOrEmpty(state.LastVolumeGuid))
            {
                target = groups.FirstOrDefault(g => g.Volumes.Any(v =>
                    string.Equals(v.VolumeGuid, state.LastVolumeGuid, StringComparison.OrdinalIgnoreCase)));
            }
        }
        if (target != null)
        {
            _volumeBox.SelectedItem = target;
        }

        if (groups.Count == 0)
        {
            SetStatus("未找到可用设备（需磁盘序列号可读，且分区总容量 ≥32MB、可用 ≥16MB）。", true);
        }
        else if (target == null)
        {
            SetStatus($"共 {groups.Count} 个设备，请选择用于验证的设备。", false);
        }
        else
        {
            var letters = string.Join("、", target.Volumes.Select(v => v.DriveLetter + ":"));
            var skipped = target.SkippedVolumes.Count > 0 ? $"，已忽略 {target.SkippedVolumes.Count} 个过小分区" : "";
            SetStatus(IsEditingMode
                ? $"已选中设备：{target.Model}（分区 {letters}{skipped}）"
                : $"已选中设备：{target.Model}（分区 {letters}），点「验证」开始。", false);
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

    /// <summary>认证态主按钮：验证 / 继续</summary>
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

        // 1) 解析本次要校验的分区（设备模式 = 该设备被授权的全部分区）
        List<VolumeInfo> targets;
        string displayName;
        if (MultiMode)
        {
            var group = SelectedGroup;
            if (group == null)
            {
                SetStatus("请先选择用于验证的设备。", true);
                return;
            }
            var authorized = group.Volumes
                .Where(v => Settings.AuthorizedVolumeGuids.Any(g =>
                    string.Equals(g, v.VolumeGuid, StringComparison.OrdinalIgnoreCase)))
                .ToList();
            if (authorized.Count == 0)
            {
                SetStatus("该设备尚未在凭据中授权，请先在编辑界面完成配对。", true);
                return;
            }
            targets = authorized;
            displayName = group.Model;
        }
        else
        {
            var v = SelectedVolume;
            if (v == null)
            {
                SetStatus("请先选择用于验证的分区。", true);
                return;
            }
            targets = [v];
            displayName = v.DriveLetter + ":";
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
            SetStatus(MultiMode ? $"正在读取设备信息（{targets.Count} 个分区）…" : "正在读取分区信息…", false);

            // 重新解析分区，避免列表过期（换盘/盘符变化）；按卷 GUID 匹配，不用盘符
            // （盘符可能已被别的卷占用）
            var all = await Task.Run(DiskInfoService.EnumerateVolumes);
            var freshTargets = new List<VolumeInfo>();
            var missing = new List<string>();
            foreach (var t in targets)
            {
                var fresh = all.FirstOrDefault(v =>
                    string.Equals(v.VolumeGuid, t.VolumeGuid, StringComparison.OrdinalIgnoreCase));
                if (fresh != null)
                {
                    freshTargets.Add(fresh);
                }
                else
                {
                    missing.Add(t.DriveLetter + ":");
                }
            }
            if (missing.Count > 0)
            {
                SetStatus($"分区 {string.Join("、", missing)} 已不可用，请重新选择。", true);
                return;
            }

            // 多凭据场景：只校验本凭据授权的分区，避免选中别的凭据配对的盘也放行
            if (Settings.AuthorizedVolumeGuids is { Count: > 0 })
            {
                var allowed = freshTargets.Where(v => Settings.AuthorizedVolumeGuids.Any(g =>
                    string.Equals(g, v.VolumeGuid, StringComparison.OrdinalIgnoreCase))).ToList();
                if (allowed.Count == 0)
                {
                    SetStatus("选中的分区不在本凭据的授权列表中（可能是另一个 U 盘密钥凭据配对的盘）。", true);
                    return;
                }
                freshTargets = allowed;
            }

            var machineGuid = await Task.Run(DiskInfoService.GetMachineGuid);
            var stateDir = PluginPaths.PluginDirectory;
            var state = await Task.Run(() => PluginStateStore.Load(stateDir));
            // 审计标签在 UI 线程算好：Task.Run 内不得触碰任何 UI 状态
            var modeTag = Settings.MultiPartitionMode ? "multi" : "single";

            var result = await Task.Run(async () => await AuthVerifier.VerifyVolumesAsync(new VerifyOptions
            {
                Settings = Settings,
                Volumes = freshTargets,
                MachineGuid = machineGuid,
                State = state,
                Report = step => Dispatcher.UIThread.Post(() => SetStatus(step, false)),
                YieldAsync = () => Task.Delay(20)
            }));

            _progress.IsVisible = false;

            if (result.Success)
            {
                _verified = true;
                _actionButton.Content = "继续";
                _actionButton.IsEnabled = true;
                var warn = result.CounterWriteBackWarning ? "（计数回写失败，防克隆计数已降级）" : "";
                SetStatusOk($"验证通过（{freshTargets.Count} 个分区）{warn}，点「继续」完成验证。");
                await Task.Run(() =>
                {
                    foreach (var kv in result.NewCounters)
                    {
                        state.SetCounter(kv.Key, kv.Value);
                    }
                    PluginStateStore.Save(stateDir, state);
                });
                await Task.Run(() => AuditLogService.Write(stateDir, "AUTH-OK",
                    displayName, freshTargets[0].VolumeGuid, freshTargets[0].DiskSerialNumber,
                    $"mode={modeTag} volumes={freshTargets.Count} layers=[{(Settings.EnableUserBinding ? "user," : "")}{(Settings.EnableTokenCheck ? "token," : "")}{(Settings.EnableSnBinding ? "sn," : "")}{(Settings.EnableVolumeGuidBinding ? "guid," : "")}{(Settings.EnableCloneCounter ? "counter" : "")}] new={result.NewCounter}"));
            }
            else
            {
                _actionButton.Content = "验证";
                _actionButton.IsEnabled = true;
                SetStatus($"✗ {result.FailedStep}：{result.FailureReason}", true);
                await Task.Run(() => AuditLogService.Write(stateDir, "AUTH-FAIL",
                    displayName, result.FailedVolumeGuid, freshTargets[0].DiskSerialNumber,
                    $"mode={modeTag} step={result.FailedStep} reason={result.FailureReason}"));
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
        if (MultiMode)
        {
            var group = SelectedGroup;
            if (group == null)
            {
                SetStatus("请先选择要读取的设备。", true);
                return;
            }
            SetStatus("正在读取设备信息…", false);
            var groups = await Task.Run(DiskInfoService.EnumerateDiskGroups);
            var freshGroup = groups.FirstOrDefault(x =>
                string.Equals(x.DiskSerial, group.DiskSerial, StringComparison.OrdinalIgnoreCase));
            if (freshGroup == null)
            {
                SetStatus("该设备已不可用，请重新选择。", true);
                return;
            }
            if (_volumeBox.ItemsSource is IEnumerable<DiskGroupInfo> groupItems)
            {
                var inList = groupItems.FirstOrDefault(x =>
                    string.Equals(x.DiskSerial, freshGroup.DiskSerial, StringComparison.OrdinalIgnoreCase));
                if (inList != null)
                {
                    _volumeBox.SelectedItem = inList;
                }
            }

            var lines = freshGroup.Volumes.Select(v =>
                $"{v.DriveLetter}:\\ {(string.IsNullOrWhiteSpace(v.VolumeLabel) ? "(无卷标)" : v.VolumeLabel)} | " +
                $"容量 {FormatSize(v.TotalSize)} | 可用 {FormatSize(v.AvailableFreeSpace)} | " +
                $"{(KeyVaultService.KeyVaultExists(v.VolumeGuid) ? "已配对" : "未配对")}").ToList();
            if (freshGroup.SkippedVolumes.Count > 0)
            {
                lines.Add($"已忽略小分区：{string.Join("、", freshGroup.SkippedVolumes.Select(v => v.DriveLetter + ":"))}" +
                         "（总容量<32MB 或可用<16MB）");
            }
            lines.Add($"磁盘序列号：{freshGroup.DiskSerial}");
            lines.Add($"设备：{freshGroup.Model} {(string.IsNullOrEmpty(freshGroup.BrandHint) ? "" : $"［{freshGroup.BrandHint}］")}");
            _deviceInfo.Text = string.Join("\n", lines);
            SetStatus($"设备信息已读取，共 {freshGroup.Volumes.Count} 个可配对分区。确认无误后点「保存配对」。", false);
            return;
        }

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

        // 选中项要在下拉框列表内重新定位（fresh 来自新枚举，不在当前 ItemsSource 里会显示为空）
        if (_volumeBox.ItemsSource is IEnumerable<VolumeInfo> items)
        {
            var inList = items.FirstOrDefault(v =>
                string.Equals(v.VolumeGuid, fresh.VolumeGuid, StringComparison.OrdinalIgnoreCase));
            if (inList != null)
            {
                _volumeBox.SelectedItem = inList;
            }
        }
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

    /// <summary>编辑态：执行配对（设备模式 = 该设备全部合格分区逐个配对）</summary>
    private async Task PairAsync()
    {
        // 先落一条"开始配对"，用于确认按钮是否真的被点击到
        try
        {
            AuditLogService.Write(PluginPaths.PluginDirectory, "PAIR-ATTEMPT",
                detail: $"instance={_instanceId} multi={Settings.MultiPartitionMode} hasGroup={SelectedGroup != null} " +
                        $"hasVolume={SelectedVolume != null} groupVols={SelectedGroup?.Volumes.Count ?? -1}");
        }
        catch
        {
            // 忽略
        }

        List<VolumeInfo> targets;
        string displayName;
        if (MultiMode)
        {
            var group = SelectedGroup;
            if (group == null)
            {
                SetStatus("请先选择要配对的设备。", true);
                return;
            }
            targets = group.Volumes;
            displayName = group.Model;
            if (targets.Count == 0)
            {
                SetStatus("该设备没有可配对的分区（分区需总容量 ≥32MB 且可用 ≥16MB）。", true);
                return;
            }
            if (targets.Count == 1)
            {
                // 单分区设备：多分区模式与单分区模式行为一致，提示一句免得误解
                SetStatus($"该设备只有 1 个可配对分区（{targets[0].DriveLetter}:），等价于单分区模式。", false);
            }
        }
        else
        {
            var v = SelectedVolume;
            if (v == null)
            {
                SetStatus("请先选择要配对的分区。", true);
                return;
            }
            targets = [v];
            displayName = v.DriveLetter + ":";
        }

        Settings.MultiPartitionMode = _chkMulti.IsChecked ?? Settings.MultiPartitionMode;
        Settings.EnableSnBinding = _chkSn.IsChecked ?? true;
        Settings.EnableVolumeGuidBinding = _chkVolume.IsChecked ?? true;
        Settings.EnableTokenCheck = _chkToken.IsChecked ?? true;
        Settings.EnableCloneCounter = _chkCounter.IsChecked ?? true;
        Settings.EnableBrandHint = _chkBrand.IsChecked ?? false;
        Settings.EnableUserBinding = _chkUser.IsChecked ?? false;

        if (!Settings.HasAnyHardBinding)
        {
            SetStatus("请至少启用一种硬绑定（磁盘序列号 / 卷标识 / token）。", true);
            return;
        }

        SetStatus($"正在配对（{targets.Count} 个分区）…", false);
        var machineGuid = await Task.Run(DiskInfoService.GetMachineGuid);
        var stateDir = PluginPaths.PluginDirectory;

        // 配对期间锁定界面，避免重复点击
        _busy = true;
        try
        {
            var state = PluginStateStore.Load(stateDir);
            string? pairError = null;
            bool ok;
            try
            {
                ok = await Task.Run(() => AuthVerifier.PairVolumes(Settings, targets, machineGuid, state, out pairError));
            }
            catch (Exception ex)
            {
                // 事件处理器是 async void，未捕获异常会静默吞掉——必须显式兜住
                SetStatus($"配对异常：{ex.GetType().Name} {ex.Message}", true);
                AuditLogService.Write(stateDir, "PAIR-ERROR", displayName,
                    targets.FirstOrDefault()?.VolumeGuid, targets.FirstOrDefault()?.DiskSerialNumber,
                    $"ex={ex.GetType().Name} msg={ex.Message}");
                throw;
            }
            if (!ok)
            {
                SetStatus($"配对失败：{pairError}", true);
                return;
            }
            PluginStateStore.Save(stateDir, state);

            await Task.Run(() => AuditLogService.Write(stateDir, "PAIR",
                displayName, targets[0].VolumeGuid, targets[0].DiskSerialNumber,
                $"mode={(MultiMode ? "multi" : "single")} volumes={targets.Count} userBound={Settings.EnableUserBinding} layers=[{(Settings.EnableSnBinding ? "sn," : "")}{(Settings.EnableVolumeGuidBinding ? "guid," : "")}{(Settings.EnableTokenCheck ? "token," : "")}{(Settings.EnableCloneCounter ? "counter" : "")}]"));

            var lines = targets.Select(v =>
            {
                var kv = KeyVaultService.KeyVaultExists(v.VolumeGuid) ? "已创建" : "未创建";
                return $"分区 {v.DriveLetter}:\\ {v.VolumeLabel} | 容量 {FormatSize(v.TotalSize)} | 可用 {FormatSize(v.AvailableFreeSpace)} | 密钥 {kv}";
            }).ToList();
            lines.Add($"磁盘序列号：{Settings.PairedDiskSerial}");
            lines.Add($"授权分区数：{Settings.AuthorizedVolumeGuids.Count}");
            lines.Add("密钥目录：.EasyAuth\\（隐藏+系统属性）");
            _deviceInfo.Text = string.Join("\n", lines);
            SetStatusOk($"配对成功（{targets.Count} 个分区）。点「确定」保存凭据后即可用它解锁。");
        }
        finally
        {
            _busy = false;
        }
    }

    private static string FormatSize(long? bytes)
    {
        if (!bytes.HasValue)
        {
            return "-";
        }
        var b = (double)bytes.Value;
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var i = 0;
        while (b >= 1024 && i < units.Length - 1)
        {
            b /= 1024;
            i++;
        }
        return $"{b:0.#} {units[i]}";
    }

    /// <summary>凭据保存前的完整性校验（编辑模式）。
    /// 判定依据：必须有硬绑定层；配对事实以"U 盘 key.bin + 插件状态"为准，
    /// 凭据里的 PairedDiskSerial/TokenHash 只是索引——多分区配对时它们可能
    /// 尚未与校验时读到的实例同步，死盯字段会导致明明配对成功却拒绝保存。
    /// 失败原因写入审计日志，便于事后定位。</summary>
    public override bool ValidateAuthorizeSettings()
    {
        var hard = Settings.HasAnyHardBinding;
        var paired = IsPaired() || HasPairingFact();
        var ok = hard && paired;
        try
        {
            var state = PluginStateStore.Load(PluginPaths.PluginDirectory);
            AuditLogService.Write(PluginPaths.PluginDirectory, ok ? "VALIDATE-OK" : "VALIDATE-FAIL",
                detail: $"instance={_instanceId} hardBinding={hard} paired={paired} hasFact={HasPairingFact()} " +
                        $"sn='{Settings.PairedDiskSerial}' tokenHashLen={Settings.TokenHash.Length} " +
                        $"authVols={Settings.AuthorizedVolumeGuids?.Count ?? -1} multi={Settings.MultiPartitionMode} " +
                        $"statePairs={state.Pairings.Count} stateCounters={state.Counters.Count}");
        }
        catch
        {
            // 日志失败不影响校验结果
        }
        return ok;
    }

    /// <summary>插件状态里是否存在配对/计数事实（等同于"某处配对过"）。
    /// 按【本凭据授权的卷】判断，不看全局——否则第二个未配对的 U 盘凭据
    /// 会因别处配过而被误判为已配对。</summary>
    private bool HasPairingFact()
    {
        try
        {
            var state = PluginStateStore.Load(PluginPaths.PluginDirectory);
            if (Settings.AuthorizedVolumeGuids is { Count: > 0 })
            {
                return Settings.AuthorizedVolumeGuids.Any(g => state.Pairings.ContainsKey(g));
            }
            if (!string.IsNullOrEmpty(Settings.PairedVolumeGuid))
            {
                return state.Pairings.ContainsKey(Settings.PairedVolumeGuid);
            }
            return false;
        }
        catch
        {
            return false;
        }
    }
}