using ClassIsland.EasyAuth.Models;

namespace ClassIsland.EasyAuth.Services;

/// <summary>认证流水线的执行结果</summary>
public class AuthVerifyResult
{
    /// <summary>是否通过全部启用的校验层</summary>
    public bool Success { get; set; }

    /// <summary>失败所处步骤名（多卷时带分区前缀）</summary>
    public string? FailedStep { get; set; }

    /// <summary>失败原因</summary>
    public string? FailureReason { get; set; }

    /// <summary>计数回写失败（U 盘不可写等）——放行但降级提示</summary>
    public bool CounterWriteBackWarning { get; set; }

    /// <summary>认证成功后的新计数（单卷场景）</summary>
    public int NewCounter { get; set; }

    /// <summary>各卷成功后的新计数（多卷场景，调用方需落盘）</summary>
    public List<KeyValuePair<string, int>> NewCounters { get; } = [];

    /// <summary>失败所在卷（多卷场景）</summary>
    public string? FailedVolumeGuid { get; set; }
}

/// <summary>认证参数</summary>
public class VerifyOptions
{
    public UsbKeyAuthSettings Settings { get; set; } = new();

    /// <summary>本次要校验的分区列表（单卷模式传一个）</summary>
    public IReadOnlyList<VolumeInfo> Volumes { get; set; } = [];

    public string? MachineGuid { get; set; }

    /// <summary>插件状态：提供按卷隔离的计数与 token 哈希（单卷兼容可为空）</summary>
    public PluginState? State { get; set; }

    /// <summary>单卷兼容用的期望计数（State 为空时生效）</summary>
    public int? ExpectedCounter { get; set; }

    public Action<string>? Report { get; set; }

    public Func<Task>? YieldAsync { get; set; }
}

/// <summary>
/// 认证流水线（UI 无关，可在控制单自测）。
/// 单卷 = 多卷列表只有一个元素；多卷时逐卷校验、任一失败即整体失败，
/// 各卷计数独立推进。
/// </summary>
public static class AuthVerifier
{
    /// <summary>单卷认证（兼容入口）。</summary>
    public static Task<AuthVerifyResult> VerifyAsync(
        UsbKeyAuthSettings settings,
        VolumeInfo volume,
        string? machineGuid,
        int? expectedCounter,
        Action<string>? report = null,
        Func<Task>? yieldAsync = null)
    {
        return VerifyVolumesAsync(new VerifyOptions
        {
            Settings = settings,
            Volumes = [volume],
            MachineGuid = machineGuid,
            ExpectedCounter = expectedCounter,
            Report = report,
            YieldAsync = yieldAsync
        });
    }

    /// <summary>多卷认证：逐卷跑流水线，任一失败即返回。</summary>
    public static async Task<AuthVerifyResult> VerifyVolumesAsync(VerifyOptions opt)
    {
        var result = new AuthVerifyResult();
        var settings = opt.Settings;
        var volumes = opt.Volumes;
        // 防御：凭据 JSON 里若显式写了 null，反序列化后列表会为 null
        settings.AuthorizedVolumeGuids ??= new List<string>();
        if (volumes.Count == 0)
        {
            result.FailedStep = "定位分区";
            result.FailureReason = "没有可校验的分区";
            return result;
        }

        var multi = volumes.Count > 1;
        var pending = new List<(VolumeInfo Volume, SingleVerifyResult One)>();
        for (var i = 0; i < volumes.Count; i++)
        {
            var volume = volumes[i];
            var label = multi ? $"{volume.DriveLetter}:\\ " : "";
            var progress = multi ? $"［第 {i + 1}/{volumes.Count} 个分区］" : "";

            // 单卷旧路径（无 state）直接用凭据里的 token 哈希；多卷路径从按卷隔离的
            // 插件状态取，仅主卷回落到凭据字段
            string? tokenHash = opt.State != null ? opt.State.GetTokenHash(volume.VolumeGuid) : settings.TokenHash;
            if (string.IsNullOrEmpty(tokenHash) &&
                string.Equals(volume.VolumeGuid, settings.PairedVolumeGuid, StringComparison.OrdinalIgnoreCase))
            {
                // 主卷兼容：旧单卷配对时 token 哈希存在凭据里
                tokenHash = settings.TokenHash;
            }

            var expected = opt.State != null ? opt.State.GetCounter(volume.VolumeGuid) : opt.ExpectedCounter;

            var one = await VerifyOneAsync(opt, volume, label, progress, tokenHash, expected);
            if (!one.Result.Success)
            {
                result.FailedStep = one.Result.FailedStep;
                result.FailureReason = one.Result.FailureReason;
                result.FailedVolumeGuid = volume.VolumeGuid;
                return result;
            }

            pending.Add((volume, one));
            result.NewCounters.Add(new KeyValuePair<string, int>(volume.VolumeGuid, one.Result.NewCounter));
            result.NewCounter = one.Result.NewCounter;
        }

        // 提交阶段：全部卷校验通过后，统一回写计数（事务式——避免中途失败造成计数错位）
        var commitIndex = 0;
        foreach (var (volume, one) in pending)
        {
            commitIndex++;
            opt.Report?.Invoke($"正在提交计数（{commitIndex}/{pending.Count}）：{volume.DriveLetter}:\\");
            if (opt.YieldAsync != null)
            {
                await opt.YieldAsync();
            }
            if (one.Payload != null &&
                !KeyVaultService.RewriteCounter(volume.VolumeGuid, one.Payload, one.Result.NewCounter,
                    opt.MachineGuid!, volume.DiskSerialNumber!, one.UserBound))
            {
                result.CounterWriteBackWarning = true;
            }        }

        result.Success = true;
        return result;
    }

    /// <summary>单卷校验的中间结果（含回写所需的明文内容）</summary>
    private record SingleVerifyResult(AuthVerifyResult Result, KeyVaultPayload? Payload, bool UserBound);

    private static async Task<SingleVerifyResult> VerifyOneAsync(
        VerifyOptions opt, VolumeInfo volume, string label, string progress, string? tokenHash, int? expectedCounter)
    {
        var settings = opt.Settings;
        var result = new AuthVerifyResult();
        var step = 0;
        KeyVaultPayload? payload = null;
        var userBound = false;

        async Task StepAsync(string name)
        {
            step++;
            opt.Report?.Invoke($"{progress}正在验证：{name}…");
            if (opt.YieldAsync != null)
            {
                await opt.YieldAsync();
            }
        }

        SingleVerifyResult Fail(string stepName, string reason)
        {
            result.Success = false;
            result.FailedStep = stepName;
            result.FailureReason = reason;
            return new SingleVerifyResult(result, null, false);
        }

        // 1) 定位分区与设备信息
        var stepName = "定位分区";
        await StepAsync(stepName);
        var serial = volume.DiskSerialNumber;
        if (string.IsNullOrWhiteSpace(serial))
        {
            return Fail(label + stepName, "无法读取该分区的磁盘序列号（可能需要检查磁盘状态）");
        }
        if (string.IsNullOrWhiteSpace(volume.VolumeGuid))
        {
            return Fail(label + stepName, "无法获取该分区的卷标识");
        }

        // 2) 读取并解密密钥文件
        stepName = "读取并解密密钥文件";
        await StepAsync(stepName);
        if (string.IsNullOrWhiteSpace(opt.MachineGuid))
        {
            return Fail(label + stepName, "无法读取本机标识（MachineGuid）");
        }
        payload = KeyVaultService.ReadKeyVault(volume.VolumeGuid, opt.MachineGuid, serial,
            out var kvStatus, out userBound);
        if (payload == null)
        {
            var reason = kvStatus switch
            {
                KeyVaultReadStatus.NotFound => $"未检测到密钥文件（该分区上没有 {KeyVaultService.KeyVaultDirName}\\{KeyVaultService.KeyVaultFileName}）",
                KeyVaultReadStatus.UserMismatch => "该密钥盘与当前 Windows 账户不匹配（账户绑定层）",
                _ => "密钥文件无法解密（可能不是本机配对的 U 盘，或文件已损坏）"
            };
            return Fail(label + stepName, reason);
        }

        // 3) Windows 账户绑定层（可选，需配对时已启用）
        if (settings.EnableUserBinding)
        {
            stepName = "校验 Windows 账户绑定";
            await StepAsync(stepName);
            if (!userBound)
            {
                return Fail(label + stepName, "密钥文件未启用 Windows 账户绑定，请重新配对");
            }
        }

        // 4) token 校验
        if (settings.EnableTokenCheck)
        {
            stepName = "校验 token";
            await StepAsync(stepName);
            if (string.IsNullOrEmpty(tokenHash) ||
                !string.Equals(CryptoService.Sha256Hex(payload.Token), tokenHash, StringComparison.OrdinalIgnoreCase))
            {
                return Fail(label + stepName, "token 不匹配（密钥文件与本机配对记录不符）");
            }
        }

        // 5) 磁盘 SN 绑定
        if (settings.EnableSnBinding)
        {
            stepName = "校验磁盘序列号";
            await StepAsync(stepName);
            var expectedSerial = string.IsNullOrEmpty(settings.PairedDiskSerial)
                ? payload.PairedDiskSerial
                : settings.PairedDiskSerial;
            var ok = string.Equals(serial, expectedSerial, StringComparison.OrdinalIgnoreCase)
                     && string.Equals(payload.PairedDiskSerial, expectedSerial, StringComparison.OrdinalIgnoreCase);
            if (!ok)
            {
                return Fail(label + stepName, "磁盘序列号不匹配（当前分区所在磁盘不是配对的那一块）");
            }
        }

        // 6) 卷 GUID 绑定
        if (settings.EnableVolumeGuidBinding)
        {
            stepName = "校验卷标识";
            await StepAsync(stepName);
            if (!string.Equals(payload.PairedVolumeGuid, volume.VolumeGuid, StringComparison.OrdinalIgnoreCase))
            {
                return Fail(label + stepName, "卷标识不匹配（同一块盘的其他分区不会被接受）");
            }
        }

        // 7) 克隆计数
        var baseline = payload.Counter;
        if (settings.EnableCloneCounter)
        {
            stepName = "校验克隆计数";
            await StepAsync(stepName);
            if (expectedCounter.HasValue && payload.Counter != expectedCounter.Value)
            {
                return Fail(label + stepName,
                    $"计数不符（密钥盘={payload.Counter}，本机={expectedCounter.Value}）——可能是过期克隆盘，或本机状态已丢失需要重新配对");
            }
        }
        result.NewCounter = baseline + 1;

        // 计数回写不在此处执行——由多卷循环在全部校验通过后统一提交（事务式）
        result.Success = true;
        return new SingleVerifyResult(result, payload, userBound);
    }

    /// <summary>单卷配对（兼容入口）。</summary>
    public static bool Pair(UsbKeyAuthSettings settings, VolumeInfo volume, string? machineGuid, out string? error)
    {
        return PairVolumes(settings, [volume], machineGuid, null, out error);
    }

    /// <summary>
    /// 多卷配对：为每个分区生成独立 token、写入各自 key.bin，
    /// 并把卷 GUID 并入凭据的授权列表（策略随凭据保存）。
    /// </summary>
    public static bool PairVolumes(UsbKeyAuthSettings settings, IReadOnlyList<VolumeInfo> volumes,
        string? machineGuid, PluginState? state, out string? error)
    {
        error = null;
        if (string.IsNullOrWhiteSpace(machineGuid))
        {
            error = "无法读取本机标识（MachineGuid）";
            return false;
        }
        if (volumes.Count == 0)
        {
            error = "没有可配对的分区";
            return false;
        }
        if (!settings.HasAnyHardBinding)
        {
            error = "请至少启用一种硬绑定（磁盘序列号 / 卷标识 / token）";
            return false;
        }
        foreach (var v in volumes)
        {
            if (string.IsNullOrWhiteSpace(v.DiskSerialNumber))
            {
                error = $"分区 {v.DriveLetter}:\\ 的磁盘序列号读取失败，无法配对";
                return false;
            }
        }

        foreach (var v in volumes)
        {
            var token = Convert.ToBase64String(CryptoService.GenerateSalt(32));
            var payload = new KeyVaultPayload
            {
                Token = token,
                Counter = 0,
                PairedDiskSerial = v.DiskSerialNumber!,
                PairedVolumeGuid = v.VolumeGuid,
                BrandHint = v.DiskModel ?? "",
                CreatedAt = DateTimeOffset.Now.ToString("yyyy-MM-ddTHH:mm:sszzz")
            };

            if (!KeyVaultService.CreateKeyVault(v.VolumeGuid, payload, machineGuid, v.DiskSerialNumber!,
                    settings.EnableUserBinding))
            {
                error = $"写入 {v.DriveLetter}:\\ 的密钥文件失败（请检查该分区是否可写）";
                return false;
            }

            var tokenHash = CryptoService.Sha256Hex(token);
            state?.SetTokenHash(v.VolumeGuid, tokenHash);
            state?.SetCounter(v.VolumeGuid, 0);

            if (!settings.AuthorizedVolumeGuids.Any(g =>
                    string.Equals(g, v.VolumeGuid, StringComparison.OrdinalIgnoreCase)))
            {
                settings.AuthorizedVolumeGuids.Add(v.VolumeGuid);
            }
        }

        // 凭据里的主卷字段（兼容单卷模式与既有结构）
        var primary = volumes[0];
        var primaryPayload = KeyVaultService.ReadKeyVault(primary.VolumeGuid, machineGuid, primary.DiskSerialNumber!, out _, out _);
        settings.PairedDiskSerial = primary.DiskSerialNumber ?? string.Empty;
        settings.PairedVolumeGuid = primary.VolumeGuid;
        settings.TokenHash = primaryPayload != null ? CryptoService.Sha256Hex(primaryPayload.Token) : string.Empty;
        settings.Counter = 0;
        settings.BrandHint = primary.DiskModel ?? "";
        return true;
    }
}
