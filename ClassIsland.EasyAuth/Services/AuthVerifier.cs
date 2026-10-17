using System.IO;
using ClassIsland.EasyAuth.Models;

namespace ClassIsland.EasyAuth.Services;

/// <summary>认证流水线的执行结果</summary>
public class AuthVerifyResult
{
    /// <summary>是否通过全部启用的校验层</summary>
    public bool Success { get; set; }

    /// <summary>失败所处步骤名（供界面高亮显示）</summary>
    public string? FailedStep { get; set; }

    /// <summary>失败原因</summary>
    public string? FailureReason { get; set; }

    /// <summary>计数回写失败（U 盘不可写等）——放行但降级提示</summary>
    public bool CounterWriteBackWarning { get; set; }

    /// <summary>认证成功后的新计数（调用方需落盘）</summary>
    public int NewCounter { get; set; }
}

/// <summary>
/// 认证流水线（UI 无关，可在控制台自测）。
/// 按设置里的分层开关依次校验，每步通过回调向界面汇报当前项，
/// 便于进度条 + 逐项状态展示。
/// </summary>
public static class AuthVerifier
{
    /// <summary>
    /// 执行认证。
    /// </summary>
    /// <param name="settings">提供方设置（含分层开关与配对信息）</param>
    /// <param name="volume">本次验证选中的卷（含卷 GUID / 磁盘 SN）</param>
    /// <param name="machineGuid">本机 MachineGuid</param>
    /// <param name="expectedCounter">本地存活计数；为 null 表示状态缺失，按密钥库当前计数接纳并重新建立基线</param>
    /// <param name="report">每一步的状态汇报回调（会先汇报再校验）</param>
    /// <param name="yieldAsync">步骤间让出 UI 线程（界面可传，测试可传 null）</param>
    public static async Task<AuthVerifyResult> VerifyAsync(
        UsbKeyAuthSettings settings,
        VolumeInfo volume,
        string? machineGuid,
        int? expectedCounter,
        Action<string>? report = null,
        Func<Task>? yieldAsync = null)
    {
        var result = new AuthVerifyResult();
        var step = 0;

        async Task StepAsync(string name)
        {
            step++;
            report?.Invoke(name);
            if (yieldAsync != null)
            {
                await yieldAsync();
            }
        }

        static AuthVerifyResult Fail(AuthVerifyResult r, string step, string reason)
        {
            r.Success = false;
            r.FailedStep = step;
            r.FailureReason = reason;
            return r;
        }

        // 1) 定位分区与设备信息
        var stepName = "定位分区";
        await StepAsync(stepName);
        var serial = volume.DiskSerialNumber;
        if (string.IsNullOrWhiteSpace(serial))
        {
            return Fail(result, stepName, "无法读取该分区的磁盘序列号（可能需要检查磁盘状态）");
        }
        if (string.IsNullOrWhiteSpace(volume.VolumeGuid))
        {
            return Fail(result, stepName, "无法获取该分区的卷标识");
        }

        // 2) 读取并解密密钥文件
        stepName = "读取并解密密钥文件";
        await StepAsync(stepName);
        if (string.IsNullOrWhiteSpace(machineGuid))
        {
            return Fail(result, stepName, "无法读取本机标识（MachineGuid）");
        }
        var payload = KeyVaultService.ReadKeyVault(volume.VolumeGuid, machineGuid, serial);
        if (payload == null)
        {
            return Fail(result, stepName,
                KeyVaultService.KeyVaultExists(volume.VolumeGuid)
                    ? "密钥文件无法解密（可能不是本机配对的 U 盘，或文件已损坏）"
                    : "未检测到密钥文件（该分区上没有 .EasyAuth\\key.bin）");
        }

        // 3) token 校验
        if (settings.EnableTokenCheck)
        {
            stepName = "校验 token";
            await StepAsync(stepName);
            if (string.IsNullOrEmpty(settings.TokenHash) ||
                !string.Equals(CryptoService.Sha256Hex(payload.Token), settings.TokenHash, StringComparison.OrdinalIgnoreCase))
            {
                return Fail(result, stepName, "token 不匹配（密钥文件与本机配对记录不符）");
            }
        }

        // 4) 磁盘 SN 绑定
        if (settings.EnableSnBinding)
        {
            stepName = "校验磁盘序列号";
            await StepAsync(stepName);
            var ok = string.Equals(serial, settings.PairedDiskSerial, StringComparison.OrdinalIgnoreCase)
                     && string.Equals(payload.PairedDiskSerial, settings.PairedDiskSerial, StringComparison.OrdinalIgnoreCase);
            if (!ok)
            {
                return Fail(result, stepName, "磁盘序列号不匹配（当前分区所在磁盘不是配对的那一块）");
            }
        }

        // 5) 卷 GUID 绑定
        if (settings.EnableVolumeGuidBinding)
        {
            stepName = "校验卷标识";
            await StepAsync(stepName);
            var ok = string.Equals(volume.VolumeGuid, settings.PairedVolumeGuid, StringComparison.OrdinalIgnoreCase)
                     && string.Equals(payload.PairedVolumeGuid, settings.PairedVolumeGuid, StringComparison.OrdinalIgnoreCase);
            if (!ok)
            {
                return Fail(result, stepName, "卷标识不匹配（同一块盘的其他分区不会被接受）");
            }
        }

        // 6) 克隆计数
        var baseline = payload.Counter;
        if (settings.EnableCloneCounter)
        {
            stepName = "校验克隆计数";
            await StepAsync(stepName);
            if (expectedCounter.HasValue && payload.Counter != expectedCounter.Value)
            {
                return Fail(result, stepName,
                    $"计数不符（密钥盘={payload.Counter}，本机={expectedCounter.Value}）——可能是过期克隆盘，或本机状态已丢失需要重新配对");
            }
        }
        result.NewCounter = baseline + 1;

        // 7) 计数回写（失败仅降级警告，不阻断放行）
        if (settings.EnableCloneCounter)
        {
            stepName = "写入新计数";
            await StepAsync(stepName);
            if (!KeyVaultService.RewriteCounter(volume.VolumeGuid, payload, result.NewCounter, machineGuid, serial))
            {
                result.CounterWriteBackWarning = true;
            }
        }

        result.Success = true;
        return result;
    }

    /// <summary>
    /// 配对：为选中分区生成 token 并写入加密密钥库，同时回填设置。
    /// </summary>
    public static bool Pair(
        UsbKeyAuthSettings settings,
        VolumeInfo volume,
        string? machineGuid,
        out string? error)
    {
        error = null;
        if (string.IsNullOrWhiteSpace(machineGuid))
        {
            error = "无法读取本机标识（MachineGuid）";
            return false;
        }
        var serial = volume.DiskSerialNumber;
        if (string.IsNullOrWhiteSpace(serial))
        {
            error = "无法读取该分区的磁盘序列号";
            return false;
        }
        if (!settings.HasAnyHardBinding)
        {
            error = "请至少启用一种硬绑定（磁盘序列号 / 卷标识 / token）";
            return false;
        }

        var tokenBytes = CryptoService.GenerateSalt(32);
        var token = Convert.ToBase64String(tokenBytes);
        var payload = new KeyVaultPayload
        {
            Token = token,
            Counter = 0,
            PairedDiskSerial = serial,
            PairedVolumeGuid = volume.VolumeGuid,
            BrandHint = volume.DiskModel ?? "",
            CreatedAt = DateTimeOffset.Now.ToString("yyyy-MM-ddTHH:mm:sszzz")
        };

        if (!KeyVaultService.CreateKeyVault(volume.VolumeGuid, payload, machineGuid, serial))
        {
            error = "写入密钥文件失败（请检查 U 盘是否可写）";
            return false;
        }

        settings.PairedDiskSerial = serial;
        settings.PairedVolumeGuid = volume.VolumeGuid;
        settings.TokenHash = CryptoService.Sha256Hex(token);
        settings.Counter = 0;
        settings.BrandHint = payload.BrandHint;
        return true;
    }
}