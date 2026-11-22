using System.IO;
using System.Security.Cryptography;

namespace ClassIsland.EasyAuth.Services;

public enum IntegrityOutcome
{
    /// <summary>与基线一致。</summary>
    Match,
    /// <summary>首次运行，已建立基线（不视为篡改）。</summary>
    BaselineCreated,
    /// <summary>发现内容差异，已记录；无法判定来源。</summary>
    Difference,
    /// <summary>凭据文件不存在（可能尚未配置，也可能被删除）。</summary>
    Missing,
    /// <summary>检测开关关闭，跳过。</summary>
    Disabled,
    /// <summary>被抑制（预留给恢复码通道），跳过。</summary>
    Suppressed,
    /// <summary>读取/写入异常，已记录但不影响启动。</summary>
    Error
}

public sealed record IntegrityResult(
    IntegrityOutcome Outcome,
    string Path,
    string? ObservedHash,
    string? BaselineHash,
    bool HasPendingDifference);

/// <summary>
/// Credentials.json 完整性检测 —— **只观测，不动作**。
///
/// 明确不做的事（v0.3.2 的取舍）：
///   - 不静默重启 ClassIsland：会打断桌面课表/提醒等常驻状态
///   - 不自动换回、不覆盖凭据文件：无法区分「宿主合法保存」与「人为修改」，
///     自动回滚会把老师刚改的密码抹掉，还会与恢复码通道互相打架
///   - 不自动更新基线：否则改一次、重启两次痕迹就被洗白。
///     差异会一直记为待确认，直到管理员在设置里点「重建基线」
///   - 不存全文副本：只存 SHA-256。副本会把 Base64 凭据内容再复制一份，
///     反而扩大攻击面；检测「有没有变」用哈希足够
///
/// 日志用中性措辞「差异」而非「篡改」：宿主每次 SaveConfig 都会重写文件，
/// 老师正常改密码同样会产生差异，插件拿不到「是谁写的」这个信号。
/// </summary>
public static class IntegrityMonitor
{
    public const string EventBaseline = "INTEGRITY-BASELINE";
    public const string EventDiff = "INTEGRITY-DIFF";
    public const string EventMissing = "INTEGRITY-NOFILE";
    public const string EventSkip = "INTEGRITY-SKIP";
    public const string EventError = "INTEGRITY-ERROR";
    public const string EventRebaseline = "INTEGRITY-REBASELINE";

    /// <summary>
    /// 从插件配置目录推导宿主凭据文件的候选路径。
    /// 插件配置目录 = {AppRoot}\data\Config\Plugins\&lt;id&gt;
    ///   本地模式：{AppRoot}\data\Config\Management\Credentials.json
    ///   集控模式：{AppRoot}\data\Management\Credentials.json
    /// 两个都查，谁存在用谁；都不存在时用本地路径作为观测目标。
    /// </summary>
    public static string[] ResolveCandidatePaths(string pluginConfigDir)
    {
        try
        {
            var configDir = Path.GetFullPath(Path.Combine(pluginConfigDir, "..", ".."));
            var dataDir = Path.GetFullPath(Path.Combine(configDir, ".."));
            return new[]
            {
                Path.Combine(configDir, "Management", "Credentials.json"),
                Path.Combine(dataDir, "Management", "Credentials.json")
            };
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    /// <summary>选一个实际存在的路径；都不存在时返回第一个候选（用于记录 NOFILE）。</summary>
    public static string SelectExistingPath(string pluginConfigDir)
    {
        var candidates = ResolveCandidatePaths(pluginConfigDir);
        if (candidates.Length == 0) return "";
        foreach (var path in candidates)
        {
            if (File.Exists(path)) return path;
        }
        return candidates[0];
    }

    /// <summary>文件内容 SHA-256（小写十六进制）。</summary>
    public static string ComputeHash(string path)
    {
        var bytes = File.ReadAllBytes(path);
        return CryptoService.Sha256Hex(bytes);
    }

    /// <summary>
    /// 启动检测。只读、只写插件自己的日志与配置，绝不碰 Credentials.json。
    /// </summary>
    /// <param name="dataDir">插件配置目录。</param>
    /// <param name="credentialPath">显式指定凭据文件路径（自测用）；null 时自动推导。</param>
    public static IntegrityResult Check(string dataDir, string? credentialPath = null)
    {
        var config = SecurityConfigStore.Load(dataDir);
        var path = credentialPath ?? SelectExistingPath(dataDir);

        if (!config.EnableTamperDetection)
        {
            ServiceLogService.Write(dataDir, EventSkip, detail: "reason=disabled");
            return new IntegrityResult(IntegrityOutcome.Disabled, path, null,
                config.CredentialsBaselineSha256, HasPending(config));
        }

        if (GuardState.IsSuppressed)
        {
            ServiceLogService.Write(dataDir, EventSkip,
                detail: $"reason=suppressed by={GuardState.Reason}");
            return new IntegrityResult(IntegrityOutcome.Suppressed, path, null,
                config.CredentialsBaselineSha256, HasPending(config));
        }

        if (string.IsNullOrEmpty(path) || !File.Exists(path))
        {
            ServiceLogService.Write(dataDir, EventMissing, detail: $"path={path}");
            return new IntegrityResult(IntegrityOutcome.Missing, path, null,
                config.CredentialsBaselineSha256, HasPending(config));
        }

        try
        {
            var observed = ComputeHash(path);

            // 首次运行：建立基线，不报差异。
            if (string.IsNullOrEmpty(config.CredentialsBaselineSha256))
            {
                SecurityConfigStore.Mutate(dataDir, cfg =>
                {
                    cfg.CredentialsBaselineSha256 = observed;
                    cfg.CredentialsBaselinePath = path;
                    cfg.CredentialsBaselineAt = DateTimeOffset.UtcNow;
                    return cfg;
                });
                ServiceLogService.Write(dataDir, EventBaseline,
                    detail: $"path={path} hash={Short(observed)}");
                return new IntegrityResult(IntegrityOutcome.BaselineCreated, path, observed, observed, false);
            }

            if (string.Equals(observed, config.CredentialsBaselineSha256, StringComparison.OrdinalIgnoreCase))
            {
                return new IntegrityResult(IntegrityOutcome.Match, path, observed,
                    config.CredentialsBaselineSha256, HasPending(config));
            }

            // 差异：只记录。same-as-last 时不重复刷屏，但仍保持待确认状态。
            var isNewDiff = !string.Equals(observed, config.LastObservedHash, StringComparison.OrdinalIgnoreCase);
            SecurityConfigStore.Mutate(dataDir, cfg => { cfg.LastObservedHash = observed; return cfg; });

            if (isNewDiff)
            {
                ServiceLogService.Write(dataDir, EventDiff,
                    detail: $"path={path} baseline={Short(config.CredentialsBaselineSha256)} " +
                            $"observed={Short(observed)} source=unknown " +
                            $"note=可能是宿主合法保存也可能是人为修改，插件无法判定；未做任何自动处理");
            }

            return new IntegrityResult(IntegrityOutcome.Difference, path, observed,
                config.CredentialsBaselineSha256, true);
        }
        catch (Exception ex)
        {
            ServiceLogService.Write(dataDir, EventError,
                detail: $"path={path} ex={ex.GetType().Name}");
            return new IntegrityResult(IntegrityOutcome.Error, path, null,
                config.CredentialsBaselineSha256, HasPending(config));
        }
    }

    /// <summary>
    /// 管理员确认「刚才是合法更新」后手动重建基线。这是唯一会更新基线的入口
    /// （除了首次建立），避免自动洗白。
    /// </summary>
    public static bool Rebaseline(string dataDir, string? credentialPath = null)
    {
        var path = credentialPath ?? SelectExistingPath(dataDir);
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return false;
        try
        {
            var observed = ComputeHash(path);
            SecurityConfigStore.Mutate(dataDir, cfg =>
            {
                cfg.CredentialsBaselineSha256 = observed;
                cfg.CredentialsBaselinePath = path;
                cfg.CredentialsBaselineAt = DateTimeOffset.UtcNow;
                cfg.LastObservedHash = null;
                return cfg;
            });
            ServiceLogService.Write(dataDir, EventRebaseline,
                detail: $"path={path} hash={Short(observed)} by=admin");
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>是否有「待管理员确认」的差异。</summary>
    public static bool HasPending(SecurityConfig config) =>
        !string.IsNullOrEmpty(config.CredentialsBaselineSha256) &&
        !string.IsNullOrEmpty(config.LastObservedHash) &&
        !string.Equals(config.CredentialsBaselineSha256, config.LastObservedHash,
            StringComparison.OrdinalIgnoreCase);

    /// <summary>状态文本，供设置界面显示。</summary>
    public static string Describe(string dataDir)
    {
        var config = SecurityConfigStore.Load(dataDir);
        if (!config.EnableTamperDetection) return "完整性检测已关闭。";
        if (string.IsNullOrEmpty(config.CredentialsBaselineSha256)) return "尚未建立基线，下次启动自动建立。";
        if (HasPending(config))
            return "⚠ 检测到凭据文件与基线不一致（来源无法判定，可能是你刚改过密码）。确认无误后点「重建基线」。";
        return $"与基线一致（建立于 {config.CredentialsBaselineAt?.ToLocalTime():yyyy-MM-dd HH:mm}）。";
    }

    private static string Short(string? hash) =>
        string.IsNullOrEmpty(hash) || hash.Length < 12 ? hash ?? "-" : hash[..12];
}
