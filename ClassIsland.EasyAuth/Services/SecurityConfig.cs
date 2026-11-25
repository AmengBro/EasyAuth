using System.IO;
using System.Text.Json;

namespace ClassIsland.EasyAuth.Services;

/// <summary>
/// 安全与应急配置，存在插件配置目录的 security.json。
///
/// 设计原则（v0.3.2）：**每个检测器/动作各自独立可开关，默认只开「只观测」**。
///   - EnableTamperDetection  完整性检测，默认开，只记录差异，不重启、不回滚、不改文件
///   - EnableTempPassword     一次性临时密码，默认开
///   - EnableSilentRestart    静默重启宿主，默认关，本版未接线（保留开关供后续版本）
///   - EnableAutoRestore      自动换回副本，默认关，本版未接线（保留开关供后续版本）
///   - EnableRecoveryCode     应急恢复码通道，默认关，本版未接线（保留开关供后续版本）
///
/// 之所以把后三个开关先放进配置而不实现：将来任何一个通道接入时，
/// 可以单独开、单独关，互不牵连；也避免「恢复码清空凭据」与「篡改检测换回副本」
/// 在同一轮启动里互相打架（本版用 GuardState.Suppress 预留互斥点）。
/// </summary>
public class SecurityConfig
{
    /// <summary>完整性检测（只观测）。关掉后启动时不读取也不比对 Credentials.json。</summary>
    public bool EnableTamperDetection { get; set; } = true;

    /// <summary>一次性临时密码通道。</summary>
    public bool EnableTempPassword { get; set; } = true;

    /// <summary>预留：静默重启宿主。本版不接线，恒按「关」处理。</summary>
    public bool EnableSilentRestart { get; set; } = false;

    /// <summary>预留：自动换回副本。本版不接线，恒按「关」处理。</summary>
    public bool EnableAutoRestore { get; set; } = false;

    /// <summary>预留：应急恢复码通道。本版不接线，恒按「关」处理。</summary>
    public bool EnableRecoveryCode { get; set; } = false;

    /// <summary>
    /// 认证态的临时密码输入区默认折叠：只显示一行小按钮，不与分区下拉框/验证按钮抢位置。
    /// （生成入口在插件设置页「设置 → U盘密钥」，凭据编辑界面上不再有安全配置区。）
    /// </summary>
    public bool TempPasswordSectionCollapsed { get; set; } = true;

    /// <summary>
    /// 连续输错多少次后临时锁定。
    /// </summary>
    public int TempPasswordMaxAttempts { get; set; } = 5;

    /// <summary>输错锁定分钟数。</summary>
    public int TempPasswordLockMinutes { get; set; } = 10;

    /// <summary>
    /// Credentials.json 的 SHA-256 基线。
    /// 只存哈希、**不存全文副本**：副本会把 Base64 凭据内容再复制一份到插件目录，
    /// 反而扩大攻击面；检测「内容有没有变」只需要哈希。
    /// </summary>
    public string? CredentialsBaselineSha256 { get; set; }

    /// <summary>基线对应的文件路径（本地模式 / 集控模式可能不同）。</summary>
    public string? CredentialsBaselinePath { get; set; }

    /// <summary>基线建立时间。</summary>
    public DateTimeOffset? CredentialsBaselineAt { get; set; }

    /// <summary>
    /// 上次观测到但与基线不同的哈希。用于两件事：
    /// 同一份改动不重复刷日志，以及让「待确认差异」状态一直留到管理员手动重建基线。
    /// </summary>
    public string? LastObservedHash { get; set; }

    // —— 一次性临时密码状态 ——
    // 只存 salted PBKDF2 哈希，绝不存明文；明文仅在「生成」那一刻显示一次。

    public string? TempPasswordHash { get; set; }
    public string? TempPasswordSalt { get; set; }
    public DateTimeOffset? TempPasswordCreatedAt { get; set; }
    public DateTimeOffset? TempPasswordUsedAt { get; set; }
    public int TempPasswordFailedAttempts { get; set; }
    public DateTimeOffset? TempPasswordLockedUntil { get; set; }

    /// <summary>
    /// 当前是否存在一枚可用（未用过）的临时密码。
    ///
    /// 临时密码**没有有效期**（v0.3.2 起）：一次性消费是它唯一的作废条件，
    /// 另有管理员手动「撤销」作为兜底。所以这里不再看过期时间。
    /// </summary>
    public bool HasActiveTempPassword() =>
        !string.IsNullOrEmpty(TempPasswordHash) &&
        !string.IsNullOrEmpty(TempPasswordSalt) &&
        TempPasswordUsedAt == null;
}

public static class SecurityConfigStore
{
    public const string FileName = "security.json";

    private static readonly object Gate = new();
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    /// <summary>读取配置；文件损坏或不存在时返回默认值，绝不因配置问题让插件加载失败。</summary>
    public static SecurityConfig Load(string dataDir)
    {
        lock (Gate)
        {
            try
            {
                var path = Path.Combine(dataDir, FileName);
                if (!File.Exists(path))
                {
                    return new SecurityConfig();
                }
                return JsonSerializer.Deserialize<SecurityConfig>(File.ReadAllText(path), Options)
                       ?? new SecurityConfig();
            }
            catch
            {
                return new SecurityConfig();
            }
        }
    }

    /// <summary>原子写入（临时文件 + 覆盖移动），避免写到一半留个坏 JSON。</summary>
    public static bool Save(string dataDir, SecurityConfig config)
    {
        lock (Gate)
        {
            try
            {
                Directory.CreateDirectory(dataDir);
                var path = Path.Combine(dataDir, FileName);
                var tmp = path + ".tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(config, Options));
                File.Move(tmp, path, true);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>
    /// 读-改-写在同一把锁内完成，用于「一次性消费」这类必须原子的操作：
    /// 两处同时验证同一枚密码时，只有第一个能把 UsedAt 写上。
    /// </summary>
    public static T Mutate<T>(string dataDir, Func<SecurityConfig, T> action)
    {
        lock (Gate)
        {
            var config = Load(dataDir);
            var result = action(config);
            Save(dataDir, config);
            return result;
        }
    }
}

/// <summary>
/// 检测器互斥点（运行时状态，不落盘）。
///
/// 本版不实现恢复码通道，但先留好接口：将来恢复码**校验通过**后调用
/// GuardState.Suppress("recovery-code-verified")，本轮启动的完整性检测即跳过，
/// 恢复动作完成后再 Rebaseline + ClearSuppression，避免「刚清空的凭据被检测换回」。
///
/// 严禁仅凭「recovery.txt 存在」就调用 Suppress —— 那等于给任何人一个
/// 「建个空文件就能永久关掉警报」的开关。必须先校验恢复码内容。
/// </summary>
public static class GuardState
{
    private static readonly object Gate = new();
    private static string? _reason;

    public static bool IsSuppressed
    {
        get { lock (Gate) return _reason != null; }
    }

    public static string? Reason
    {
        get { lock (Gate) return _reason; }
    }

    public static void Suppress(string reason)
    {
        if (string.IsNullOrWhiteSpace(reason)) return;
        lock (Gate) _reason = reason;
    }

    public static void ClearSuppression()
    {
        lock (Gate) _reason = null;
    }

    /// <summary>
    /// 恢复码门控（纯逻辑，本版只提供骨架、不接线读写 recovery.txt）。
    ///
    /// 关键：**不能只看「文件存在」就抑制检测**，否则任何人建一个空的
    /// recovery.txt 就能永久关掉完整性警报。必须同时满足：
    ///   1) 恢复码通道在配置里已启用
    ///   2) 文件存在
    ///   3) 内容校验通过（由未来的恢复码通道负责计算 verified）
    /// 校验不通过时不但不抑制，还应记一条可疑事件，由调用方处理。
    /// </summary>
    /// <returns>true 表示已抑制（调用方应跳过本轮检测并重建基线）。</returns>
    public static bool RecoveryGate(bool channelEnabled, bool fileExists, bool codeVerified)
    {
        if (!channelEnabled || !fileExists) return false;
        if (!codeVerified) return false;
        Suppress("recovery-code-verified");
        return true;
    }
}
