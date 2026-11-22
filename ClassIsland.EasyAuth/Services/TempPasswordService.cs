using System.Security.Cryptography;
using System.Text;

namespace ClassIsland.EasyAuth.Services;

public enum TempPasswordOutcome
{
    Ok,
    Disabled,
    NoActive,
    Expired,
    Used,
    Locked,
    Mismatch,
    Malformed
}

/// <summary>一枚临时密码的创建结果。明文只在创建时返回一次，之后本机不再保存。</summary>
public sealed record TempPasswordIssue(string Plaintext, DateTimeOffset ExpiresAt);

/// <summary>
/// 一次性临时密码：管理员在插件自己的设置里手动创建，用于 U 盘不在身边时应急解锁。
///
/// 安全约束：
///   - 本机只存 salted PBKDF2 哈希，绝不存明文；明文仅在创建那一刻显示
///   - 一次性：验证成功的同一原子操作内写 UsedAt，用完即废
///   - 短时效：默认 15 分钟，过期失效
///   - 输错限流：连续错误达上限后临时锁定
///   - 恒定时间比较，避免时序侧信道
///
/// 诚实的边界：配置写在插件配置目录，师生同一 Windows 账户时学生也能读写该目录。
/// 所以这是**应急通道**，不是防破解机制；真正的边界仍是目录 ACL 或集控模式。
/// </summary>
public static class TempPasswordService
{
    /// <summary>去掉易混淆字符（0/O/1/I/L）的字母表，纯可打印 ASCII，方便手输/复制。</summary>
    public const string Alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

    public const int PasswordLength = 12;
    public const int SaltSize = 16;
    public const int Pbkdf2Iterations = 100_000;

    public const string EventCreate = "TEMP-CREATE";
    public const string EventRevoke = "TEMP-REVOKE";
    public const string EventAuthOk = "AUTH-TEMP-OK";
    public const string EventAuthFail = "AUTH-TEMP-FAIL";

    /// <summary>清洗用户输入：去首尾空白、去控制字符，大写化（字母表为大写）。</summary>
    public static string Normalize(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return "";
        var cleaned = new string(raw.Where(c => !char.IsControl(c) && !char.IsWhiteSpace(c)).ToArray());
        return cleaned.ToUpperInvariant();
    }

    /// <summary>用密码学随机数生成明文。</summary>
    public static string GeneratePlaintext()
    {
        var chars = new char[PasswordLength];
        for (var i = 0; i < chars.Length; i++)
        {
            chars[i] = Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)];
        }
        return new string(chars);
    }

    private static string DeriveHash(string normalized, byte[] salt) =>
        Convert.ToBase64String(CryptoService.DeriveKey(normalized, salt, Pbkdf2Iterations));

    /// <summary>哈希是否匹配（恒定时间比较）。</summary>
    public static bool Matches(string normalized, string saltBase64, string hashBase64)
    {
        try
        {
            var salt = Convert.FromBase64String(saltBase64);
            var expected = Convert.FromBase64String(hashBase64);
            var actual = Convert.FromBase64String(DeriveHash(normalized, salt));
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 创建一枚新密码。同一时刻只允许一枚有效密码：创建新的会作废旧记录。
    /// 返回明文（仅此一次），失败返回 null（配置写入失败时不能把明文交出去）。
    /// </summary>
    public static TempPasswordIssue? Create(string dataDir, DateTimeOffset? now = null, int? ttlMinutes = null)
    {
        var at = now ?? DateTimeOffset.UtcNow;
        var salt = CryptoService.GenerateSalt(SaltSize);
        var plaintext = GeneratePlaintext();
        var saltText = Convert.ToBase64String(salt);
        var hash = DeriveHash(Normalize(plaintext), salt);
        var ttl = Math.Clamp(ttlMinutes ?? 15, 1, 24 * 60);
        var expires = at.AddMinutes(ttl);

        SecurityConfigStore.Mutate(dataDir, cfg =>
        {
            cfg.TempPasswordSalt = saltText;
            cfg.TempPasswordHash = hash;
            cfg.TempPasswordCreatedAt = at;
            cfg.TempPasswordExpiresAt = expires;
            cfg.TempPasswordUsedAt = null;
            cfg.TempPasswordFailedAttempts = 0;
            cfg.TempPasswordLockedUntil = null;
            return cfg;
        });

        // Mutate 内部已 Save；这里再确认一次文件确实写成功，避免"显示了密码但没落盘"
        var stored = SecurityConfigStore.Load(dataDir);
        if (stored.TempPasswordHash != hash) return null;

        ServiceLogService.Write(dataDir, EventCreate,
            detail: $"expires={expires:yyyy-MM-dd HH:mm:ss} ttl={ttl}min");
        return new TempPasswordIssue(plaintext, expires);
    }

    /// <summary>撤销当前密码。</summary>
    public static void Revoke(string dataDir)
    {
        SecurityConfigStore.Mutate(dataDir, cfg =>
        {
            cfg.TempPasswordHash = null;
            cfg.TempPasswordSalt = null;
            cfg.TempPasswordCreatedAt = null;
            cfg.TempPasswordExpiresAt = null;
            cfg.TempPasswordUsedAt = null;
            cfg.TempPasswordFailedAttempts = 0;
            cfg.TempPasswordLockedUntil = null;
            return cfg;
        });
        ServiceLogService.Write(dataDir, EventRevoke, detail: "reason=manual");
    }

    /// <summary>
    /// 校验并**原子消费**一枚密码。成功时同一临界区内写入 UsedAt，
    /// 因此两个并发的验证请求只有一个能拿到 Ok。
    /// </summary>
    public static TempPasswordOutcome Verify(string dataDir, string? raw, DateTimeOffset? now = null)
    {
        var at = now ?? DateTimeOffset.UtcNow;
        var input = Normalize(raw);
        if (input.Length == 0) return TempPasswordOutcome.Malformed;

        return SecurityConfigStore.Mutate(dataDir, cfg =>
        {
            if (!cfg.EnableTempPassword) return TempPasswordOutcome.Disabled;

            if (string.IsNullOrEmpty(cfg.TempPasswordHash) || string.IsNullOrEmpty(cfg.TempPasswordSalt))
                return TempPasswordOutcome.NoActive;

            if (cfg.TempPasswordUsedAt != null) return TempPasswordOutcome.Used;

            if (cfg.TempPasswordExpiresAt != null && at >= cfg.TempPasswordExpiresAt.Value)
                return TempPasswordOutcome.Expired;

            if (cfg.TempPasswordLockedUntil != null && at < cfg.TempPasswordLockedUntil.Value)
                return TempPasswordOutcome.Locked;

            if (cfg.TempPasswordLockedUntil != null && at >= cfg.TempPasswordLockedUntil.Value)
            {
                // 锁定到期，重置计数后继续本轮校验
                cfg.TempPasswordFailedAttempts = 0;
                cfg.TempPasswordLockedUntil = null;
            }

            if (!Matches(input, cfg.TempPasswordSalt, cfg.TempPasswordHash))
            {
                cfg.TempPasswordFailedAttempts++;
                if (cfg.TempPasswordFailedAttempts >= Math.Max(1, cfg.TempPasswordMaxAttempts))
                {
                    cfg.TempPasswordLockedUntil = at.AddMinutes(Math.Max(1, cfg.TempPasswordLockMinutes));
                }
                return TempPasswordOutcome.Mismatch;
            }

            // 一次性：写 UsedAt，明文不再可用
            cfg.TempPasswordUsedAt = at;
            cfg.TempPasswordFailedAttempts = 0;
            cfg.TempPasswordLockedUntil = null;
            return TempPasswordOutcome.Ok;
        });
    }

    /// <summary>供界面显示的状态文本（不泄露哈希）。</summary>
    public static string Describe(string dataDir, DateTimeOffset? now = null)
    {
        var at = now ?? DateTimeOffset.UtcNow;
        var cfg = SecurityConfigStore.Load(dataDir);
        if (!cfg.EnableTempPassword) return "临时密码通道已关闭。";
        if (cfg.TempPasswordUsedAt != null)
            return $"上一枚已于 {cfg.TempPasswordUsedAt.Value.ToLocalTime():yyyy-MM-dd HH:mm:ss} 使用并作废。";
        if (cfg.TempPasswordExpiresAt == null || string.IsNullOrEmpty(cfg.TempPasswordHash))
            return "当前没有临时密码。";
        if (at >= cfg.TempPasswordExpiresAt.Value)
            return $"上一枚已于 {cfg.TempPasswordExpiresAt.Value.ToLocalTime():yyyy-MM-dd HH:mm:ss} 过期。";
        if (cfg.TempPasswordLockedUntil != null && at < cfg.TempPasswordLockedUntil.Value)
            return $"输错次数过多，{cfg.TempPasswordLockedUntil.Value.ToLocalTime():HH:mm:ss} 前暂时锁定。";
        var left = cfg.TempPasswordExpiresAt.Value - at;
        return $"存在一枚有效临时密码，剩余 {left.TotalMinutes:F0} 分钟；使用一次后立即作废。";
    }
}
