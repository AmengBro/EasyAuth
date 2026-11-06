using System.IO;
using System.Text;

namespace ClassIsland.EasyAuth.Services;

/// <summary>
/// 两个日志文件，各司其职（都写在 ClassIsland 的插件配置目录里）：
///   audit.log   审计日志——只记「谁在什么时候拿哪块盘解锁」及凭据绑定/变更
///   service.log 运行日志——API 启停、提醒调度、控件生命周期等运维事件
/// 混在一起会让审计记录被运维噪声淹没，所以 AuditLogService.Write 自带兜底路由：
/// 传进来的事件不是审计事件时，自动转写到 service.log。
/// </summary>
internal static class RollingLog
{
    private const long MaxBytes = 1_000_000;
    private const int MaxFiles = 3;

    public static string BuildLine(string eventType, string? driveLetter,
        string? volumeGuid, string? diskSerial, string? detail)
    {
        return string.Join(' ',
            DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss.fff"),
            $"[{eventType}]",
            $"drive={driveLetter ?? "-"}",
            $"vol={ShortGuid(volumeGuid)}",
            $"sn={diskSerial ?? "-"}",
            detail ?? "").TrimEnd();
    }

    public static void Append(string path, string line)
    {
        try
        {
            RotateIfNeeded(path);
            File.AppendAllText(path, line + Environment.NewLine, Encoding.UTF8);
        }
        catch
        {
            // 日志失败不影响主流程
        }
    }

    public static string ReadTail(string path, int lines, string emptyText)
    {
        try
        {
            if (!File.Exists(path))
            {
                return emptyText;
            }
            var all = File.ReadAllLines(path);
            return string.Join(Environment.NewLine, all.Skip(Math.Max(0, all.Length - lines)));
        }
        catch
        {
            return "（读取日志失败）";
        }
    }

    private static void RotateIfNeeded(string path)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.Length < MaxBytes)
        {
            return;
        }
        for (var i = MaxFiles - 1; i >= 1; i--)
        {
            var older = $"{path}.{i}";
            var newer = $"{path}.{i + 1}";
            if (i == MaxFiles - 1 && File.Exists(newer))
            {
                File.Delete(newer);
            }
            if (File.Exists(older))
            {
                File.Move(older, newer, true);
            }
        }
        File.Move(path, $"{path}.1", true);
    }

    private static string ShortGuid(string? volumeGuid)
    {
        if (string.IsNullOrEmpty(volumeGuid))
        {
            return "-";
        }
        var i = volumeGuid.IndexOf('{');
        if (i < 0)
        {
            return volumeGuid.Length > 12 ? volumeGuid[..12] : volumeGuid;
        }
        var close = volumeGuid.IndexOf('}', i);
        if (close < 0)
        {
            return "-";
        }
        var guid = volumeGuid[(i + 1)..close];
        return guid.Length > 8 ? guid[..8] : guid;
    }
}

/// <summary>
/// 审计日志：只记录认证结果（AUTH-* / VALIDATE-*）与凭据绑定（PAIR*）。
/// 按大小轮转，界面「查看审计日志」读的就是这个文件。
/// </summary>
public static class AuditLogService
{
    public const string LogFileName = "audit.log";

    /// <summary>哪些事件算审计事件；其余一律归运行日志。</summary>
    public static bool IsAuditEvent(string eventType) =>
        eventType.StartsWith("AUTH-", StringComparison.Ordinal) ||
        eventType.StartsWith("VALIDATE-", StringComparison.Ordinal) ||
        eventType.StartsWith("PAIR", StringComparison.Ordinal);

    /// <summary>追加一条审计记录；非审计事件会自动转写 service.log。</summary>
    public static void Write(string dataDir, string eventType, string? driveLetter = null,
        string? volumeGuid = null, string? diskSerial = null, string? detail = null)
    {
        if (!IsAuditEvent(eventType))
        {
            ServiceLogService.Write(dataDir, eventType, driveLetter, volumeGuid, diskSerial, detail);
            return;
        }
        RollingLog.Append(Path.Combine(dataDir, LogFileName),
            RollingLog.BuildLine(eventType, driveLetter, volumeGuid, diskSerial, detail));
    }

    /// <summary>读取最近若干行（界面「查看审计日志」用）。</summary>
    public static string ReadTail(string dataDir, int lines = 15)
    {
        return RollingLog.ReadTail(Path.Combine(dataDir, LogFileName), lines, "（暂无审计记录）");
    }
}

/// <summary>
/// 运行日志：API 启停、提醒调度、控件加载/恢复、数据迁移等运维事件。
/// 审计日志里不该出现这些，排查 API 问题看这个文件。
/// </summary>
public static class ServiceLogService
{
    public const string LogFileName = "service.log";

    public static void Write(string dataDir, string eventType, string? driveLetter = null,
        string? volumeGuid = null, string? diskSerial = null, string? detail = null)
    {
        RollingLog.Append(Path.Combine(dataDir, LogFileName),
            RollingLog.BuildLine(eventType, driveLetter, volumeGuid, diskSerial, detail));
    }

    public static string ReadTail(string dataDir, int lines = 15)
    {
        return RollingLog.ReadTail(Path.Combine(dataDir, LogFileName), lines, "（暂无运行记录）");
    }
}
