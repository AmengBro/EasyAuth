using System.IO;
using System.Text;

namespace ClassIsland.EasyAuth.Services;

/// <summary>
/// 审计日志：记录每次配对与认证的结果（时间/分区/磁盘SN/结果/失败层）。
/// 文件写在插件自己的目录，按大小轮转，便于事后追溯。
/// </summary>
public static class AuditLogService
{
    public const string LogFileName = "audit.log";

    private const long MaxBytes = 1_000_000;
    private const int MaxFiles = 3;

    /// <summary>追加一条审计记录。事件类型建议：PAIR / AUTH-OK / AUTH-FAIL。</summary>
    public static void Write(string stateDir, string eventType, string? driveLetter = null,
        string? volumeGuid = null, string? diskSerial = null, string? detail = null)
    {
        try
        {
            var path = Path.Combine(stateDir, LogFileName);
            RotateIfNeeded(path);
            var line = string.Join(' ',
                DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                $"[{eventType}]",
                $"drive={driveLetter ?? "-"}",
                $"vol={ShortGuid(volumeGuid)}",
                $"sn={diskSerial ?? "-"}",
                detail ?? "");
            File.AppendAllText(path, line.TrimEnd() + Environment.NewLine, Encoding.UTF8);
        }
        catch
        {
            // 日志失败不影响主流程
        }
    }

    /// <summary>读取最近若干行（界面「查看审计日志」用）。</summary>
    public static string ReadTail(string stateDir, int lines = 15)
    {
        try
        {
            var path = Path.Combine(stateDir, LogFileName);
            if (!File.Exists(path))
            {
                return "（暂无审计记录）";
            }
            var all = File.ReadAllLines(path);
            return string.Join(Environment.NewLine, all.Skip(Math.Max(0, all.Length - lines)));
        }
        catch
        {
            return "（读取审计日志失败）";
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