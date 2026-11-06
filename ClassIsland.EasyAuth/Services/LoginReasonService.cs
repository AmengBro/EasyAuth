using Avalonia;
using Avalonia.Threading;

namespace ClassIsland.EasyAuth.Services;

/// <summary>一次验证成功的上下文，供弹窗回填审计记录。</summary>
public sealed record LoginReasonContext(
    string DataDir, string? Drive, string? VolumeGuid, string? DiskSerial);

/// <summary>
/// 「本次登录原因」补充采集。
/// 设计原则：认证成功已经发生，这里只做**旁路记录**——非模态、可忽略、超时自动消失，
/// 绝不阻塞「继续」，也不影响认证结果。每次验证成功都在 audit.log 留一条闭环记录，
/// 便于事后排查「谁在什么时候解锁、为什么、有没有留下原因」。
/// </summary>
public static class LoginReasonService
{
    /// <summary>未点击输入框时，弹窗多少秒后自动关闭。</summary>
    public const int AutoCloseSeconds = 10;

    /// <summary>原因最大长度，防止把审计日志撑爆。</summary>
    public const int MaxReasonLength = 200;

    public const string AuditEvent = "AUTH-REASON";

    private static LoginReasonWindow? _current;

    /// <summary>
    /// 清洗用户输入：去掉换行/制表符等控制字符（否则可以伪造出新的日志行），
    /// 去首尾空白并限长。空白原因返回空串。
    /// </summary>
    public static string Sanitize(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return "";
        }
        var text = new string(raw.Where(c => !char.IsControl(c)).ToArray()).Trim();
        return text.Length > MaxReasonLength ? text[..MaxReasonLength] : text;
    }

    /// <summary>
    /// 把本次采集结果写进 audit.log。outcome 取值：
    /// provided / dismissed / timeout / superseded / no-ui。
    /// 未填写也写一条，保证每条成功登录都有闭环。
    /// </summary>
    public static void Record(LoginReasonContext ctx, string? rawReason, string outcome)
    {
        var clean = Sanitize(rawReason);
        var reasonPart = clean.Length == 0
            ? "reason=（未填写）"
            : $"reason=\"{clean.Replace('"', '\'')}\"";
        AuditLogService.Write(ctx.DataDir, AuditEvent, ctx.Drive, ctx.VolumeGuid, ctx.DiskSerial,
            $"outcome={outcome} {reasonPart}");
    }

    /// <summary>
    /// 非模态弹出输入框。任意线程可调用：一律 Post 到 Avalonia UI 线程，
    /// 调用方立刻返回，不等待用户操作。
    /// </summary>
    public static void Prompt(LoginReasonContext ctx)
    {
        try
        {
            Dispatcher.UIThread.Post(() => Show(ctx));
        }
        catch
        {
            // UI 线程不可用时也要留下审计闭环
            Record(ctx, null, "no-ui");
        }
    }

    private static void Show(LoginReasonContext ctx)
    {
        try
        {
            if (Application.Current == null)
            {
                Record(ctx, null, "no-ui");
                return;
            }
            // 同时只保留一个窗口，避免连续验证时叠成一摞
            if (_current is { IsVisible: true })
            {
                _current.CloseWith("superseded");
            }
            var window = new LoginReasonWindow(ctx);
            _current = window;
            window.Show();
        }
        catch
        {
            Record(ctx, null, "no-ui");
        }
    }
}
