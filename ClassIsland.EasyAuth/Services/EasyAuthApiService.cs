using System.Net;
using System.Text;
using System.Text.Json;
using ClassIsland.Core.Abstractions.Services;
using ClassIsland.Shared;
using ClassIsland.Shared.Enums;
using ClassIsland.Shared.IPC.Abstractions.Services;
using ClassIsland.Shared.Models.Profile;
using Microsoft.Extensions.Hosting;

namespace ClassIsland.EasyAuth.Services;

/// <summary>本地 API 配置（api.json）</summary>
public class ApiConfig
{
    /// <summary>是否启用本地 API</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>监听端口（仅绑定 127.0.0.1）</summary>
    public int Port { get; set; } = 24721;

    /// <summary>访问令牌；为空表示不校验（本机回环）</summary>
    public string Token { get; set; } = "";
}

/// <summary>一条待触发/已创建的提醒</summary>
public class ScheduledReminder
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public string Title { get; set; } = "";
    public string Message { get; set; } = "";
    public DateTime CreatedAt { get; set; } = DateTime.Now;
    public DateTime DueAt { get; set; }
    public double DurationSeconds { get; set; } = 5;
    public bool Fired { get; set; }
}

/// <summary>
/// EasyAuth 本地 HTTP API：让外部程序（如 Tauri 应用）便捷获取课程信息并创建提醒。
/// 只绑定 127.0.0.1，不对外网开放。
/// </summary>
public class EasyAuthApiService : IHostedService, IDisposable
{
    private const string ConfigFileName = "api.json";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    private readonly List<ScheduledReminder> _reminders = new();
    private readonly object _reminderLock = new();
    private HttpListener? _listener;
    private CancellationTokenSource _cts = new();
    private Task? _listenTask;
    private Task? _timerTask;

    public ApiConfig Config { get; private set; } = new();

    /// <summary>监听地址，供日志与界面展示。</summary>
    public string BaseUrl => $"http://127.0.0.1:{Config.Port}";

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        LoadConfig();
        if (!Config.Enabled)
        {
            return;
        }
        try
        {
            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://127.0.0.1:{Config.Port}/");
            _listener.Start();
        }
        catch (Exception ex)
        {
            AuditLogService.Write(PluginPaths.PluginDirectory, "API-START-FAIL",
                detail: $"port={Config.Port} ex={ex.GetType().Name} {ex.Message}");
            return;
        }

        AuditLogService.Write(PluginPaths.PluginDirectory, "API-START", detail: $"url={BaseUrl}");
        _listenTask = Task.Run(ListenLoopAsync);
        _timerTask = Task.Run(ReminderTimerLoopAsync);
        await Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _cts.Cancel();
        try
        {
            _listener?.Stop();
        }
        catch
        {
            // 忽略
        }
        if (_listenTask != null)
        {
            await Task.WhenAny(_listenTask, Task.Delay(2000));
        }
        if (_timerTask != null)
        {
            await Task.WhenAny(_timerTask, Task.Delay(2000));
        }
        AuditLogService.Write(PluginPaths.PluginDirectory, "API-STOP");
    }

    private void LoadConfig()
    {
        try
        {
            var path = PluginPaths.Combine(ConfigFileName);
            if (File.Exists(path))
            {
                Config = JsonSerializer.Deserialize<ApiConfig>(File.ReadAllText(path)) ?? new ApiConfig();
            }
        }
        catch
        {
            Config = new ApiConfig();
        }
    }

    // ---------- 请求循环 ----------

    private async Task ListenLoopAsync()
    {
        while (!_cts.IsCancellationRequested && _listener is { IsListening: true })
        {
            HttpListenerContext ctx;
            try
            {
                ctx = await _listener.GetContextAsync();
            }
            catch
            {
                return;
            }
            _ = Task.Run(() => HandleRequestAsync(ctx));
        }
    }

    private async Task HandleRequestAsync(HttpListenerContext ctx)
    {
        var path = ctx.Request.Url?.AbsolutePath.TrimEnd('/').ToLowerInvariant() ?? "";
        try
        {
            if (!string.IsNullOrEmpty(Config.Token))
            {
                var auth = ctx.Request.Headers["Authorization"] ?? "";
                if (auth != $"Bearer {Config.Token}")
                {
                    await WriteJsonAsync(ctx, 401, new { error = "未授权" });
                    return;
                }
            }

            switch (ctx.Request.HttpMethod)
            {
                case "GET" when path is "" or "/api" or "/api/status":
                    await HandleStatusAsync(ctx);
                    break;
                case "GET" when path == "/api/next-class":
                    await HandleNextClassAsync(ctx);
                    break;
                case "GET" when path == "/api/class-plan":
                    await HandleClassPlanAsync(ctx);
                    break;
                case "POST" when path == "/api/reminder":
                    await HandleCreateReminderAsync(ctx);
                    break;
                case "GET" when path == "/api/reminders":
                    await HandleListRemindersAsync(ctx);
                    break;
                case "DELETE" when path.StartsWith("/api/reminder/"):
                    await HandleCancelReminderAsync(ctx, path["/api/reminder/".Length..]);
                    break;
                default:
                    await WriteJsonAsync(ctx, 404, new { error = "未知的接口" });
                    break;
            }
        }
        catch (Exception ex)
        {
            await WriteJsonAsync(ctx, 500, new { error = ex.Message });
        }
    }

    // ---------- 各接口 ----------

    /// <summary>
    /// 安全获取课程服务。宿主环境异常时返回 null 而不是把异常抛给调用方，
    /// 避免 API 直接吐「找不到程序集」之类的 500。
    /// </summary>
    private static ILessonsService? TryGetLessonsService()
    {
        try
        {
            return IAppHost.TryGetService<ILessonsService>();
        }
        catch
        {
            return null;
        }
    }

    /// <summary>安全获取档案服务（用于把 SubjectId 反查成科目）。</summary>
    private static IProfileService? TryGetProfileService()
    {
        try
        {
            return IAppHost.TryGetService<IProfileService>();
        }
        catch
        {
            return null;
        }
    }

    private static async Task HandleStatusAsync(HttpListenerContext ctx)
    {
        var lessons = TryGetLessonsService();
        await WriteJsonAsync(ctx, 200, new
        {
            plugin = "EasyAuth",
            version = "0.3.0",
            api = "local-http",
            classPlanLoaded = lessons?.IsClassPlanLoaded ?? false,
            timerRunning = lessons?.IsTimerRunning ?? false
        });
    }

    private static async Task HandleNextClassAsync(HttpListenerContext ctx)
    {
        var lessons = TryGetLessonsService();
        if (lessons == null)
        {
            await WriteJsonAsync(ctx, 503, new { error = "课程服务不可用" });
            return;
        }

        var nextSubject = lessons.NextClassSubject;
        var nextLayout = lessons.NextClassTimeLayoutItem;
        var currentSubject = lessons.CurrentSubject;
        var onClassLeft = lessons.OnClassLeftTime;
        var breakLeft = lessons.OnBreakingTimeLeftTime;
        var state = lessons.CurrentState;

        // 判断是否真有下一节
        var hasNext = !ReferenceEquals(nextSubject, Subject.Fallback)
                      && !ReferenceEquals(nextSubject, Subject.Empty)
                      && nextSubject != null;

        await WriteJsonAsync(ctx, 200, new
        {
            state = state.ToString(),
            isInClass = state == TimeState.OnClass,
            isBreaking = state == TimeState.Breaking,
            isAfterSchool = state == TimeState.AfterSchool,
            hasNextClass = hasNext,
            nextClass = hasNext
                ? new
                {
                    name = nextSubject!.Name,
                    initial = nextSubject.Initial,
                    teacher = nextSubject.TeacherName,
                    startTime = nextLayout.StartTime.ToString(@"hh\:mm\:ss"),
                    endTime = nextLayout.EndTime.ToString(@"hh\:mm\:ss"),
                    durationSeconds = nextLayout.Last.TotalSeconds
                }
                : null,
            currentClass = currentSubject != null
                ? new
                {
                    name = currentSubject.Name,
                    teacher = currentSubject.TeacherName,
                    startTime = lessons.CurrentTimeLayoutItem.StartTime.ToString(@"hh\:mm\:ss"),
                    endTime = lessons.CurrentTimeLayoutItem.EndTime.ToString(@"hh\:mm\:ss")
                }
                : null,
            secondsUntilNextClass = onClassLeft.TotalSeconds,
            secondsUntilBreak = breakLeft.TotalSeconds,
            timeUntilNextClass = FormatTimeSpan(onClassLeft),
            timeUntilBreak = FormatTimeSpan(breakLeft)
        });
    }

    private static async Task HandleClassPlanAsync(HttpListenerContext ctx)
    {
        var lessons = TryGetLessonsService();
        if (lessons == null)
        {
            await WriteJsonAsync(ctx, 503, new { error = "课程服务不可用" });
            return;
        }

        DateTime date = DateTime.Today;
        var q = ctx.Request.QueryString["date"];
        if (!string.IsNullOrEmpty(q) && DateTime.TryParse(q, out var parsed))
        {
            date = parsed.Date;
        }

        var plan = lessons.GetClassPlanByDate(date, out _);
        if (plan == null)
        {
            await WriteJsonAsync(ctx, 200, new { date = date.ToString("yyyy-MM-dd"), classes = Array.Empty<object>() });
            return;
        }

        // ClassInfo 只存 SubjectId，需要经档案的科目字典反查
        var subjects = TryGetProfileService()?.Profile.Subjects;

        var classes = new List<object>();
        foreach (var cls in plan.Classes)
        {
            var subject = cls.SubjectId != Guid.Empty && subjects != null &&
                          subjects.TryGetValue(cls.SubjectId, out var s)
                ? s
                : null;
            classes.Add(new
            {
                subject = subject?.Name ?? "",
                teacher = subject?.TeacherName ?? "",
                enabled = cls.IsEnabled
            });
        }

        var layout = plan.TimeLayout?.Layouts ?? Enumerable.Empty<TimeLayoutItem>();
        var timePoints = layout.Select(t => new
        {
            start = t.StartTime.ToString(@"hh\:mm\:ss"),
            end = t.EndTime.ToString(@"hh\:mm\:ss"),
            timeType = t.TimeType switch
            {
                0 => "class",
                1 => "break",
                2 => "divider",
                3 => "action",
                _ => "unknown"
            },
            breakName = t.BreakNameText
        }).ToArray();

        await WriteJsonAsync(ctx, 200, new
        {
            date = date.ToString("yyyy-MM-dd"),
            classes,
            timePoints
        });
    }

    private async Task HandleCreateReminderAsync(HttpListenerContext ctx)
    {
        using var reader = new StreamReader(ctx.Request.InputStream, Encoding.UTF8);
        var body = await reader.ReadToEndAsync();
        var req = JsonSerializer.Deserialize<ReminderRequest>(body, JsonOptions) ?? new ReminderRequest();

        if (string.IsNullOrWhiteSpace(req.Title) && string.IsNullOrWhiteSpace(req.Message))
        {
            await WriteJsonAsync(ctx, 400, new { error = "title 与 message 至少填一个" });
            return;
        }

        // 三种定时方式，按优先级：
        //   1) atTime   绝对时间（"HH:mm:ss" 或 ISO 8601），已过则算明天
        //   2) delaySeconds 相对延时秒数
        //   3) 都未提供  立即触发
        DateTime dueAt;
        string mode;
        if (!string.IsNullOrWhiteSpace(req.AtTime))
        {
            if (!TryParseAtTime(req.AtTime, out dueAt))
            {
                await WriteJsonAsync(ctx, 400,
                    new { error = "atTime 格式不正确，支持 \"HH:mm:ss\" 或 ISO 8601（如 2026-10-24T10:05:00）" });
                return;
            }
            mode = "atTime";
        }
        else
        {
            var delay = Math.Max(0, req.DelaySeconds ?? 0);
            dueAt = DateTime.Now.AddSeconds(delay);
            mode = delay > 0 ? "delay" : "immediate";
        }

        var reminder = new ScheduledReminder
        {
            Title = req.Title ?? "",
            Message = req.Message ?? "",
            DueAt = dueAt,
            DurationSeconds = req.DurationSeconds is > 0 and < 600 ? req.DurationSeconds.Value : 5
        };
        lock (_reminderLock)
        {
            _reminders.Add(reminder);
        }

        AuditLogService.Write(PluginPaths.PluginDirectory, "API-REMINDER",
            detail: $"id={reminder.Id} mode={mode} dueAt={reminder.DueAt:HH:mm:ss} title={reminder.Title}");

        // 立即触发的（无延时、时间已过）不等下一轮 tick，当场发掉。
        // 通知发送失败绝不能影响接口响应——这里必须兜住。
        if (mode == "immediate" || reminder.DueAt <= DateTime.Now)
        {
            lock (_reminderLock)
            {
                _reminders.Remove(reminder);
                reminder.Fired = true;
                _reminders.Add(reminder);
            }
            try
            {
                FireReminder(reminder);
            }
            catch (Exception ex)
            {
                AuditLogService.Write(PluginPaths.PluginDirectory, "API-REMINDER-FAIL",
                    detail: $"id={reminder.Id} ex={ex.GetType().Name} {ex.Message}");
            }
        }

        await WriteJsonAsync(ctx, 200, new
        {
            id = reminder.Id,
            mode,
            dueAt = reminder.DueAt,
            secondsLeft = Math.Max(0, (reminder.DueAt - DateTime.Now).TotalSeconds)
        });
    }

    /// <summary>
    /// 解析绝对时间。支持 "HH:mm:ss" / "HH:mm"（当天，已过则顺延到明天）
    /// 与 ISO 8601（如 2026-10-24T10:05:00）。
    /// </summary>
    private static bool TryParseAtTime(string input, out DateTime result)
    {
        result = default;
        var text = input.Trim();

        // ISO 8601
        if (DateTime.TryParse(text, out var iso))
        {
            result = iso;
            return true;
        }

        // 当天时刻 HH:mm[:ss]，已过则顺延明天
        if (TimeSpan.TryParse(text, out var timeOfDay))
        {
            var today = DateTime.Today + timeOfDay;
            result = today > DateTime.Now ? today : today.AddDays(1);
            return true;
        }

        return false;
    }

    private async Task HandleListRemindersAsync(HttpListenerContext ctx)
    {
        List<ScheduledReminder> snapshot;
        lock (_reminderLock)
        {
            snapshot = _reminders.ToList();
        }
        await WriteJsonAsync(ctx, 200, new
        {
            pending = snapshot.Where(r => !r.Fired).Select(r => new
            {
                id = r.Id,
                title = r.Title,
                message = r.Message,
                dueAt = r.DueAt,
                secondsLeft = Math.Max(0, (r.DueAt - DateTime.Now).TotalSeconds)
            }),
            fired = snapshot.Where(r => r.Fired).Select(r => new
            {
                id = r.Id,
                title = r.Title,
                firedAt = r.DueAt
            })
        });
    }

    private async Task HandleCancelReminderAsync(HttpListenerContext ctx, string id)
    {
        var removed = false;
        lock (_reminderLock)
        {
            var item = _reminders.FirstOrDefault(r =>
                string.Equals(r.Id, id, StringComparison.OrdinalIgnoreCase) && !r.Fired);
            if (item != null)
            {
                _reminders.Remove(item);
                removed = true;
            }
        }
        await WriteJsonAsync(ctx, removed ? 200 : 404, new { removed, id });
    }

    // ---------- 提醒调度 ----------

    private async Task ReminderTimerLoopAsync()
    {
        // 250ms 粒度：到点即触发，不再有最长 1 秒的等待
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(250));
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                await timer.WaitForNextTickAsync(_cts.Token);
            }
            catch
            {
                return;
            }

            List<ScheduledReminder> due;
            lock (_reminderLock)
            {
                due = _reminders.Where(r => !r.Fired && r.DueAt <= DateTime.Now).ToList();
            }

            foreach (var r in due)
            {
                r.Fired = true;
                FireReminder(r);
            }

            // 清理 24 小时前的已触发记录
            lock (_reminderLock)
            {
                _reminders.RemoveAll(r => r.Fired && r.DueAt < DateTime.Now.AddHours(-24));
            }
        }
    }

    private static void FireReminder(ScheduledReminder r)
    {
        try
        {
            var provider = EasyAuthNotificationProvider.Current;
            if (provider == null)
            {
                AuditLogService.Write(PluginPaths.PluginDirectory, "API-REMINDER-FAIL",
                    detail: $"id={r.Id} 提醒提供方未就绪");
                return;
            }

            var title = string.IsNullOrWhiteSpace(r.Title) ? "提醒" : r.Title;
            var body = string.IsNullOrWhiteSpace(r.Message)
                ? title
                : $"{title}：{r.Message}";

            var request = new ClassIsland.Core.Models.Notification.NotificationRequest
            {
                MaskContent = ClassIsland.Core.Models.Notification.NotificationContent
                    .CreateTwoIconsMask(body),
                OverlayContent = ClassIsland.Core.Models.Notification.NotificationContent
                    .CreateSimpleTextContent(body)
            };
            request.MaskContent.Duration = TimeSpan.FromSeconds(r.DurationSeconds);
            request.OverlayContent.Duration = TimeSpan.FromSeconds(r.DurationSeconds);
            provider.ShowNotification(request);

            AuditLogService.Write(PluginPaths.PluginDirectory, "API-REMINDER-OK",
                detail: $"id={r.Id} title={r.Title}");
        }
        catch (Exception ex)
        {
            AuditLogService.Write(PluginPaths.PluginDirectory, "API-REMINDER-FAIL",
                detail: $"id={r.Id} ex={ex.GetType().Name} {ex.Message}");
        }
    }

    // ---------- 工具 ----------

    private static string FormatTimeSpan(TimeSpan ts)
    {
        if (ts <= TimeSpan.Zero)
        {
            return "00:00:00";
        }
        return $"{(int)ts.TotalHours:D2}:{ts.Minutes:D2}:{ts.Seconds:D2}";
    }

    private static async Task WriteJsonAsync(HttpListenerContext ctx, int status, object body)
    {
        var json = JsonSerializer.Serialize(body, JsonOptions);
        var bytes = Encoding.UTF8.GetBytes(json);
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json; charset=utf-8";
        ctx.Response.ContentLength64 = bytes.Length;
        await ctx.Response.OutputStream.WriteAsync(bytes);
        ctx.Response.Close();
    }

    public void Dispose()
    {
        _cts.Dispose();
        _listener?.Close();
    }

    private class ReminderRequest
    {
        public string? Title { get; set; }
        public string? Message { get; set; }
        /// <summary>相对延时秒数。与 atTime 同时存在时 atTime 优先。</summary>
        public double? DelaySeconds { get; set; }
        /// <summary>绝对时间："HH:mm:ss"（当天，已过则顺延明天）或 ISO 8601。</summary>
        public string? AtTime { get; set; }
        public double? DurationSeconds { get; set; }
    }
}
