using ClassIsland.EasyAuth.Services;
using Microsoft.Extensions.Hosting;

namespace ClassIsland.EasyAuth;

/// <summary>
/// 启动后的安全自检：宿主启动完成时异步跑一次完整性检测。
///
/// 本服务**只观测**：读 Credentials.json 算哈希、写插件自己的 service.log / security.json，
/// 绝不重启 ClassIsland、绝不改凭据文件、绝不自动回滚。
///
/// 恢复码通道（本版未接线）将来若接入，请把校验逻辑挂到 RecoveryProbe 上：
/// 它会在完整性检测之前执行，校验通过才允许调用 GuardState.Suppress + Rebaseline，
/// 这样「恢复动作」与「篡改检测」在同一轮启动里天然互斥，不会互相打架。
/// 严禁裸写「recovery.txt 存在就跳过检测」——见 GuardState.RecoveryGate。
/// </summary>
public class SecurityStartupService : IHostedService
{
    /// <summary>
    /// 恢复码通道钩子。返回 true 表示本轮已由恢复通道接管（检测应跳过）。
    /// 本版恒为 null，仅作为顺序保证的扩展点。
    /// </summary>
    public static Func<string, bool>? RecoveryProbe { get; set; }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        // 不阻塞宿主启动：文件很小，但仍放到后台线程，避免卡住 UI 初始化。
        _ = Task.Run(() =>
        {
            try
            {
                var dir = PluginPaths.PluginDirectory;
                PluginPaths.EnsureDataDirectory();

                var handledByRecovery = false;
                try
                {
                    var probe = RecoveryProbe;
                    if (probe != null) handledByRecovery = probe(dir);
                }
                catch (Exception ex)
                {
                    ServiceLogService.Write(dir, "SECURITY-RECOVERY-ERROR",
                        detail: $"ex={ex.GetType().Name}（恢复通道异常，按未接管处理，继续检测）");
                }

                if (handledByRecovery)
                {
                    ServiceLogService.Write(dir, "SECURITY-START",
                        detail: "skipped=recovery-channel 完整性检测本轮被恢复码通道抑制");
                    return;
                }

                var result = IntegrityMonitor.Check(dir);
                var cfg = SecurityConfigStore.Load(dir);
                ServiceLogService.Write(dir, "SECURITY-START",
                    detail: $"outcome={result.Outcome} tamper={cfg.EnableTamperDetection} " +
                            $"tempPassword={cfg.EnableTempPassword} " +
                            $"silentRestart={cfg.EnableSilentRestart}(未接线) " +
                            $"autoRestore={cfg.EnableAutoRestore}(未接线) " +
                            $"recoveryCode={cfg.EnableRecoveryCode}(未接线) " +
                            $"pendingDiff={result.HasPendingDifference}");
            }
            catch (Exception ex)
            {
                // 自检失败绝不能影响 ClassIsland 启动
                try
                {
                    ServiceLogService.Write(PluginPaths.PluginDirectory, "SECURITY-START-ERROR",
                        detail: $"ex={ex.GetType().Name}");
                }
                catch
                {
                    // ignored
                }
            }
        }, cancellationToken);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
