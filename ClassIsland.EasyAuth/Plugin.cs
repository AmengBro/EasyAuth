using ClassIsland.Core.Abstractions;
using ClassIsland.Core.Attributes;
using ClassIsland.Core.Extensions.Registry;
using ClassIsland.EasyAuth.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace ClassIsland.EasyAuth;

[PluginEntrance]
public class Plugin : PluginBase
{
    public override void Initialize(HostBuilderContext context, IServiceCollection services)
    {
        // ClassIsland 的 PluginService 在调用 Initialize 之前就已经把
        // PluginConfigFolder 设为 {AppConfig}\Plugins\<id> 并建好目录。
        // 插件自己的配置/日志一律写那里，不写 DLL 所在的安装目录。
        PluginPaths.Configure(PluginConfigFolder);
        PluginPaths.EnsureDataDirectory();

        // 升级兼容：把旧版写在安装目录的 state.json / api.json 复制过来（不删除原件）
        var migrated = PluginPaths.MigrateLegacyFiles();
        if (migrated.Count > 0)
        {
            ServiceLogService.Write(PluginPaths.PluginDirectory, "DATA-MIGRATE",
                detail: $"from={PluginPaths.InstallDirectory} files={string.Join(",", migrated)}");
        }

        services.AddAuthorizeProvider<UsbKeyAuthorizeProvider>();
        // 提醒渠道：本地 API 创建提醒时使用
        services.AddNotificationProvider<EasyAuthNotificationProvider>();
        // 本地 HTTP API：供 Tauri 等外部程序查询课程与创建提醒
        services.AddHostedService<EasyAuthApiService>();
    }
}
