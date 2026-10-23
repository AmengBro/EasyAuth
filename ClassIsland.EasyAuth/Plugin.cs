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
        services.AddAuthorizeProvider<UsbKeyAuthorizeProvider>();
        // 提醒渠道：本地 API 创建提醒时使用
        services.AddNotificationProvider<EasyAuthNotificationProvider>();
        // 本地 HTTP API：供 Tauri 等外部程序查询课程与创建提醒
        services.AddHostedService<EasyAuthApiService>();
    }
}
