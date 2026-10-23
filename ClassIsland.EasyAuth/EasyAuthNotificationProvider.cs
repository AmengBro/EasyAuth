using ClassIsland.Core.Abstractions.Services.NotificationProviders;
using ClassIsland.Core.Attributes;

namespace ClassIsland.EasyAuth;

/// <summary>
/// EasyAuth 自己的提醒渠道。
/// 插件要发提醒必须经过一个已注册的提醒提供方（<see cref="INotificationHostService"/>
/// 的 ShowNotification 是 internal，只能由提供方代为调用），
/// 因此注册一个专用渠道，供本地 HTTP API 创建提醒时使用。
/// </summary>
[NotificationProviderInfo("6b2f1a4c-8d3e-4f5a-9c7b-0e1d2a3b4c5d",
    "EasyAuth", "\ue7c7",
    "由 EasyAuth 本地 API 创建的提醒（供 Tauri 等外部程序调用）")]
public class EasyAuthNotificationProvider : NotificationProviderBase
{
    /// <summary>当前实例，供 API 服务发送提醒。</summary>
    public static EasyAuthNotificationProvider? Current { get; private set; }

    public EasyAuthNotificationProvider()
    {
        Current = this;
    }
}
