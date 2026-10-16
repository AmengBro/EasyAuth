using Avalonia;
using Avalonia.Controls;
using ClassIsland.Core.Abstractions.Controls;
using ClassIsland.Core.Attributes;
using ClassIsland.EasyAuth.Models;

namespace ClassIsland.EasyAuth;

/// <summary>
/// U盘密钥认证提供方（M1 占位）。
/// M2 落地配对层（卷枚举 + SN/卷GUID + key.bin 加解密），M3 落地四层校验。
/// </summary>
[AuthorizeProviderInfo("easyauth.usbkey", "U盘密钥", "\ue72e")]
public class UsbKeyAuthorizeProvider : AuthorizeProviderControlBase<UsbKeyAuthSettings>
{
    public UsbKeyAuthorizeProvider()
    {
        Content = new StackPanel
        {
            Margin = new Thickness(8),
            Children =
            {
                new TextBlock { Text = "EasyAuth · U盘密钥" },
                new TextBlock { Text = "M1 占位：配对与认证逻辑即将落地" }
            }
        };
    }

    public override bool ValidateAuthorizeSettings()
    {
        // 配对完成后 PairedDiskSerial 非空即视为设置有效
        return !string.IsNullOrWhiteSpace(Settings.PairedDiskSerial);
    }
}
