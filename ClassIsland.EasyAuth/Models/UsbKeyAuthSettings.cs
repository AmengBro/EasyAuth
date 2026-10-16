namespace ClassIsland.EasyAuth.Models;

/// <summary>
/// U盘密钥认证提供方的设置，随凭据一起以 JSON 序列化进 Credentials.json。
/// </summary>
public class UsbKeyAuthSettings
{
    /// <summary>配对时记录的磁盘硬件序列号（WMI Win32_DiskDrive.SerialNumber）</summary>
    public string PairedDiskSerial { get; set; } = "";

    /// <summary>配对时记录的 key.bin 所在卷 GUID（\\?\Volume{...}\）</summary>
    public string PairedVolumeGuid { get; set; } = "";

    /// <summary>配对 token 的 SHA-256（hex），不明文存储 token 本身</summary>
    public string TokenHash { get; set; } = "";

    /// <summary>克隆计数：须与 U 盘 key.bin 内的计数相等才放行</summary>
    public int Counter { get; set; }

    /// <summary>配对时记录的磁盘型号（仅作界面提示，不参与判定）</summary>
    public string BrandHint { get; set; } = "";
}
