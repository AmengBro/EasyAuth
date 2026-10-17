namespace ClassIsland.EasyAuth.Models;

/// <summary>
/// U盘密钥认证提供方的设置，随凭据一起以 JSON 序列化进 Credentials.json。
/// </summary>
public class UsbKeyAuthSettings
{
    /// <summary>配对时记录的磁盘硬件序列号（P/Invoke IOCTL 读取）</summary>
    public string PairedDiskSerial { get; set; } = "";

    /// <summary>配对时记录的 key.bin 所在卷 GUID（\\?\Volume{...}\）</summary>
    public string PairedVolumeGuid { get; set; } = "";

    /// <summary>配对 token 的 SHA-256（hex），不明文存储 token 本身</summary>
    public string TokenHash { get; set; } = "";

    /// <summary>克隆计数：须与 U 盘 key.bin 内的计数相等才放行</summary>
    public int Counter { get; set; }

    /// <summary>配对时记录的磁盘型号（仅作界面提示，不参与判定）</summary>
    public string BrandHint { get; set; } = "";

    // ---- 分层开关（复选框）----

    /// <summary>启用磁盘 SN 绑定</summary>
    public bool EnableSnBinding { get; set; } = true;

    /// <summary>启用卷 GUID 绑定（防同盘异分区克隆）</summary>
    public bool EnableVolumeGuidBinding { get; set; } = true;

    /// <summary>启用 token 校验</summary>
    public bool EnableTokenCheck { get; set; } = true;

    /// <summary>启用克隆计数</summary>
    public bool EnableCloneCounter { get; set; } = true;

    /// <summary>启用品牌提示（仅提示，不参与判定）</summary>
    public bool EnableBrandHint { get; set; } = true;

    /// <summary>
    /// 启用 Windows 账户绑定（DPAPI CurrentUser 包裹密钥文件）。
    /// 仅当教师使用独占 Windows 账户时才有增益；共享账户下相当于无额外保护。
    /// 启用后需重新配对（密钥文件从 v1 升级为 v2 容器）。
    /// </summary>
    public bool EnableUserBinding { get; set; }

    /// <summary>是否至少启用了一种硬绑定（SN/卷GUID/token 至少其一）</summary>
    public bool HasAnyHardBinding => EnableSnBinding || EnableVolumeGuidBinding || EnableTokenCheck;
}
