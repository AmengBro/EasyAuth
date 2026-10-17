using System.Text.Json.Serialization;

namespace ClassIsland.EasyAuth.Models;

/// <summary>
/// U 盘密钥文件（.EasyAuth\key.bin）解密后的内容。
/// 整体经 AES-256-GCM 加密，密钥派生自「机器GUID + 磁盘SN」，
/// 因此拷到别的机器或别的盘上都无法解密。
/// </summary>
public class KeyVaultPayload
{
    /// <summary>配对时生成的随机 token（明文只存在于加密 blob 内）</summary>
    public string Token { get; set; } = "";

    /// <summary>克隆计数：每次成功认证 +1，须与本地存活计数相等</summary>
    public int Counter { get; set; }

    /// <summary>配对时的磁盘 SN（与本地设置交叉核对）</summary>
    public string PairedDiskSerial { get; set; } = "";

    /// <summary>配对时的卷 GUID（与本地设置交叉核对）</summary>
    public string PairedVolumeGuid { get; set; } = "";

    /// <summary>配对时的磁盘型号（提示用）</summary>
    public string BrandHint { get; set; } = "";

    /// <summary>配对时间（ISO 8601）</summary>
    public string CreatedAt { get; set; } = "";

    /// <summary>密钥库格式版本</summary>
    [JsonIgnore]
    public const int FormatVersion = 1;
}
