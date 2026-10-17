using System.IO;
using System.Text;
using System.Text.Json;
using ClassIsland.EasyAuth.Models;

namespace ClassIsland.EasyAuth.Services;

/// <summary>
/// U 盘密钥库（.EasyAuth\key.bin）读写服务。
/// 文件容器格式（v1）：
///   magic "EAKV1" (5B) | salt (16B) | nonce (12B) | tag (16B) | cipher (AES-256-GCM(payload JSON))
/// 密钥 = PBKDF2-SHA256("{machineGuid}|{diskSerial}", salt)，与机器和磁盘双绑定。
/// </summary>
public static class KeyVaultService
{
    public const string KeyVaultDirName = ".EasyAuth";
    public const string KeyVaultFileName = "key.bin";

    private static readonly byte[] Magic = "EAKV1"u8.ToArray();

    /// <summary>密钥目录：&lt;卷根&gt;\.EasyAuth</summary>
    public static string GetKeyVaultDir(string volumeRoot)
    {
        return Path.Combine(volumeRoot, KeyVaultDirName);
    }

    /// <summary>密钥文件：&lt;卷根&gt;\.EasyAuth\key.bin</summary>
    public static string GetKeyVaultPath(string volumeRoot)
    {
        return Path.Combine(GetKeyVaultDir(volumeRoot), KeyVaultFileName);
    }

    /// <summary>密钥文件是否存在。</summary>
    public static bool KeyVaultExists(string volumeRoot)
    {
        return File.Exists(GetKeyVaultPath(volumeRoot));
    }

    /// <summary>
    /// 配对：创建密钥目录（隐藏+系统属性）并写入加密密钥库。
    /// 返回是否成功；已存在旧文件时覆盖（重新配对）。
    /// </summary>
    public static bool CreateKeyVault(string volumeRoot, KeyVaultPayload payload, string machineGuid, string diskSerial)
    {
        try
        {
            var dir = GetKeyVaultDir(volumeRoot);
            Directory.CreateDirectory(dir);
            // 按用户要求：点开头文件夹 + system 属性，资源管理器里不可见
            new DirectoryInfo(dir).Attributes = FileAttributes.Hidden | FileAttributes.System;

            var salt = CryptoService.GenerateSalt();
            var key = CryptoService.DeriveKey($"{machineGuid}|{diskSerial}", salt);
            var json = JsonSerializer.Serialize(payload);
            var plain = Encoding.UTF8.GetBytes(json);
            var (cipher, nonce, tag) = CryptoService.AesGcmEncrypt(plain, key);

            using var ms = new MemoryStream();
            ms.Write(Magic);
            ms.Write(salt);
            ms.Write(nonce);
            ms.Write(tag);
            ms.Write(cipher);
            File.WriteAllBytes(GetKeyVaultPath(volumeRoot), ms.ToArray());
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 读取并解密密钥库。任何一步失败（不存在/格式错/密钥不符/被篡改）返回 null。
    /// </summary>
    public static KeyVaultPayload? ReadKeyVault(string volumeRoot, string machineGuid, string diskSerial)
    {
        try
        {
            var path = GetKeyVaultPath(volumeRoot);
            if (!File.Exists(path))
            {
                return null;
            }

            var bytes = File.ReadAllBytes(path);
            var headerLen = Magic.Length + 16 + 12 + 16;
            if (bytes.Length < headerLen || !bytes.AsSpan(0, Magic.Length).SequenceEqual(Magic))
            {
                return null;
            }

            var salt = bytes.AsSpan(Magic.Length, 16).ToArray();
            var nonce = bytes.AsSpan(Magic.Length + 16, 12).ToArray();
            var tag = bytes.AsSpan(Magic.Length + 28, 16).ToArray();
            var cipher = bytes.AsSpan(headerLen).ToArray();

            var key = CryptoService.DeriveKey($"{machineGuid}|{diskSerial}", salt);
            var plain = CryptoService.AesGcmDecrypt(cipher, nonce, tag, key);
            if (plain == null)
            {
                return null;
            }

            return JsonSerializer.Deserialize<KeyVaultPayload>(Encoding.UTF8.GetString(plain));
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// 克隆计数回写：用新计数重新加密覆盖密钥库。
    /// </summary>
    public static bool RewriteCounter(string volumeRoot, KeyVaultPayload payload, int newCounter,
        string machineGuid, string diskSerial)
    {
        var updated = new KeyVaultPayload
        {
            Token = payload.Token,
            Counter = newCounter,
            PairedDiskSerial = payload.PairedDiskSerial,
            PairedVolumeGuid = payload.PairedVolumeGuid,
            BrandHint = payload.BrandHint,
            CreatedAt = payload.CreatedAt
        };
        return CreateKeyVault(volumeRoot, updated, machineGuid, diskSerial);
    }
}
