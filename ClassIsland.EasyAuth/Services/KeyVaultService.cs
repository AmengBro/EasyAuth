using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ClassIsland.EasyAuth.Models;

namespace ClassIsland.EasyAuth.Services;

/// <summary>密钥文件读取状态（用于给界面精确的失败原因）</summary>
public enum KeyVaultReadStatus
{
    Ok,
    NotFound,
    UserMismatch,
    Corrupt
}

/// <summary>
/// U 盘密钥库（.EasyAuth\key.bin）读写服务。
/// 容器格式：
///   v1: magic "EAKV1"(5B) | salt(16B) | nonce(12B) | tag(16B) | cipher(AES-256-GCM(payload JSON))
///   v2: magic "EAKV2"(5B) | DPAPI(CurrentUser) 包裹的 v1 容器 —— 额外绑定 Windows 账户
/// 内层密钥 = PBKDF2-SHA256("{machineGuid}|{diskSerial}", salt)，与机器和磁盘双绑定；
/// 外层 v2 再用当前 Windows 账户加密，形成 账户 + 机器 + 磁盘 三重绑定。
/// </summary>
public static class KeyVaultService
{
    public const string KeyVaultDirName = ".EasyAuth";
    public const string KeyVaultFileName = "key.bin";

    private static readonly byte[] MagicV1 = "EAKV1"u8.ToArray();
    private static readonly byte[] MagicV2 = "EAKV2"u8.ToArray();

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

    /// <summary>密钥文件是否为 v2（启用 Windows 账户绑定）。</summary>
    public static bool IsUserBound(string volumeRoot)
    {
        try
        {
            var bytes = File.ReadAllBytes(GetKeyVaultPath(volumeRoot));
            return bytes.Length >= 5 && bytes.AsSpan(0, 5).SequenceEqual(MagicV2);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 配对：创建密钥目录（隐藏+系统属性）并写入加密密钥库。
    /// userBound=true 时额外用当前 Windows 账户包裹（启用该层后需重新配对）。
    /// </summary>
    public static bool CreateKeyVault(string volumeRoot, KeyVaultPayload payload, string machineGuid,
        string diskSerial, bool userBound = false)
    {
        try
        {
            var dir = GetKeyVaultDir(volumeRoot);
            Directory.CreateDirectory(dir);
            // 按用户要求：点开头文件夹 + system 属性，资源管理器里不可见
            new DirectoryInfo(dir).Attributes = FileAttributes.Hidden | FileAttributes.System;

            var salt = CryptoService.GenerateSalt();
            var key = CryptoService.DeriveKey($"{machineGuid}|{diskSerial}", salt);
            var plain = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload));
            var (cipher, nonce, tag) = CryptoService.AesGcmEncrypt(plain, key);

            using var inner = new MemoryStream();
            inner.Write(MagicV1);
            inner.Write(salt);
            inner.Write(nonce);
            inner.Write(tag);
            inner.Write(cipher);
            var innerBytes = inner.ToArray();

            var outBytes = userBound
                ? Combine(MagicV2, ProtectedData.Protect(innerBytes, null, DataProtectionScope.CurrentUser))
                : innerBytes;

            File.WriteAllBytes(GetKeyVaultPath(volumeRoot), outBytes);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 读取并解密密钥库。失败返回 null，并通过 status 区分原因：
    /// NotFound=没有密钥文件 / UserMismatch=Windows 账户不匹配 / Corrupt=损坏或非本机本盘。
    /// </summary>
    public static KeyVaultPayload? ReadKeyVault(string volumeRoot, string machineGuid, string diskSerial,
        out KeyVaultReadStatus status, out bool userBound)
    {
        status = KeyVaultReadStatus.Corrupt;
        userBound = false;
        try
        {
            var path = GetKeyVaultPath(volumeRoot);
            if (!File.Exists(path))
            {
                status = KeyVaultReadStatus.NotFound;
                return null;
            }

            var bytes = File.ReadAllBytes(path);
            if (bytes.Length < 5)
            {
                return null;
            }

            byte[] inner;
            if (bytes.AsSpan(0, 5).SequenceEqual(MagicV2))
            {
                userBound = true;
                try
                {
                    inner = ProtectedData.Unprotect(bytes[5..], null, DataProtectionScope.CurrentUser);
                }
                catch (CryptographicException)
                {
                    status = KeyVaultReadStatus.UserMismatch;
                    return null;
                }
            }
            else if (bytes.AsSpan(0, 5).SequenceEqual(MagicV1))
            {
                inner = bytes;
            }
            else
            {
                return null;
            }

            var headerLen = MagicV1.Length + 16 + 12 + 16;
            if (inner.Length < headerLen || !inner.AsSpan(0, MagicV1.Length).SequenceEqual(MagicV1))
            {
                return null;
            }

            var salt = inner.AsSpan(MagicV1.Length, 16).ToArray();
            var nonce = inner.AsSpan(MagicV1.Length + 16, 12).ToArray();
            var tag = inner.AsSpan(MagicV1.Length + 28, 16).ToArray();
            var cipher = inner.AsSpan(headerLen).ToArray();

            var key = CryptoService.DeriveKey($"{machineGuid}|{diskSerial}", salt);
            var plain = CryptoService.AesGcmDecrypt(cipher, nonce, tag, key);
            if (plain == null)
            {
                return null;
            }

            var payload = JsonSerializer.Deserialize<KeyVaultPayload>(Encoding.UTF8.GetString(plain));
            if (payload == null)
            {
                return null;
            }
            status = KeyVaultReadStatus.Ok;
            return payload;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// 克隆计数回写：用新计数重新加密覆盖密钥库（保持原有账户绑定层）。
    /// </summary>
    public static bool RewriteCounter(string volumeRoot, KeyVaultPayload payload, int newCounter,
        string machineGuid, string diskSerial, bool userBound = false)
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
        return CreateKeyVault(volumeRoot, updated, machineGuid, diskSerial, userBound);
    }

    private static byte[] Combine(byte[] head, byte[] tail)
    {
        var result = new byte[head.Length + tail.Length];
        head.CopyTo(result, 0);
        tail.CopyTo(result, head.Length);
        return result;
    }
}