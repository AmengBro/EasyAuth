using System.Security.Cryptography;
using System.Text;

namespace ClassIsland.EasyAuth.Services;

/// <summary>
/// 加密工具：AES-256-GCM + PBKDF2 + SHA-256。
/// </summary>
public static class CryptoService
{
    private const int KeySizeBytes = 32;
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;

    /// <summary>PBKDF2-SHA256 派生密钥。</summary>
    public static byte[] DeriveKey(string password, byte[] salt, int iterations = 100_000)
    {
        return Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, KeySizeBytes);
    }

    /// <summary>生成随机盐。</summary>
    public static byte[] GenerateSalt(int size = 16)
    {
        return RandomNumberGenerator.GetBytes(size);
    }

    /// <summary>SHA-256 十六进制串（小写）。</summary>
    public static string Sha256Hex(string text)
    {
        return ToHexLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
    }

    /// <summary>SHA-256 十六进制串（小写，字节输入）。</summary>
    public static string Sha256Hex(byte[] data)
    {
        return ToHexLower(SHA256.HashData(data));
    }

    private static string ToHexLower(byte[] bytes)
    {
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    /// <summary>AES-GCM 加密，返回 (密文, nonce, tag)。</summary>
    public static (byte[] Cipher, byte[] Nonce, byte[] Tag) AesGcmEncrypt(byte[] plaintext, byte[] key, byte[]? associatedData = null)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        var cipher = new byte[plaintext.Length];
        var tag = new byte[TagSizeBytes];
        using var aes = new AesGcm(key, TagSizeBytes);
        aes.Encrypt(nonce, plaintext, cipher, tag, associatedData);
        return (cipher, nonce, tag);
    }

    /// <summary>AES-GCM 解密，认证失败返回 null。</summary>
    public static byte[]? AesGcmDecrypt(byte[] cipher, byte[] nonce, byte[] tag, byte[] key, byte[]? associatedData = null)
    {
        try
        {
            var plaintext = new byte[cipher.Length];
            using var aes = new AesGcm(key, TagSizeBytes);
            aes.Decrypt(nonce, cipher, tag, plaintext, associatedData);
            return plaintext;
        }
        catch (AuthenticationTagMismatchException)
        {
            return null;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }
}
