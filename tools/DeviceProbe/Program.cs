using System.Text;
using ClassIsland.EasyAuth.Services;

// M2 设备探测层自测：不依赖 ClassIsland，直接跑真实硬件查询
Console.OutputEncoding = Encoding.UTF8;

Console.WriteLine("== MachineGuid ==");
Console.WriteLine(DiskInfoService.GetMachineGuid() ?? "(读取失败)");

Console.WriteLine();
Console.WriteLine("== 卷列表（mountvol 解析 + IOCTL 映射）==");
var volumes = DiskInfoService.EnumerateVolumes();
foreach (var v in volumes)
{
    Console.WriteLine($"{v.DisplayName,-8} label={(v.VolumeLabel ?? "-"),-12} " +
                      $"guid={v.VolumeGuid} " +
                      $"SN={(v.DiskSerialNumber ?? "读取失败")} " +
                      $"model={(v.DiskModel ?? "-")} " +
                      $"info={v.InfoComplete}");
}
Console.WriteLine($"共 {volumes.Count} 个带盘符卷");

Console.WriteLine();
Console.WriteLine("== 诊断（C: 卷逐步探测）==");
var cVol = volumes.FirstOrDefault(v => v.DriveLetter == "C");
if (cVol != null)
{
    Console.WriteLine(DiskInfoService.DiagnoseVolume(cVol.VolumeGuid));
}

Console.WriteLine();
Console.WriteLine("== 加密自测 ==");
var salt = CryptoService.GenerateSalt();
var key = CryptoService.DeriveKey("test-password", salt);
var (cipher, nonce, tag) = CryptoService.AesGcmEncrypt(Encoding.UTF8.GetBytes("hello easyauth"), key);
var plain = CryptoService.AesGcmDecrypt(cipher, nonce, tag, key);
Console.WriteLine(plain == null ? "AES-GCM: FAIL" : "AES-GCM: " + Encoding.UTF8.GetString(plain));
var tampered = CryptoService.AesGcmDecrypt(cipher, nonce, tag, CryptoService.DeriveKey("wrong", salt));
Console.WriteLine("错密钥拒绝: " + (tampered == null ? "PASS" : "FAIL"));
Console.WriteLine("Sha256Hex(abc): " + CryptoService.Sha256Hex("abc"));
