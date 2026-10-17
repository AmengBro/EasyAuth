using System.Text;
using ClassIsland.EasyAuth.Models;
using ClassIsland.EasyAuth.Services;

// ============ M2 设备探测层自测：不依赖 ClassIsland，直接跑真实硬件查询 ============
Console.OutputEncoding = Encoding.UTF8;

Console.WriteLine("== MachineGuid ==");
Console.WriteLine(DiskInfoService.GetMachineGuid() ?? "(读取失败)");

Console.WriteLine();
Console.WriteLine("== 卷列表（mountvol 解析 + WMI 两跳关联）==");
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

// ============ M3 认证逻辑端到端测试：Temp 目录仿真卷，不触碰真实 U 盘 ============
Console.WriteLine();
Console.WriteLine("== 认证逻辑端到端测试（仿真卷） ==");

var testRoot = Path.Combine(Path.GetTempPath(), "easyauth-kv-test");
if (Directory.Exists(testRoot))
{
    Directory.Delete(testRoot, true);
}
var volA = Path.Combine(testRoot, "VolA");
var volB = Path.Combine(testRoot, "VolB");
Directory.CreateDirectory(volA);
Directory.CreateDirectory(volB);

const string testMachineGuid = "TEST-MACHINE-GUID-0001";
const string serialA = "TEST_SERIAL_A";
const string serialB = "TEST_SERIAL_B";

var settings = new UsbKeyAuthSettings();
var volInfoA = new VolumeInfo
{
    VolumeGuid = volA,
    DiskSerialNumber = serialA,
    DiskModel = "WD My Passport 264F (仿真)",
    DriveLetter = "Z"
};
var volInfoB = new VolumeInfo
{
    VolumeGuid = volB,
    DiskSerialNumber = serialB,
    DiskModel = "其他盘 (仿真)",
    DriveLetter = "Y"
};

var pass = 0;
var fail = 0;
void Case(string name, bool ok, string detail = "")
{
    if (ok)
    {
        pass++;
    }
    else
    {
        fail++;
    }
    Console.WriteLine($"  [{(ok ? "PASS" : "FAIL")}] {name}{(detail.Length > 0 ? " | " + detail : "")}");
}

async Task CaseAsync(string name, UsbKeyAuthSettings s, VolumeInfo vol, string? machine, int? expectedCounter, string expectStep)
{
    var r = await AuthVerifier.VerifyAsync(s, vol, machine, expectedCounter);
    var ok = r.Success ? expectStep == "OK" : string.Equals(r.FailedStep, expectStep, StringComparison.Ordinal);
    var detail = r.Success ? $"新计数={r.NewCounter}" : $"失败步骤={r.FailedStep} 原因={r.FailureReason}";
    Case(name, ok, detail);
}

// 1) 配对
var pairOk = AuthVerifier.Pair(settings, volInfoA, testMachineGuid, out var pairErr);
Case("配对（写入 key.bin）", pairOk, pairErr ?? "");
if (!pairOk)
{
    Console.WriteLine("配对失败，后续用例跳过");
    return;
}
var kvDir = KeyVaultService.GetKeyVaultDir(volA);
var kvAttrs = File.GetAttributes(kvDir);
Case("密钥目录为 Hidden|System", File.Exists(KeyVaultService.GetKeyVaultPath(volA))
    && (kvAttrs & FileAttributes.Hidden) == FileAttributes.Hidden
    && (kvAttrs & FileAttributes.System) == FileAttributes.System, $"attrs={kvAttrs}");
Case("设置回填（SN/卷GUID/token哈希）",
    settings.PairedDiskSerial == serialA && settings.PairedVolumeGuid == volA
    && settings.TokenHash.Length == 64 && settings.Counter == 0);

// 快照 key.bin（用于模拟过期克隆盘）
var snapshot = File.ReadAllBytes(KeyVaultService.GetKeyVaultPath(volA));

// 2) 正常认证
var r1 = await AuthVerifier.VerifyAsync(settings, volInfoA, testMachineGuid, 0);
Case("首次认证通过", r1.Success && !r1.CounterWriteBackWarning && r1.NewCounter == 1,
    $"success={r1.Success} warn={r1.CounterWriteBackWarning} new={r1.NewCounter}");
var payloadAfter = KeyVaultService.ReadKeyVault(volA, testMachineGuid, serialA);
Case("计数已回写密钥库", payloadAfter?.Counter == 1, $"payload.Counter={payloadAfter?.Counter}");

// 3) 再次认证（计数推进）
await CaseAsync("再次认证通过（计数推进）", settings, volInfoA, testMachineGuid, 1, "OK");

// 4) 过期克隆盘模拟：把 key.bin 回滚到 counter=0，本机期望计数=2
File.WriteAllBytes(KeyVaultService.GetKeyVaultPath(volA), snapshot);
await CaseAsync("过期克隆盘（计数回滚）被拒", settings, volInfoA, testMachineGuid, 2, "校验克隆计数");

// 5) 异盘克隆：把 .EasyAuth 拷到 VolB（不同 SN）→ 解密应失败
CopyDirectory(Path.Combine(volA, KeyVaultService.KeyVaultDirName), Path.Combine(volB, KeyVaultService.KeyVaultDirName));
await CaseAsync("异盘克隆（换 SN）解密失败", settings, volInfoB, testMachineGuid, 0, "读取并解密密钥文件");

// 6) 异机克隆：同一份 key.bin 换 MachineGuid → 解密失败
await CaseAsync("异机克隆（换机器标识）解密失败", settings, volInfoA, "OTHER-MACHINE-GUID", 0, "读取并解密密钥文件");

// 7) token 被篡改
var settingsBadToken = CloneSettings(settings);
settingsBadToken.TokenHash = new string('d', 64);
File.WriteAllBytes(KeyVaultService.GetKeyVaultPath(volA), snapshot);
await CaseAsync("token 被篡改被拒", settingsBadToken, volInfoA, testMachineGuid, 0, "校验 token");

// 8) SN 不匹配
var settingsBadSn = CloneSettings(settings);
settingsBadSn.PairedDiskSerial = "SOME_OTHER_SERIAL";
await CaseAsync("磁盘 SN 不匹配被拒", settingsBadSn, volInfoA, testMachineGuid, 0, "校验磁盘序列号");

// 9) 同盘另一分区：把 key 文件夹拷到同一块盘的另一个分区（SN 相同，唯一防线是卷标识层）
var otherPartitionPath = Path.Combine(testRoot, "VolA2");
Directory.CreateDirectory(otherPartitionPath);
CopyDirectory(Path.Combine(volA, KeyVaultService.KeyVaultDirName),
    Path.Combine(otherPartitionPath, KeyVaultService.KeyVaultDirName));
var volInfoOtherPartition = new VolumeInfo
{
    VolumeGuid = otherPartitionPath,
    DiskSerialNumber = serialA,
    DiskModel = "同盘另一分区",
    DriveLetter = "W"
};
await CaseAsync("同盘另一分区被卷标识层拒绝", settings, volInfoOtherPartition, testMachineGuid, 0, "校验卷标识");

// 10) 缺少 MachineGuid
await CaseAsync("读不到本机标识被拒", settings, volInfoA, null, 0, "读取并解密密钥文件");

// 11) 分层开关：仅计数层可用 → 正常放行
File.WriteAllBytes(KeyVaultService.GetKeyVaultPath(volA), snapshot);
var settingsCounterOnly = CloneSettings(settings);
settingsCounterOnly.EnableSnBinding = false;
settingsCounterOnly.EnableVolumeGuidBinding = false;
settingsCounterOnly.EnableTokenCheck = false;
await CaseAsync("仅启用计数层时正常放行", settingsCounterOnly, volInfoA, testMachineGuid, 0, "OK");

// 12) 全关硬绑定时配对应被护栏拦截
var settingsNoHard = CloneSettings(settings);
settingsNoHard.EnableSnBinding = false;
settingsNoHard.EnableVolumeGuidBinding = false;
settingsNoHard.EnableTokenCheck = false;
var volC = Path.Combine(testRoot, "VolC");
Directory.CreateDirectory(volC);
var volInfoC = new VolumeInfo { VolumeGuid = volC, DiskSerialNumber = serialA };
var guardOk = !AuthVerifier.Pair(settingsNoHard, volInfoC, testMachineGuid, out var guardErr);
Case("全关硬绑定时配对被护栏拦截", guardOk, guardErr ?? "");

Console.WriteLine();
Console.WriteLine($"用例结果：{pass} 通过 / {fail} 失败");

static UsbKeyAuthSettings CloneSettings(UsbKeyAuthSettings s)
{
    return new UsbKeyAuthSettings
    {
        PairedDiskSerial = s.PairedDiskSerial,
        PairedVolumeGuid = s.PairedVolumeGuid,
        TokenHash = s.TokenHash,
        Counter = s.Counter,
        BrandHint = s.BrandHint,
        EnableSnBinding = s.EnableSnBinding,
        EnableVolumeGuidBinding = s.EnableVolumeGuidBinding,
        EnableTokenCheck = s.EnableTokenCheck,
        EnableCloneCounter = s.EnableCloneCounter,
        EnableBrandHint = s.EnableBrandHint
    };
}

static void CopyDirectory(string src, string dst)
{
    Directory.CreateDirectory(dst);
    foreach (var file in Directory.GetFiles(src))
    {
        File.Copy(file, Path.Combine(dst, Path.GetFileName(file)), true);
    }
}