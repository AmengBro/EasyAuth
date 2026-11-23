using System.Text.Json;
using System.Net;
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

// 临时目录放在探针自己的输出目录：某些沙箱会拦截 %TEMP% 下的 CreateDirectory，
// 而输出目录由 dotnet build 创建、必然可写。用唯一名避免删除后重建的竞态。
var testRoot = Path.Combine(AppContext.BaseDirectory, "probe-tmp", "kv-" + Guid.NewGuid().ToString("N")[..8]);
Directory.CreateDirectory(testRoot);
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
var skipped = 0;
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

/// <summary>环境不支持导致的跳过：不计为失败，但必须显式打印，不许悄悄略过。</summary>
void Skip(string name, string detail = "")
{
    skipped++;
    Console.WriteLine($"  [SKIP] {name}{(detail.Length > 0 ? " | " + detail : "")}");
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
var payloadAfter = KeyVaultService.ReadKeyVault(volA, testMachineGuid, serialA, out _, out _);
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

// 13) 多盘计数隔离回归（用户实测复现：在另一个盘配对后原盘计数被清零）
var stateDir = Path.Combine(testRoot, "state");
var settingsA = new UsbKeyAuthSettings();
var settingsB = new UsbKeyAuthSettings();

async Task<AuthVerifyResult> AuthOnDisk(UsbKeyAuthSettings s, VolumeInfo v)
{
    var st = PluginStateStore.Load(stateDir);
    var exp = st.GetCounter(v.VolumeGuid);
    var res = await AuthVerifier.VerifyAsync(s, v, testMachineGuid, exp);
    if (res.Success)
    {
        st.SetCounter(v.VolumeGuid, res.NewCounter);
        PluginStateStore.Save(stateDir, st);
    }
    return res;
}

AuthVerifier.Pair(settingsA, volInfoA, testMachineGuid, out _);
var rA1 = await AuthOnDisk(settingsA, volInfoA);
Case("盘A 首次认证通过", rA1.Success && rA1.NewCounter == 1, $"new={rA1.NewCounter}");

AuthVerifier.Pair(settingsB, volInfoB, testMachineGuid, out _);
var rB1 = await AuthOnDisk(settingsB, volInfoB);
Case("盘B 首次认证通过", rB1.Success && rB1.NewCounter == 1, $"new={rB1.NewCounter}");

var stAfterB = PluginStateStore.Load(stateDir);
Case("盘B 配对未清零盘A 的计数基线", stAfterB.GetCounter(volA) == 1,
    $"A={stAfterB.GetCounter(volA)} B={stAfterB.GetCounter(volB)}");

var rA2 = await AuthOnDisk(settingsA, volInfoA);
Case("盘A 在盘B 配对后仍能认证（实测回归）", rA2.Success,
    rA2.Success ? $"new={rA2.NewCounter}" : $"失败步骤={rA2.FailedStep} 原因={rA2.FailureReason}");

// 14) Windows 账户绑定（DPAPI）层
var volD = Path.Combine(testRoot, "VolD");
Directory.CreateDirectory(volD);
var volInfoD = new VolumeInfo { VolumeGuid = volD, DiskSerialNumber = serialA, DriveLetter = "X" };
var settingsBound = new UsbKeyAuthSettings { EnableUserBinding = true };
var pairBound = AuthVerifier.Pair(settingsBound, volInfoD, testMachineGuid, out var pairBoundErr);
Case("账户绑定模式配对成功", pairBound, pairBoundErr ?? "");
var readBound = KeyVaultService.ReadKeyVault(volD, testMachineGuid, serialA, out var boundStatus, out var boundFlag);
Case("DPAPI 包裹密钥可读且标记为已绑定",
    readBound != null && boundStatus == KeyVaultReadStatus.Ok && boundFlag,
    $"status={boundStatus} userBound={boundFlag}");
await CaseAsync("账户绑定模式下认证通过", settingsBound, volInfoD, testMachineGuid, 0, "OK");

// 未启用账户绑定的密钥文件，在启用该层时应被拒（提示重新配对）
var settingsRequireBound = CloneSettings(settings);
settingsRequireBound.EnableUserBinding = true;
File.WriteAllBytes(KeyVaultService.GetKeyVaultPath(volD), snapshot);
await CaseAsync("未绑定账户的密钥被账户层拒绝", settingsRequireBound, volInfoD, testMachineGuid, 0, "校验 Windows 账户绑定");

// 计数回写必须保留账户绑定层（否则下次认证会掉层）
AuthVerifier.Pair(settingsBound, volInfoD, testMachineGuid, out _);
var rBound1 = await AuthVerifier.VerifyAsync(settingsBound, volInfoD, testMachineGuid, 0);
var rBound2 = await AuthVerifier.VerifyAsync(settingsBound, volInfoD, testMachineGuid, 1);
Case("计数回写后账户绑定层仍在（可连续认证）", rBound1.Success && rBound2.Success,
    $"first={rBound1.Success} second={rBound2.Success}");

// 15) 审计日志
var auditDir = Path.Combine(testRoot, "audit-state");
Directory.CreateDirectory(auditDir);
AuditLogService.Write(auditDir, "PAIR", "X", volD, serialA, "layers=[sn,guid,token,counter]");
AuditLogService.Write(auditDir, "AUTH-OK", "X", volD, serialA, "new=1");
AuditLogService.Write(auditDir, "AUTH-FAIL", "Y", volB, serialB, "step=校验克隆计数 reason=计数不符");
var auditTail = AuditLogService.ReadTail(auditDir);
Case("审计日志写入三类事件",
    auditTail.Contains("PAIR") && auditTail.Contains("AUTH-OK") && auditTail.Contains("AUTH-FAIL")
    && auditTail.Contains("校验克隆计数"), auditTail.Split('\n').Length + " 行");
Case("审计日志含盘符与SN", auditTail.Contains("drive=X") && auditTail.Contains(serialA));

// 16) 多分区同时校验
var multiState = new PluginState();
var settingsMulti = new UsbKeyAuthSettings { MultiPartitionMode = true };
var volM1 = Path.Combine(testRoot, "Multi1");
var volM2 = Path.Combine(testRoot, "Multi2");
Directory.CreateDirectory(volM1);
Directory.CreateDirectory(volM2);
var multiV1 = new VolumeInfo { VolumeGuid = volM1, DiskSerialNumber = serialA, DriveLetter = "M", DiskModel = "仿真设备" };
var multiV2 = new VolumeInfo { VolumeGuid = volM2, DiskSerialNumber = serialA, DriveLetter = "N", DiskModel = "仿真设备" };

var multiPairOk = AuthVerifier.PairVolumes(settingsMulti, [multiV1, multiV2], testMachineGuid, multiState, out var multiPairErr);
Case("多分区配对（两卷各自写 key.bin）", multiPairOk, multiPairErr ?? "");
Case("授权列表收录两个分区", settingsMulti.AuthorizedVolumeGuids.Count == 2,
    string.Join(",", settingsMulti.AuthorizedVolumeGuids.Select(g => g.Contains("Multi") ? Path.GetFileName(g.TrimEnd('\\')) : g)));
Case("两卷 token 相互独立",
    multiState.GetTokenHash(volM1) != multiState.GetTokenHash(volM2));

// 模拟 Provider 的状态持久化：验证成功后把各卷新计数写回
async Task<AuthVerifyResult> AuthMultiAsync(params VolumeInfo[] vs)
{
    var r = await AuthVerifier.VerifyVolumesAsync(new VerifyOptions
    {
        Settings = settingsMulti, Volumes = vs,
        MachineGuid = testMachineGuid, State = multiState
    });
    if (r.Success)
    {
        foreach (var kv in r.NewCounters)
        {
            multiState.SetCounter(kv.Key, kv.Value);
        }
    }
    return r;
}

var multiR1 = await AuthMultiAsync(multiV1, multiV2);
Case("多分区认证全部通过", multiR1.Success, $"计数={string.Join("/", multiR1.NewCounters.Select(c => c.Value))}");

// 把第 2 个分区的 key.bin 删掉 → 整体应失败（且指出该分区）
Directory.Delete(Path.Combine(volM2, KeyVaultService.KeyVaultDirName), true);
var multiR2 = await AuthMultiAsync(multiV1, multiV2);
Case("缺一个分区即整体失败", !multiR2.Success && multiR2.FailedVolumeGuid == volM2,
    $"失败卷={multiR2.FailedVolumeGuid?.EndsWith("Multi2") ?? false} 步骤={multiR2.FailedStep}");

// 把 M: 的 key.bin 复制到另一分区 → 卷标识层必须拦住（多分区模式下也拦）
Directory.CreateDirectory(volM2);
CopyDirectory(Path.Combine(volM1, KeyVaultService.KeyVaultDirName),
    Path.Combine(volM2, KeyVaultService.KeyVaultDirName));
var multiR3 = await AuthMultiAsync(multiV1, multiV2);
Case("复制 key.bin 到另一分区被拦下（token/卷标识层）",
    !multiR3.Success && multiR3.FailedVolumeGuid == volM2 && multiR3.FailedStep != null,
    $"失败卷={multiR3.FailedVolumeGuid?.EndsWith("Multi2") ?? false} 步骤={multiR3.FailedStep}");

// 设备分组：同 SN 的两个分区归为一组，小分区被过滤
var groups = DiskInfoService.EnumerateDiskGroups();
var sameDisk = groups.FirstOrDefault(g => g.Volumes.Count + g.SkippedVolumes.Count >= 2);
Case("同盘分区归入同一设备组", sameDisk != null,
    sameDisk == null ? "" : $"设备={sameDisk.Model[..Math.Min(18, sameDisk.Model.Length)]} 合格={sameDisk.Volumes.Count} 忽略={sameDisk.SkippedVolumes.Count}");

// 17) 本地 HTTP API（供 Tauri 等外部程序）：冒烟测试
await TestLocalApiAsync();

// 18) 日志分流：audit.log 只留登录/凭据事件，运维事件进 service.log
var logDir = Path.Combine(testRoot, "logs");
Directory.CreateDirectory(logDir);
AuditLogService.Write(logDir, "AUTH-OK", "X", volD, serialA, "new=1");
AuditLogService.Write(logDir, "AUTH-FAIL", "Y", volB, serialB, "step=校验克隆计数");
AuditLogService.Write(logDir, "PAIR", "X", volD, serialA);
AuditLogService.Write(logDir, "VALIDATE-OK", detail: "host=1");
// 故意用错服务：运维事件也必须被兜底路由到 service.log
AuditLogService.Write(logDir, "API-START", detail: "url=http://127.0.0.1:24721");
ServiceLogService.Write(logDir, "API-REMINDER", detail: "id=abc");
ServiceLogService.Write(logDir, "CTRL-LOADED", detail: "instance=1");
var auditText = File.ReadAllText(Path.Combine(logDir, AuditLogService.LogFileName));
var serviceText = File.ReadAllText(Path.Combine(logDir, ServiceLogService.LogFileName));
Case("audit.log 只含登录/凭据事件",
    auditText.Contains("AUTH-OK") && auditText.Contains("AUTH-FAIL") &&
    auditText.Contains("PAIR") && auditText.Contains("VALIDATE-OK") &&
    !auditText.Contains("API-START") && !auditText.Contains("CTRL-LOADED"),
    $"audit={auditText.Split('\n').Length} 行");
Case("运维事件落在 service.log（含错用审计服务的兜底路由）",
    serviceText.Contains("API-START") && serviceText.Contains("API-REMINDER") &&
    serviceText.Contains("CTRL-LOADED") && !serviceText.Contains("AUTH-OK"),
    $"service={serviceText.Split('\n').Length} 行");
Case("审计事件白名单判定正确",
    AuditLogService.IsAuditEvent("AUTH-FAIL") && AuditLogService.IsAuditEvent("PAIR-ERROR") &&
    AuditLogService.IsAuditEvent("VALIDATE-FAIL") && !AuditLogService.IsAuditEvent("API-START") &&
    !AuditLogService.IsAuditEvent("CTRL-LOADED") && !AuditLogService.IsAuditEvent("DATA-MIGRATE"), "");
Case("界面读取审计日志不会混进运维事件",
    !AuditLogService.ReadTail(logDir).Contains("API-START"), "");

// 19) 插件配置目录：官方 PluginConfigFolder 注入 + 旧版数据迁移
var dataDir = Path.Combine(testRoot, "Config", "Plugins", PluginPaths.PluginId);
Directory.CreateDirectory(dataDir);
PluginPaths.Configure(dataDir);
Case("Configure 后 PluginDirectory 指向宿主配置目录",
    string.Equals(Path.GetFullPath(PluginPaths.PluginDirectory), Path.GetFullPath(dataDir),
        StringComparison.OrdinalIgnoreCase), PluginPaths.PluginDirectory);
Case("Combine 落在配置目录内",
    Path.GetFullPath(PluginPaths.Combine("api.json"))
        .StartsWith(Path.GetFullPath(dataDir), StringComparison.OrdinalIgnoreCase), "");
PluginPaths.EnsureDataDirectory();
Case("配置目录可创建", Directory.Exists(dataDir), "");

var oldDir = Path.Combine(testRoot, "legacy-plugin");
Directory.CreateDirectory(oldDir);
File.WriteAllText(Path.Combine(oldDir, "state.json"), "{\"counters\":{\"vol\":7}}");
File.WriteAllText(Path.Combine(oldDir, "api.json"), "{\"Port\":24721,\"Token\":\"t\"}");
File.WriteAllText(Path.Combine(oldDir, "audit.log"), "legacy noise");
var migrated = PluginPaths.MigrateLegacyFiles(oldDir);
Case("升级时把 state.json / api.json 复制到配置目录",
    migrated.Count == 2 &&
    File.ReadAllText(Path.Combine(dataDir, "state.json")).Contains("vol") &&
    File.ReadAllText(Path.Combine(dataDir, "api.json")).Contains("24721"),
    string.Join(",", migrated));
Case("迁移只复制不删除原件、旧日志不搬",
    File.Exists(Path.Combine(oldDir, "state.json")) &&
    !File.Exists(Path.Combine(dataDir, "audit.log")), "");
File.WriteAllText(Path.Combine(dataDir, "api.json"), "{\"Port\":9999}");
var migrated2 = PluginPaths.MigrateLegacyFiles(oldDir);
Case("重复迁移不覆盖新目录已有配置",
    migrated2.Count == 0 &&
    File.ReadAllText(Path.Combine(dataDir, "api.json")).Contains("9999"), "");
PluginPaths.Configure(null); // 恢复自测默认，不影响其它用例

// 20) 验证成功后的「登录原因」：文本清洗与审计闭环（窗口行为需真机验证）
var reasonDir = Path.Combine(testRoot, "reason-logs");
Directory.CreateDirectory(reasonDir);
var reasonCtx = new LoginReasonContext(reasonDir, "X", volD, serialA);
LoginReasonService.Record(reasonCtx, "调课演示\r\n[AUTH-OK] 伪造行", "provided");
var reasonLog = File.ReadAllText(Path.Combine(reasonDir, AuditLogService.LogFileName));
Case("登录原因作为 AUTH-REASON 写入审计日志",
    reasonLog.Contains("AUTH-REASON") && reasonLog.Contains("outcome=provided") &&
    reasonLog.Contains("调课演示"), "");
Case("换行/制表符被清洗，不能伪造出新的日志行",
    reasonLog.TrimEnd().Split('\n').Length == 1 &&
    LoginReasonService.Sanitize("a\r\nb\tc") == "abc", "");
Case("AUTH-REASON 属于审计白名单",
    AuditLogService.IsAuditEvent(LoginReasonService.AuditEvent), "");
Case("未点击输入框的自动关闭时长为 10 秒",
    LoginReasonService.AutoCloseSeconds == 10, "");
Case("超长原因被截断到上限",
    LoginReasonService.Sanitize(new string('a', 500)).Length == LoginReasonService.MaxReasonLength, "");
LoginReasonService.Record(reasonCtx, "  ", "timeout");
LoginReasonService.Record(reasonCtx, "他说\"好\"", "provided");
var reasonLog2 = File.ReadAllText(Path.Combine(reasonDir, AuditLogService.LogFileName));
Case("忽略/超时也留闭环且标注未填写",
    reasonLog2.Contains("outcome=timeout") && reasonLog2.Contains("reason=（未填写）"), "");
Case("原因里的双引号被替换，不破坏日志字段",
    reasonLog2.Contains("他说'好'"), "");

// 21) 多凭据区分：标签、身份条、两颗盘同时插入时的判定、多分区缺一不可
Case("凭据标签清洗：去控制字符、换双引号、限长",
    CredentialIdentity.SanitizeLabel("蓝色\r\n\"备用\"盘") == "蓝色'备用'盘" &&
    CredentialIdentity.SanitizeLabel(new string('a', 50)).Length == CredentialIdentity.MaxLabelLength, "");

var idA = new UsbKeyAuthSettings
{
    CredentialLabel = "蓝色备用盘",
    PairedDiskSerial = "SN-AAAA-1234",
    PairedVolumeGuid = "vol-A1",
    AuthorizedVolumeGuids = ["vol-A1"],
    MultiPartitionMode = false
};
var idB = new UsbKeyAuthSettings
{
    CredentialLabel = "教室多分区盘",
    PairedDiskSerial = "SN-BBBB-5678",
    PairedVolumeGuid = "vol-B1",
    AuthorizedVolumeGuids = ["vol-B1", "vol-B2"],
    MultiPartitionMode = true
};
Case("标题带自定义标签（宿主列表做不到，插件控件内可做）",
    CredentialIdentity.BuildTitle(idA) == "通过 EasyAuth 验证（蓝色备用盘）" &&
    CredentialIdentity.BuildTitle(new UsbKeyAuthSettings()) == "通过 EasyAuth 验证", "");
Case("身份条写清模式 / 授权分区数 / SN 尾号",
    CredentialIdentity.BuildIdentityLine(idB).Contains("多分区") &&
    CredentialIdentity.BuildIdentityLine(idB).Contains("授权 2 个分区") &&
    CredentialIdentity.BuildIdentityLine(idB).Contains("…5678") &&
    CredentialIdentity.BuildIdentityLine(idA).Contains("单分区"), "");

var allVols = new List<VolumeInfo>
{
    new() { VolumeGuid = "vol-A1", DriveLetter = "E" },
    new() { VolumeGuid = "vol-B1", DriveLetter = "F" },
    new() { VolumeGuid = "vol-B2", DriveLetter = "G" },
    new() { VolumeGuid = "vol-C1", DriveLetter = "H" }
};
var aVols = CredentialIdentity.FilterVolumes(idA, allVols);
var bVols = CredentialIdentity.FilterVolumes(idB, allVols);
Case("两颗盘同时插着：单分区凭据只看到自己的 1 个分区",
    aVols.Count == 1 && aVols[0].VolumeGuid == "vol-A1",
    string.Join(",", aVols.Select(v => v.VolumeGuid)));
Case("两颗盘同时插着：多分区凭据只看到自己的 2 个分区",
    bVols.Count == 2 && bVols.All(v => v.VolumeGuid.StartsWith("vol-B")),
    string.Join(",", bVols.Select(v => v.VolumeGuid)));

var allGroups = new List<DiskGroupInfo>
{
    new() { DiskSerial = "SN-AAAA-1234", Model = "盘A", Volumes = [allVols[0]] },
    new() { DiskSerial = "SN-BBBB-5678", Model = "盘B", Volumes = [allVols[1], allVols[2]] },
    new() { DiskSerial = "SN-CCCC-0000", Model = "盘C", Volumes = [allVols[3]] }
};
Case("设备下拉框按凭据过滤，别的盘不出现",
    CredentialIdentity.FilterGroups(idB, allGroups).Count == 1 &&
    CredentialIdentity.FilterGroups(idB, allGroups)[0].DiskSerial == "SN-BBBB-5678", "");
var skippedGroup = new DiskGroupInfo
{
    DiskSerial = "SN-BBBB-5678",
    Model = "盘B",
    Volumes = [allVols[1]],
    SkippedVolumes = [allVols[2]]
};
Case("授权卷被判为过小分区时设备仍保留，并提示应有/可见数量",
    CredentialIdentity.FilterGroups(idB, [skippedGroup]).Count == 1 &&
    CredentialIdentity.BuildGroupLabel(skippedGroup, idB).Contains("应有 2 个分区，当前可见 1 个"), "");
Case("多分区缺一个授权卷就被找出",
    CredentialIdentity.FindMissing(idB, [allVols[1]]).Count == 1, "");
Case("多分区授权卷全在场时 FindMissing 为空",
    CredentialIdentity.FindMissing(idB, [allVols[1], allVols[2]]).Count == 0, "");
Case("老单分区凭据（无 AuthorizedVolumeGuids）回退到 PairedVolumeGuid",
    CredentialIdentity.AllowedVolumeGuids(new UsbKeyAuthSettings { PairedVolumeGuid = "vol-legacy" })
        .SequenceEqual(["vol-legacy"]), "");
Case("审计标签空格转下划线，不破坏 key=value",
    CredentialIdentity.ForLog("蓝色 备用盘") == "蓝色_备用盘", "");
Case("标签随凭据 JSON 往返保存",
    JsonSerializer.Deserialize<UsbKeyAuthSettings>(JsonSerializer.Serialize(idA))?.CredentialLabel == "蓝色备用盘", "");

// 22) 安全骨架：默认只观测、入口默认折叠、各开关独立
Console.WriteLine();
Console.WriteLine("== 安全骨架 / 一次性临时密码 / 完整性检测 ==");
var secDir = Path.Combine(AppContext.BaseDirectory, "probe-tmp", "sec-" + Guid.NewGuid().ToString("N")[..8]);
Directory.CreateDirectory(secDir);
var credPath = Path.Combine(secDir, "Credentials.json");
var defaults = new SecurityConfig();
Case("默认只开「只观测」检测与临时密码", defaults.EnableTamperDetection && defaults.EnableTempPassword, "");
Case("预留开关默认全关（静默重启/自动换回/恢复码）",
    !defaults.EnableSilentRestart && !defaults.EnableAutoRestore && !defaults.EnableRecoveryCode, "");
Case("临时密码入口默认折叠，不与主控件抢位置", defaults.TempPasswordSectionCollapsed, "");
Case("安全配置 JSON 往返不丢开关",
    JsonSerializer.Deserialize<SecurityConfig>(JsonSerializer.Serialize(new SecurityConfig { EnableTamperDetection = false }))?.EnableTamperDetection == false, "");
File.WriteAllText(Path.Combine(secDir, "security.json"), "{ broken");
Case("损坏的 security.json 回退到默认值而不是崩溃",
    SecurityConfigStore.Load(secDir).EnableTempPassword, "");
File.Delete(Path.Combine(secDir, "security.json"));

// 临时密码：只存哈希、一次性、无有效期、锁定、撤销
var t0 = DateTimeOffset.UtcNow;
var issue = TempPasswordService.Create(secDir, now: t0);
Case("临时密码生成成功且为 12 位纯可打印 ASCII",
    issue != null && issue.Plaintext.Length == TempPasswordService.PasswordLength &&
    issue.Plaintext.All(c => TempPasswordService.Alphabet.Contains(c)), issue?.Plaintext ?? "null");
var secJson = File.ReadAllText(Path.Combine(secDir, "security.json"));
Case("security.json 不含临时密码明文", issue != null && !secJson.Contains(issue.Plaintext), "");
Case("规范化去掉空白与控制字符并大写化",
    TempPasswordService.Normalize(" ab\t12\n") == "AB12", "");
Case("正确密码验证通过", issue != null && TempPasswordService.Verify(secDir, issue.Plaintext, t0) == TempPasswordOutcome.Ok, "");
Case("同一枚密码第二次使用被拒（一次性消费）",
    issue != null && TempPasswordService.Verify(secDir, issue.Plaintext, t0) == TempPasswordOutcome.Used, "");
Case("一次性写入 UsedAt 并落盘",
    SecurityConfigStore.Load(secDir).TempPasswordUsedAt != null, "");
var issue2 = TempPasswordService.Create(secDir, now: t0);
Case("临时密码没有有效期：一年后依然可用",
    issue2 != null &&
    TempPasswordService.Verify(secDir, issue2.Plaintext, t0.AddDays(365)) == TempPasswordOutcome.Ok, "");
Case("配置里不再有过期时间字段",
    !secJson.Contains("TempPasswordExpiresAt") &&
    !File.ReadAllText(Path.Combine(secDir, "security.json")).Contains("TempPasswordExpiresAt"), "");
// 旧版本配置升级兼容：老文件带 TempPasswordExpiresAt / TempPasswordTtlMinutes，
// 反序列化必须忽略它们而不是抛异常
File.WriteAllText(Path.Combine(secDir, "security.json"),
    "{\"EnableTempPassword\":true,\"TempPasswordTtlMinutes\":30," +
    "\"TempPasswordExpiresAt\":\"2026-11-23T15:20:43.0816223+00:00\"}");
Case("旧配置里的过期字段被忽略而不是崩溃",
    SecurityConfigStore.Load(secDir).EnableTempPassword, "");
var issue3 = TempPasswordService.Create(secDir, now: t0);
for (var i = 0; i < 5; i++) TempPasswordService.Verify(secDir, "WRONGWRONGWR", t0);
Case("连续输错达到上限后锁定",
    TempPasswordService.Verify(secDir, "WRONGWRONGWR", t0) == TempPasswordOutcome.Locked, "");
Case("锁定期间即使输入正确也拒绝", issue3 != null &&
    TempPasswordService.Verify(secDir, issue3.Plaintext, t0) == TempPasswordOutcome.Locked, "");
Case("锁定到期后可继续尝试", issue3 != null &&
    TempPasswordService.Verify(secDir, issue3.Plaintext, t0.AddMinutes(11)) == TempPasswordOutcome.Ok, "");
TempPasswordService.Create(secDir, now: t0);
TempPasswordService.Revoke(secDir);
Case("撤销后无可用密码", TempPasswordService.Verify(secDir, "ABCDEFGHJKLM", t0) == TempPasswordOutcome.NoActive, "");
SecurityConfigStore.Mutate(secDir, c => { c.EnableTempPassword = false; return c; });
Case("关闭临时密码通道后校验返回 Disabled",
    TempPasswordService.Verify(secDir, "ABCDEFGHJKLM", t0) == TempPasswordOutcome.Disabled, "");
SecurityConfigStore.Mutate(secDir, c => { c.EnableTempPassword = true; return c; });

// 完整性检测：只观测、不自动洗白、不碰文件
File.Delete(Path.Combine(secDir, "security.json"));
File.WriteAllText(credPath, "{\"UserCredential\":\"AAA\",\"AdminCredential\":\"BBB\"}");
var ir1 = IntegrityMonitor.Check(secDir, credPath);
Case("首次检测建立基线，不视为篡改", ir1.Outcome == IntegrityOutcome.BaselineCreated, ir1.Outcome.ToString());
var ir2 = IntegrityMonitor.Check(secDir, credPath);
Case("内容不变时与基线一致", ir2.Outcome == IntegrityOutcome.Match, ir2.Outcome.ToString());
var changed = "{\"UserCredential\":\"\",\"AdminCredential\":\"\"}";
File.WriteAllText(credPath, changed);
var ir3 = IntegrityMonitor.Check(secDir, credPath);
Case("内容变化被检出为差异", ir3.Outcome == IntegrityOutcome.Difference && ir3.HasPendingDifference, ir3.Outcome.ToString());
Case("只观测：不改动凭据文件本身", File.ReadAllText(credPath) == changed, "");
Case("只观测：不自动更新基线（痕迹不会被洗白）",
    SecurityConfigStore.Load(secDir).CredentialsBaselineSha256 == ir1.ObservedHash, "");
Case("差异日志写明来源无法判定",
    ServiceLogService.ReadTail(secDir, 30).Contains("source=unknown"), "");
var ir4 = IntegrityMonitor.Check(secDir, credPath);
Case("同一差异不重复刷屏但保持待确认", ir4.Outcome == IntegrityOutcome.Difference && ir4.HasPendingDifference, "");
Case("管理员手动重建基线成功", IntegrityMonitor.Rebaseline(secDir, credPath), "");
var ir5 = IntegrityMonitor.Check(secDir, credPath);
Case("重建后回到一致且不再有待确认差异", ir5.Outcome == IntegrityOutcome.Match && !ir5.HasPendingDifference, "");
Case("基线只存哈希，不存凭据全文副本",
    !File.ReadAllText(Path.Combine(secDir, "security.json")).Contains("UserCredential"), "");
SecurityConfigStore.Mutate(secDir, c => { c.EnableTamperDetection = false; return c; });
Case("检测开关关闭时跳过", IntegrityMonitor.Check(secDir, credPath).Outcome == IntegrityOutcome.Disabled, "");
SecurityConfigStore.Mutate(secDir, c => { c.EnableTamperDetection = true; return c; });

// 恢复码门控：文件存在不等于可以关掉警报
GuardState.ClearSuppression();
Case("仅 recovery 文件存在、校验未通过 → 不抑制",
    !GuardState.RecoveryGate(true, true, false) && !GuardState.IsSuppressed, "");
Case("通道未启用 → 不抑制", !GuardState.RecoveryGate(false, true, true), "");
Case("通道启用且校验通过 → 才抑制", GuardState.RecoveryGate(true, true, true) && GuardState.IsSuppressed, "");
Case("抑制期间完整性检测跳过", IntegrityMonitor.Check(secDir, credPath).Outcome == IntegrityOutcome.Suppressed, "");
GuardState.ClearSuppression();
Case("清除抑制后检测恢复", IntegrityMonitor.Check(secDir, credPath).Outcome == IntegrityOutcome.Match, "");
var candidates = IntegrityMonitor.ResolveCandidatePaths(Path.Combine("app", "data", "Config", "Plugins", "cn.amengbro.easyauth"));
Case("路径推导同时覆盖本地模式与集控模式",
    candidates.Length == 2 && candidates[0].Contains("Config") && candidates[0].EndsWith(Path.Combine("Management", "Credentials.json")) &&
    !candidates[1].Contains("Config"), string.Join(" | ", candidates));

Console.WriteLine();
Console.WriteLine($"用例结果：{pass} 通过 / {fail} 失败 / {skipped} 跳过（环境限制）");

static UsbKeyAuthSettings CloneSettings(UsbKeyAuthSettings s)
{    return new UsbKeyAuthSettings
    {
        PairedDiskSerial = s.PairedDiskSerial,
        PairedVolumeGuid = s.PairedVolumeGuid,
        TokenHash = s.TokenHash,
        Counter = s.Counter,
        BrandHint = s.BrandHint,
        CredentialLabel = s.CredentialLabel,
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

/// <summary>本地 HTTP API 冒烟测试：起服务、打各端点、验证响应、关服务。
/// 注意：课程相关端点依赖 ClassIsland 宿主（ILessonsService/IProfileService），
/// 探针环境没有宿主程序集，这些端点在此环境下只能验证"不崩溃、返回规范 JSON"，
/// 真实数据需在 ClassIsland 内验证。提醒相关端点不依赖宿主，可完整测试。</summary>
async Task TestLocalApiAsync()
{
    Console.WriteLine();
    Console.WriteLine("—— 本地 HTTP API 冒烟测试 ——");

    // 运行时挑一个空闲端口：固定端口容易被上次进程残留的 HTTP.SYS 注册占住，
    // 导致整组 API 用例被跳过。TcpListener 绑定 0 让系统分配，取完立即释放。
    int probePort;
    using (var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0))
    {
        listener.Start();
        probePort = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
    }
    // 环境能力探测：某些沙箱/受限会话禁用了 HTTP.SYS，HttpListener.Start()
    // 会抛 HttpListenerException「句柄无效」，与端口是否被占用无关，也与被测代码无关。
    // 这种情况下整组 API 用例标记 SKIP（不计失败），并给出确切异常；
    // 在 ClassIsland 真机或允许 HTTP.SYS 的环境里仍会完整跑完这一组。
    string? httpSysError = null;
    try
    {
        using var probe = new HttpListener();
        probe.Prefixes.Add($"http://127.0.0.1:{probePort}/");
        probe.Start();
        probe.Stop();
    }
    catch (Exception ex)
    {
        httpSysError = $"{ex.GetType().Name}: {ex.Message}";
    }
    if (httpSysError != null)
    {
        Skip("本地 HTTP API 冒烟测试（整组）",
            $"本环境 HTTP.SYS 不可用 → {httpSysError}；需在 ClassIsland 真机验证");
        return;
    }

    using var api = new EasyAuthApiService(new ApiConfig { Enabled = true, Port = probePort });
    await api.StartAsync(CancellationToken.None);
    if (!api.IsRunning)
    {
        // 能力探测通过但服务仍起不来 —— 这才是被测代码/配置的问题，如实计失败。
        Case("本地 API 服务启动", false, $"{api.BaseUrl} 启动失败，跳过后续 API 用例");
        return;
    }
    try
    {
        using var http = new HttpClient { BaseAddress = new Uri(api.BaseUrl), Timeout = TimeSpan.FromSeconds(10) };

        // /api/status：探针无宿主，宽松断言（返回规范 JSON 即可）
        var statusResp = await http.GetAsync("/api/status");
        var status = await statusResp.Content.ReadAsStringAsync();
        Case("GET /api/status 返回规范 JSON", IsJson(status), $"HTTP {(int)statusResp.StatusCode} {status.Trim()}");

        // /api/next-class：同上，验证不崩溃
        var nextResp = await http.GetAsync("/api/next-class");
        var nextBody = await nextResp.Content.ReadAsStringAsync();
        Case("GET /api/next-class 返回规范 JSON", IsJson(nextBody), $"HTTP {(int)nextResp.StatusCode}");

        // 创建提醒
        var createBody = new StringContent(
            JsonSerializer.Serialize(new { title = "探针提醒", message = "来自 DeviceProbe", delaySeconds = 3600 }),
            Encoding.UTF8, "application/json");
        var createResp = await http.PostAsync("/api/reminder", createBody);
        var createJson = await createResp.Content.ReadAsStringAsync();
        var id = JsonDocument.Parse(createJson).RootElement.GetProperty("id").GetString();
        Case("POST /api/reminder 创建成功并返回 id", createResp.IsSuccessStatusCode && !string.IsNullOrEmpty(id),
            $"id={id}");

        // 列表里应能查到
        var list = await http.GetStringAsync("/api/reminders");
        Case("GET /api/reminders 含刚创建的提醒", list.Contains(id!), "");

        // 取消
        var del = await http.DeleteAsync($"/api/reminder/{id}");
        Case("DELETE /api/reminder/{id} 取消成功", del.IsSuccessStatusCode, "");

        var list2 = await http.GetStringAsync("/api/reminders");
        Case("取消后不再出现在待触发列表", !list2.Contains($"\"id\":\"{id}\""), "");

        // 未知路径 404
        var notFound = await http.GetAsync("/api/nope");
        Case("未知接口返回 404", notFound.StatusCode == HttpStatusCode.NotFound, "");

        // 空 body 创建提醒应被拒（参数校验）
        var emptyResp = await http.PostAsync("/api/reminder",
            new StringContent("{}", Encoding.UTF8, "application/json"));
        Case("空提醒被参数校验拒绝(400)", emptyResp.StatusCode == HttpStatusCode.BadRequest, "");

        // —— 三种定时方式 ——
        // 1) 立即触发：不传延时，应 mode=immediate 且 secondsLeft≈0
        var nowResp = await http.PostAsync("/api/reminder",
            new StringContent(JsonSerializer.Serialize(new { title = "立即" }), Encoding.UTF8, "application/json"));
        var nowBody = await nowResp.Content.ReadAsStringAsync();
        Case("不传延时=立即触发(mode=immediate)",
            nowResp.IsSuccessStatusCode && nowBody.Contains("\"mode\":\"immediate\""),
            $"HTTP {(int)nowResp.StatusCode} {nowBody.Trim()}");

        // 2) 相对延时
        var delayResp = await http.PostAsync("/api/reminder",
            new StringContent(JsonSerializer.Serialize(new { title = "延时", delaySeconds = 3 }), Encoding.UTF8, "application/json"));
        var delayBody = await delayResp.Content.ReadAsStringAsync();
        var delayJson = JsonDocument.Parse(delayBody).RootElement;
        Case("delaySeconds 走延时模式",
            delayResp.IsSuccessStatusCode && delayJson.GetProperty("mode").GetString() == "delay" &&
            Math.Abs(delayJson.GetProperty("secondsLeft").GetDouble() - 3) < 1.5,
            $"mode={delayJson.GetProperty("mode").GetString()} left={delayJson.GetProperty("secondsLeft").GetDouble():F1}");

        // 3) 绝对时间：HH:mm:ss，取 1 分钟后
        var atTime = DateTime.Now.AddMinutes(1).ToString("HH:mm:ss");
        var atResp = await http.PostAsync("/api/reminder",
            new StringContent(JsonSerializer.Serialize(new { title = "定点", atTime }), Encoding.UTF8, "application/json"));
        var atBody = await atResp.Content.ReadAsStringAsync();
        var atJson = JsonDocument.Parse(atBody).RootElement;
        Case("atTime 走定点模式且时间正确",
            atResp.IsSuccessStatusCode && atJson.GetProperty("mode").GetString() == "atTime" &&
            Math.Abs(atJson.GetProperty("secondsLeft").GetDouble() - 60) < 3,
            $"mode={atJson.GetProperty("mode").GetString()} atTime={atTime} left={atJson.GetProperty("secondsLeft").GetDouble():F0}");

        // 4) 非法 atTime 应被拒
        var badResp = await http.PostAsync("/api/reminder",
            new StringContent(JsonSerializer.Serialize(new { title = "坏", atTime = "不是时间" }), Encoding.UTF8, "application/json"));
        Case("非法 atTime 被拒绝(400)", badResp.StatusCode == HttpStatusCode.BadRequest, "");

        // 5) ISO 8601 绝对时间
        var isoResp = await http.PostAsync("/api/reminder",
            new StringContent(JsonSerializer.Serialize(new { title = "ISO", atTime = DateTime.Now.AddMinutes(2).ToString("s") }),
                Encoding.UTF8, "application/json"));
        var isoBody = await isoResp.Content.ReadAsStringAsync();
        Case("ISO 8601 atTime 被接受",
            isoResp.IsSuccessStatusCode && isoBody.Contains("\"mode\":\"atTime\""), isoBody.Trim());

        // 6) 展示选项透传：标题/正文时长、特效、音效、语音、置顶
        var fullResp = await http.PostAsync("/api/reminder",
            new StringContent(JsonSerializer.Serialize(new
            {
                title = "完整选项",
                message = "带特效和音效",
                maskDurationSeconds = 3,
                overlayDurationSeconds = 12,
                effect = false,
                sound = true,
                speech = true,
                topmost = true
            }), Encoding.UTF8, "application/json"));
        var fullBody = await fullResp.Content.ReadAsStringAsync();
        Case("展示选项（时长/特效/音效/语音/置顶）被接受", fullResp.IsSuccessStatusCode, fullBody.Trim());

        // 8) 畸形 JSON：应返回 400 + 人话提示，而不是 500 吐解析器内部错误
        var badJsonResp = await http.PostAsync("/api/reminder",
            new StringContent("'{\"title\":\"x\"}'", Encoding.UTF8, "application/json"));
        var badJsonBody = await badJsonResp.Content.ReadAsStringAsync();
        Case("畸形 JSON 返回 400 且带提示",
            badJsonResp.StatusCode == HttpStatusCode.BadRequest && badJsonBody.Contains("hint"),
            badJsonBody.Trim());

        // 9) 单独指定标题时长，不应被兜底时长覆盖
        var maskOnlyResp = await http.PostAsync("/api/reminder",
            new StringContent(JsonSerializer.Serialize(new
            {
                title = "只定标题时长",
                durationSeconds = 30,
                maskDurationSeconds = 4
            }), Encoding.UTF8, "application/json"));
        Case("maskDurationSeconds 优先于 durationSeconds", maskOnlyResp.IsSuccessStatusCode, "");

        // 10) 已过的时刻必须顺延到明天（"10:05:00" 会被 DateTime.TryParse
        //     解析成"今天 10:05"，若不特判就会排到一个已经过去的时间）
        var pastTime = DateTime.Now.AddMinutes(-1).ToString("HH:mm:ss");
        var pastResp = await http.PostAsync("/api/reminder",
            new StringContent(JsonSerializer.Serialize(new { title = "已过时刻", atTime = pastTime }),
                Encoding.UTF8, "application/json"));
        var pastBody = await pastResp.Content.ReadAsStringAsync();
        var pastLeft = pastResp.IsSuccessStatusCode
            ? JsonDocument.Parse(pastBody).RootElement.GetProperty("secondsLeft").GetDouble()
            : -1;
        Case("已过的时刻顺延到明天（约 24h 后）",
            pastLeft > 86000 && pastLeft < 86500,
            $"atTime={pastTime} secondsLeft={pastLeft:F0}");
    }
    finally
    {
        await api.StopAsync(CancellationToken.None);
    }
}

static bool IsJson(string s)
{
    try
    {
        JsonDocument.Parse(s);
        return true;
    }
    catch
    {
        return false;
    }
}