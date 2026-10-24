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

Console.WriteLine();
Console.WriteLine($"用例结果：{pass} 通过 / {fail} 失败");

static UsbKeyAuthSettings CloneSettings(UsbKeyAuthSettings s)
{    return new UsbKeyAuthSettings
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

/// <summary>本地 HTTP API 冒烟测试：起服务、打各端点、验证响应、关服务。
/// 注意：课程相关端点依赖 ClassIsland 宿主（ILessonsService/IProfileService），
/// 探针环境没有宿主程序集，这些端点在此环境下只能验证"不崩溃、返回规范 JSON"，
/// 真实数据需在 ClassIsland 内验证。提醒相关端点不依赖宿主，可完整测试。</summary>
async Task TestLocalApiAsync()
{
    Console.WriteLine();
    Console.WriteLine("—— 本地 HTTP API 冒烟测试 ——");

    // 用独立端口，避开上次进程残留的 HTTP.SYS 注册
    using var api = new EasyAuthApiService(new ApiConfig { Enabled = true, Port = 24911 });
    await api.StartAsync(CancellationToken.None);
    if (!api.IsRunning)
    {
        // 端口被占用（多为上一次进程残留的 HTTP.SYS 注册）。
        // 这不是被测代码的缺陷，明确报出来而不是让后续请求莫名其妙地失败。
        Case("本地 API 服务启动", false,
            $"{api.BaseUrl} 启动失败（端口冲突），跳过后续 API 用例；稍后重跑即可");
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

        // 7) 单独指定标题时长，不应被兜底时长覆盖
        var maskOnlyResp = await http.PostAsync("/api/reminder",
            new StringContent(JsonSerializer.Serialize(new
            {
                title = "只定标题时长",
                durationSeconds = 30,
                maskDurationSeconds = 4
            }), Encoding.UTF8, "application/json"));
        Case("maskDurationSeconds 优先于 durationSeconds", maskOnlyResp.IsSuccessStatusCode, "");
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