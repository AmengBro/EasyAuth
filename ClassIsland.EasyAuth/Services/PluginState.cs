using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ClassIsland.EasyAuth.Services;

/// <summary>
/// 插件自有状态：按卷隔离的存活克隆计数。
/// 存放在插件自己的目录（data/Plugins/&lt;插件id&gt;/state.json），
/// 不写 ClassIsland 的凭据文件——凭据只在编辑模式保存，
/// 认证时改内存里的 ProviderSettings 不会落盘。
///
/// 为什么按卷存字典而不是单个值：key.bin 是每盘一份，计数基线必须与配对的那块盘
/// 对应。全局单值会导致"在 B 盘配对把 A 盘的基线清零"，A 盘随即认证失败。
/// </summary>
public class PluginState
{
    /// <summary>卷 GUID -&gt; 存活计数（大小写不敏感匹配）</summary>
    public Dictionary<string, int> Counters { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>状态文件是否已存在（区分"首次"与"计数不符"）</summary>
    [JsonIgnore]
    public bool Exists { get; set; }

    /// <summary>单卷的配对信息</summary>
    public class PairingRecord
    {
        /// <summary>该卷 key.bin 内 token 的 SHA-256</summary>
        public string TokenHash { get; set; } = "";

        /// <summary>配对时该卷所在磁盘的序列号（控件重建后用于恢复凭据设置）</summary>
        public string DiskSerial { get; set; } = "";

        /// <summary>配对时的设备型号（仅界面展示）</summary>
        public string BrandHint { get; set; } = "";

        /// <summary>该卷配对时是否处于多分区模式（控件重建后恢复下拉框语义）</summary>
        public bool MultiPartitionMode { get; set; }
    }

    /// <summary>上次在界面上选择的分区（纯体验偏好，与安全无关）</summary>
    public string LastVolumeGuid { get; set; } = "";

    /// <summary>卷 GUID -&gt; 配对信息（多分区模式下每卷各自独立 token）</summary>
    public Dictionary<string, PairingRecord> Pairings { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>取某卷的 token 哈希；无记录返回 null</summary>
    public string? GetTokenHash(string volumeGuid)
    {
        return Pairings.TryGetValue(volumeGuid, out var r) ? r.TokenHash : null;
    }

    /// <summary>写入某卷的 token 哈希</summary>
    public void SetTokenHash(string volumeGuid, string tokenHash)
    {
        Pairings[volumeGuid] = new PairingRecord { TokenHash = tokenHash };
    }

    /// <summary>取某卷的期望计数；无记录返回 null（调用方按"接纳当前计数"处理）。</summary>
    public int? GetCounter(string volumeGuid)
    {
        return Counters.TryGetValue(volumeGuid, out var value) ? value : null;
    }

    /// <summary>写入某卷的存活计数。</summary>
    public void SetCounter(string volumeGuid, int value)
    {
        Counters[volumeGuid] = value;
    }
}

public static class PluginStateStore
{
    public const string StateFileName = "state.json";

    /// <summary>加载状态；文件不存在（或旧单值格式）返回 Exists=false 的空状态。</summary>
    public static PluginState Load(string stateDir)
    {
        var path = Path.Combine(stateDir, StateFileName);
        try
        {
            if (File.Exists(path))
            {
                var state = JsonSerializer.Deserialize<PluginState>(File.ReadAllText(path));
                if (state != null)
                {
                    // 规范化比较器，并过滤空键
                    var normalized = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                    foreach (var kv in state.Counters)
                    {
                        if (!string.IsNullOrWhiteSpace(kv.Key))
                        {
                            normalized[kv.Key] = kv.Value;
                        }
                    }
                    state.Counters = normalized;

                    var pairings = new Dictionary<string, PluginState.PairingRecord>(StringComparer.OrdinalIgnoreCase);
                    foreach (var kv in state.Pairings)
                    {
                        if (!string.IsNullOrWhiteSpace(kv.Key) && kv.Value != null)
                        {
                            pairings[kv.Key] = kv.Value;
                        }
                    }
                    state.Pairings = pairings;
                    state.Exists = true;
                    return state;
                }
            }
        }
        catch
        {
            // 损坏当作不存在处理（调用方按首次接纳）
        }
        return new PluginState();
    }

    /// <summary>保存状态。</summary>
    public static bool Save(string stateDir, PluginState state)
    {
        try
        {
            Directory.CreateDirectory(stateDir);
            File.WriteAllText(Path.Combine(stateDir, StateFileName),
                JsonSerializer.Serialize(state));
            return true;
        }
        catch
        {
            return false;
        }
    }
}