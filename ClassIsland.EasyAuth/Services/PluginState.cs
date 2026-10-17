using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ClassIsland.EasyAuth.Services;

/// <summary>
/// 插件自有状态（存活克隆计数）。
/// 存放在插件自己的目录（data/Plugins/&lt;插件id&gt;/state.json），
/// 不写 ClassIsland 的凭据文件——凭据只在编辑模式保存，
/// 认证时改内存里的 ProviderSettings 不会落盘。
/// </summary>
public class PluginState
{
    /// <summary>当前存活计数（上次成功认证时的值）</summary>
    public int LiveCounter { get; set; }

    /// <summary>配对时的卷 GUID（信息字段，便于排查）</summary>
    public string PairedVolumeGuid { get; set; } = "";

    /// <summary>状态文件是否已存在（区分"首次"与"计数不符"）</summary>
    [JsonIgnore]
    public bool Exists { get; set; }
}

public static class PluginStateStore
{
    public const string StateFileName = "state.json";

    /// <summary>加载状态；文件不存在返回 Exists=false 的空状态。</summary>
    public static PluginState Load(string stateDir)
    {
        var path = Path.Combine(stateDir, StateFileName);
        try
        {
            if (File.Exists(path))
            {
                var state = JsonSerializer.Deserialize<PluginState>(File.ReadAllText(path)) ?? new PluginState();
                state.Exists = true;
                return state;
            }
        }
        catch
        {
            // 损坏当作不存在处理（调用方按首次配对接纳）
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
