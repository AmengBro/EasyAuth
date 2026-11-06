using System.IO;

namespace ClassIsland.EasyAuth.Services;

/// <summary>
/// 插件自有文件的目录解析。
///
/// ClassIsland 把两个目录分得很清楚（见 PluginService / 插件基础知识文档）：
///   data\Plugins\&lt;插件id&gt;\            插件安装目录：只放 DLL、manifest.yml、图标等，
///                                       插件更新时会被整目录替换/删除，且不会被自动备份。
///   data\Config\Plugins\&lt;插件id&gt;\      插件配置目录：插件自己写的配置与日志都放这里，
///                                       会被自动备份，更新插件不会丢。
/// 宿主通过 PluginBase.PluginConfigFolder 把后者交给插件，我们在 Plugin.Initialize 里注入。
///
/// 绝不能用 AppContext.BaseDirectory —— 插件跑在独立 AssemblyLoadContext 里，
/// 那个属性返回的是 ClassIsland 宿主程序目录。
/// </summary>
public static class PluginPaths
{
    public const string PluginId = "cn.amengbro.easyauth";

    private static string? _configuredDirectory;

    /// <summary>
    /// 由插件入口注入宿主提供的配置目录（PluginBase.PluginConfigFolder）。
    /// 传 null / 空表示清除注入，回到自测回退路径。
    /// </summary>
    public static void Configure(string? configFolder)
    {
        _configuredDirectory = string.IsNullOrWhiteSpace(configFolder)
            ? null
            : Path.GetFullPath(configFolder);
    }

    /// <summary>插件配置目录：state.json / api.json / audit.log / service.log 全部写这里。</summary>
    public static string PluginDirectory => _configuredDirectory ?? ResolveFallbackDirectory();

    /// <summary>插件安装目录（本程序集所在），只在升级迁移时用来读取旧版遗留数据。</summary>
    public static string InstallDirectory { get; } = ResolveInstallDirectory();

    /// <summary>插件配置目录下的子路径。</summary>
    public static string Combine(params string[] parts)
    {
        return Path.Combine(new[] { PluginDirectory }.Concat(parts).ToArray());
    }

    /// <summary>确保配置目录存在。宿主一般会建好，这里再兜一层。</summary>
    public static void EnsureDataDirectory()
    {
        try
        {
            Directory.CreateDirectory(PluginDirectory);
        }
        catch
        {
            // 只读环境下由各写入方的 try/catch 兜底
        }
    }

    /// <summary>
    /// 升级兼容：v0.3.0 及更早版本把配置写在插件安装目录，改到配置目录后
    /// 一次性把仍能影响功能的文件复制过来。
    /// 只搬 state.json（存活计数 / 配对事实）与 api.json（API 令牌）；
    /// 日志不搬——旧 audit.log 混着运维事件，留在原处当历史留存即可。
    /// 只复制、不移动、不删除原件，迁移失败静默忽略并继续用新目录。
    /// 返回实际复制的文件名列表，供运行日志记录。
    /// </summary>
    /// <param name="legacyDirectory">旧目录；不传则用插件安装目录（仅自测时显式指定）。</param>
    public static List<string> MigrateLegacyFiles(string? legacyDirectory = null)
    {
        var copied = new List<string>();
        try
        {
            var dest = PluginDirectory;
            var src = legacyDirectory ?? InstallDirectory;
            if (SameDirectory(src, dest))
            {
                return copied;
            }
            Directory.CreateDirectory(dest);
            foreach (var name in new[] { PluginStateStore.StateFileName, "api.json" })
            {
                var from = Path.Combine(src, name);
                var to = Path.Combine(dest, name);
                if (File.Exists(from) && !File.Exists(to))
                {
                    File.Copy(from, to);
                    copied.Add(name);
                }
            }
        }
        catch
        {
            // 迁移失败不影响插件加载
        }
        return copied;
    }

    private static bool SameDirectory(string a, string b)
    {
        try
        {
            var left = Path.GetFullPath(a).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var right = Path.GetFullPath(b).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            return string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static string ResolveFallbackDirectory()
    {
        // 插件入口没注入时（独立自测、外部加载等），按便携版约定推导，
        // 仍然不往插件安装目录里写东西。
        try
        {
            var guessed = Path.Combine(AppContext.BaseDirectory, "data", "Config", "Plugins", PluginId);
            Directory.CreateDirectory(guessed);
            return guessed;
        }
        catch
        {
            return InstallDirectory;
        }
    }

    private static string ResolveInstallDirectory()
    {
        try
        {
            var location = typeof(PluginPaths).Assembly.Location;
            if (!string.IsNullOrEmpty(location))
            {
                var dir = Path.GetDirectoryName(location);
                if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
                {
                    return dir;
                }
            }
        }
        catch
        {
            // 忽略，走回退
        }
        return AppContext.BaseDirectory;
    }
}
