using System.IO;
using System.Reflection;

namespace ClassIsland.EasyAuth.Services;

/// <summary>
/// 插件自有文件的目录解析。
/// </summary>
public static class PluginPaths
{
    /// <summary>
    /// 插件自己的目录（data\Plugins\&lt;插件id&gt;\）。
    /// 不能用 AppContext.BaseDirectory——插件运行在独立的 AssemblyLoadContext 中，
    /// 那个属性返回的是 ClassIsland 宿主程序目录，会把 state.json / audit.log
    /// 写进程序目录（污染安装目录、更新即丢、只读安装时静默失败）。
    /// </summary>
    public static string PluginDirectory { get; } = ResolvePluginDirectory();

    private static string ResolvePluginDirectory()
    {
        // 优先用插件程序集自身的位置
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

        // 回退：宿主基目录（单文件/内存加载等异常场景）
        return AppContext.BaseDirectory;
    }

    /// <summary>插件目录下的子路径。</summary>
    public static string Combine(params string[] parts)
    {
        return Path.Combine(new[] { PluginDirectory }.Concat(parts).ToArray());
    }
}
