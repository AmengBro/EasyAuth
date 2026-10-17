using System.Diagnostics;

namespace ClassIsland.EasyAuth.Services;

/// <summary>
/// mountvol 输出解析器。按结构解析，不依赖本地化表头文字
/// （中文 Windows 下表头为"当前装入的 VolumeName 值为:"等）。
/// 只收录带盘符挂载点的卷；隐藏/EFI/恢复分区（无挂载点）被跳过。
/// </summary>
public static class MountVolParser
{
    /// <summary>
    /// 执行 mountvol 并解析输出。返回带盘符的卷列表。
    /// </summary>
    public static List<ParsedVolume> EnumerateVolumesWithLetters()
    {
        var output = RunMountVol();
        var result = new List<ParsedVolume>();
        if (string.IsNullOrEmpty(output))
        {
            return result;
        }

        ParsedVolume? current = null;
        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r').Trim();

            // 卷 GUID 行：\\?\Volume{xxxxxxxx-....}\
            if (line.StartsWith(@"\\?\Volume{") && line.EndsWith("\\"))
            {
                var start = line.IndexOf('{') + 1;
                var end = line.IndexOf('}', start);
                if (start > 0 && end > start)
                {
                    current = new ParsedVolume
                    {
                        VolumeGuid = @"\\?\Volume{" + line.Substring(start, end - start) + "}\\"
                    };
                    result.Add(current);
                }
                continue;
            }

            // 挂载点行：盘符（如 C:\）。目录挂载点与无挂载点卷在此场景不收录
            if (current != null && line.Length == 3 && char.IsLetter(line[0]) && line[1] == ':' && line[2] == '\\')
            {
                var letter = char.ToUpperInvariant(line[0]) + @":\";
                if (!current.MountPoints.Contains(letter))
                {
                    current.MountPoints.Add(letter);
                }
            }
        }

        return result;
    }

    private static string RunMountVol()
    {
        try
        {
            var psi = new ProcessStartInfo("mountvol")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null)
            {
                return "";
            }
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);
            return output;
        }
        catch
        {
            return "";
        }
    }
}

/// <summary>mountvol 解析出的一个卷</summary>
public class ParsedVolume
{
    public string VolumeGuid { get; set; } = "";

    public List<string> MountPoints { get; set; } = [];
}
