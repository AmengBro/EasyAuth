using System.Text;
using ClassIsland.EasyAuth.Models;

namespace ClassIsland.EasyAuth.Services;

/// <summary>
/// 凭据身份：把「这条凭据对应哪支 U 盘、用哪种模式」讲清楚。
///
/// 宿主的授权窗口把每条凭据显示成固定模板「用 {ProviderInfo.Name} 继续」，
/// 而 ProviderInfo 来自全局注册表、Name 是只读的编译期 Attribute，
/// 插件无法给每条凭据单独加括号标识（CredentialItem.CustomName 目前也没有任何 UI 使用）。
/// 所以身份信息只能呈现于插件自己的控件区域；这里集中放纯逻辑，便于自测。
/// </summary>
public static class CredentialIdentity
{
    /// <summary>标签最大长度，避免撑爆授权窗口，也避免超长审计字段。</summary>
    public const int MaxLabelLength = 24;

    /// <summary>
    /// 清洗用户输入的凭据标签：去控制字符（否则能伪造日志行 / 撑乱布局）、
    /// 双引号换单引号、限长。空标签表示「未命名」。
    /// </summary>
    public static string SanitizeLabel(string? raw)
    {
        if (string.IsNullOrEmpty(raw))
        {
            return "";
        }
        var sb = new StringBuilder();
        foreach (var c in raw)
        {
            if (char.IsControl(c))
            {
                continue;
            }
            sb.Append(c == '"' ? '\'' : c);
        }
        var s = sb.ToString().Trim();
        return s.Length <= MaxLabelLength ? s : s[..MaxLabelLength];
    }

    /// <summary>审计日志用：标签里的空格换成下划线，保持 key=value 格式可读。</summary>
    public static string ForLog(string? raw) => SanitizeLabel(raw).Replace(' ', '_');

    /// <summary>控件顶部标题。这就是用户想要的「括号标识」，只是落在插件自己的区域。</summary>
    public static string BuildTitle(UsbKeyAuthSettings s)
    {
        var label = SanitizeLabel(s.CredentialLabel);
        return label.Length == 0 ? "通过 EasyAuth 验证" : $"通过 EasyAuth 验证（{label}）";
    }

    /// <summary>序列号尾 4 位，够认盘又不至于把完整 SN 铺在屏幕上。</summary>
    public static string ShortSerial(string? serial)
    {
        var s = (serial ?? "").Trim();
        if (s.Length == 0)
        {
            return "";
        }
        return s.Length <= 4 ? s : "…" + s[^4..];
    }

    /// <summary>
    /// 本凭据授权的卷 GUID 集合。
    /// 老凭据（单分区）可能没有 AuthorizedVolumeGuids，回退到 PairedVolumeGuid。
    /// 这是「两颗盘同时插着时用哪一个」的唯一判定依据——模式与盘都跟着凭据走，
    /// 不跟着当前插着的设备自动切换。
    /// </summary>
    public static IReadOnlyList<string> AllowedVolumeGuids(UsbKeyAuthSettings s)
    {
        var list = (s.AuthorizedVolumeGuids ?? [])
            .Where(g => !string.IsNullOrWhiteSpace(g))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (list.Count == 0 && !string.IsNullOrWhiteSpace(s.PairedVolumeGuid))
        {
            list.Add(s.PairedVolumeGuid);
        }
        return list;
    }

    public static bool IsAllowed(UsbKeyAuthSettings s, string? volumeGuid)
    {
        if (string.IsNullOrWhiteSpace(volumeGuid))
        {
            return false;
        }
        return AllowedVolumeGuids(s).Any(g =>
            string.Equals(g, volumeGuid, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>认证态：卷下拉框只留本凭据授权的分区；编辑态仍列全量以便配对新盘。</summary>
    public static List<VolumeInfo> FilterVolumes(UsbKeyAuthSettings s, IEnumerable<VolumeInfo> all)
        => all.Where(v => IsAllowed(s, v.VolumeGuid)).ToList();

    /// <summary>
    /// 认证态：设备下拉框只留含本凭据授权分区的设备。
    /// 授权卷被「过小分区」规则丢掉的设备也要保留，否则用户会以为盘根本没插。
    /// 不改写 group.Volumes，避免影响 VerifyAsync 里按授权列表取交集的既有逻辑。
    /// </summary>
    public static List<DiskGroupInfo> FilterGroups(UsbKeyAuthSettings s, IEnumerable<DiskGroupInfo> all)
        => all.Where(g => g.Volumes.Any(v => IsAllowed(s, v.VolumeGuid))
                          || g.SkippedVolumes.Any(v => IsAllowed(s, v.VolumeGuid))).ToList();

    /// <summary>设备下拉框文字：说明本凭据要求几个分区、当前可见几个。</summary>
    public static string BuildGroupLabel(DiskGroupInfo g, UsbKeyAuthSettings s)
    {
        var visible = g.Volumes.Count(v => IsAllowed(s, v.VolumeGuid));
        var required = AllowedVolumeGuids(s).Count;
        var tail = required > visible
            ? $" · 本凭据应有 {required} 个分区，当前可见 {visible} 个"
            : $" · 本凭据 {visible} 个分区";
        return $"{g.Model}（SN {g.DiskSerial}）{tail}";
    }

    /// <summary>一行身份摘要，显示在标题下方。</summary>
    public static string BuildIdentityLine(UsbKeyAuthSettings s)
    {
        var allowed = AllowedVolumeGuids(s);
        if (allowed.Count == 0)
        {
            return "本凭据：尚未配对（请先在编辑界面完成配对）";
        }
        var label = SanitizeLabel(s.CredentialLabel);
        var who = label.Length > 0
            ? label
            : (string.IsNullOrWhiteSpace(s.BrandHint) ? "未命名" : s.BrandHint.Trim());
        var mode = s.MultiPartitionMode ? "多分区同时校验" : "单分区校验";
        var sn = ShortSerial(s.PairedDiskSerial);
        return $"本凭据：{who} · {mode} · 授权 {allowed.Count} 个分区" +
               (sn.Length == 0 ? "" : $" · SN {sn}");
    }

    /// <summary>
    /// 找出「本凭据要求、但当前枚举结果里没有」的授权卷。
    /// 多分区模式下缺任何一个都不应放行，否则只插一部分分区即可绕过。
    /// </summary>
    public static List<string> FindMissing(UsbKeyAuthSettings s, IEnumerable<VolumeInfo> present)
    {
        var seen = new HashSet<string>(
            present.Select(v => v.VolumeGuid ?? ""), StringComparer.OrdinalIgnoreCase);
        return AllowedVolumeGuids(s).Where(g => !seen.Contains(g)).ToList();
    }
}
