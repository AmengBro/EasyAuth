namespace ClassIsland.EasyAuth.Models;

/// <summary>
/// 设备视图：一个物理磁盘（含其所有可校验分区）。
/// 多分区同时校验模式下，下拉框展示设备名；选中设备即校验其全部合格分区。
/// </summary>
public class DiskGroupInfo
{
    /// <summary>分组键：磁盘硬件序列号（同一物理磁盘的所有分区 SN 相同）</summary>
    public string DiskSerial { get; set; } = "";

    /// <summary>设备名（磁盘型号）</summary>
    public string Model { get; set; } = "未知设备";

    /// <summary>该设备下参与校验的分区（已过滤小分区）</summary>
    public List<VolumeInfo> Volumes { get; set; } = [];

    /// <summary>该设备下被丢弃的小分区（仅提示用）</summary>
    public List<VolumeInfo> SkippedVolumes { get; set; } = [];

    /// <summary>下拉框显示名</summary>
    public string DisplayName =>
        $"{Model}（{(string.IsNullOrEmpty(DiskSerial) ? "序列号未知" : "SN " + DiskSerial)}）" +
        $"· {Volumes.Count} 个分区";

    /// <summary>品牌提示（是否 WD 等，仅界面展示）</summary>
    public string BrandHint =>
        Model.Contains("WD", StringComparison.OrdinalIgnoreCase) ? "WD" :
        Model.Contains("Samsung", StringComparison.OrdinalIgnoreCase) ? "Samsung" :
        Model.Contains("Kingston", StringComparison.OrdinalIgnoreCase) ? "Kingston" :
        Model.Contains("SanDisk", StringComparison.OrdinalIgnoreCase) ? "SanDisk" : "";
}
