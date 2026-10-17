namespace ClassIsland.EasyAuth.Models;

/// <summary>
/// 一个可访问卷（分区）的探测信息。
/// </summary>
public class VolumeInfo
{
    /// <summary>卷 GUID 路径，形如 \\?\Volume{...}\</summary>
    public string VolumeGuid { get; set; } = "";

    /// <summary>挂载点列表（盘符，如 C:\）</summary>
    public List<string> MountPoints { get; set; } = [];

    /// <summary>主盘符（如 "C"），无盘符卷为空</summary>
    public string DriveLetter { get; set; } = "";

    /// <summary>下拉框显示名（有盘符显示盘符，否则显示卷 GUID）</summary>
    public string DisplayName => string.IsNullOrEmpty(DriveLetter) ? VolumeGuid : DriveLetter + @":\";

    /// <summary>卷标（读取失败为 null）</summary>
    public string? VolumeLabel { get; set; }

    /// <summary>卷的磁盘设备号（IOCTL_STORAGE_GET_DEVICE_NUMBER，读取失败为 null）</summary>
    public int? DeviceNumber { get; set; }

    /// <summary>所在物理磁盘的硬件序列号（经卷句柄读取，失败为 null）</summary>
    public string? DiskSerialNumber { get; set; }

    /// <summary>所在物理磁盘的型号（读取失败为 null）</summary>
    public string? DiskModel { get; set; }

    /// <summary>分区总容量（字节，读取失败为 null）</summary>
    public long? TotalSize { get; set; }

    /// <summary>分区可用空间（字节，读取失败为 null）</summary>
    public long? AvailableFreeSpace { get; set; }

    /// <summary>驱动器类型（Removable/Fixed/Network 等，读取失败为 null）</summary>
    public string? DriveType { get; set; }

    /// <summary>设备信息是否完整读取（SN 非空）</summary>
    public bool InfoComplete => !string.IsNullOrWhiteSpace(DiskSerialNumber);
}
