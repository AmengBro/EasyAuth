using System.Management;
using System.Runtime.InteropServices;
using ClassIsland.EasyAuth.Models;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace ClassIsland.EasyAuth.Services;

/// <summary>
/// 磁盘/卷设备信息探测。
/// - 卷枚举/盘符/卷GUID：mountvol 解析（按结构，免本地化表头）
/// - 磁盘序列号/型号：WMI（Win32_LogicalDisk -> Win32_DiskDrive 关联查询，免管理员）
/// - 卷设备号：IOCTL_STORAGE_GET_DEVICE_NUMBER（经卷句柄，免管理员，仅诊断用）
/// 注意：IOCTL_STORAGE_QUERY_PROPERTY 无法经卷句柄下发（ERROR_CALL_NOT_IMPLEMENTED=24），
/// 而打开 \\.\PhysicalDriveN 需要管理员权限，故序列号走 WMI。
/// </summary>
public static class DiskInfoService
{
    private const uint IoCtlStorageGetDeviceNumber = 0x002D1080;
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;

    /// <summary>多分区校验的容量门槛：分区总容量小于 32MB 视为系统保留分区，丢弃</summary>
    public const long MinVolumeTotalBytes = 32L * 1024 * 1024;

    /// <summary>多分区校验的容量门槛：分区可用空间小于 16MB 视为不可用，丢弃</summary>
    public const long MinVolumeFreeBytes = 16L * 1024 * 1024;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    /// <summary>读取本机 MachineGuid（HKLM\SOFTWARE\Microsoft\Cryptography），失败返回 null。</summary>
    public static string? GetMachineGuid()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
            return key?.GetValue("MachineGuid") as string;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// 枚举所有带盘符的卷及其所在磁盘信息。
    /// </summary>
    public static List<VolumeInfo> EnumerateVolumes()
    {
        var volumes = new List<VolumeInfo>();

        foreach (var p in MountVolParser.EnumerateVolumesWithLetters())
        {
            var letter = p.MountPoints.FirstOrDefault();
            if (string.IsNullOrEmpty(letter))
            {
                continue;
            }

            var info = new VolumeInfo
            {
                VolumeGuid = p.VolumeGuid,
                MountPoints = p.MountPoints,
                DriveLetter = letter.TrimEnd('\\', ':')
            };
            try
            {
                var drive = new DriveInfo(info.DriveLetter + ":\\");
                if (drive.IsReady)
                {
                    info.VolumeLabel = drive.VolumeLabel;
                    info.TotalSize = drive.TotalSize;
                    info.AvailableFreeSpace = drive.AvailableFreeSpace;
                }
                info.DriveType = drive.DriveType.ToString();
            }
            catch
            {
                // 卷未就绪时卷标/容量读不到，忽略
            }

            var disk = GetDiskByLetter(info.DriveLetter);
            info.DiskSerialNumber = disk?.Serial;
            info.DiskModel = disk?.Model;

            volumes.Add(info);
        }

        return volumes;
    }

    /// <summary>
    /// 设备视图：按磁盘序列号把分区归组，过滤掉过小的分区（系统保留/恢复分区）。
    /// 多分区同时校验模式下由界面展示该列表。
    /// </summary>
    public static List<DiskGroupInfo> EnumerateDiskGroups()
    {
        var groups = new List<DiskGroupInfo>();
        var bySerial = new Dictionary<string, DiskGroupInfo>(StringComparer.OrdinalIgnoreCase);

        foreach (var v in EnumerateVolumes())
        {
            if (string.IsNullOrWhiteSpace(v.DiskSerialNumber))
            {
                // 读不到序列号的卷无法归组，只在单分区模式下可用
                continue;
            }
            var serial = v.DiskSerialNumber;
            if (!bySerial.TryGetValue(serial, out var group))
            {
                group = new DiskGroupInfo
                {
                    DiskSerial = serial,
                    Model = string.IsNullOrWhiteSpace(v.DiskModel) ? "未知设备" : v.DiskModel!
                };
                bySerial[serial] = group;
                groups.Add(group);
            }

            var tooSmall =
                (v.TotalSize.HasValue && v.TotalSize.Value < MinVolumeTotalBytes) ||
                (v.AvailableFreeSpace.HasValue && v.AvailableFreeSpace.Value < MinVolumeFreeBytes);
            if (tooSmall)
            {
                group.SkippedVolumes.Add(v);
            }
            else
            {
                group.Volumes.Add(v);
            }
        }

        // 可移动设备排前面（U 盘优先），其次按分区数多的排
        return groups
            .Where(g => g.Volumes.Count > 0)
            .OrderByDescending(g => g.Volumes.Any(v => v.DriveType == "Removable"))
            .ThenByDescending(g => g.Volumes.Count)
            .ToList();
    }

    /// <summary>
    /// 通过盘符查询所在物理磁盘的序列号/型号（WMI 两跳关联查询，免管理员）。
    /// Win32_LogicalDisk 与 Win32_DiskDrive 无直接关联，必须经
    /// Win32_LogicalDiskToPartition -> Win32_DiskDriveToDiskPartition 两跳。
    /// 失败返回 null。
    /// </summary>
    public static (string? Serial, string? Model)? GetDiskByLetter(string letter)
    {
        if (string.IsNullOrWhiteSpace(letter))
        {
            return null;
        }
        try
        {
            // 第一跳：盘符 -> 分区
            using var partSearcher = new ManagementObjectSearcher(
                $"ASSOCIATORS OF {{Win32_LogicalDisk.DeviceID='{letter}:'}} WHERE ResultClass=Win32_DiskPartition");
            foreach (var p in partSearcher.Get())
            {
                using var part = (ManagementObject)p;
                var partId = part["DeviceID"] as string;
                if (string.IsNullOrEmpty(partId))
                {
                    continue;
                }

                // 第二跳：分区 -> 磁盘
                using var diskSearcher = new ManagementObjectSearcher(
                    $"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{EscapeWql(partId)}'}} WHERE ResultClass=Win32_DiskDrive");
                foreach (var d in diskSearcher.Get())
                {
                    using var disk = (ManagementObject)d;
                    var serial = disk["SerialNumber"] as string;
                    var model = disk["Model"] as string;
                    return (string.IsNullOrWhiteSpace(serial) ? null : serial.Trim(),
                            string.IsNullOrWhiteSpace(model) ? null : model.Trim());
                }
            }
        }
        catch
        {
            // WMI 服务异常等，忽略
        }
        return null;
    }

    /// <summary>WQL 字符串字面量转义（单引号翻倍）。</summary>
    private static string EscapeWql(string value)
    {
        return value.Replace("'", "''");
    }

    /// <summary>
    /// 诊断用：对指定卷 GUID 逐步探测。
    /// </summary>
    public static string DiagnoseVolume(string volumeGuid)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"volume={volumeGuid}");

        var parsedLetter = MountVolParser.EnumerateVolumesWithLetters()
            .FirstOrDefault(v => v.VolumeGuid == volumeGuid)?.MountPoints.FirstOrDefault();
        sb.AppendLine($"letter={parsedLetter ?? "(无)"}");

        if (!string.IsNullOrEmpty(parsedLetter))
        {
            var letter = parsedLetter.TrimEnd('\\', ':');
            var disk = GetDiskByLetter(letter);
            sb.AppendLine(disk?.Serial != null
                ? $"wmi serial={disk.Value.Serial} model={disk.Value.Model}"
                : "wmi serial=FAIL");
        }

        var devicePath = volumeGuid.TrimEnd('\\');
        using var handle = CreateFileW(devicePath, GenericRead, FileShareRead | FileShareWrite,
            IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        sb.AppendLine(handle.IsInvalid
            ? $"openHandle=FAIL err={Marshal.GetLastWin32Error()}"
            : "openHandle=OK");
        if (!handle.IsInvalid)
        {
            var buffer = Marshal.AllocHGlobal(64);
            try
            {
                var ok = DeviceIoControl(handle, IoCtlStorageGetDeviceNumber, IntPtr.Zero, 0,
                    buffer, 64, out var returned, IntPtr.Zero);
                sb.AppendLine(ok && returned >= 12
                    ? $"devNum={Marshal.ReadInt32(buffer, 4)}"
                    : $"devNum=FAIL err={Marshal.GetLastWin32Error()}");
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        return sb.ToString();
    }
}
