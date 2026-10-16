using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Laveyana.Security.IntegrationTests;

/// <summary>EXPERIMENTAL / TEST ONLY. Constructs Windows mount-point junctions for security tests.</summary>
/// <remarks>Never use this helper against an existing directory or outside disposable test paths.</remarks>
[SupportedOSPlatform("windows")]
internal static class WindowsJunctionTestSupport
{
    private const uint IoReparseTagMountPoint = 0xA0000003;
    private const uint FsctlSetReparsePoint = 0x000900A4;
    private const uint GenericWrite = 0x40000000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint OpenExisting = 3;
    private const int ErrorPrivilegeNotHeld = 1314;
    private const int ErrorNotSupported = 50;
    private const int ErrorInvalidFunction = 1;

    internal static void CreateJunction(string junction, string target)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Junction tests require Windows.");
        }

        if (Directory.Exists(junction) || File.Exists(junction))
        {
            throw new IOException("Junction test entry already exists; refusing to replace it.");
        }

        string targetPath = Path.GetFullPath(target);
        if (!Directory.Exists(targetPath) || targetPath.StartsWith(@"\\", StringComparison.Ordinal))
        {
            throw new IOException("Junction target must be an existing local directory.");
        }

        // NTFS mount-point reparse data requires an NT substitute name (\\??\\C:\\...).
        string substitute = @"\??\" + targetPath;
        byte[] substituteBytes = Encoding.Unicode.GetBytes(substitute);
        byte[] printBytes = Encoding.Unicode.GetBytes(targetPath);
        int nameOffset = checked(substituteBytes.Length + sizeof(char));
        int dataLength = checked(8 + substituteBytes.Length + sizeof(char) +
            printBytes.Length + sizeof(char));
        if (dataLength > ushort.MaxValue || nameOffset > ushort.MaxValue)
        {
            throw new IOException("Junction target path is too long for a reparse buffer.");
        }

        byte[] buffer = new byte[8 + dataLength];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(0, 4),
            IoReparseTagMountPoint);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(4, 2),
            checked((ushort)dataLength));
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(8, 2), 0);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(10, 2),
            checked((ushort)substituteBytes.Length));
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(12, 2),
            checked((ushort)nameOffset));
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(14, 2),
            checked((ushort)printBytes.Length));
        substituteBytes.CopyTo(buffer, 16);
        printBytes.CopyTo(buffer, checked(16 + nameOffset));

        Directory.CreateDirectory(junction);
        bool created = false;
        try
        {
            using SafeFileHandle handle = CreateFileW(junction, GenericWrite,
                (uint)(FileShare.ReadWrite | FileShare.Delete), nint.Zero, OpenExisting,
                FileFlagBackupSemantics | FileFlagOpenReparsePoint, nint.Zero);
            if (handle.IsInvalid)
            {
                throw new IOException("Cannot open the disposable junction directory.",
                    new Win32Exception(Marshal.GetLastPInvokeError()));
            }

            if (!DeviceIoControl(handle, FsctlSetReparsePoint, buffer, (uint)buffer.Length,
                    nint.Zero, 0, out _, nint.Zero))
            {
                int error = Marshal.GetLastPInvokeError();
                // Missing NTFS support or privilege is a platform skip, not a pass.
                // Do not hide any other error (in particular INVALID_PARAMETER).
                if (error is ErrorPrivilegeNotHeld or ErrorNotSupported or ErrorInvalidFunction)
                {
                    NUnit.Framework.Assert.Ignore($"NTFS junction creation unavailable (Windows error {error}).");
                }

                throw new IOException("Creating a Windows junction failed.", new Win32Exception(error));
            }

            created = true;
        }
        finally
        {
            // A failed setup must not leave an ordinary empty directory behind.
            // Dispose the native handle before the non-recursive cleanup.
            if (!created && Directory.Exists(junction) &&
                !File.GetAttributes(junction).HasFlag(FileAttributes.ReparsePoint))
            {
                Directory.Delete(junction);
            }
        }
    }

    internal static void DeleteJunctionIfPresent(string path)
    {
        if (!Directory.Exists(path) && !File.Exists(path))
        {
            return;
        }

        if (!File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
        {
            throw new IOException("Refusing to remove a non-junction test directory.");
        }

        // Directory.Delete without recursion removes the reparse entry, not its target.
        Directory.Delete(path);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "CreateFileW", SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string filename, uint desiredAccess,
        uint shareMode, nint securityAttributes, uint creationDisposition,
        uint flagsAndAttributes, nint templateFile);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(SafeFileHandle device, uint ioControlCode,
        byte[] input, uint inputSize, nint output, uint outputSize,
        out uint bytesReturned, nint overlapped);
}
