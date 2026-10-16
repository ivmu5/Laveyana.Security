using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Laveyana.Security.FileSystem.Storage;

/// <summary>Linux-specific directory-relative filesystem operations with no-follow descriptors.</summary>
/// <remarks>All mutations stay bound to the opened directory even if its pathname is renamed.</remarks>
internal sealed class LinuxSecureDirectory : IDisposable
{
    private const int AtFdcwd = -100;
    private const int AtSymlinkNoFollow = 0x100;
    private const int AtEmptyPath = 0x1000;
    private const uint StatxBasicStats = 0x7ff;
    private const int OReadOnly = 0;
    private const int OWriteOnly = 1;
    private const int OReadWrite = 2;
    private const int OCreate = 0x40;
    private const int OExclusive = 0x80;
    private const int ODirectory = 0x10000;
    private const int ONoFollow = 0x20000;
    private const int OCloseOnExec = 0x80000;
    private const int OSync = 0x101000;
    private const int LockExclusiveNonBlocking = 2 | 4;
    private const int RegularFile = 0x8000;
    private const int DirectoryFile = 0x4000;
    private const int TypeMask = 0xF000;
    private const int GroupOrOtherPermissions = 0x3F;
    private const int StickyBit = 0x200;
    private const int ENoEnt = 2;
    private const int EWouldBlock = 11;
    private const uint OwnerReadWrite = 0x180; // octal 0600

    private readonly SafeFileHandle _directory;

    private LinuxSecureDirectory(int descriptor)
    {
        _directory = new SafeFileHandle((IntPtr)descriptor, ownsHandle: true);
    }

    internal static LinuxSecureDirectory Open(string root)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("Linux descriptor-based store access requires Linux.");
        }

        ValidateAncestors(root);
        int descriptor = open(root, OReadOnly | ODirectory | ONoFollow | OCloseOnExec, 0);
        if (descriptor < 0)
        {
            throw NativeError("Opening store root");
        }

        LinuxSecureDirectory directory = new(descriptor);
        try
        {
            directory.VerifyDescriptor(descriptor, true);
            LinuxStatx pathState = GetStat(AtFdcwd, root, AtSymlinkNoFollow);
            LinuxStatx handleState = GetStat(descriptor, "", AtEmptyPath);
            if (pathState.Inode != handleState.Inode || pathState.DeviceMajor != handleState.DeviceMajor ||
                pathState.DeviceMinor != handleState.DeviceMinor)
            {
                throw new IOException("Store root changed during directory acquisition.");
            }

            return directory;
        }
        catch
        {
            directory.Dispose();
            throw;
        }
    }

    internal bool Exists(string name)
    {
        ValidateName(name);
        if (statx(Fd, name, AtSymlinkNoFollow, StatxBasicStats, out LinuxStatx state) != 0)
        {
            if (Marshal.GetLastPInvokeError() == ENoEnt)
            {
                return false;
            }

            throw NativeError("Inspecting store entry");
        }

        RequireStatFields(state);
        VerifyState(state, false);
        return true;
    }

    internal FileStream OpenRead(string name)
    {
        int descriptor = OpenChild(name, OReadOnly | ONoFollow | OCloseOnExec, 0);
        try
        {
            VerifyDescriptor(descriptor, false);
        }
        catch
        {
            close(descriptor);
            throw;
        }

        return AsStream(descriptor, FileAccess.Read);
    }

    internal FileStream CreateTemporary(string name)
    {
        int descriptor = OpenChild(name,
            OWriteOnly | OCreate | OExclusive | ONoFollow | OCloseOnExec | OSync, OwnerReadWrite);
        try
        {
            VerifyDescriptor(descriptor, false);
        }
        catch
        {
            close(descriptor);
            throw;
        }

        return AsStream(descriptor, FileAccess.Write);
    }

    internal FileStream? TryAcquireLock(string name)
    {
        int descriptor = OpenChild(name, OReadWrite | OCreate | ONoFollow | OCloseOnExec, OwnerReadWrite);
        try
        {
            VerifyDescriptor(descriptor, false);
            if (flock(descriptor, LockExclusiveNonBlocking) != 0)
            {
                int errno = Marshal.GetLastPInvokeError();
                if (errno == EWouldBlock)
                {
                    close(descriptor);
                    return null;
                }

                throw new IOException($"Cannot lock store file (errno {errno}).");
            }

        }
        catch
        {
            close(descriptor);
            throw;
        }

        return AsStream(descriptor, FileAccess.ReadWrite);
    }

    internal void Move(string temporaryName, string destinationName, bool overwrite)
    {
        ValidateName(temporaryName);
        ValidateName(destinationName);
        if (Exists(destinationName) && !overwrite)
        {
            throw new IOException("Store destination already exists.");
        }

        int result = overwrite
            ? renameat(Fd, temporaryName, Fd, destinationName)
            : renameat2(Fd, temporaryName, Fd, destinationName, 1);
        if (result != 0)
        {
            throw NativeError("Replacing store snapshot");
        }

        // Post-rename failure is an uncertain commit; callers must reconcile.
        if (fsync(Fd) != 0)
        {
            throw NativeError("Synchronizing store directory");
        }
    }

    internal void Remove(string name)
    {
        ValidateName(name);
        if (Exists(name) && unlinkat(Fd, name, 0) != 0)
        {
            throw NativeError("Removing temporary store file");
        }
    }

    public void Dispose() => _directory.Dispose();

    private int Fd => checked((int)_directory.DangerousGetHandle());

    private int OpenChild(string name, int flags, uint mode)
    {
        ValidateName(name);
        int descriptor = openat(Fd, name, flags, mode);
        if (descriptor < 0)
        {
            throw NativeError("Opening store child");
        }

        return descriptor;
    }

    private static FileStream AsStream(int descriptor, FileAccess access)
    {
        SafeFileHandle handle = new((IntPtr)descriptor, ownsHandle: true);
        try
        {
            return new FileStream(handle, access, 65536, isAsync: true);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static void ValidateName(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name is "." or ".." ||
            name.Contains('/') || name.Contains('\\') || name.Contains('\0'))
        {
            throw new ArgumentException("Store entry must be a single canonical filename.", nameof(name));
        }
    }

    private static void ValidateAncestors(string root)
    {
        string current = Path.GetPathRoot(root)!;
        uint currentUser = geteuid();
        foreach (string component in root[current.Length..].Split(Path.DirectorySeparatorChar,
            StringSplitOptions.RemoveEmptyEntries))
        {
            ValidateAncestor(current, currentUser, false);
            current = Path.Combine(current, component);
        }

        ValidateAncestor(current, currentUser, true);
    }

    private static void ValidateAncestor(string path, uint currentUser, bool isRoot)
    {
        LinuxStatx stat = GetStat(AtFdcwd, path, AtSymlinkNoFollow);
        if ((stat.Mode & TypeMask) != DirectoryFile)
        {
            throw new IOException("A store path component is redirected or is not a directory.");
        }

        int mode = stat.Mode;
        if (isRoot)
        {
            if (stat.Uid != currentUser || (mode & GroupOrOtherPermissions) != 0 ||
                (mode & 0x1C0) != 0x1C0) // 0700 required for owner
            {
                throw new UnauthorizedAccessException("Store root must be owner-controlled mode 0700.");
            }
        }
        else if ((stat.Uid != 0 && stat.Uid != currentUser) ||
            ((mode & 0x12) != 0 && !(stat.Uid == 0 && (mode & StickyBit) != 0)))
        {
            // 0x12 = other/group write bits (octal 022).
            throw new UnauthorizedAccessException("Unsafe writable or foreign-owned ancestor directory.");
        }
    }

    private void VerifyDescriptor(int descriptor, bool directory)
    {
        LinuxStatx state = GetStat(descriptor, "", AtEmptyPath);
        VerifyState(state, directory);
    }

    private static void VerifyState(LinuxStatx state, bool directory)
    {
        if ((state.Mode & TypeMask) != (directory ? DirectoryFile : RegularFile))
        {
            throw new IOException("Store entry is redirected or has an invalid type.");
        }

        if (state.Uid != geteuid() || (state.Mode & GroupOrOtherPermissions) != 0 ||
            (directory && (state.Mode & 0x1C0) != 0x1C0))
        {
            throw new UnauthorizedAccessException("Store file owner/mode validation failed.");
        }
    }

    private static LinuxStatx GetStat(int fd, string path, int flags)
    {
        if (statx(fd, path, flags, StatxBasicStats, out LinuxStatx state) != 0)
        {
            throw NativeError("Inspecting store filesystem metadata");
        }

        RequireStatFields(state);
        return state;
    }

    private static void RequireStatFields(LinuxStatx state)
    {
        if ((state.Mask & 0x10B) != 0x10B) // STATX_TYPE|STATX_MODE|STATX_UID|STATX_INO
        {
            throw new IOException("Filesystem did not report required statx metadata.");
        }
    }

    private static IOException NativeError(string operation) =>
        new($"{operation} failed: {new Win32Exception(Marshal.GetLastPInvokeError()).Message}");

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct LinuxStatx
    {
        [FieldOffset(0)] public uint Mask;
        [FieldOffset(20)] public uint Uid;
        [FieldOffset(28)] public ushort Mode;
        [FieldOffset(32)] public ulong Inode;
        [FieldOffset(136)] public uint DeviceMajor;
        [FieldOffset(140)] public uint DeviceMinor;
    }

    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int open(string path, int flags, uint mode);

    [DllImport("libc", EntryPoint = "openat", SetLastError = true)]
    private static extern int openat(int fd, string name, int flags, uint mode);

    [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
    private static extern int statx(int fd, string path, int flags, uint mask, out LinuxStatx state);

    [DllImport("libc", EntryPoint = "renameat", SetLastError = true)]
    private static extern int renameat(int oldFd, string oldName, int newFd, string newName);

    [DllImport("libc", EntryPoint = "renameat2", SetLastError = true)]
    private static extern int renameat2(int oldFd, string oldName, int newFd, string newName, uint flags);

    [DllImport("libc", EntryPoint = "unlinkat", SetLastError = true)]
    private static extern int unlinkat(int fd, string name, int flags);

    [DllImport("libc", EntryPoint = "flock", SetLastError = true)]
    private static extern int flock(int fd, int operation);

    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static extern int fsync(int fd);

    [DllImport("libc", EntryPoint = "close", SetLastError = true)]
    private static extern int close(int fd);

    [DllImport("libc", EntryPoint = "geteuid")]
    private static extern uint geteuid();
}
