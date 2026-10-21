using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Laveyana.Security.FileSystem.Storage;

/// <summary>Linux-specific directory-relative filesystem operations with no-follow descriptors.</summary>
/// <remarks>
/// EXPERIMENTAL / TEST ONLY: the Linux backend is not production-approved.
/// All mutations stay bound to the opened directory even if its pathname is renamed.
/// Root descriptor references are retained across native calls to avoid close/reuse races.
/// </remarks>
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
        bool rootReferenceAdded = false;
        try
        {
            int rootFd = AcquireDirectoryDescriptor(ref rootReferenceAdded);
            return ExistsCore(rootFd, name);
        }
        finally
        {
            if (rootReferenceAdded)
            {
                _directory.DangerousRelease();
            }
        }
    }

    // Caller must hold a SafeHandle reference for the entire native operation.
    private static bool ExistsCore(int rootFd, string name)
    {
        if (statx(rootFd, name, AtSymlinkNoFollow, StatxBasicStats, out LinuxStatx state) != 0)
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

    internal FileStream? TryAcquireLock(string name, bool createIfMissing)
    {
        int flags = OReadWrite | ONoFollow | OCloseOnExec;
        if (createIfMissing)
        {
            flags |= OCreate;
        }

        int descriptor = OpenChild(name, flags, OwnerReadWrite);
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

    internal void Move(string temporaryName, string destinationName, bool overwrite) =>
        MoveWithFault(temporaryName, destinationName, overwrite, null);

    internal void MoveWithFault(string temporaryName, string destinationName, bool overwrite,
        Action<StoreWriteBoundary, string>? fault)
    {
        ValidateName(temporaryName);
        ValidateName(destinationName);
        bool rootReferenceAdded = false;
        try
        {
            // The same pinned directory descriptor covers the destination check,
            // rename and durability barrier, even if Dispose races with Move.
            int rootFd = AcquireDirectoryDescriptor(ref rootReferenceAdded);
            if (ExistsCore(rootFd, destinationName) && !overwrite)
            {
                throw new IOException("Store destination already exists.");
            }

            int result = overwrite
                ? renameat(rootFd, temporaryName, rootFd, destinationName)
                : renameat2(rootFd, temporaryName, rootFd, destinationName, 1);
            if (result != 0)
            {
                throw NativeError("Replacing store snapshot");
            }

            fault?.Invoke(StoreWriteBoundary.AfterRename, destinationName);
            // Post-rename failure is an uncertain commit; callers must reconcile.
            if (fsync(rootFd) != 0)
            {
                throw NativeError("Synchronizing store directory");
            }

            fault?.Invoke(StoreWriteBoundary.DirectoryFlushed, destinationName);
        }
        finally
        {
            if (rootReferenceAdded)
            {
                _directory.DangerousRelease();
            }
        }
    }

    /// <summary>
    /// Enumerates abandoned temporary names from the pinned directory, not its mutable pathname.
    /// The caller holds the store lock. This does not delete or trust returned entries.
    /// </summary>
    internal IReadOnlyList<string> EnumeratePendingNames()
    {
        // The glibc/musl 64-bit dirent ABI places d_reclen at 16 and d_name at 19.
        // Refuse unknown ABIs instead of silently parsing incorrect native memory.
        if (IntPtr.Size != 8)
        {
            throw new PlatformNotSupportedException("Pinned Linux directory enumeration requires a 64-bit ABI.");
        }

        bool rootReferenceAdded = false;
        int duplicate;
        try
        {
            int rootFd = AcquireDirectoryDescriptor(ref rootReferenceAdded);
            // Use a fresh open-file description so readdir does not change the
            // root descriptor's directory cursor or depend on its pathname.
            duplicate = openat(rootFd, ".", OReadOnly | ODirectory | ONoFollow | OCloseOnExec, 0);
            if (duplicate < 0)
            {
                throw NativeError("Opening the pinned directory for enumeration");
            }
        }
        finally
        {
            if (rootReferenceAdded)
            {
                _directory.DangerousRelease();
            }
        }

        nint dir = fdopendir(duplicate);
        if (dir == nint.Zero)
        {
            int error = Marshal.GetLastPInvokeError();
            close(duplicate);
            throw new IOException("Opening a pinned directory stream failed.", new Win32Exception(error));
        }

        bool completed = false;
        try
        {
            List<string> results = new();
            nint errnoLocation = __errno_location();
            if (errnoLocation == nint.Zero)
            {
                throw new IOException("Cannot obtain Linux directory enumeration error state.");
            }

            for (;;)
            {
                // A null readdir return can mean end-of-directory OR error.
                Marshal.WriteInt32(errnoLocation, 0);
                nint entry = readdir(dir);
                if (entry == nint.Zero)
                {
                    int error = Marshal.ReadInt32(errnoLocation);
                    if (error != 0)
                    {
                        throw new IOException("Enumerating the pinned directory failed.",
                            new Win32Exception(error));
                    }

                    break;
                }

                const int nameOffset = 19;
                int recordLength = unchecked((ushort)Marshal.ReadInt16(entry, 16));
                int nameCapacity = recordLength - nameOffset;
                if (nameCapacity is < 1 or > 256)
                {
                    throw new IOException("Linux directory enumeration returned an invalid record length.");
                }

                int nameLength = 0;
                bool ascii = true;
                while (nameLength < nameCapacity && Marshal.ReadByte(entry, nameOffset + nameLength) != 0)
                {
                    if (Marshal.ReadByte(entry, nameOffset + nameLength) > 0x7F)
                    {
                        ascii = false;
                    }

                    nameLength++;
                }

                if (nameLength == nameCapacity)
                {
                    throw new IOException("Linux directory enumeration returned an unterminated filename.");
                }

                if (!ascii || nameLength == 0)
                {
                    continue;
                }

                byte[] nameBytes = new byte[nameLength];
                Marshal.Copy(IntPtr.Add(entry, nameOffset), nameBytes, 0, nameLength);
                string name = System.Text.Encoding.ASCII.GetString(nameBytes);
                if (name.StartsWith(".pending-", StringComparison.Ordinal) &&
                    name.EndsWith(".tmp", StringComparison.Ordinal))
                {
                    results.Add(name);
                }
            }

            results.Sort(StringComparer.Ordinal);
            completed = true;
            return results;
        }
        finally
        {
            // fdopendir owns the duplicate descriptor after success.
            // Never retry close after EINTR: its outcome may be ambiguous.
            int result = closedir(dir);
            if (result != 0 && completed)
            {
                throw NativeError("Closing the pinned directory stream");
            }
        }
    }

    internal void Remove(string name)
    {
        ValidateName(name);
        bool rootReferenceAdded = false;
        try
        {
            // Keep the same directory pinned across inspection and unlinkat.
            int rootFd = AcquireDirectoryDescriptor(ref rootReferenceAdded);
            if (ExistsCore(rootFd, name) && unlinkat(rootFd, name, 0) != 0)
            {
                throw NativeError("Removing temporary store file");
            }
        }
        finally
        {
            if (rootReferenceAdded)
            {
                _directory.DangerousRelease();
            }
        }
    }

    public void Dispose() => _directory.Dispose();

    private int AcquireDirectoryDescriptor(ref bool rootReferenceAdded)
    {
        // A raw Linux directory fd is not protected from concurrent Dispose.
        // DangerousAddRef prevents close/reuse until DangerousRelease in finally.
        _directory.DangerousAddRef(ref rootReferenceAdded);
        return checked((int)_directory.DangerousGetHandle());
    }

    private int OpenChild(string name, int flags, uint mode)
    {
        ValidateName(name);
        bool rootReferenceAdded = false;
        try
        {
            int rootFd = AcquireDirectoryDescriptor(ref rootReferenceAdded);
            int descriptor = openat(rootFd, name, flags, mode);
            if (descriptor < 0)
            {
                throw NativeError("Opening store child");
            }

            // The child fd remains independently valid after releasing rootFd.
            return descriptor;
        }
        finally
        {
            if (rootReferenceAdded)
            {
                _directory.DangerousRelease();
            }
        }
    }

    private static FileStream AsStream(int descriptor, FileAccess access)
    {
        SafeFileHandle handle = new((IntPtr)descriptor, ownsHandle: true);
        try
        {
            // openat() gives us a synchronous native descriptor. FileStream
            // still supports ReadAsync/WriteAsync through its synchronous-handle fallback.
            return new FileStream(handle, access, 65536, isAsync: false);
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

    [DllImport("libc", EntryPoint = "fdopendir", SetLastError = true)]
    private static extern nint fdopendir(int fd);

    [DllImport("libc", EntryPoint = "readdir", SetLastError = true)]
    private static extern nint readdir(nint directory);

    [DllImport("libc", EntryPoint = "closedir", SetLastError = true)]
    private static extern int closedir(nint directory);

    [DllImport("libc", EntryPoint = "__errno_location")]
    private static extern nint __errno_location();

    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static extern int fsync(int fd);

    [DllImport("libc", EntryPoint = "close", SetLastError = true)]
    private static extern int close(int fd);

    [DllImport("libc", EntryPoint = "geteuid")]
    private static extern uint geteuid();
}
