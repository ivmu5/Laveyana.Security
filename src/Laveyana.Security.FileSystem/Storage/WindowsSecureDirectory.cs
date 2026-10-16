using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Laveyana.Security.FileSystem.Storage;

/// <summary>Experimental Windows directory-pinned, no-follow filesystem operations.</summary>
/// <remarks>
/// EXPERIMENTAL / TEST ONLY: the native Windows backend is not production-approved.
/// An opened directory handle anchors child I/O; ACLs are checked on opened handles.
/// No guarantee is provided against same-identity processes, rollback or power loss.
/// This implementation requires Windows build, runtime and adversarial security tests.
/// </remarks>
internal sealed class WindowsSecureDirectory : IDisposable
{
    private const uint FileReadData = 0x0001;
    private const uint FileListDirectory = 0x0001;
    private const uint FileAddFile = 0x0002;
    private const uint FileDeleteChild = 0x0040;
    private const uint FileWriteData = 0x0002;
    private const uint FileTraverse = 0x0020;
    private const uint FileReadAttributes = 0x0080;
    private const uint Delete = 0x00010000;
    private const uint ReadControl = 0x00020000;
    private const uint Synchronize = 0x00100000;
    private const uint ObjCaseInsensitive = 0x0040;
    private const uint ObjDontReparse = 0x1000;
    private const uint FileOpen = 1;
    private const uint FileCreate = 2;
    private const uint FileOpenIf = 3;
    private const uint FileSynchronousIoNonAlert = 0x20;
    private const uint FileNonDirectoryFile = 0x40;
    private const uint FileOpenReparsePoint = 0x00200000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint OpenExisting = 3; // Win32 OPEN_EXISTING, not NT FILE_OPEN (= 1).
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileAttributeDirectory = 0x10;
    private const uint FileAttributeReparsePoint = 0x400;
    private const int FileAttributeTagInfo = 9;
    private const int FileFullDirectoryInfo = 14;
    private const int FileFullDirectoryRestartInfo = 15;
    private const int ErrorNoMoreFiles = 18;
    private const int ErrorFileNotFound = 2;
    private const int DirectoryBufferSize = 65536;
    private const int DirectoryNameOffset = 68; // FILE_FULL_DIR_INFO.FileName
    private const int DirectoryNameLengthOffset = 60;
    private const int FileRenameInformation = 10; // Native NT FILE_INFORMATION_CLASS, not Win32 FileRenameInfo.
    private const int FileDispositionInfo = 4;
    private const int StatusObjectNameNotFound = unchecked((int)0xC0000034);
    private const int StatusObjectPathNotFound = unchecked((int)0xC000003A);

    private readonly SafeFileHandle _directory;

    private WindowsSecureDirectory(SafeFileHandle directory) => _directory = directory;

    internal static WindowsSecureDirectory Open(string root)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows-specific store operations require Windows.");
        }

        WindowsStorePathGuard.ValidateRoot(root);
        SafeFileHandle handle = CreateFileW(root, FileListDirectory | FileAddFile | FileDeleteChild |
            FileTraverse | FileReadAttributes | ReadControl | Synchronize,
            (uint)(FileShare.ReadWrite | FileShare.Delete), nint.Zero, OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint, nint.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw new IOException("Unable to pin the Windows store directory.",
                new Win32Exception(error));
        }

        try
        {
            VerifyHandle(handle, directory: true);
            // Ancestors are checked again, but only the pinned handle is used for child I/O.
            WindowsStorePathGuard.ValidateRoot(root);
            return new WindowsSecureDirectory(handle);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    internal bool Exists(string name)
    {
        using SafeFileHandle? handle = OpenChild(name, FileReadAttributes | ReadControl |
            Synchronize, FileOpen, (uint)(FileShare.ReadWrite | FileShare.Delete), allowMissing: true);
        return handle is not null;
    }

    internal FileStream OpenRead(string name)
    {
        SafeFileHandle handle = OpenChild(name, FileReadData | FileReadAttributes |
            ReadControl | Synchronize, FileOpen, (uint)(FileShare.Read | FileShare.Delete))!;
        return AsStream(handle, FileAccess.Read);
    }

    internal FileStream CreateTemporary(string name)
    {
        SafeFileHandle handle = OpenChild(name, FileWriteData | FileReadAttributes |
            ReadControl | Synchronize, FileCreate, 0)!;
        return AsStream(handle, FileAccess.Write);
    }

    internal FileStream TryAcquireLock(string name)
    {
        SafeFileHandle handle = OpenChild(name, FileReadData | FileWriteData | FileReadAttributes |
            ReadControl | Synchronize, FileOpenIf, 0)!;
        return AsStream(handle, FileAccess.ReadWrite);
    }

    internal void Move(string temporaryName, string destinationName, bool overwrite)
    {
        ValidateName(destinationName);
        if (Exists(destinationName) && !overwrite)
        {
            throw new IOException("The store destination already exists.");
        }

        using SafeFileHandle source = OpenChild(temporaryName, Delete | FileReadAttributes |
            ReadControl | Synchronize, FileOpen, 0)!;
        byte[] nameBytes = System.Text.Encoding.Unicode.GetBytes(destinationName);
        int rootOffset = IntPtr.Size == 8 ? 8 : 4;
        int lengthOffset = rootOffset + IntPtr.Size;
        int nameOffset = lengthOffset + sizeof(int);
        int size = checked(nameOffset + nameBytes.Length);
        nint info = Marshal.AllocHGlobal(size);
        try
        {
            // FILE_RENAME_INFO, including explicitly initialized alignment bytes.
            Marshal.Copy(new byte[size], 0, info, size);
            Marshal.WriteByte(info, overwrite ? (byte)1 : (byte)0);
            Marshal.WriteIntPtr(info, rootOffset, _directory.DangerousGetHandle());
            Marshal.WriteInt32(info, lengthOffset, nameBytes.Length);
            Marshal.Copy(nameBytes, 0, IntPtr.Add(info, nameOffset), nameBytes.Length);
            // TEST ONLY: the Win32 SetFileInformationByHandle wrapper may reject
            // non-null RootDirectory with ERROR_INVALID_PARAMETER (87). The native
            // rename request uses the already pinned directory handle directly.
            // Do not fall back to an absolute pathname: that would restore TOCTOU.
            int status = NtSetInformationFile(source, out _, info,
                checked((uint)size), FileRenameInformation);
            if (status != 0)
            {
                int error = unchecked((int)RtlNtStatusToDosError(status));
                throw new IOException($"Renaming the staged store file failed (NTSTATUS 0x{status:X8}).",
                    new Win32Exception(error));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(info);
        }

        // Failure here is an uncertain commit; never blindly repeat a mutation.
        if (!Exists(destinationName))
        {
            throw new IOException("The renamed store entry could not be verified.");
        }
    }

    /// <summary>Enumerates stale staging filenames using the retained directory handle.</summary>
    internal IReadOnlyList<string> EnumeratePendingNames()
    {
        List<string> names = new();
        nint buffer = Marshal.AllocHGlobal(DirectoryBufferSize);
        try
        {
            int queryClass = FileFullDirectoryRestartInfo;
            for (;;)
            {
                if (!GetFileInformationByHandleEx(_directory, queryClass, buffer, DirectoryBufferSize))
                {
                    int error = Marshal.GetLastPInvokeError();
                    if (error == ErrorNoMoreFiles ||
                        (queryClass == FileFullDirectoryRestartInfo && error == ErrorFileNotFound))
                    {
                        return names;
                    }

                    throw new IOException("Cannot enumerate the pinned Windows store directory.",
                        new Win32Exception(error));
                }

                queryClass = FileFullDirectoryInfo;
                int offset = 0;
                for (;;)
                {
                    int filenameLength = Marshal.ReadInt32(buffer, offset + DirectoryNameLengthOffset);
                    int next = Marshal.ReadInt32(buffer, offset);
                    if (filenameLength < 0 || (filenameLength & 1) != 0 ||
                        filenameLength > 1024 ||
                        offset > DirectoryBufferSize - DirectoryNameOffset - filenameLength)
                    {
                        throw new IOException("Windows directory enumeration returned malformed entry metadata.");
                    }

                    string? name = Marshal.PtrToStringUni(IntPtr.Add(buffer, offset + DirectoryNameOffset),
                        filenameLength / sizeof(char));
                    if (name is not null && name.StartsWith(".pending-", StringComparison.OrdinalIgnoreCase) &&
                        name.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase))
                    {
                        names.Add(name);
                    }

                    if (next == 0)
                    {
                        break;
                    }

                    if (next < DirectoryNameOffset || (next & 7) != 0 ||
                        offset >= DirectoryBufferSize - next)
                    {
                        throw new IOException("Windows directory enumeration returned an invalid entry offset.");
                    }

                    offset += next;
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    internal void Remove(string name)
    {
        using SafeFileHandle? handle = OpenChild(name, Delete | FileReadAttributes |
            ReadControl | Synchronize, FileOpen, 0, allowMissing: true);
        if (handle is null)
        {
            return;
        }

        nint info = Marshal.AllocHGlobal(sizeof(int));
        try
        {
            Marshal.WriteInt32(info, 1);
            if (!SetFileInformationByHandle(handle, FileDispositionInfo, info, sizeof(int)))
            {
                throw NativeError("Deleting a temporary store file");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(info);
        }
    }

    public void Dispose() => _directory.Dispose();

    private SafeFileHandle? OpenChild(string name, uint access, uint disposition,
        uint share, bool allowMissing = false)
    {
        ValidateName(name);
        nint nameBuffer = Marshal.StringToHGlobalUni(name);
        nint unicodeBuffer = nint.Zero;
        try
        {
            UnicodeString unicode = new()
            {
                Length = checked((ushort)(name.Length * sizeof(char))),
                MaximumLength = checked((ushort)(name.Length * sizeof(char))),
                Buffer = nameBuffer
            };
            unicodeBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
            Marshal.StructureToPtr(unicode, unicodeBuffer, false);
            ObjectAttributes attributes = new()
            {
                Length = Marshal.SizeOf<ObjectAttributes>(),
                RootDirectory = _directory.DangerousGetHandle(),
                ObjectName = unicodeBuffer,
                Attributes = ObjCaseInsensitive | ObjDontReparse
            };
            int status = NtCreateFile(out SafeFileHandle handle, access, ref attributes,
                out _, nint.Zero, 0, share, disposition,
                FileSynchronousIoNonAlert | FileNonDirectoryFile | FileOpenReparsePoint,
                nint.Zero, 0);
            if (status < 0)
            {
                handle?.Dispose();
                if (allowMissing && (status == StatusObjectNameNotFound || status == StatusObjectPathNotFound))
                {
                    return null;
                }

                int error = unchecked((int)RtlNtStatusToDosError(status));
                throw new IOException($"Windows store entry open failed (NTSTATUS 0x{status:X8}).",
                    new Win32Exception(error));
            }

            try
            {
                VerifyHandle(handle, directory: false);
                return handle;
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(unicodeBuffer);
            Marshal.FreeHGlobal(nameBuffer);
        }
    }

    private static void VerifyHandle(SafeFileHandle handle, bool directory)
    {
        if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo,
            out FileAttributeTag information, (uint)Marshal.SizeOf<FileAttributeTag>()))
        {
            throw NativeError("Inspecting the opened store entry");
        }

        if ((information.Attributes & FileAttributeReparsePoint) != 0 ||
            ((information.Attributes & FileAttributeDirectory) != 0) != directory)
        {
            throw new IOException("The opened store entry has an unsafe reparse point or type.");
        }

        if (OperatingSystem.IsWindows())
        {
            WindowsStorePathGuard.ValidateHandle(handle, directory);
        }
    }

    private static FileStream AsStream(SafeFileHandle handle, FileAccess access)
    {
        try
        {
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
            name.Contains('/') || name.Contains('\\') || name.Contains(':') || name.Contains('\0') ||
            name.EndsWith('.') || name.EndsWith(' ') || name.Length > 128)
        {
            throw new ArgumentException("Store entry must be a canonical single filename.", nameof(name));
        }
    }

    private static IOException NativeError(string operation) =>
        new($"{operation} failed.", new Win32Exception(Marshal.GetLastPInvokeError()));

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public nint Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public int Length;
        public nint RootDirectory;
        public nint ObjectName;
        public uint Attributes;
        public nint SecurityDescriptor;
        public nint SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock
    {
        public nint Status;
        public nuint Information;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTag
    {
        public uint Attributes;
        public uint ReparseTag;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint desiredAccess,
        uint shareMode, nint securityAttributes, uint creationDisposition, uint flagsAndAttributes,
        nint templateFile);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtCreateFile(out SafeFileHandle handle, uint desiredAccess,
        ref ObjectAttributes attributes, out IoStatusBlock ioStatus, nint allocationSize,
        uint fileAttributes, uint shareAccess, uint createDisposition, uint createOptions,
        nint eaBuffer, uint eaLength);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtSetInformationFile(SafeFileHandle fileHandle,
        out IoStatusBlock ioStatus, nint fileInformation, uint length, int fileInformationClass);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern uint RtlNtStatusToDosError(int status);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle,
        int informationClass, out FileAttributeTag information, uint bufferSize);

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle,
        int informationClass, nint buffer, int bufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle handle,
        int informationClass, nint fileInformation, int bufferSize);
}
