using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.FileSystem.Storage;
using NUnit.Framework;

namespace Laveyana.Security.IntegrationTests;

/// <summary>
/// EXPERIMENTAL / TEST ONLY: SA-02 architecture-regression tests for the
/// native handle lifetime, ancestor owner policy and non-mutating opens.
/// </summary>
public sealed partial class FileSystemKeyStoreTests
{
    [Test]
    [Category("ArchitectureRegression")]
    public async Task ReadOnlyOpenPreservesPendingFilesAndCommittedStoreBytes()
    {
        FileSystemKeyStore writable = await Open();
        KeyId id = KeyId.New();
        Assert.That((await writable.TryCreateAsync(await CreateRequest(id, _name))).Status,
            Is.EqualTo(Laveyana.Security.Abstractions.Storage.KeyStoreMutationStatus.Applied));

        string pendingPath = Path.Combine(_root, $".pending-{Guid.NewGuid():N}.tmp");
        byte[] pendingBytes = [0x01, 0x02, 0x03, 0x04];
        await File.WriteAllBytesAsync(pendingPath, pendingBytes);
        SecureLinuxTestFile(pendingPath);
        string snapshotPath = Path.Combine(_root, "store.lsfs");
        string bootstrapPath = Path.Combine(_root, "bootstrap.lspb");
        string lockPath = Path.Combine(_root, ".store.lock");
        byte[] snapshotBefore = await File.ReadAllBytesAsync(snapshotPath);
        byte[] bootstrapBefore = await File.ReadAllBytesAsync(bootstrapPath);
        byte[] lockBefore = await File.ReadAllBytesAsync(lockPath);
        string[] entriesBefore = Directory.GetFileSystemEntries(_root)
            .Select(Path.GetFileName).OrderBy(x => x, StringComparer.Ordinal).ToArray()!;

        using FileSystemKeyStore reader = await FileSystemKeyStore.OpenAsync(
            new FileSystemKeyStoreOptions(_root), _protector);
        Assert.That((await reader.FindByIdAsync(_provider, id))?.KeyId, Is.EqualTo(id));
        Assert.That(await File.ReadAllBytesAsync(pendingPath), Is.EqualTo(pendingBytes));
        Assert.That(await File.ReadAllBytesAsync(snapshotPath), Is.EqualTo(snapshotBefore));
        Assert.That(await File.ReadAllBytesAsync(bootstrapPath), Is.EqualTo(bootstrapBefore));
        Assert.That(await File.ReadAllBytesAsync(lockPath), Is.EqualTo(lockBefore));
        Assert.That(Directory.GetFileSystemEntries(_root)
            .Select(Path.GetFileName).OrderBy(x => x, StringComparer.Ordinal).ToArray(),
            Is.EqualTo(entriesBefore));
    }

    [Test]
    [Category("ArchitectureRegression")]
    public async Task ReadOnlyOpenWithoutExistingLockFailsWithoutCreatingIt()
    {
        await Open();
        string lockPath = Path.Combine(_root, ".store.lock");
        string snapshotPath = Path.Combine(_root, "store.lsfs");
        byte[] snapshotBefore = await File.ReadAllBytesAsync(snapshotPath);
        File.Delete(lockPath);

        Assert.ThrowsAsync<IOException>(async () => await FileSystemKeyStore.OpenAsync(
            new FileSystemKeyStoreOptions(_root) { LockTimeout = TimeSpan.FromMilliseconds(350) },
            _protector));
        Assert.That(File.Exists(lockPath), Is.False,
            "A non-writable open must not create the missing lock file.");
        Assert.That(await File.ReadAllBytesAsync(snapshotPath), Is.EqualTo(snapshotBefore));
    }

    [Test]
    [Category("ArchitectureRegression")]
    public void ReadOnlyOpenWithoutRootNeverCreatesDirectories()
    {
        Assert.That(Directory.Exists(_root), Is.False);
        Assert.ThrowsAsync<InvalidOperationException>(async () => await FileSystemKeyStore.OpenAsync(
            new FileSystemKeyStoreOptions(_root), _protector));
        Assert.That(Directory.Exists(_root), Is.False);
    }

    [Test]
    [Category("ArchitectureRegression")]
    public async Task ReadOnlyOpenDoesNotCleanPendingFilesWhenSnapshotIsInvalid()
    {
        await Open();
        string pendingPath = Path.Combine(_root, $".pending-{Guid.NewGuid():N}.tmp");
        byte[] pendingBytes = [0xA5, 0x5A];
        await File.WriteAllBytesAsync(pendingPath, pendingBytes);
        SecureLinuxTestFile(pendingPath);
        string snapshotPath = Path.Combine(_root, "store.lsfs");
        byte[] corrupted = await File.ReadAllBytesAsync(snapshotPath);
        corrupted[20] ^= 0x40;
        await File.WriteAllBytesAsync(snapshotPath, corrupted);

        Assert.ThrowsAsync<InvalidDataException>(async () => await FileSystemKeyStore.OpenAsync(
            new FileSystemKeyStoreOptions(_root), _protector));
        Assert.That(await File.ReadAllBytesAsync(pendingPath), Is.EqualTo(pendingBytes));
        Assert.That(await File.ReadAllBytesAsync(snapshotPath), Is.EqualTo(corrupted));
    }

    [Test]
    [Category("WindowsOnly")]
    [Category("ArchitectureRegression")]
    [SupportedOSPlatform("windows")]
    public async Task WindowsPinnedOpenReadAndConcurrentDisposeNeverReturnInvalidStream()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Windows native handle-lifetime test.");
            return;
        }

        await Open();
        for (int iteration = 0; iteration < 48; iteration++)
        {
            object pinned = OpenWindowsDirectoryForTest();
            using FileStream? stream = await RaceWithDisposeAsync(pinned, directory =>
                (FileStream)InvokeNativeForTest(directory, "OpenRead", "store.lsfs")!);
            if (stream is not null)
            {
                Assert.That(stream.ReadByte(), Is.GreaterThanOrEqualTo(0),
                    "A successful open must return a live file handle even after root disposal.");
            }
        }
    }

    [Test]
    [Category("WindowsOnly")]
    [Category("ArchitectureRegression")]
    [SupportedOSPlatform("windows")]
    public async Task WindowsPinnedEnumerateAndConcurrentDisposeNeverReturnMalformedEntries()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Windows directory enumeration handle-lifetime test.");
            return;
        }

        await Open();
        string pendingName = $".pending-{Guid.NewGuid():N}.tmp";
        await File.WriteAllBytesAsync(Path.Combine(_root, pendingName), [0x01]);
        for (int iteration = 0; iteration < 24; iteration++)
        {
            object pinned = OpenWindowsDirectoryForTest();
            IReadOnlyList<string>? names = await RaceWithDisposeAsync(pinned, directory =>
                (IReadOnlyList<string>)InvokeNativeForTest(directory, "EnumeratePendingNames")!);
            if (names is not null)
            {
                Assert.That(names, Does.Contain(pendingName));
            }
        }
    }

    [Test]
    [Category("WindowsOnly")]
    [Category("ArchitectureRegression")]
    [SupportedOSPlatform("windows")]
    public async Task WindowsPinnedRenameAndConcurrentDisposeKeepExactlyOneValidCopy()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Windows native rename handle-lifetime test.");
            return;
        }

        await Open();
        for (int iteration = 0; iteration < 24; iteration++)
        {
            string stagedName = $".pending-{Guid.NewGuid():N}.tmp";
            string targetName = $"lifetime-{Guid.NewGuid():N}.tmp";
            string stagedPath = Path.Combine(_root, stagedName);
            string targetPath = Path.Combine(_root, targetName);
            byte[] payload = [0x53, 0x41, 0x30, 0x32, checked((byte)iteration)];
            await File.WriteAllBytesAsync(stagedPath, payload);

            object pinned = OpenWindowsDirectoryForTest();
            _ = await RaceWithDisposeAsync(pinned, directory =>
            {
                InvokeNativeForTest(directory, "Move", stagedName, targetName, false);
                return new object();
            });

            bool stagedExists = File.Exists(stagedPath);
            bool targetExists = File.Exists(targetPath);
            Assert.That(stagedExists ^ targetExists, Is.True,
                "Disposal must not duplicate or lose the staged file during native rename.");
            Assert.That(await File.ReadAllBytesAsync(stagedExists ? stagedPath : targetPath),
                Is.EqualTo(payload));
        }
    }

    [Test]
    [Category("WindowsOnly")]
    [Category("ArchitectureRegression")]
    [SupportedOSPlatform("windows")]
    public async Task WindowsDisposedPinnedDirectoryRejectsNewNativeOperations()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Windows post-disposal native-operation test.");
            return;
        }

        await Open();
        object pinned = OpenWindowsDirectoryForTest();
        ((IDisposable)pinned).Dispose();
        Assert.Throws<ObjectDisposedException>(() =>
            InvokeNativeForTest(pinned, "OpenRead", "store.lsfs"));
        Assert.Throws<ObjectDisposedException>(() =>
            InvokeNativeForTest(pinned, "EnumeratePendingNames"));
    }

    [TestCase("S-1-1-0")]
    [TestCase("S-1-5-11")]
    [Category("WindowsOnly")]
    [Category("ArchitectureRegression")]
    [SupportedOSPlatform("windows")]
    public void WindowsAncestorAclRejectsUntrustedOwnerEvenWithoutUnsafeAces(string ownerSid)
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Windows synthetic owner-policy test.");
            return;
        }

        DirectorySecurity descriptor = CreateSyntheticAcl(new SecurityIdentifier(ownerSid));
        Assert.Throws<UnauthorizedAccessException>(() => ValidateWindowsAclForTest(descriptor, false));
    }

    [TestCase("S-1-5-18")]
    [TestCase("S-1-5-32-544")]
    [TestCase("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")]
    [Category("WindowsOnly")]
    [Category("ArchitectureRegression")]
    [SupportedOSPlatform("windows")]
    public void WindowsAncestorAclAcceptsExplicitlyTrustedSystemOwner(string ownerSid)
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Windows synthetic trusted-owner policy test.");
            return;
        }

        DirectorySecurity descriptor = CreateSyntheticAcl(new SecurityIdentifier(ownerSid));
        Assert.DoesNotThrow(() => ValidateWindowsAclForTest(descriptor, false));
    }

    [Test]
    [Category("WindowsOnly")]
    [Category("ArchitectureRegression")]
    [SupportedOSPlatform("windows")]
    public void WindowsIsolatedRootDoesNotTrustSystemOwnerByAncestorException()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Windows isolated owner-policy test.");
            return;
        }

        DirectorySecurity descriptor = CreateSyntheticAcl(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        Assert.Throws<UnauthorizedAccessException>(() => ValidateWindowsAclForTest(descriptor, true));
    }

    [Test]
    [Category("WindowsOnly")]
    [Category("ArchitectureRegression")]
    [SupportedOSPlatform("windows")]
    public void WindowsAncestorStillRejectsDangerousGrantWithTrustedOwner()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Windows ancestor ACE policy test.");
            return;
        }

        using WindowsIdentity current = WindowsIdentity.GetCurrent();
        DirectorySecurity descriptor = CreateSyntheticAcl(current.User!);
        descriptor.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            FileSystemRights.ChangePermissions, AccessControlType.Allow));
        Assert.Throws<UnauthorizedAccessException>(() => ValidateWindowsAclForTest(descriptor, false));
    }

    [SupportedOSPlatform("windows")]
    private static DirectorySecurity CreateSyntheticAcl(SecurityIdentifier owner)
    {
        using WindowsIdentity current = WindowsIdentity.GetCurrent();
        DirectorySecurity descriptor = new();
        descriptor.SetAccessRuleProtection(true, false);
        descriptor.SetOwner(owner);
        descriptor.AddAccessRule(new FileSystemAccessRule(current.User!,
            FileSystemRights.FullControl, AccessControlType.Allow));
        return descriptor;
    }

    [SupportedOSPlatform("windows")]
    private static void ValidateWindowsAclForTest(FileSystemSecurity descriptor, bool isolated)
    {
        Type guard = typeof(FileSystemKeyStore).Assembly.GetType(
            "Laveyana.Security.FileSystem.Storage.WindowsStorePathGuard", true)!;
        MethodInfo method = guard.GetMethod("ValidateAcl", BindingFlags.Static | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("Cannot find the Windows ACL policy method.");
        try
        {
            method.Invoke(null, [descriptor, isolated]);
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }
    }

    [SupportedOSPlatform("windows")]
    private object OpenWindowsDirectoryForTest()
    {
        Type native = typeof(FileSystemKeyStore).Assembly.GetType(
            "Laveyana.Security.FileSystem.Storage.WindowsSecureDirectory", true)!;
        MethodInfo open = native.GetMethod("Open", BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException("Cannot find Windows directory opener.");
        return open.Invoke(null, [_root])!;
    }

    [SupportedOSPlatform("windows")]
    private static object? InvokeNativeForTest(object directory, string methodName, params object[] arguments)
    {
        MethodInfo method = directory.GetType().GetMethod(methodName,
            BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new InvalidOperationException($"Cannot find native operation {methodName}.");
        try
        {
            return method.Invoke(directory, arguments);
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }
    }

    [SupportedOSPlatform("windows")]
    private static async Task<T?> RaceWithDisposeAsync<T>(object directory, Func<object, T> action)
        where T : class
    {
        using ManualResetEventSlim start = new(false);
        Task<T?> operation = Task.Run(() =>
        {
            start.Wait();
            try
            {
                return action(directory);
            }
            catch (ObjectDisposedException)
            {
                // Dispose won the race before this operation acquired the root handle.
                return null;
            }
        });
        Task dispose = Task.Run(() =>
        {
            start.Wait();
            ((IDisposable)directory).Dispose();
        });
        start.Set();
        try
        {
            return await operation;
        }
        finally
        {
            await dispose;
            ((IDisposable)directory).Dispose();
        }
    }

    private static void SecureLinuxTestFile(string path)
    {
        if (OperatingSystem.IsLinux())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }
}
