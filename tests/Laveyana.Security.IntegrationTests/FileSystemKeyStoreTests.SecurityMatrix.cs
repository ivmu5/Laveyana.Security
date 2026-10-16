using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Storage;
using Laveyana.Security.FileSystem.Storage;
using NUnit.Framework;

namespace Laveyana.Security.IntegrationTests;

/// <summary>EXPERIMENTAL / TEST ONLY: targeted Windows SA-02 attack and recovery cases.</summary>
public sealed partial class FileSystemKeyStoreTests
{
    [Test]
    [Category("WindowsOnly")]
    [Category("Adversarial")]
    [SupportedOSPlatform("windows")]
    public async Task WindowsReopenRejectsJunctionAtReplacedRootWithoutTouchingDecoy()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Windows directory-handle and junction test.");
            return;
        }

        FileSystemKeyStore live = await Open();
        string pinned = _root + "-matrix-pinned";
        string decoy = _root + "-matrix-decoy";
        string markerPath = Path.Combine(decoy, "sentinel.bin");
        byte[] marker = Encoding.UTF8.GetBytes("junction-must-not-receive-writes");
        Directory.CreateDirectory(decoy);
        await File.WriteAllBytesAsync(markerPath, marker);
        Directory.Move(_root, pinned);
        try
        {
            WindowsJunctionTestSupport.CreateJunction(_root, decoy);
            Assert.That(File.GetAttributes(_root).HasFlag(FileAttributes.ReparsePoint), Is.True);

            Assert.ThrowsAsync<IOException>(async () => await FileSystemKeyStore.OpenAsync(
                new FileSystemKeyStoreOptions(_root) { EnableExperimentalWrites = true }, _protector));

            KeyId id = KeyId.New();
            KeyName name = new("pinned-after-reopen-rejected");
            Assert.That((await live.TryCreateAsync(await CreateRequest(id, name))).Status,
                Is.EqualTo(KeyStoreMutationStatus.Applied));
            Assert.That((await live.FindByNameAsync(_provider, name))!.KeyId, Is.EqualTo(id));
            Assert.That(await File.ReadAllBytesAsync(markerPath), Is.EqualTo(marker));
            Assert.That(Directory.GetFileSystemEntries(decoy), Is.EquivalentTo(new[] { markerPath }));
        }
        finally
        {
            WindowsJunctionTestSupport.DeleteJunctionIfPresent(_root);
            Directory.Move(pinned, _root);
            Directory.Delete(decoy, recursive: true);
        }
    }

    [Test]
    [Category("WindowsOnly")]
    [Category("Adversarial")]
    [SupportedOSPlatform("windows")]
    public async Task WindowsBootstrapSymlinkIsRejectedBeforeReadingTarget()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Windows bootstrap reparse test.");
            return;
        }

        await Open();
        string bootstrap = Path.Combine(_root, "bootstrap.lspb");
        string backup = Path.Combine(_root, "bootstrap-test-backup.bin");
        File.Move(bootstrap, backup);
        try
        {
            try
            {
                File.CreateSymbolicLink(bootstrap, backup);
            }
            catch (IOException error) when (error.HResult == unchecked((int)0x80070522))
            {
                Assert.Ignore("Windows symlink privilege 1314 is unavailable.");
                return;
            }
            catch (UnauthorizedAccessException)
            {
                Assert.Ignore("Windows symlink creation is not permitted.");
                return;
            }

            Assert.That(File.GetAttributes(bootstrap).HasFlag(FileAttributes.ReparsePoint), Is.True);
            Assert.ThrowsAsync<IOException>(async () => await Open());
        }
        finally
        {
            if (File.Exists(bootstrap))
            {
                File.Delete(bootstrap);
            }
            File.Move(backup, bootstrap);
        }
    }

    [Test]
    [Category("WindowsOnly")]
    [Category("Adversarial")]
    [SupportedOSPlatform("windows")]
    public async Task WindowsPendingSymlinkIsNotFollowedOrRemovedAsOrdinaryStagedFile()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Windows pending-file reparse test.");
            return;
        }

        await Open();
        string pending = Path.Combine(_root, $".pending-{Guid.NewGuid():N}.tmp");
        string external = _root + "-outside-pending-target.bin";
        byte[] marker = Encoding.UTF8.GetBytes("external-pending-target-must-survive");
        await File.WriteAllBytesAsync(external, marker);
        try
        {
            try
            {
                File.CreateSymbolicLink(pending, external);
            }
            catch (IOException error) when (error.HResult == unchecked((int)0x80070522))
            {
                Assert.Ignore("Windows symlink privilege 1314 is unavailable.");
                return;
            }
            catch (UnauthorizedAccessException)
            {
                Assert.Ignore("Windows symlink creation is not permitted.");
                return;
            }

            Assert.That(File.GetAttributes(pending).HasFlag(FileAttributes.ReparsePoint), Is.True);
            Assert.ThrowsAsync<IOException>(async () => await Open());
            Assert.That(await File.ReadAllBytesAsync(external), Is.EqualTo(marker));
        }
        finally
        {
            if (File.Exists(pending))
            {
                File.Delete(pending);
            }
            if (File.Exists(external))
            {
                File.Delete(external);
            }
        }
    }

    [Test]
    [Category("WindowsOnly")]
    [Category("Recovery")]
    [SupportedOSPlatform("windows")]
    public async Task WindowsMultipleOrphanedPendingFilesAreRemovedAfterAuthentication()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Windows pending cleanup test.");
            return;
        }

        FileSystemKeyStore store = await Open();
        KeyId id = KeyId.New();
        Assert.That((await store.TryCreateAsync(await CreateRequest(id, _name))).Status,
            Is.EqualTo(KeyStoreMutationStatus.Applied));
        byte[] committed = await File.ReadAllBytesAsync(Path.Combine(_root, "store.lsfs"));
        string[] pending = Enumerable.Range(0, 3)
            .Select(_ => Path.Combine(_root, $".pending-{Guid.NewGuid():N}.tmp"))
            .ToArray();
        foreach (string path in pending)
        {
            await File.WriteAllBytesAsync(path, [1, 2, 3, 4]);
        }

        FileSystemKeyStore reopened = await Open();
        Assert.That(pending.All(path => !File.Exists(path)), Is.True);
        Assert.That((await reopened.FindByIdAsync(_provider, id))!.KeyId, Is.EqualTo(id));
        Assert.That(await File.ReadAllBytesAsync(Path.Combine(_root, "store.lsfs")),
            Is.EqualTo(committed), "Pending cleanup must not rewrite the authenticated snapshot.");
    }

    [Test]
    [Category("WindowsOnly")]
    [Category("Recovery")]
    [SupportedOSPlatform("windows")]
    public async Task WindowsCorruptSnapshotNeverTriggersPendingCleanup()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Windows fail-closed recovery test.");
            return;
        }

        await Open();
        string pending = Path.Combine(_root, $".pending-{Guid.NewGuid():N}.tmp");
        await File.WriteAllBytesAsync(pending, [11, 12, 13]);
        string snapshot = Path.Combine(_root, "store.lsfs");
        byte[] bytes = await File.ReadAllBytesAsync(snapshot);
        bytes[20] ^= 0x10;
        await File.WriteAllBytesAsync(snapshot, bytes);

        Assert.ThrowsAsync<InvalidDataException>(async () => await Open());
        Assert.That(File.Exists(pending), Is.True,
            "Failed authentication must not silently discard staged evidence.");
    }

    [Test]
    [Category("WindowsOnly")]
    [Category("Recovery")]
    [SupportedOSPlatform("windows")]
    public async Task WindowsMissingCommittedSnapshotCannotBeReplacedByPendingCandidate()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Windows incomplete commit test.");
            return;
        }

        await Open();
        string pending = Path.Combine(_root, $".pending-{Guid.NewGuid():N}.tmp");
        await File.WriteAllBytesAsync(pending, [1, 2, 3, 4]);
        File.Delete(Path.Combine(_root, "store.lsfs"));

        Assert.ThrowsAsync<FileNotFoundException>(async () => await Open());
        Assert.That(File.Exists(pending), Is.True,
            "A staged file cannot be promoted to a committed snapshot without authentication.");
    }

    [Test]
    [Category("WindowsOnly")]
    [Category("Recovery")]
    [SupportedOSPlatform("windows")]
    public async Task WindowsTruncatedCommittedSnapshotFailsClosedWithoutResettingBootstrap()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Windows truncated-snapshot test.");
            return;
        }

        await Open();
        byte[] bootstrap = await File.ReadAllBytesAsync(Path.Combine(_root, "bootstrap.lspb"));
        await File.WriteAllBytesAsync(Path.Combine(_root, "store.lsfs"), [1, 2, 3]);

        Assert.ThrowsAsync<InvalidDataException>(async () => await Open());
        Assert.That(await File.ReadAllBytesAsync(Path.Combine(_root, "bootstrap.lspb")),
            Is.EqualTo(bootstrap), "Failed open must not reset the store identity.");
    }

    [Test]
    [Category("WindowsOnly")]
    [Category("Adversarial")]
    [SupportedOSPlatform("windows")]
    public async Task WindowsExclusiveLockConflictWaitsThenTimesOutWithoutBypass()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Windows cooperative lock-contention test.");
            return;
        }

        await Open();
        string path = Path.Combine(_root, ".store.lock");
        using (FileStream held = new(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            Assert.ThrowsAsync<TimeoutException>(async () => await FileSystemKeyStore.OpenAsync(
                new FileSystemKeyStoreOptions(_root)
                {
                    EnableExperimentalWrites = true,
                    LockTimeout = TimeSpan.FromMilliseconds(350)
                }, _protector));
        }

        FileSystemKeyStore reopened = await Open();
        Assert.That(await reopened.FindByNameAsync(_provider, _name), Is.Null);
    }

    [Test]
    [Category("WindowsOnly")]
    [Category("Interprocess")]
    [Category("Recovery")]
    [SupportedOSPlatform("windows")]
    public async Task WindowsKilledExternalPendingWriterCannotAlterCommittedSnapshot()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Windows independent process staged-write interruption test.");
            return;
        }

        using CancellationTokenSource deadline = new(TimeSpan.FromSeconds(30));
        FileSystemKeyStore store = await Open();
        KeyId id = KeyId.New();
        Assert.That((await store.TryCreateAsync(await CreateRequest(id, _name))).Status,
            Is.EqualTo(KeyStoreMutationStatus.Applied));
        string snapshot = Path.Combine(_root, "store.lsfs");
        byte[] committed = await File.ReadAllBytesAsync(snapshot, deadline.Token);
        string pending = Path.Combine(_root, $".pending-{Guid.NewGuid():N}.tmp");
        string script = _root + "-pending-worker.cmd";
        Process? worker = null;
        try
        {
            await File.WriteAllTextAsync(script,
                PendingFileWriterScript.Replace("\n", "\r\n", StringComparison.Ordinal), deadline.Token);
            worker = StartSa02Cmd(script, new Dictionary<string, string>
            {
                ["LAVEYANA_SA02_PENDING"] = pending
            });
            while (!File.Exists(pending) || new FileInfo(pending).Length == 0)
            {
                deadline.Token.ThrowIfCancellationRequested();
                if (worker.HasExited)
                {
                    throw new IOException($"Staged writer exited prematurely ({worker.ExitCode}).");
                }
                await Task.Delay(25, deadline.Token);
            }

            Assert.That(worker.HasExited, Is.False,
                "The separate writer must still be running when it is forcibly terminated.");
            worker.Kill(entireProcessTree: true);
            await worker.WaitForExitAsync(deadline.Token);
            Assert.That(worker.HasExited, Is.True);
            FileSystemKeyStore reopened = await Open();
            Assert.That(File.Exists(pending), Is.False);
            Assert.That((await reopened.FindByIdAsync(_provider, id))!.KeyId, Is.EqualTo(id));
            Assert.That(await File.ReadAllBytesAsync(snapshot, deadline.Token), Is.EqualTo(committed));
        }
        finally
        {
            if (worker is not null)
            {
                if (!worker.HasExited)
                {
                    worker.Kill(entireProcessTree: true);
                }
                await worker.WaitForExitAsync();
                worker.Dispose();
            }
            if (File.Exists(script))
            {
                File.Delete(script);
            }
        }
    }

    [Test]
    [Category("WindowsOnly")]
    [Category("Interprocess")]
    [Category("Adversarial")]
    [SupportedOSPlatform("windows")]
    public async Task WindowsExternalProcessRemovingSnapshotIsDetectedWithoutAutoRecovery()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Windows external namespace modification test.");
            return;
        }

        using CancellationTokenSource deadline = new(TimeSpan.FromSeconds(30));
        FileSystemKeyStore store = await Open();
        KeyId id = KeyId.New();
        Assert.That((await store.TryCreateAsync(await CreateRequest(id, _name))).Status,
            Is.EqualTo(KeyStoreMutationStatus.Applied));
        string snapshot = Path.Combine(_root, "store.lsfs");
        string backup = Path.Combine(_root, "external-process-snapshot-backup.bin");
        string script = _root + "-snapshot-worker.cmd";
        try
        {
            await File.WriteAllTextAsync(script,
                ExternalSnapshotMoveScript.Replace("\n", "\r\n", StringComparison.Ordinal), deadline.Token);
            using Process worker = StartSa02Cmd(script, new Dictionary<string, string>
            {
                ["LAVEYANA_SA02_SNAPSHOT"] = snapshot,
                ["LAVEYANA_SA02_BACKUP"] = backup
            });
            await worker.WaitForExitAsync(deadline.Token);
            Assert.That(worker.ExitCode, Is.EqualTo(0));
            Assert.That(File.Exists(snapshot), Is.False);
            Assert.That(File.Exists(backup), Is.True);

            Assert.ThrowsAsync<FileNotFoundException>(async () =>
                await store.FindByIdAsync(_provider, id));
            Assert.ThrowsAsync<FileNotFoundException>(async () => await Open());
        }
        finally
        {
            // Restore the original committed file regardless of test assertions.
            if (File.Exists(backup) && !File.Exists(snapshot))
            {
                File.Move(backup, snapshot);
            }
            if (File.Exists(script))
            {
                File.Delete(script);
            }
        }

        Assert.That((await store.FindByIdAsync(_provider, id))!.KeyId, Is.EqualTo(id));
    }

    [SupportedOSPlatform("windows")]
    private static Process StartSa02Cmd(string script, IReadOnlyDictionary<string, string> environment)
    {
        var info = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "cmd.exe"),
            Arguments = $"/d /s /c \"\"{script}\"\"",
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = false,
            RedirectStandardError = false
        };
        foreach (KeyValuePair<string, string> item in environment)
        {
            info.Environment[item.Key] = item.Value;
        }

        Process process = new() { StartInfo = info };
        if (!process.Start())
        {
            process.Dispose();
            throw new IOException("Unable to start an independent Windows test worker.");
        }
        return process;
    }

    // An intentionally uncommitted staged-file writer. This exercises process
    // termination and startup cleanup, NOT a crash inside FileSystemKeyStore.CommitAsync.
    private const string PendingFileWriterScript = """
        @echo off
        > "%LAVEYANA_SA02_PENDING%" echo uncommitted-incomplete-staging
        :again
        >> "%LAVEYANA_SA02_PENDING%" echo uncommitted-data
        ping -n 2 127.0.0.1 >nul
        goto again
        """;

    private const string ExternalSnapshotMoveScript = """
        @echo off
        if not exist "%LAVEYANA_SA02_SNAPSHOT%" exit /b 61
        move /Y "%LAVEYANA_SA02_SNAPSHOT%" "%LAVEYANA_SA02_BACKUP%" >nul
        if errorlevel 1 exit /b 62
        exit /b 0
        """;
}
