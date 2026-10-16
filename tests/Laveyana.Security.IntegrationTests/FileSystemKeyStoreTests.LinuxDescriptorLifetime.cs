using System.Reflection;
using System.Runtime.ExceptionServices;
using Laveyana.Security.FileSystem.Storage;
using NUnit.Framework;

namespace Laveyana.Security.IntegrationTests;

/// <summary>
/// EXPERIMENTAL / TEST ONLY: Linux descriptor-lifetime regressions for SA02-LIN-01.
/// The directory is accessed by reflection to keep the production API internal.
/// </summary>
[TestFixture]
[NonParallelizable]
[Category("LinuxOnly")]
[Category("ArchitectureRegression")]
public sealed class LinuxSecureDirectoryLifetimeTests
{
    private const UnixFileMode OwnerDirectoryMode = UnixFileMode.UserRead |
        UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode OwnerFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private string _root = string.Empty;

    [SetUp]
    public void SetUp()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        _root = Path.Combine(Path.GetTempPath(), $"laveyana-linux-lifetime-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_root);
        File.SetUnixFileMode(_root, OwnerDirectoryMode);
    }

    [TearDown]
    public void TearDown()
    {
        if (OperatingSystem.IsLinux() && Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [Test]
    public async Task LinuxOpenReadConcurrentDisposeKeepsReturnedStreamValid()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Ignore("Linux descriptor-lifetime test.");
            return;
        }

        byte[] expected = [0x4C, 0x53, 0x30, 0x32];
        WriteOwnedFile("source.bin", expected);
        for (int iteration = 0; iteration < 64; iteration++)
        {
            object directory = OpenDirectory(_root);
            using FileStream? stream = await RaceWithDisposeAsync(directory, current =>
                (FileStream)Invoke(current, "OpenRead", "source.bin")!);
            if (stream is not null)
            {
                Assert.That(stream.ReadByte(), Is.EqualTo(expected[0]));
                Assert.That(stream.ReadByte(), Is.EqualTo(expected[1]));
            }
        }

        Assert.That(File.ReadAllBytes(Path.Combine(_root, "source.bin")), Is.EqualTo(expected));
    }

    [Test]
    public async Task LinuxExistsConcurrentDisposeNeverUsesAnInvalidDirectoryDescriptor()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Ignore("Linux descriptor-lifetime test.");
            return;
        }

        WriteOwnedFile("exists.bin", [0x11]);
        for (int iteration = 0; iteration < 96; iteration++)
        {
            object directory = OpenDirectory(_root);
            _ = await RaceWithDisposeAsync(directory, current =>
            {
                bool exists = (bool)Invoke(current, "Exists", "exists.bin")!;
                Assert.That(exists, Is.True);
                return new object();
            });
        }

        Assert.That(File.ReadAllBytes(Path.Combine(_root, "exists.bin")), Is.EqualTo(new byte[] { 0x11 }));
    }

    [Test]
    public async Task LinuxCreateTemporaryConcurrentDisposeNeverReturnsABrokenChildHandle()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Ignore("Linux descriptor-lifetime test.");
            return;
        }

        for (int iteration = 0; iteration < 40; iteration++)
        {
            string name = $".pending-{Guid.NewGuid():N}.tmp";
            object directory = OpenDirectory(_root);
            using FileStream? stream = await RaceWithDisposeAsync(directory, current =>
                (FileStream)Invoke(current, "CreateTemporary", name)!);
            if (stream is not null)
            {
                byte[] expected = [0x53, 0x41, checked((byte)iteration)];
                stream.Write(expected);
                stream.Flush(flushToDisk: true);
                Assert.That(File.ReadAllBytes(Path.Combine(_root, name)), Is.EqualTo(expected));
            }
            else
            {
                Assert.That(File.Exists(Path.Combine(_root, name)), Is.False,
                    "An operation rejected before acquiring the root handle must not create a file.");
            }
        }
    }

    [Test]
    public async Task LinuxLockConcurrentDisposeRetainsTheIndependentFlockHandle()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Ignore("Linux descriptor-lifetime test.");
            return;
        }

        for (int iteration = 0; iteration < 32; iteration++)
        {
            string name = $".lock-{Guid.NewGuid():N}.tmp";
            object directory = OpenDirectory(_root);
            FileStream? acquired = await RaceWithDisposeAsync<FileStream>(directory, current =>
                (FileStream?)Invoke(current, "TryAcquireLock", name, true));
            if (acquired is null)
            {
                Assert.That(File.Exists(Path.Combine(_root, name)), Is.False,
                    "Disposal before lock acquisition must not create a lock file.");
                continue;
            }

            using (acquired)
            {
                acquired.WriteByte(0x5A);
                acquired.Flush();
                using IDisposable verifier = (IDisposable)OpenDirectory(_root);
                FileStream? competing = (FileStream?)Invoke(verifier, "TryAcquireLock", name, false);
                using (competing)
                {
                    Assert.That(competing, Is.Null, "The returned lock must stay held after root disposal.");
                }
            }

            using IDisposable reopened = (IDisposable)OpenDirectory(_root);
            using FileStream? next = (FileStream?)Invoke(reopened, "TryAcquireLock", name, false);
            Assert.That(next, Is.Not.Null, "Releasing the independent child lock must allow reacquisition.");
        }
    }

    [Test]
    public async Task LinuxMoveConcurrentDisposePreservesExactlyOneCompleteFile()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Ignore("Linux descriptor-lifetime test.");
            return;
        }

        for (int iteration = 0; iteration < 32; iteration++)
        {
            string stage = $".pending-{Guid.NewGuid():N}.tmp";
            string destination = $"snapshot-{Guid.NewGuid():N}.tmp";
            byte[] payload = [0x52, 0x45, 0x4E, checked((byte)iteration)];
            WriteOwnedFile(stage, payload);
            object directory = OpenDirectory(_root);
            _ = await RaceWithDisposeAsync(directory, current =>
            {
                Invoke(current, "Move", stage, destination, false);
                return new object();
            });

            string sourcePath = Path.Combine(_root, stage);
            string destinationPath = Path.Combine(_root, destination);
            bool sourceExists = File.Exists(sourcePath);
            bool destinationExists = File.Exists(destinationPath);
            Assert.That(sourceExists ^ destinationExists, Is.True,
                "A concurrent dispose must neither lose nor duplicate the staged file.");
            Assert.That(File.ReadAllBytes(sourceExists ? sourcePath : destinationPath), Is.EqualTo(payload));
        }
    }


    [Test]
    public async Task LinuxOverwriteMoveConcurrentDisposePreservesOldOrNewSnapshot()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Ignore("Linux descriptor-lifetime test.");
            return;
        }

        for (int iteration = 0; iteration < 32; iteration++)
        {
            string stage = $".pending-{Guid.NewGuid():N}.tmp";
            string destination = $"snapshot-{Guid.NewGuid():N}.tmp";
            byte[] previous = [0xAA, checked((byte)iteration)];
            byte[] replacement = [0xBB, checked((byte)iteration)];
            WriteOwnedFile(destination, previous);
            WriteOwnedFile(stage, replacement);
            object directory = OpenDirectory(_root);
            object? completed = await RaceWithDisposeAsync(directory, current =>
            {
                Invoke(current, "Move", stage, destination, true);
                return new object();
            });

            Assert.That(File.Exists(Path.Combine(_root, destination)), Is.True);
            if (completed is null)
            {
                Assert.That(File.Exists(Path.Combine(_root, stage)), Is.True);
                Assert.That(File.ReadAllBytes(Path.Combine(_root, destination)), Is.EqualTo(previous));
                Assert.That(File.ReadAllBytes(Path.Combine(_root, stage)), Is.EqualTo(replacement));
            }
            else
            {
                Assert.That(File.Exists(Path.Combine(_root, stage)), Is.False);
                Assert.That(File.ReadAllBytes(Path.Combine(_root, destination)), Is.EqualTo(replacement));
            }
        }
    }

    [Test]
    public async Task LinuxRemoveConcurrentDisposeCannotDeleteTheWrongFile()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Ignore("Linux descriptor-lifetime test.");
            return;
        }

        byte[] sentinel = [0xCA, 0xFE, 0xBA, 0xBE];
        WriteOwnedFile("protected.bin", sentinel);
        for (int iteration = 0; iteration < 40; iteration++)
        {
            string name = $".pending-{Guid.NewGuid():N}.tmp";
            byte[] payload = [0xD0, checked((byte)iteration)];
            WriteOwnedFile(name, payload);
            object directory = OpenDirectory(_root);
            object? completed = await RaceWithDisposeAsync(directory, current =>
            {
                Invoke(current, "Remove", name);
                return new object();
            });

            if (completed is not null)
            {
                Assert.That(File.Exists(Path.Combine(_root, name)), Is.False);
            }
            else
            {
                Assert.That(File.ReadAllBytes(Path.Combine(_root, name)), Is.EqualTo(payload));
            }

            Assert.That(File.ReadAllBytes(Path.Combine(_root, "protected.bin")), Is.EqualTo(sentinel));
        }
    }

    [Test]
    public void LinuxDisposedDirectoryRejectsAllSubsequentNativeOperations()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Ignore("Linux descriptor-lifetime test.");
            return;
        }

        WriteOwnedFile("source.bin", [0x01]);
        object directory = OpenDirectory(_root);
        ((IDisposable)directory).Dispose();
        Assert.Throws<ObjectDisposedException>(() => Invoke(directory, "Exists", "source.bin"));
        Assert.Throws<ObjectDisposedException>(() => Invoke(directory, "OpenRead", "source.bin"));
        Assert.Throws<ObjectDisposedException>(() => Invoke(directory, "CreateTemporary", "staged.tmp"));
        Assert.Throws<ObjectDisposedException>(() => Invoke(directory, "TryAcquireLock", "lock.tmp", true));
        Assert.Throws<ObjectDisposedException>(() => Invoke(directory, "Move", "source.bin", "moved.bin", false));
        Assert.Throws<ObjectDisposedException>(() => Invoke(directory, "Remove", "source.bin"));
        Assert.That(File.ReadAllBytes(Path.Combine(_root, "source.bin")), Is.EqualTo(new byte[] { 0x01 }));
        Assert.That(File.Exists(Path.Combine(_root, "staged.tmp")), Is.False);
        Assert.That(File.Exists(Path.Combine(_root, "lock.tmp")), Is.False);
        Assert.That(File.Exists(Path.Combine(_root, "moved.bin")), Is.False);
    }

    [Test]
    public async Task LinuxPinnedRootConcurrentDisposeCannotWriteIntoReplacementDirectory()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Ignore("Linux pinned-root lifetime test.");
            return;
        }

        string original = Path.Combine(_root, "original");
        string relocated = Path.Combine(_root, "relocated");
        Directory.CreateDirectory(original);
        File.SetUnixFileMode(original, OwnerDirectoryMode);
        object directory = OpenDirectory(original);
        Directory.Move(original, relocated);
        Directory.CreateDirectory(original);
        File.SetUnixFileMode(original, OwnerDirectoryMode);
        byte[] sentinel = [0xAA, 0xBB, 0xCC];
        WriteOwnedFile(Path.Combine("original", "sentinel.bin"), sentinel);

        const string stagedName = "new-pending.tmp";
        using FileStream? stream = await RaceWithDisposeAsync(directory, current =>
            (FileStream)Invoke(current, "CreateTemporary", stagedName)!);
        if (stream is not null)
        {
            stream.WriteByte(0x52);
            stream.Flush(flushToDisk: true);
            Assert.That(File.ReadAllBytes(Path.Combine(relocated, stagedName)),
                Is.EqualTo(new byte[] { 0x52 }));
        }
        else
        {
            Assert.That(File.Exists(Path.Combine(relocated, stagedName)), Is.False);
        }

        Assert.That(File.Exists(Path.Combine(original, stagedName)), Is.False,
            "The replacement pathname must never receive a relative write.");
        Assert.That(File.ReadAllBytes(Path.Combine(original, "sentinel.bin")), Is.EqualTo(sentinel));
    }

    private void WriteOwnedFile(string name, byte[] bytes)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("Linux file-mode tests require Linux.");
        }

        string path = Path.Combine(_root, name);
        File.WriteAllBytes(path, bytes);
        File.SetUnixFileMode(path, OwnerFileMode);
    }

    private static object OpenDirectory(string root)
    {
        Type directoryType = typeof(FileSystemKeyStore).Assembly.GetType(
            "Laveyana.Security.FileSystem.Storage.LinuxSecureDirectory", throwOnError: true)!;
        MethodInfo method = directoryType.GetMethod("Open", BindingFlags.Static |
            BindingFlags.NonPublic | BindingFlags.Public)!;
        return InvokeMethod(method, null, root)!;
    }

    private static object? Invoke(object directory, string methodName, params object?[] arguments)
    {
        MethodInfo method = directory.GetType().GetMethod(methodName,
            BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public)!;
        return InvokeMethod(method, directory, arguments);
    }

    private static object? InvokeMethod(MethodInfo method, object? instance, params object?[] arguments)
    {
        try
        {
            return method.Invoke(instance, arguments);
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }
    }

    private static async Task<T?> RaceWithDisposeAsync<T>(object directory, Func<object, T?> action)
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
                // Dispose won before the operation acquired a SafeHandle reference.
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
}
