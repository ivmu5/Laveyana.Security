using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Persistence;
using Laveyana.Security.Abstractions.Storage;
using Laveyana.Security.FileSystem.Storage;
using NUnit.Framework;

namespace Laveyana.Security.IntegrationTests;

public sealed partial class FileSystemKeyStoreTests
{
    // EXPERIMENTAL / TEST ONLY: an independent Windows cmd.exe worker repeatedly
    // replaces the *path* to a pinned root with a disposable NTFS junction.
    // Only temporary per-test directories are ever modified.
    [Test]
    [Category("WindowsOnly")]
    [Category("Adversarial")]
    [Category("Interprocess")]
    [SupportedOSPlatform("windows")]
    public async Task WindowsExternalProcessJunctionSwapsCannotRedirectPinnedWrites()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Independent-process Windows junction race test.");
            return;
        }

        using CancellationTokenSource deadline = new(TimeSpan.FromSeconds(30));
        FileSystemKeyStore store = await Open();
        string pinnedRoot = _root + "-external-process-pinned";
        string decoy = _root + "-external-process-decoy";
        string workerScript = _root + "-external-process-worker.cmd";
        string progressFile = _root + "-external-process-progress.txt";
        string stopFile = _root + "-external-process-stop.txt";
        string sentinel = Path.Combine(decoy, "sentinel.bin");
        byte[] marker = Encoding.UTF8.GetBytes("external-process-must-not-write-here");
        Process? attacker = null;
        bool rootMoved = false;

        Directory.CreateDirectory(decoy);
        try
        {
            await File.WriteAllBytesAsync(sentinel, marker, deadline.Token);
            await File.WriteAllTextAsync(workerScript,
                ExternalProcessJunctionWorker.Replace("\n", "\r\n", StringComparison.Ordinal),
                deadline.Token);

            // The active store has already pinned the original directory handle.
            // Rename that object, then let a second OS process control its old name.
            Directory.Move(_root, pinnedRoot);
            rootMoved = true;

            var psi = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.SystemDirectory, "cmd.exe"),
                // cmd /s removes the surrounding pair of quotes: the script path
                // remains correctly quoted even when the user profile has spaces.
                Arguments = $"/d /s /c \"\"{workerScript}\"\"",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardInput = false,
                RedirectStandardOutput = false,
                RedirectStandardError = false
            };
            psi.Environment["LAVEYANA_SA02_ALIAS"] = _root;
            psi.Environment["LAVEYANA_SA02_DECOY"] = decoy;
            psi.Environment["LAVEYANA_SA02_PROGRESS"] = progressFile;
            psi.Environment["LAVEYANA_SA02_STOP"] = stopFile;
            attacker = new Process { StartInfo = psi };
            if (!attacker.Start())
            {
                throw new IOException("Failed to start the separate junction-swap process.");
            }

            // Require evidence of multiple actual replacements, not merely that
            // a child process was launched. The second process remains alive while
            // all store mutations run.
            int beforeWrites = await WaitForExternalJunctionIterationsAsync(
                attacker, progressFile, minimum: 4, deadline.Token);

            const int writeCount = 24;
            var requests = new List<(KeyId Id, KeyName Name, KeyStoreCreateRequest Request)>();
            for (int i = 0; i < writeCount; i++)
            {
                KeyId id = KeyId.New();
                KeyName name = new($"external-process-pinned-{i}");
                requests.Add((id, name, await CreateRequest(id, name)));
            }

            Task<KeyStoreMutationResult>[] writes = requests.Select(item => Task.Run(
                async () => await store.TryCreateAsync(item.Request, deadline.Token),
                deadline.Token)).ToArray();
            KeyStoreMutationResult[] outcomes = await Task.WhenAll(writes);
            Assert.That(outcomes.All(x => x.Status == KeyStoreMutationStatus.Applied), Is.True);

            // Check the adversarial worker continued making replacements while
            // the parent was busy writing (bounded observation, not exhaustive).
            int afterWrites = await WaitForExternalJunctionIterationsAsync(
                attacker, progressFile, beforeWrites + 4, deadline.Token);
            Assert.That(afterWrites, Is.GreaterThan(beforeWrites));

            foreach (var request in requests)
            {
                KeyStoreEntry? entry = await store.FindByNameAsync(
                    _provider, request.Name, deadline.Token);
                Assert.That(entry, Is.Not.Null);
                Assert.That(entry!.KeyId, Is.EqualTo(request.Id));
            }

            Assert.That(await File.ReadAllBytesAsync(sentinel, deadline.Token), Is.EqualTo(marker));
            Assert.That(Directory.GetFileSystemEntries(decoy), Is.EquivalentTo(new[] { sentinel }),
                "Writes crossed the pinned directory boundary into the external target.");
            Assert.That(File.Exists(Path.Combine(pinnedRoot, "store.lsfs")), Is.True);
        }
        finally
        {
            if (attacker is not null)
            {
                try
                {
                    // Stop the external process *before* restoring/deleting names.
                    await File.WriteAllTextAsync(stopFile, "stop", CancellationToken.None);
                    using CancellationTokenSource exitDeadline = new(TimeSpan.FromSeconds(5));
                    try
                    {
                        await attacker.WaitForExitAsync(exitDeadline.Token);
                    }
                    catch (OperationCanceledException)
                    {
                        if (!attacker.HasExited)
                        {
                            attacker.Kill(entireProcessTree: true);
                        }

                        await attacker.WaitForExitAsync();
                    }
                }
                finally
                {
                    attacker.Dispose();
                }
            }

            if (rootMoved)
            {
                // Only remove a genuine reparse entry. Never recursively delete
                // a path which might lead to the decoy directory.
                if (Directory.Exists(_root))
                {
                    if (!File.GetAttributes(_root).HasFlag(FileAttributes.ReparsePoint))
                    {
                        throw new IOException("Unexpected non-reparse path at the test root.");
                    }

                    WindowsJunctionTestSupport.DeleteJunctionIfPresent(_root);
                }

                Directory.Move(pinnedRoot, _root);
            }

            // The decoy is a real disposable directory created by this test;
            // validate this before recursive cleanup.
            if (Directory.Exists(decoy))
            {
                if (File.GetAttributes(decoy).HasFlag(FileAttributes.ReparsePoint))
                {
                    throw new IOException("Unexpected reparse point at the decoy path.");
                }

                Directory.Delete(decoy, recursive: true);
            }

            if (File.Exists(workerScript))
            {
                File.Delete(workerScript);
            }
            if (File.Exists(progressFile))
            {
                File.Delete(progressFile);
            }
            if (File.Exists(stopFile))
            {
                File.Delete(stopFile);
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private static async Task<int> WaitForExternalJunctionIterationsAsync(
        Process attacker, string progressFile, int minimum, CancellationToken cancellationToken)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (attacker.HasExited)
            {
                throw new IOException(
                    $"The independent junction-swap worker exited prematurely (code {attacker.ExitCode}).");
            }

            try
            {
                if (File.Exists(progressFile) &&
                    int.TryParse(File.ReadAllText(progressFile).Trim(), out int count) &&
                    count >= minimum)
                {
                    return count;
                }
            }
            catch (IOException)
            {
                // Another process is rewriting the progress file; retry briefly.
            }

            await Task.Delay(20, cancellationToken);
        }
    }

    // The Windows cmd worker runs as a separate OS process, using only paths
    // generated by this test. It never traverses the junction target for writes.
    private const string ExternalProcessJunctionWorker = """
        @echo off
        setlocal EnableExtensions DisableDelayedExpansion
        if not exist "%LAVEYANA_SA02_DECOY%\sentinel.bin" exit /b 51
        set /a count=0 >nul
        :again
        if exist "%LAVEYANA_SA02_STOP%" goto done
        if exist "%LAVEYANA_SA02_ALIAS%" rmdir "%LAVEYANA_SA02_ALIAS%" >nul 2>&1
        if exist "%LAVEYANA_SA02_ALIAS%" exit /b 52
        mklink /J "%LAVEYANA_SA02_ALIAS%" "%LAVEYANA_SA02_DECOY%" >nul 2>&1
        if errorlevel 1 exit /b 53
        set /a count+=1 >nul
        > "%LAVEYANA_SA02_PROGRESS%" echo %count%
        goto again
        :done
        if exist "%LAVEYANA_SA02_ALIAS%" rmdir "%LAVEYANA_SA02_ALIAS%" >nul 2>&1
        if exist "%LAVEYANA_SA02_ALIAS%" exit /b 54
        exit /b 0
        """;
}
