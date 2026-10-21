using System.Diagnostics;
using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Payloads;
using Laveyana.Security.FileSystem.Storage;
using Laveyana.Security.Software;
using NUnit.Framework;

namespace Laveyana.Security.IntegrationTests;

public sealed partial class FileSystemKeyStoreTests
{
    [TestCase(nameof(StoreWriteBoundary.TemporaryCreated), false)]
    [TestCase(nameof(StoreWriteBoundary.DataWritten), false)]
    [TestCase(nameof(StoreWriteBoundary.FileFlushed), false)]
    [TestCase(nameof(StoreWriteBoundary.BeforeRename), false)]
    [TestCase(nameof(StoreWriteBoundary.AfterRename), true)]
    [TestCase(nameof(StoreWriteBoundary.DirectoryFlushed), true)]
    [TestCase(nameof(StoreWriteBoundary.Published), true)]
    [Category("Interprocess")]
    public async Task KilledLibraryWriterReopensOneAuthenticatedSnapshot(string boundaryName, bool committed)
    {
        StoreWriteBoundary boundary = Enum.Parse<StoreWriteBoundary>(boundaryName);
        if (boundary == StoreWriteBoundary.DirectoryFlushed && !OperatingSystem.IsLinux())
        {
            Assert.Ignore("No verified Windows directory persistence barrier is implemented.");
            return;
        }

        _protector = new TestProtector(secret: StoreProcessWorkerTests.FixtureKey);
        await Open();
        byte[] before = (await CurrentSnapshotAsync()).Bytes;
        string signal = _root + "-kill-signal";
        using Process driver = StoreProcessWorkerTests.Start("kill", _root, signal, _provider, boundary);
        Task<string> output = driver.StandardOutput.ReadToEndAsync();
        Task<string> errors = driver.StandardError.ReadToEndAsync();
        try
        {
            using CancellationTokenSource deadline = new(TimeSpan.FromSeconds(40));
            await KillAtSignalAsync(driver, signal, output, errors, deadline.Token);
            using (FileSystemKeyStore reopened = await FileSystemKeyStore.OpenAsync(new(_root)
            {
                EnableExperimentalWrites = true,
            }, _protector))
            {
                Assert.That(await reopened.FindByNameAsync(_provider, new("process-key")), committed ? Is.Not.Null : Is.Null);
            }

            byte[] after = (await CurrentSnapshotAsync()).Bytes;
            Assert.That(after.AsSpan().SequenceEqual(before), Is.EqualTo(!committed));
            using FileSystemKeyStore again = await FileSystemKeyStore.OpenAsync(new(_root), _protector);
            Assert.That(await again.FindByNameAsync(_provider, new("process-key")), committed ? Is.Not.Null : Is.Null);
            Assert.That((await CurrentSnapshotAsync()).Bytes, Is.EqualTo(after));
        }
        finally
        {
            await StopWorkerAsync(driver);
            File.Delete(signal);
        }
    }

    [Test]
    [Category("Interprocess")]
    public async Task IndependentLibraryProcessesClaimExactlyOneName()
    {
        _protector = new TestProtector(secret: StoreProcessWorkerTests.FixtureKey);
        FileSystemKeyStore reader = await Open();
        string leftSignal = _root + "-claim-left";
        string rightSignal = _root + "-claim-right";
        using Process left = StoreProcessWorkerTests.Start("claim", _root, leftSignal, _provider);
        using Process right = StoreProcessWorkerTests.Start("claim", _root, rightSignal, _provider);
        Task<string>[] logs = [left.StandardOutput.ReadToEndAsync(), left.StandardError.ReadToEndAsync(),
            right.StandardOutput.ReadToEndAsync(), right.StandardError.ReadToEndAsync()];
        try
        {
            using CancellationTokenSource deadline = new(TimeSpan.FromSeconds(45));
            await Task.WhenAll(left.WaitForExitAsync(deadline.Token), right.WaitForExitAsync(deadline.Token));
            string log = string.Join("\n", await Task.WhenAll(logs));
            Assert.That(left.ExitCode, Is.Zero, log);
            Assert.That(right.ExitCode, Is.Zero, log);
            Assert.That(new[] { await File.ReadAllTextAsync(leftSignal), await File.ReadAllTextAsync(rightSignal) },
                Is.EquivalentTo(new[] { "Applied", "NameTaken" }));
            Assert.That(await reader.FindByNameAsync(_provider, new("process-key")), Is.Not.Null);
        }
        finally
        {
            await StopWorkerAsync(left);
            await StopWorkerAsync(right);
            File.Delete(leftSignal);
            File.Delete(rightSignal);
        }
    }

    [Test]
    [Category("Interprocess")]
    public async Task RestartedProcessCannotResetStoredAesNonceLifetime()
    {
        _protector = new TestProtector(secret: StoreProcessWorkerTests.FixtureKey);
        FileSystemKeyStore store = await Open();
        SoftwareKeyProviderBackend backend = new(_provider, store, _protector);
        KeyDescriptor key = await backend.CreateAsync(new("restart-nonce"), WellKnownAlgorithms.Aes256Gcm,
            [WellKnownCapabilities.Encrypt, WellKnownCapabilities.Decrypt]);
        EncryptedPayload payload = await backend.EncryptAsync(new(_provider, key.KeyId), new byte[] { 1, 2, 3 });
        string payloadPath = _root + "-payload";
        string signal = _root + "-nonce-signal";
        await File.WriteAllBytesAsync(payloadPath, ManagedPayloadCodec.Encode(payload));
        using Process worker = StoreProcessWorkerTests.Start("reopen-nonce", _root, signal, _provider, payload: payloadPath);
        Task<string> output = worker.StandardOutput.ReadToEndAsync();
        Task<string> errors = worker.StandardError.ReadToEndAsync();
        try
        {
            using CancellationTokenSource deadline = new(TimeSpan.FromSeconds(40));
            await worker.WaitForExitAsync(deadline.Token);
            Assert.That(worker.ExitCode, Is.Zero, $"{await output} {await errors}");
            Assert.That(await File.ReadAllTextAsync(signal), Is.EqualTo("unknown-history-rejected;decrypt-passed"));
        }
        finally
        {
            await StopWorkerAsync(worker);
            File.Delete(signal);
            File.Delete(payloadPath);
        }
    }

    [TestCase(nameof(StoreWriteBoundary.FileFlushed), RollbackCandidateJournal.CandidateName, false, false)]
    [TestCase(nameof(StoreWriteBoundary.AfterRename), RollbackCandidateJournal.CandidateName, true, false)]
    [TestCase(nameof(StoreWriteBoundary.FileFlushed), RollbackCandidateJournal.IntentName, true, false)]
    [TestCase(nameof(StoreWriteBoundary.AfterRename), RollbackCandidateJournal.IntentName, true, true)]
    [Category("Interprocess")]
    public async Task KilledJournalWriterPreservesExactCandidateAndPartialIntentEvidence(string boundaryName,
        string target, bool candidateExpected, bool intentExpected)
    {
        _protector = new TestProtector(secret: StoreProcessWorkerTests.FixtureKey);
        (Guid storeId, RollbackPreparedWrite write) = await NewPreparedWriteAsync();
        string signal = _root + "-journal-signal";
        string intentPath = _root + "-worker-intent";
        await File.WriteAllBytesAsync(intentPath, write.EncodeIntent());
        using Process driver = StoreProcessWorkerTests.Start("kill-journal", _root, signal, _provider,
            Enum.Parse<StoreWriteBoundary>(boundaryName), intentPath, target);
        Task<string> output = driver.StandardOutput.ReadToEndAsync();
        Task<string> errors = driver.StandardError.ReadToEndAsync();
        try
        {
            using CancellationTokenSource deadline = new(TimeSpan.FromSeconds(40));
            await KillAtSignalAsync(driver, signal, output, errors, deadline.Token);
            (LinuxSecureDirectory? linux, WindowsSecureDirectory? windows) = OpenJournalDirectory();
            using LinuxSecureDirectory? linuxOwner = linux;
            using WindowsSecureDirectory? windowsOwner = windows;
            using FileStream held = (linux?.TryAcquireLock(".store.lock", false) ?? windows?.TryAcquireLock(".store.lock", false))
                ?? throw new IOException("Could not acquire journal inspection lock.");
            Assert.That(File.Exists(Path.Combine(_root, RollbackCandidateJournal.CandidateName)), Is.EqualTo(candidateExpected));
            Assert.That(File.Exists(Path.Combine(_root, RollbackCandidateJournal.IntentName)), Is.EqualTo(intentExpected));
            if (intentExpected)
            {
                RollbackPreparedWrite? restored = await RollbackCandidateJournal.ReadAsync(linux, windows, _protector, storeId);
                Assert.That(restored!.Prepared.Matches(write.Prepared), Is.True);
                Assert.That(restored.PrepareRequestId.Equals(write.PrepareRequestId), Is.True);
                Assert.That(restored.FinalizeRequestId.Equals(write.FinalizeRequestId), Is.True);
            }
            else if (candidateExpected)
            {
                Assert.ThrowsAsync<InvalidDataException>(async () =>
                    await RollbackCandidateJournal.ReadAsync(linux, windows, _protector, storeId));
                Assert.That(await File.ReadAllBytesAsync(Path.Combine(_root, RollbackCandidateJournal.CandidateName)),
                    Is.EqualTo(write.ExportCandidateCopy()));
            }
            else
            {
                Assert.That(await RollbackCandidateJournal.ReadAsync(linux, windows, _protector, storeId), Is.Null);
            }
        }
        finally
        {
            await StopWorkerAsync(driver);
            File.Delete(signal);
            File.Delete(intentPath);
        }
    }

    private static async Task KillAtSignalAsync(Process driver, string signal, Task<string> output,
        Task<string> errors, CancellationToken cancellationToken)
    {
        int writerId = 0;
        while (writerId == 0)
        {
            if (driver.HasExited)
            {
                Assert.Fail($"Worker exited before boundary: {await output} {await errors}");
            }

            if (File.Exists(signal))
            {
                int.TryParse(await File.ReadAllTextAsync(signal, cancellationToken), out writerId);
            }

            if (writerId == 0)
            {
                await Task.Delay(20, cancellationToken);
            }
        }

        Assert.That(writerId, Is.Not.EqualTo(Environment.ProcessId));
        using (Process writer = Process.GetProcessById(writerId))
        {
            writer.Kill(entireProcessTree: true);
            await writer.WaitForExitAsync(cancellationToken);
        }

        await driver.WaitForExitAsync(cancellationToken);
        Assert.That(driver.ExitCode, Is.Not.Zero, "The writer must actually terminate abnormally.");
    }

    private static async Task StopWorkerAsync(Process worker)
    {
        if (!worker.HasExited)
        {
            worker.Kill(entireProcessTree: true);
            using CancellationTokenSource deadline = new(TimeSpan.FromSeconds(10));
            await worker.WaitForExitAsync(deadline.Token);
        }
    }
}
