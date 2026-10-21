using System.Diagnostics;
using System.Runtime.InteropServices;
using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Payloads;
using Laveyana.Security.FileSystem.Storage;
using Laveyana.Security.Software;
using NUnit.Framework;

namespace Laveyana.Security.IntegrationTests;

/// <summary>A test-only child entry point. No environment-controlled hooks exist in production code.</summary>
[TestFixture]
internal sealed class StoreProcessWorkerTests
{
    // Public, synthetic fixture material; never suitable for real data.
    internal static readonly byte[] FixtureKey = Enumerable.Repeat((byte)0xA7, 32).ToArray();
    internal const string ModeVariable = "LAVEYANA_TEST_WORKER_MODE";

    [Test]
    public async Task RunWorker()
    {
        string? mode = Environment.GetEnvironmentVariable(ModeVariable);
        if (mode is null)
        {
            Assert.Ignore("Child entry point; exercised by parent process tests.");
            return;
        }

        string root = Required("LAVEYANA_TEST_WORKER_ROOT");
        string signal = Required("LAVEYANA_TEST_WORKER_SIGNAL");
        ProviderId provider = ProviderId.Parse(Required("LAVEYANA_TEST_WORKER_PROVIDER"));
        FileSystemKeyStoreTests.TestProtector protector = new(secret: FixtureKey);
        if (mode is not ("init" or "inspect" or "kill" or "kill-journal" or "claim" or "reopen-nonce"))
        {
            throw new InvalidOperationException("Unknown test worker mode.");
        }

        string target = Environment.GetEnvironmentVariable("LAVEYANA_TEST_WORKER_TARGET") ?? "store.lsfs";
        StoreWriteBoundary? stop = mode.StartsWith("kill", StringComparison.Ordinal)
            ? Enum.Parse<StoreWriteBoundary>(Required("LAVEYANA_TEST_WORKER_BOUNDARY")) : null;
        Action<StoreWriteBoundary, string> fault = (point, name) =>
        {
            if (name == target && point == stop)
            {
                // Publish the PID only after closing the writer handle. On Windows,
                // observing File.Exists while WriteAllText is still writing can race
                // with the exclusive file share and fail the parent read.
                string pending = signal + ".pending";
                File.WriteAllText(pending, Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture));
                File.Move(pending, signal);
                // The parent kills this exact writer while its real store lock is held.
                using ManualResetEventSlim never = new(false);
                never.Wait();
            }
        };
        using FileSystemKeyStore store = await FileSystemKeyStore.OpenAsync(new(root)
        {
            EnableExperimentalWrites = mode is not ("reopen-nonce" or "inspect"),
            WriteFault = fault,
        }, protector);
        if (mode is "init" or "inspect")
        {
            bool exists = await store.FindByNameAsync(provider, new("process-key")) is not null;
            await File.WriteAllTextAsync(signal, exists ? "authenticated-candidate" : "authenticated-old");
            return;
        }

        if (mode == "kill-journal")
        {
            byte[] intent = await File.ReadAllBytesAsync(Required("LAVEYANA_TEST_WORKER_PAYLOAD"));
            byte[] snapshot = await File.ReadAllBytesAsync(Path.Combine(root, "store.lsfs"));
            RollbackPreparedWrite write = RollbackPreparedWrite.DecodeIntent(intent, snapshot);
            using LinuxSecureDirectory? linux = OperatingSystem.IsLinux() ? LinuxSecureDirectory.Open(root) : null;
            using WindowsSecureDirectory? windows = OperatingSystem.IsWindows() ? WindowsSecureDirectory.Open(root) : null;
            using FileStream held = (linux?.TryAcquireLock(".store.lock", false) ?? windows?.TryAcquireLock(".store.lock", false))
                ?? throw new IOException("Could not acquire the test journal lock.");
            await RollbackCandidateJournal.StageAsync(linux, windows, protector, write, fault: fault);
            Assert.Fail("Journal worker did not stop at the requested boundary.");
            return;
        }

        SoftwareKeyProviderBackend backend = new(provider, store, protector);
        if (mode == "reopen-nonce")
        {
            byte[] encoded = await File.ReadAllBytesAsync(Required("LAVEYANA_TEST_WORKER_PAYLOAD"));
            EncryptedPayload payload = ManagedPayloadCodec.DecodeEncrypted(encoded);
            Assert.ThrowsAsync<System.Security.Cryptography.CryptographicException>(async () =>
                await backend.EncryptAsync(new(provider, payload.Reference.KeyId), new byte[] { 1, 2, 3 }));
            Assert.That(await backend.DecryptAsync(payload), Is.EqualTo(new byte[] { 1, 2, 3 }));
            await File.WriteAllTextAsync(signal, "unknown-history-rejected;decrypt-passed");
            return;
        }

        try
        {
            await backend.CreateAsync(new("process-key"), WellKnownAlgorithms.Aes256Gcm,
                [WellKnownCapabilities.Encrypt, WellKnownCapabilities.Decrypt]);
            await File.WriteAllTextAsync(signal, "Applied");
        }
        catch (SoftwareKeyConflictException error) when (mode == "claim" && error.Reason == "NameTaken")
        {
            await File.WriteAllTextAsync(signal, "NameTaken");
        }
    }

    internal static Process Start(string mode, string root, string signal, ProviderId provider,
        StoreWriteBoundary? boundary = null, string? payload = null, string? target = null)
    {
        string host = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? Path.GetFullPath(
            Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "..", "..", "..",
                OperatingSystem.IsWindows() ? "dotnet.exe" : "dotnet"));
        ProcessStartInfo start = new(host)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = AppContext.BaseDirectory,
        };
        start.ArgumentList.Add("vstest");
        start.ArgumentList.Add(typeof(StoreProcessWorkerTests).Assembly.Location);
        start.ArgumentList.Add("/TestCaseFilter:FullyQualifiedName~StoreProcessWorkerTests.RunWorker");
        start.Environment[ModeVariable] = mode;
        start.Environment["LAVEYANA_TEST_WORKER_ROOT"] = root;
        start.Environment["LAVEYANA_TEST_WORKER_SIGNAL"] = signal;
        start.Environment["LAVEYANA_TEST_WORKER_PROVIDER"] = provider.Value.ToString("D");
        if (boundary.HasValue)
        {
            start.Environment["LAVEYANA_TEST_WORKER_BOUNDARY"] = boundary.Value.ToString();
        }

        if (payload is not null)
        {
            start.Environment["LAVEYANA_TEST_WORKER_PAYLOAD"] = payload;
        }

        if (target is not null)
        {
            start.Environment["LAVEYANA_TEST_WORKER_TARGET"] = target;
        }

        return Process.Start(start) ?? throw new IOException("Could not start the store test worker.");
    }

    private static string Required(string name) => Environment.GetEnvironmentVariable(name)
        ?? throw new InvalidOperationException($"Missing test worker setting: {name}.");
}
