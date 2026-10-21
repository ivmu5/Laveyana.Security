using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.FileSystem.Storage;
using NUnit.Framework;

namespace Laveyana.Security.IntegrationTests;

/// <summary>SA-08 B-05: root relocation must not redirect Linux pending-file cleanup.</summary>
public sealed partial class FileSystemKeyStoreTests
{
    [Test]
    [Category("LinuxOnly")]
    [Category("ArchitectureRegression")]
    public async Task LinuxPendingCleanupEnumeratesThePinnedRootAfterPathReplacement()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Ignore("Linux-only pinned directory enumeration regression.");
            return;
        }

        await Open();
        string movedRoot = _root + "-moved";
        string originalPending = $".pending-{Guid.NewGuid():N}.tmp";
        string decoyPending = $".pending-{Guid.NewGuid():N}.tmp";
        string originalPath = Path.Combine(_root, originalPending);
        byte[] originalPayload = [0x11, 0x22, 0x33];
        byte[] decoyPayload = [0x55, 0x66, 0x77];
        await File.WriteAllBytesAsync(originalPath, originalPayload);
        File.SetUnixFileMode(originalPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        byte[] snapshotBefore = await File.ReadAllBytesAsync(Path.Combine(_root, "store.lsfs"));
        bool relocated = false;
        try
        {
            // This callback occurs after OpenAsync pinned the original root handle
            // but before it completes authenticated LoadAsync and pending cleanup.
            IKeyStoreProtector protector = new RelocationProtector(_protector, () =>
            {
                // Platform analysis does not carry the guard above into callbacks.
                if (!OperatingSystem.IsLinux())
                {
                    throw new PlatformNotSupportedException("Linux-only relocation fixture.");
                }

                Directory.Move(_root, movedRoot);
                relocated = true;
                Directory.CreateDirectory(_root, UnixFileMode.UserRead | UnixFileMode.UserWrite |
                    UnixFileMode.UserExecute);
                File.WriteAllBytes(Path.Combine(_root, decoyPending), decoyPayload);
            });

            using FileSystemKeyStore reopened = await FileSystemKeyStore.OpenAsync(
                new FileSystemKeyStoreOptions(_root) { EnableExperimentalWrites = true }, protector);
            Assert.That(relocated, Is.True, "The test must reach the relocation boundary.");
            Assert.Multiple(() =>
            {
                Assert.That(File.Exists(Path.Combine(movedRoot, originalPending)), Is.False,
                    "Cleanup must find the orphan in its original pinned root.");
                Assert.That(File.ReadAllBytes(Path.Combine(_root, decoyPending)), Is.EqualTo(decoyPayload),
                    "The replacement pathname's files must be untouched.");
                Assert.That(File.ReadAllBytes(Path.Combine(movedRoot, "store.lsfs")),
                    Is.EqualTo(snapshotBefore), "Committed snapshot bytes must remain unchanged.");
            });
        }
        finally
        {
            if (relocated)
            {
                // The replacement is only a disposable fixture owned by this test.
                if (Directory.Exists(_root))
                {
                    Directory.Delete(_root, recursive: true);
                }

                Directory.Move(movedRoot, _root);
            }
        }
    }

    private sealed class RelocationProtector : IKeyStoreProtector
    {
        private readonly IKeyStoreProtector _inner;
        private Action? _onFirstUnprotect;

        internal RelocationProtector(IKeyStoreProtector inner, Action onFirstUnprotect)
        {
            _inner = inner;
            _onFirstUnprotect = onFirstUnprotect;
        }

        public ProtectorReference CurrentReference => _inner.CurrentReference;

        public ValueTask<ProtectedStoreEnvelope> ProtectAsync(SensitiveMaterialLease plaintext,
            ProtectionPurpose purpose, ReadOnlyMemory<byte> authenticatedContext,
            CancellationToken cancellationToken = default) =>
            _inner.ProtectAsync(plaintext, purpose, authenticatedContext, cancellationToken);

        public ValueTask<SensitiveMaterialLease> UnprotectAsync(ProtectedStoreEnvelope envelope,
            ProtectionPurpose expectedPurpose, ReadOnlyMemory<byte> authenticatedContext,
            CancellationToken cancellationToken = default)
        {
            Interlocked.Exchange(ref _onFirstUnprotect, null)?.Invoke();
            return _inner.UnprotectAsync(envelope, expectedPurpose, authenticatedContext, cancellationToken);
        }
    }
}
