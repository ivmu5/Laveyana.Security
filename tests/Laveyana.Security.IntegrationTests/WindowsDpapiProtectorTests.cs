using System.Security.Cryptography;
using System.Runtime.Versioning;
using System.Text;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.FileSystem.Storage;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Windows.Protection;
using NUnit.Framework;

namespace Laveyana.Security.IntegrationTests;

[TestFixture]
public sealed class WindowsDpapiProtectorTests
{
    private static readonly ProtectorReference Reference = new("laveyana.windows.integration", 1);
    private static readonly byte[] Context = Encoding.ASCII.GetBytes("laveyana/test/store/v1/key-7/version-2");

    [Category("NonWindowsOnly")]
    [Test]
    public void UnsupportedOperatingSystemFailsClosed()
    {
        if (OperatingSystem.IsWindows())
        {
            Assert.Ignore("This negative-platform test runs on non-Windows hosts only.");
            return;
        }

        // Intentionally verify rejection on an unsupported OS.
#pragma warning disable CA1416
        Assert.Throws<PlatformNotSupportedException>(() => new WindowsDpapiUserProtector(Reference));
#pragma warning restore CA1416
    }

    [Category("WindowsOnly")]
    [Test]
    [SupportedOSPlatform("windows")]
    public async Task RoundTripAcrossInstancesDoesNotMutateCallerLease()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Requires Windows DPAPI.");
            return;
        }

        byte[] secret = RandomNumberGenerator.GetBytes(100);
        try
        {
            using SensitiveMaterialLease original = SensitiveMaterialLease.CreateCopy(secret);
            var writer = new WindowsDpapiUserProtector(Reference);
            ProtectedStoreEnvelope envelope = await writer.ProtectAsync(original, ProtectionPurpose.KeyMaterial, Context);
            Assert.That(envelope.Protector, Is.EqualTo(Reference));
            Assert.That(envelope.Purpose, Is.EqualTo(ProtectionPurpose.KeyMaterial));
            Assert.That(envelope.ToString(), Does.Not.Contain(Convert.ToHexString(secret)));
            Assert.That(envelope.ExportEncodedCopy().AsSpan().IndexOf(secret), Is.LessThan(0));

            var reader = new WindowsDpapiUserProtector(Reference);
            using SensitiveMaterialLease restored = await reader.UnprotectAsync(envelope, ProtectionPurpose.KeyMaterial, Context);
            bool same = false;
            restored.UseMaterial(bytes => same = bytes.SequenceEqual(secret));
            Assert.That(same, Is.True);
            bool originalStillSame = false;
            original.UseMaterial(bytes => originalStillSame = bytes.SequenceEqual(secret));
            Assert.That(originalStillSame, Is.True);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    [Category("WindowsOnly")]
    [Test]
    [SupportedOSPlatform("windows")]
    public async Task WrongContextAndWrongPurposeNeverDecrypt()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Requires Windows DPAPI.");
            return;
        }

        var protector = new WindowsDpapiUserProtector(Reference);
        using SensitiveMaterialLease lease = SensitiveMaterialLease.CreateCopy("a secret"u8);
        ProtectedStoreEnvelope ciphertext = await protector.ProtectAsync(lease, ProtectionPurpose.Metadata, Context);
        Assert.ThrowsAsync<CryptographicException>(async () =>
            await protector.UnprotectAsync(ciphertext, ProtectionPurpose.Metadata, "wrong-context"u8.ToArray()));
        Assert.ThrowsAsync<CryptographicException>(async () =>
            await protector.UnprotectAsync(ciphertext, ProtectionPurpose.KeyMaterial, Context));
        var mislabeled = new ProtectedStoreEnvelope(Reference, ProtectionPurpose.KeyMaterial, ciphertext.ExportEncodedCopy());
        Assert.ThrowsAsync<CryptographicException>(async () =>
            await protector.UnprotectAsync(mislabeled, ProtectionPurpose.KeyMaterial, Context));
    }

    [Category("WindowsOnly")]
    [Test]
    [SupportedOSPlatform("windows")]
    public async Task DifferentIdentityOrGenerationCannotReadAnEnvelope()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Requires Windows DPAPI.");
            return;
        }

        var protector = new WindowsDpapiUserProtector(Reference);
        using SensitiveMaterialLease lease = SensitiveMaterialLease.CreateCopy("material"u8);
        ProtectedStoreEnvelope ciphertext = await protector.ProtectAsync(lease, ProtectionPurpose.KeyMaterial, Context);
        var wrongId = new WindowsDpapiUserProtector(new ProtectorReference("another.app", 1));
        var wrongGeneration = new WindowsDpapiUserProtector(new ProtectorReference(Reference.Id!, 2));
        Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrongId.UnprotectAsync(ciphertext, ProtectionPurpose.KeyMaterial, Context));
        Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrongGeneration.UnprotectAsync(ciphertext, ProtectionPurpose.KeyMaterial, Context));
        var relabeled = new ProtectedStoreEnvelope(wrongId.CurrentReference, ProtectionPurpose.KeyMaterial,
            ciphertext.ExportEncodedCopy());
        Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrongId.UnprotectAsync(relabeled, ProtectionPurpose.KeyMaterial, Context));
    }

    [Category("WindowsOnly")]
    [Test]
    [SupportedOSPlatform("windows")]
    public async Task TamperedEnvelopeAndUnknownWireVersionFailClosed()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Requires Windows DPAPI.");
            return;
        }

        var protector = new WindowsDpapiUserProtector(Reference);
        using SensitiveMaterialLease lease = SensitiveMaterialLease.CreateCopy("material"u8);
        ProtectedStoreEnvelope ciphertext = await protector.ProtectAsync(lease, ProtectionPurpose.KeyMaterial, Context);
        byte[] corrupted = ciphertext.ExportEncodedCopy();
        corrupted[^1] ^= 0xA5;
        Assert.ThrowsAsync<CryptographicException>(async () =>
            await protector.UnprotectAsync(new ProtectedStoreEnvelope(Reference, ProtectionPurpose.KeyMaterial, corrupted),
                ProtectionPurpose.KeyMaterial, Context));
        byte[] versioned = ciphertext.ExportEncodedCopy();
        versioned[4] = 42;
        Assert.ThrowsAsync<CryptographicException>(async () =>
            await protector.UnprotectAsync(new ProtectedStoreEnvelope(Reference, ProtectionPurpose.KeyMaterial, versioned),
                ProtectionPurpose.KeyMaterial, Context));
        byte[] truncated = ciphertext.ExportEncodedCopy()[..^1];
        Assert.ThrowsAsync<CryptographicException>(async () =>
            await protector.UnprotectAsync(new ProtectedStoreEnvelope(Reference, ProtectionPurpose.KeyMaterial, truncated),
                ProtectionPurpose.KeyMaterial, Context));
    }

    [Category("WindowsOnly")]
    [Test]
    [SupportedOSPlatform("windows")]
    public async Task MissingContextAndCancellationAreRejectedBeforeAccess()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Requires Windows DPAPI.");
            return;
        }

        var protector = new WindowsDpapiUserProtector(Reference);
        using SensitiveMaterialLease lease = SensitiveMaterialLease.CreateCopy("material"u8);
        Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () =>
            await protector.ProtectAsync(lease, ProtectionPurpose.Metadata, Array.Empty<byte>()));
        using var source = new CancellationTokenSource();
        source.Cancel();
        Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await protector.ProtectAsync(lease, ProtectionPurpose.KeyMaterial, Context, source.Token));
    }

    [Category("WindowsOnly")]
    [Test]
    [SupportedOSPlatform("windows")]
    public async Task PersistedFileSystemSnapshotCanReopenWithNewProtectorInstance()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Requires Windows DPAPI.");
            return;
        }

        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrWhiteSpace(profile))
        {
            throw new InvalidOperationException("Cannot locate a user-owned test directory.");
        }

        string root = Path.Combine(profile, $"laveyana-dpapi-test-{Guid.NewGuid():N}");
        try
        {
            var options = new FileSystemKeyStoreOptions(root) { EnableExperimentalWrites = true };
            using (FileSystemKeyStore first = await FileSystemKeyStore.OpenAsync(
                options, new WindowsDpapiUserProtector(Reference)))
            {
                Assert.That(await first.FindByNameAsync(ProviderId.New(), new KeyName("missing")), Is.Null);
            }

            using (FileSystemKeyStore second = await FileSystemKeyStore.OpenAsync(
                options, new WindowsDpapiUserProtector(Reference)))
            {
                Assert.That(await second.FindByNameAsync(ProviderId.New(), new KeyName("missing")), Is.Null);
            }
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, true);
            }
        }
    }

}
