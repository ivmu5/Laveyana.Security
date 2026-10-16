using NUnit.Framework;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Versioning;
using System.Text;
using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Persistence;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Abstractions.Storage;
using Laveyana.Security.FileSystem.Storage;
using Laveyana.Security.Protection;
using Laveyana.Security.Software;

namespace Laveyana.Security.IntegrationTests;

[TestFixture]
public sealed class FileSystemKeyStoreTests
{
    private string _root = null!;
    private TestProtector _protector = null!;
    private readonly List<FileSystemKeyStore> _opened = new();
    private readonly ProviderId _provider = ProviderId.New();
    private readonly KeyName _name = new("sample");

    [SetUp]
    public void SetUp()
    {
        // Windows Temp can contain writable ACEs granted to sandbox groups.
        // Keep these security tests in a user-owned location instead.
        string basePath = OperatingSystem.IsWindows()
            ? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
            : Path.GetTempPath();
        if (string.IsNullOrWhiteSpace(basePath))
        {
            throw new InvalidOperationException("Cannot locate the integration-test base directory.");
        }

        _root = Path.Combine(basePath, $"laveyana-fs-test-{Guid.NewGuid():N}");
        _protector = new TestProtector();
    }

    [TearDown]
    public void TearDown()
    {
        foreach (FileSystemKeyStore store in _opened)
        {
            store.Dispose();
        }

        _opened.Clear();
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, true);
        }
    }

    [Test]
    public async Task TwoIndependentInstancesAtomicallyClaimOneName()
    {
        FileSystemKeyStore first = await Open();
        FileSystemKeyStore second = await Open();
        KeyId keyA = KeyId.New();
        KeyId keyB = KeyId.New();
        KeyStoreCreateRequest requestA = await CreateRequest(keyA, _name);
        KeyStoreCreateRequest requestB = await CreateRequest(keyB, _name);
        Task<KeyStoreMutationResult> taskA = Task.Run(async () => await first.TryCreateAsync(requestA));
        Task<KeyStoreMutationResult> taskB = Task.Run(async () => await second.TryCreateAsync(requestB));
        KeyStoreMutationResult[] outcomes = await Task.WhenAll(taskA, taskB);
        Assert.That(outcomes.Count(x => x.Status == KeyStoreMutationStatus.Applied), Is.EqualTo(1));
        Assert.That(outcomes.Count(x => x.Status == KeyStoreMutationStatus.NameTaken), Is.EqualTo(1));
        KeyStoreEntry? persisted = await second.FindByNameAsync(_provider, _name);
        Assert.That(persisted, Is.Not.Null);
        Assert.That(persisted!.KeyId == keyA || persisted.KeyId == keyB, Is.True);
    }

    [Test]
    public async Task ReplaceIsCasAndMaterialReadIsRevisionConsistentAcrossOpenInstances()
    {
        FileSystemKeyStore first = await Open();
        KeyId key = KeyId.New();
        await first.TryCreateAsync(await CreateRequest(key, _name));
        FileSystemKeyStore second = await Open();
        KeyStoreReplaceRequest replace = new(_provider, key, new KeyStoreRevision(1),
            await Metadata(key, 2, 20), [KeyStoreMaterialChange.Upsert(
                new KeyReference(_provider, key, new KeyVersion(2)), await Material(key, 2, 21))]);
        Assert.That((await second.TryReplaceAsync(replace)).Status, Is.EqualTo(KeyStoreMutationStatus.Applied));
        Assert.That((await first.TryReplaceAsync(replace)).Status,
            Is.EqualTo(KeyStoreMutationStatus.RevisionMismatch));
        Assert.That((await first.ReadMaterialAsync(new KeyReference(_provider, key, new KeyVersion(2)),
            new KeyStoreRevision(1))).Status, Is.EqualTo(KeyStoreMaterialReadStatus.RevisionMismatch));
        Assert.That((await first.ReadMaterialAsync(new KeyReference(_provider, key, new KeyVersion(2)),
            new KeyStoreRevision(2))).Status, Is.EqualTo(KeyStoreMaterialReadStatus.Found));
    }

    [Test]
    public async Task DeletedIdRemainsReservedButNameCanBeReclaimed()
    {
        FileSystemKeyStore store = await Open();
        KeyId id = KeyId.New();
        KeyStoreCreateRequest initial = await CreateRequest(id, _name);
        Assert.That((await store.TryCreateAsync(initial)).Status, Is.EqualTo(KeyStoreMutationStatus.Applied));
        Assert.That((await store.TryDeleteAsync(_provider, id, new KeyStoreRevision(1))).Status,
            Is.EqualTo(KeyStoreMutationStatus.Applied));
        Assert.That((await store.TryCreateAsync(initial)).Status,
            Is.EqualTo(KeyStoreMutationStatus.KeyAlreadyExists));
        KeyId next = KeyId.New();
        Assert.That((await store.TryCreateAsync(await CreateRequest(next, _name))).Status,
            Is.EqualTo(KeyStoreMutationStatus.Applied));
        Assert.That((await store.FindByNameAsync(_provider, _name))!.KeyId, Is.EqualTo(next));
    }

    [Test]
    public async Task CorruptSnapshotNeverRecreatesOrUsesUnauthenticatedState()
    {
        FileSystemKeyStore store = await Open();
        KeyId id = KeyId.New();
        await store.TryCreateAsync(await CreateRequest(id, _name));
        string path = Path.Combine(_root, "store.lsfs");
        byte[] bytes = await File.ReadAllBytesAsync(path);
        bytes[20] ^= 0x40;
        await File.WriteAllBytesAsync(path, bytes);
        Assert.ThrowsAsync<InvalidDataException>(async () => await store.FindByIdAsync(_provider, id));
        Assert.ThrowsAsync<InvalidDataException>(async () => await Open());
    }

    [Test]
    public async Task AbandonedTempIsRemovedOnlyAfterAuthenticatingCommittedSnapshot()
    {
        await Open();
        string abandoned = Path.Combine(_root, ".pending-1234567890abcdef.tmp");
        await File.WriteAllBytesAsync(abandoned, [1, 2, 3, 4]);
        if (OperatingSystem.IsLinux())
        {
            File.SetUnixFileMode(abandoned, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        await Open();
        Assert.That(File.Exists(abandoned), Is.False);
    }

    [Test]
    public async Task HistoricalSnapshotReplayCannotBeDetectedWithoutExternalRollbackAuthority()
    {
        FileSystemKeyStore store = await Open();
        byte[] previous = await File.ReadAllBytesAsync(Path.Combine(_root, "store.lsfs"));
        await store.TryCreateAsync(await CreateRequest(KeyId.New(), _name));
        await File.WriteAllBytesAsync(Path.Combine(_root, "store.lsfs"), previous);
        FileSystemKeyStore reopened = await Open();
        Assert.That(await reopened.FindByNameAsync(_provider, _name), Is.Null);
        Assert.That(reopened.Capabilities.ProvidesRollbackProtection, Is.False);
    }

    [Test]
    public async Task WritesAreOptInAndMissingProtectorOrWrongKeyIsRejected()
    {
        await Open();
        FileSystemKeyStore readOnly = await FileSystemKeyStore.OpenAsync(new FileSystemKeyStoreOptions(_root), _protector);
        KeyStoreCreateRequest request = await CreateRequest(KeyId.New(), _name);
        Assert.ThrowsAsync<InvalidOperationException>(async () => await readOnly.TryCreateAsync(request));
        Assert.ThrowsAsync<CryptographicException>(async () => await FileSystemKeyStore.OpenAsync(
            new FileSystemKeyStoreOptions(_root), new TestProtector()));
        Assert.ThrowsAsync<InvalidOperationException>(async () => await FileSystemKeyStore.OpenAsync(
            new FileSystemKeyStoreOptions(_root) { ExpectedStoreInstanceId = Guid.NewGuid() }, _protector));
    }

    [Test]
    public async Task FutureStoreFormatIsRejectedInsteadOfBeingDowngraded()
    {
        await Open();
        string path = Path.Combine(_root, "store.lsfs");
        byte[] bytes = await File.ReadAllBytesAsync(path);
        bytes[4] = 2;
        await File.WriteAllBytesAsync(path, bytes);
        Assert.ThrowsAsync<InvalidDataException>(async () => await Open());
    }

    [Test]
    public async Task IncompleteInitialBootstrapIsRejectedWithoutResettingIdentity()
    {
        await Open();
        File.Delete(Path.Combine(_root, "store.lsfs"));
        Assert.ThrowsAsync<FileNotFoundException>(async () => await Open());
    }

    [Test]
    public async Task RedirectedRootIsRejectedAtInitialization()
    {
        if (OperatingSystem.IsWindows())
        {
            Assert.Ignore("Unix symbolic link smoke check; Windows reparse tests belong to Phase 13.");
        }

        await Open();
        string alias = _root + "-alias";
        Directory.CreateSymbolicLink(alias, _root);
        try
        {
            Assert.ThrowsAsync<IOException>(async () => await FileSystemKeyStore.OpenAsync(
                new FileSystemKeyStoreOptions(alias), _protector));
        }
        finally
        {
            Directory.Delete(alias);
        }
    }

    [Test]
    public async Task CancellationBeforeStoreLockDoesNotCreateRecords()
    {
        FileSystemKeyStore store = await Open();
        using CancellationTokenSource source = new();
        source.Cancel();
        KeyStoreCreateRequest request = await CreateRequest(KeyId.New(), _name);
        Assert.ThrowsAsync<OperationCanceledException>(async () => await store.TryCreateAsync(request, source.Token));
        Assert.That(await store.FindByNameAsync(_provider, _name), Is.Null);
    }

    [Category("LinuxOnly")]
    [Test]
    public async Task InsecureRootPermissionsAreRejectedWithoutRepair()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Ignore("Linux owner/mode test.");
            return;
        }

        await Open();
        File.SetUnixFileMode(_root, UnixFileMode.UserRead | UnixFileMode.UserWrite |
            UnixFileMode.UserExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
        try
        {
            Assert.ThrowsAsync<UnauthorizedAccessException>(async () => await Open());
        }
        finally
        {
            File.SetUnixFileMode(_root, UnixFileMode.UserRead | UnixFileMode.UserWrite |
                UnixFileMode.UserExecute);
        }
    }

    [Category("LinuxOnly")]
    [Test]
    public async Task ExistingRootWithoutOwnerWritePermissionIsRejected()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Ignore("Linux owner/mode test.");
            return;
        }

        await Open();
        File.SetUnixFileMode(_root, UnixFileMode.UserRead | UnixFileMode.UserExecute);
        try
        {
            Assert.ThrowsAsync<UnauthorizedAccessException>(async () => await Open());
        }
        finally
        {
            File.SetUnixFileMode(_root, UnixFileMode.UserRead | UnixFileMode.UserWrite |
                UnixFileMode.UserExecute);
        }
    }

    [Category("LinuxOnly")]
    [TestCase("store.lsfs")]
    [TestCase("bootstrap.lspb")]
    [TestCase(".store.lock")]
    public async Task InsecureExistingFilePermissionsAreRejected(string file)
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Ignore("Linux file permissions test.");
            return;
        }

        await Open();
        string path = Path.Combine(_root, file);
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite |
            UnixFileMode.GroupRead);
        try
        {
            Assert.ThrowsAsync<UnauthorizedAccessException>(async () => await Open());
        }
        finally
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    [Category("LinuxOnly")]
    [TestCase("store.lsfs")]
    [TestCase("bootstrap.lspb")]
    [TestCase(".store.lock")]
    public async Task ReplacedCriticalFileSymlinkIsRejected(string file)
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Ignore("Linux no-follow test.");
            return;
        }

        await Open();
        string entry = Path.Combine(_root, file);
        string backup = Path.Combine(_root, "saved_" + file.TrimStart('.'));
        File.Move(entry, backup);
        File.CreateSymbolicLink(entry, backup);
        try
        {
            Assert.ThrowsAsync<IOException>(async () => await Open());
        }
        finally
        {
            File.Delete(entry);
            File.Move(backup, entry);
        }
    }

    [Category("LinuxOnly")]
    [Test]
    public async Task SymlinkInAncestorIsRejected()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Ignore("Linux no-follow ancestor test.");
            return;
        }

        await Open();
        string alias = Path.Combine(Path.GetTempPath(), $"laveyana-alias-{Guid.NewGuid():N}");
        Directory.CreateSymbolicLink(alias, Path.GetDirectoryName(_root)!);
        try
        {
            string redirected = Path.Combine(alias, Path.GetFileName(_root));
            Assert.ThrowsAsync<IOException>(async () => await FileSystemKeyStore.OpenAsync(
                new FileSystemKeyStoreOptions(redirected), _protector));
        }
        finally
        {
            Directory.Delete(alias);
        }
    }

    [Category("LinuxOnly")]
    [Test]
    public async Task GroupWritableAncestorWithoutTrustedStickyDirectoryIsRejected()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Ignore("Linux ancestor permission test.");
            return;
        }

        string parent = Path.Combine(Path.GetTempPath(), $"laveyana-parent-{Guid.NewGuid():N}");
        string child = Path.Combine(parent, "store");
        Directory.CreateDirectory(parent, UnixFileMode.UserRead | UnixFileMode.UserWrite |
            UnixFileMode.UserExecute | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute);
        try
        {
            Assert.ThrowsAsync<UnauthorizedAccessException>(async () => await FileSystemKeyStore.OpenAsync(
                new FileSystemKeyStoreOptions(child) { EnableExperimentalWrites = true }, _protector));
        }
        finally
        {
            Directory.Delete(parent, true);
        }
    }

    [Category("LinuxOnly")]
    [Test]
    public async Task LinuxOpenDescriptorRemainsPinnedAfterPathRename()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Ignore("Linux pinned directory test.");
            return;
        }

        using FileSystemKeyStore store = await Open();
        string movedRoot = _root + "-renamed";
        Directory.Move(_root, movedRoot);
        try
        {
            KeyId id = KeyId.New();
            Assert.That((await store.TryCreateAsync(await CreateRequest(id, _name))).Status,
                Is.EqualTo(KeyStoreMutationStatus.Applied));
            Assert.That(File.Exists(Path.Combine(movedRoot, "store.lsfs")), Is.True);
            Assert.That((await store.FindByNameAsync(_provider, _name))!.KeyId, Is.EqualTo(id));
        }
        finally
        {
            Directory.Move(movedRoot, _root);
        }
    }

    [Category("LinuxOnly")]
    [Test]
    public async Task UnixFilePermissionCheckRejectsInsecureSnapshotEvenForReadOnlyOpen()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Ignore("Linux mode test.");
            return;
        }

        await Open();
        string snapshot = Path.Combine(_root, "store.lsfs");
        File.SetUnixFileMode(snapshot, UnixFileMode.UserRead | UnixFileMode.UserWrite |
            UnixFileMode.OtherRead);
        try
        {
            Assert.ThrowsAsync<UnauthorizedAccessException>(async () => await FileSystemKeyStore.OpenAsync(
                new FileSystemKeyStoreOptions(_root), _protector));
        }
        finally
        {
            File.SetUnixFileMode(snapshot, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    [Category("WindowsOnly")]
    [Test]
    [SupportedOSPlatform("windows")]
    public async Task WindowsInheritOnlyGrantOnAncestorDoesNotInvalidateIsolatedStore()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Requires Windows ACL support.");
            return;
        }

        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrWhiteSpace(profile))
        {
            throw new InvalidOperationException("Cannot locate a user-owned test directory.");
        }

        string parent = Path.Combine(profile, $"laveyana-acl-parent-{Guid.NewGuid():N}");
        Directory.CreateDirectory(parent);
        try
        {
            DirectoryInfo parentDirectory = new(parent);
            DirectorySecurity acl = FileSystemAclExtensions.GetAccessControl(parentDirectory);
            acl.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                FileSystemRights.Modify,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.InheritOnly,
                AccessControlType.Allow));
            FileSystemAclExtensions.SetAccessControl(parentDirectory, acl);

            string storeRoot = Path.Combine(parent, "store");
            using FileSystemKeyStore store = await FileSystemKeyStore.OpenAsync(
                new FileSystemKeyStoreOptions(storeRoot) { EnableExperimentalWrites = true },
                _protector);
            Assert.That(await store.FindByNameAsync(_provider, _name), Is.Null);
        }
        finally
        {
            Directory.Delete(parent, recursive: true);
        }
    }

    [Category("WindowsOnly")]
    [Test]
    [SupportedOSPlatform("windows")]
    public async Task WindowsRootRejectsUnexpectedReadGrant()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Windows DACL test.");
            return;
        }

        await Open();
        DirectoryInfo root = new(_root);
        DirectorySecurity acl = FileSystemAclExtensions.GetAccessControl(root);
        acl.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.Read,
            AccessControlType.Allow));
        FileSystemAclExtensions.SetAccessControl(root, acl);
        Assert.ThrowsAsync<UnauthorizedAccessException>(async () => await Open());
    }

    [Category("WindowsOnly")]
    [Test]
    [SupportedOSPlatform("windows")]
    public async Task WindowsExistingSnapshotRejectsAdditionalReader()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Windows file ACL test.");
            return;
        }

        await Open();
        FileInfo snapshot = new(Path.Combine(_root, "store.lsfs"));
        FileSecurity acl = FileSystemAclExtensions.GetAccessControl(snapshot);
        acl.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.Read,
            AccessControlType.Allow));
        FileSystemAclExtensions.SetAccessControl(snapshot, acl);
        Assert.ThrowsAsync<UnauthorizedAccessException>(async () => await Open());
    }

    [Test]
    public async Task RootSnapshotMigrationChangesManifestAndBootstrapWithoutChangingKeyRecords()
    {
        FileSystemKeyStore oldStore = await Open();
        KeyId keyId = KeyId.New();
        Assert.That((await oldStore.TryCreateAsync(await CreateRequest(keyId, _name))).Status,
            Is.EqualTo(KeyStoreMutationStatus.Applied));
        string bootstrapFile = Path.Combine(_root, "bootstrap.lspb");
        Guid pinned = ProtectorBootstrapRecord.Decode(await File.ReadAllBytesAsync(bootstrapFile)).StoreInstanceId;
        TestProtector current = new(2);
        ProtectorGenerationRouter router = new(current,
            [new HistoricalProtectorRegistration(_protector, HistoricalProtectorStatus.LegacyReadOnly)]);
        FileSystemKeyStoreOptions options = new(_root)
        {
            EnableExperimentalWrites = true,
            ExpectedStoreInstanceId = pinned
        };
        Assert.ThrowsAsync<InvalidOperationException>(async () => await FileSystemKeyStore.OpenAsync(options, router));
        FileSystemKeyStore migrating = await FileSystemKeyStore.OpenForMigrationAsync(
            options, router, _protector.CurrentReference);
        _opened.Add(migrating);
        Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await migrating.TryCreateAsync(await CreateRequest(KeyId.New(), new KeyName("blocked"))));
        Assert.That(await migrating.ReprotectRootAsync(), Is.True);
        Assert.That(await migrating.ReprotectRootAsync(), Is.False);
        Assert.That(ProtectorBootstrapRecord.Decode(await File.ReadAllBytesAsync(bootstrapFile)).Protector,
            Is.EqualTo(current.CurrentReference));
        FileSystemKeyStore reopened = await FileSystemKeyStore.OpenAsync(options, router);
        _opened.Add(reopened);
        KeyStoreEntry found = (await reopened.FindByIdAsync(_provider, keyId))!;
        Assert.That(found.Revision.Value, Is.EqualTo(1));
        Assert.That(found.KeyId, Is.EqualTo(keyId));
        Assert.That(found.ProtectedMetadata.Protector, Is.EqualTo(_protector.CurrentReference));
        Assert.That((await reopened.ReadMaterialAsync(new KeyReference(_provider, keyId, new KeyVersion(1)),
            new KeyStoreRevision(1))).ProtectedMaterial!.Protector, Is.EqualTo(_protector.CurrentReference));
    }

    [Test]
    public async Task ReopenRepairsCrashBetweenSnapshotAndBootstrapReplacement()
    {
        await Open();
        string bootstrapFile = Path.Combine(_root, "bootstrap.lspb");
        byte[] oldBootstrap = await File.ReadAllBytesAsync(bootstrapFile);
        Guid pinned = ProtectorBootstrapRecord.Decode(oldBootstrap).StoreInstanceId;
        TestProtector current = new(2);
        ProtectorGenerationRouter router = new(current,
            [new HistoricalProtectorRegistration(_protector, HistoricalProtectorStatus.LegacyReadOnly)]);
        FileSystemKeyStoreOptions options = new(_root)
        {
            EnableExperimentalWrites = true,
            ExpectedStoreInstanceId = pinned
        };
        FileSystemKeyStore first = await FileSystemKeyStore.OpenForMigrationAsync(
            options, router, _protector.CurrentReference);
        _opened.Add(first);
        Assert.That(await first.ReprotectRootAsync(), Is.True);
        // Simulates a power loss after snapshot commit but before bootstrap commit.
        await File.WriteAllBytesAsync(bootstrapFile, oldBootstrap);
        Assert.ThrowsAsync<InvalidOperationException>(async () => await FileSystemKeyStore.OpenAsync(options, router));
        FileSystemKeyStore recovering = await FileSystemKeyStore.OpenForMigrationAsync(
            options, router, _protector.CurrentReference);
        _opened.Add(recovering);
        Assert.That(await recovering.ReprotectRootAsync(), Is.True);
        Assert.That(ProtectorBootstrapRecord.Decode(await File.ReadAllBytesAsync(bootstrapFile)).Protector,
            Is.EqualTo(current.CurrentReference));
        FileSystemKeyStore normal = await FileSystemKeyStore.OpenAsync(options, router);
        _opened.Add(normal);
        Assert.That(await normal.FindByNameAsync(_provider, _name), Is.Null);
    }

    [Test]
    public async Task FullRootAndKeyMigrationAllowsOpeningWithCurrentProtectorOnly()
    {
        FileSystemKeyStore oldStore = await Open();
        SoftwareKeyProviderBackend original = new(_provider, oldStore, _protector);
        var key = await original.CreateAsync(new KeyName("real-profile"), WellKnownAlgorithms.HmacSha256,
            [WellKnownCapabilities.Mac, WellKnownCapabilities.VerifyMac]);
        LogicalKeyHandle handle = new(_provider, key.KeyId);
        await original.RotateAsync(handle);
        Guid pinned = ProtectorBootstrapRecord.Decode(
            await File.ReadAllBytesAsync(Path.Combine(_root, "bootstrap.lspb"))).StoreInstanceId;
        TestProtector current = new(2);
        ProtectorGenerationRouter router = new(current,
            [new HistoricalProtectorRegistration(_protector, HistoricalProtectorStatus.LegacyReadOnly)]);
        FileSystemKeyStoreOptions options = new(_root)
        {
            EnableExperimentalWrites = true,
            ExpectedStoreInstanceId = pinned
        };
        FileSystemKeyStore migrating = await FileSystemKeyStore.OpenForMigrationAsync(
            options, router, _protector.CurrentReference);
        _opened.Add(migrating);
        Assert.That(await migrating.ReprotectRootAsync(), Is.True);
        KeyReprotectionResult result = await new SoftwareKeyReprotectionService(_provider, migrating, router)
            .ReprotectAsync(handle);
        Assert.That(result.Status, Is.EqualTo(KeyReprotectionStatus.Reprotected));
        FileSystemKeyStore currentOnly = await FileSystemKeyStore.OpenAsync(options, current);
        _opened.Add(currentOnly);
        SoftwareKeyProviderBackend backend = new(_provider, currentOnly, current);
        Assert.That((await backend.FindLogicalAsync(handle))!.ActiveVersion, Is.EqualTo(new KeyVersion(2)));
        Assert.That((await backend.FindExactAsync(handle.AtVersion(new KeyVersion(1))))!.State,
            Is.EqualTo(Laveyana.Security.Abstractions.Models.KeyVersionState.Retired));
    }

    [Test]
    public async Task RootMigrationRequiresPinnedUuidAndExactLegacyReference()
    {
        await Open();
        TestProtector current = new(2);
        ProtectorGenerationRouter router = new(current,
            [new HistoricalProtectorRegistration(_protector, HistoricalProtectorStatus.LegacyReadOnly)]);
        Assert.ThrowsAsync<ArgumentException>(async () => await FileSystemKeyStore.OpenForMigrationAsync(
            new FileSystemKeyStoreOptions(_root) { EnableExperimentalWrites = true },
            router, _protector.CurrentReference));
        Guid actual = ProtectorBootstrapRecord.Decode(
            await File.ReadAllBytesAsync(Path.Combine(_root, "bootstrap.lspb"))).StoreInstanceId;
        Assert.ThrowsAsync<InvalidOperationException>(async () => await FileSystemKeyStore.OpenForMigrationAsync(
            new FileSystemKeyStoreOptions(_root)
            {
                EnableExperimentalWrites = true,
                ExpectedStoreInstanceId = Guid.NewGuid()
            }, router, _protector.CurrentReference));
        Assert.ThrowsAsync<InvalidOperationException>(async () => await FileSystemKeyStore.OpenForMigrationAsync(
            new FileSystemKeyStoreOptions(_root)
            {
                EnableExperimentalWrites = true,
                ExpectedStoreInstanceId = actual
            }, router, new ProtectorReference("untrusted", 5)));
    }

    private async ValueTask<FileSystemKeyStore> Open()
    {
        try
        {
            FileSystemKeyStore store = await FileSystemKeyStore.OpenAsync(
                new FileSystemKeyStoreOptions(_root) { EnableExperimentalWrites = true }, _protector);
            _opened.Add(store);
            return store;
        }
        catch (UnauthorizedAccessException)
        {
            if (OperatingSystem.IsWindows())
            {
                LogWindowsOwnerDiagnostics();
            }

            throw;
        }
    }

    // Temporary CI diagnostic. No production ACL policy is changed by this method.
    [SupportedOSPlatform("windows")]
    private void LogWindowsOwnerDiagnostics()
    {
        try
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            TestContext.Progress.WriteLine($"ACL DIAGNOSTIC: UserSid={identity.User?.Value ?? "<null>"}; " +
                $"TokenOwnerSid={identity.Owner?.Value ?? "<null>"}");

            string lockPath = Path.Combine(_root, ".store.lock");
            foreach (string path in new[] { _root, lockPath })
            {
                if (!Directory.Exists(path) && !File.Exists(path))
                {
                    TestContext.Progress.WriteLine($"ACL DIAGNOSTIC: {Path.GetFileName(path)} missing");
                    continue;
                }

                FileSystemSecurity acl = Directory.Exists(path)
                    ? FileSystemAclExtensions.GetAccessControl(new DirectoryInfo(path))
                    : FileSystemAclExtensions.GetAccessControl(new FileInfo(path));
                string ownerSid = acl.GetOwner(typeof(SecurityIdentifier)).Value;
                TestContext.Progress.WriteLine($"ACL DIAGNOSTIC: {Path.GetFileName(path)} OwnerSid={ownerSid}");
            }
        }
        catch (Exception ex)
        {
            TestContext.Progress.WriteLine($"ACL DIAGNOSTIC: Unable to inspect owner: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private async Task<KeyStoreCreateRequest> CreateRequest(KeyId id, KeyName name) => new(
        _provider, id, name, await Metadata(id, 1, 10),
        [KeyStoreMaterialChange.Upsert(new KeyReference(_provider, id, new KeyVersion(1)),
            await Material(id, 1, 11))]);

    private async Task<ProtectedStoreEnvelope> Metadata(KeyId key, long revision, byte value)
    {
        using SensitiveMaterialLease lease = SensitiveMaterialLease.CreateCopy([value]);
        return await _protector.ProtectAsync(lease, ProtectionPurpose.Metadata,
            KeyStoreProtectionContext.ForMetadata(_provider, key, new KeyStoreRevision(revision)));
    }

    private async Task<ProtectedStoreEnvelope> Material(KeyId key, long version, byte value)
    {
        using SensitiveMaterialLease lease = SensitiveMaterialLease.CreateCopy([value]);
        return await _protector.ProtectAsync(lease, ProtectionPurpose.KeyMaterial,
            KeyStoreProtectionContext.ForKeyMaterial(new KeyReference(_provider, key, new KeyVersion(version))));
    }

    private sealed class TestProtector : IKeyStoreProtector
    {
        private readonly byte[] _secret = RandomNumberGenerator.GetBytes(32);

        public TestProtector(int generation = 1) => CurrentReference = new("integration-test", generation);

        public ProtectorReference CurrentReference { get; }

        public ValueTask<ProtectedStoreEnvelope> ProtectAsync(SensitiveMaterialLease plaintext,
            ProtectionPurpose purpose, ReadOnlyMemory<byte> authenticatedContext,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] tag = new byte[16];
            byte[] encrypted = new byte[plaintext.Length];
            byte[] aad = MakeAad(purpose, authenticatedContext);
            using (AesGcm aes = new(_secret, 16))
            {
                plaintext.UseMaterial(span => aes.Encrypt(nonce, span, encrypted, tag, aad));
            }

            byte[] output = new byte[nonce.Length + tag.Length + encrypted.Length];
            nonce.CopyTo(output, 0);
            tag.CopyTo(output, nonce.Length);
            encrypted.CopyTo(output, nonce.Length + tag.Length);
            return ValueTask.FromResult(new ProtectedStoreEnvelope(CurrentReference, purpose, output));
        }

        public ValueTask<SensitiveMaterialLease> UnprotectAsync(ProtectedStoreEnvelope envelope,
            ProtectionPurpose expectedPurpose, ReadOnlyMemory<byte> authenticatedContext,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (envelope.Protector != CurrentReference || envelope.Purpose != expectedPurpose)
            {
                throw new CryptographicException("Wrong reference or purpose.");
            }

            byte[] data = envelope.ExportEncodedCopy();
            if (data.Length < 29)
            {
                throw new CryptographicException("Invalid envelope.");
            }

            byte[] plaintext = new byte[data.Length - 28];
            try
            {
                using AesGcm aes = new(_secret, 16);
                aes.Decrypt(data.AsSpan(0, 12), data.AsSpan(28), data.AsSpan(12, 16),
                    plaintext, MakeAad(expectedPurpose, authenticatedContext));
                return ValueTask.FromResult(SensitiveMaterialLease.TakeOwnership(plaintext));
            }
            catch
            {
                CryptographicOperations.ZeroMemory(plaintext);
                throw;
            }
        }

        private byte[] MakeAad(ProtectionPurpose purpose, ReadOnlyMemory<byte> context) =>
            Encoding.UTF8.GetBytes($"{(int)purpose}|{CurrentReference}|{Convert.ToHexString(context.Span)}");
    }
}
