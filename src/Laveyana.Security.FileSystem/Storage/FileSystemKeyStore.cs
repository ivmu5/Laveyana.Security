using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Persistence;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Abstractions.Rollback;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Abstractions.Storage;
using static Laveyana.Security.FileSystem.Storage.FileSystemSnapshotCodec;

namespace Laveyana.Security.FileSystem.Storage;

/// <summary>A protected, single-snapshot, cooperatively locked experimental filesystem store.</summary>
/// <remarks>
/// EXPERIMENTAL / TEST ONLY: not approved to protect production secrets.
/// The Windows handle-relative backend is an unverified SA-02 remediation candidate.
/// Platform builds, adversarial races, durability and security review are still required.
/// The caller must explicitly enable experimental writes. Only already-protected material is accepted. Snapshot routing
/// identifiers and names are not confidential; an authenticated manifest prevents
/// undetected mutation of the whole snapshot but NOT replay of an older valid snapshot.
/// No rollback-protected nonce allocation or forensic secure erase is claimed.
/// </remarks>
public sealed class FileSystemKeyStore : IKeyStore, IDisposable
{
    private const string BootstrapName = "bootstrap.lspb";
    private const string SnapshotName = "store.lsfs";
    private const string LockName = ".store.lock";
    private const string PendingPrefix = ".pending-";
    private const string PendingSuffix = ".tmp";

    private readonly FileSystemKeyStoreOptions _options;
    private readonly IKeyStoreProtector _protector;
    private Guid _instanceId;
    private LinuxSecureDirectory? _linuxDirectory;
    private WindowsSecureDirectory? _windowsDirectory;
    private readonly ProtectorReference? _migrationLegacyReference;
    private ProtectorReference _lastSnapshotReference;
    private bool _migrationRootCompleted;

    private FileSystemKeyStore(FileSystemKeyStoreOptions options, IKeyStoreProtector protector,
        ProtectorReference? migrationLegacyReference = null)
    {
        _options = options;
        _protector = protector;
        _migrationLegacyReference = migrationLegacyReference;
        _migrationRootCompleted = !migrationLegacyReference.HasValue;
    }

    /// <summary>Filesystem snapshots have no independent rollback-resistant authority.</summary>
    public KeyStoreCapabilities Capabilities { get; } = new(false);

    private static bool IsValidLockTimeout(TimeSpan timeout) =>
        timeout > TimeSpan.Zero && timeout <= TimeSpan.FromMinutes(5);

    /// <summary>Opens an initialized store using an explicitly selected root protector.</summary>
    /// <remarks>Rejects missing or corrupt data rather than silently recreating it.</remarks>
    public static async ValueTask<FileSystemKeyStore> OpenAsync(FileSystemKeyStoreOptions options,
        IKeyStoreProtector protector, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(protector);
        if (!protector.CurrentReference.IsDefined ||
            !IsValidLockTimeout(options.LockTimeout) ||
            options.ExpectedStoreInstanceId == Guid.Empty)
        {
            throw new ArgumentException("Invalid store options or protector identity.");
        }

        // Stage 2B1: external authority verification is read-only until durable
        // staging/publication/recovery and downgrade protection are implemented.
        if (options.RollbackAuthority is not null &&
            (options.EnableExperimentalWrites || !options.ExpectedStoreInstanceId.HasValue ||
             options.ExpectedStoreInstanceId == Guid.Empty))
        {
            throw new ArgumentException(
                "Rollback inspection requires read-only access and a pinned store UUID.", nameof(options));
        }

        FileSystemKeyStore store = new(options, protector);
        try
        {
            await store.InitializeAsync(cancellationToken).ConfigureAwait(false);
            return store;
        }
        catch
        {
            store.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Opens an existing experimental store solely for explicit migration of its root snapshot.
    /// A caller must pin the existing store UUID and exact historical protector reference.
    /// The supplied protector must authenticate both generations; normal opens never allow legacy.
    /// </summary>
    public static async ValueTask<FileSystemKeyStore> OpenForMigrationAsync(FileSystemKeyStoreOptions options,
        IKeyStoreProtector currentAndLegacyProtector, ProtectorReference legacyReference,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(currentAndLegacyProtector);
        if (!legacyReference.IsDefined || !currentAndLegacyProtector.CurrentReference.IsDefined ||
            legacyReference == currentAndLegacyProtector.CurrentReference ||
            !IsValidLockTimeout(options.LockTimeout) ||
            options.RollbackAuthority is not null ||
            !options.EnableExperimentalWrites || !options.ExpectedStoreInstanceId.HasValue ||
            options.ExpectedStoreInstanceId == Guid.Empty || !Directory.Exists(options.RootDirectory))
        {
            throw new ArgumentException("Migration requires an existing store, pinned UUID, experimental writes and distinct generations.");
        }

        FileSystemKeyStore store = new(options, currentAndLegacyProtector, legacyReference);
        try
        {
            await store.InitializeAsync(cancellationToken).ConfigureAwait(false);
            return store;
        }
        catch
        {
            store.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Migrates the authenticated root snapshot first, then the public bootstrap reference.
    /// If a crash separates the two durable replacements, reopen with OpenForMigrationAsync
    /// and run this method again; no key material or inner envelopes are modified.
    /// </summary>
    /// <returns>True if either file required migration, false if both were already current.</returns>
    public async ValueTask<bool> ReprotectRootAsync(CancellationToken cancellationToken = default)
    {
        if (!_migrationLegacyReference.HasValue)
        {
            throw new InvalidOperationException("Root re-protection requires an explicit migration session.");
        }

        if (!_options.EnableExperimentalWrites)
        {
            throw new InvalidOperationException("Root migration is experimental and cannot run in read-only mode.");
        }

        using FileStream held = await AcquireLockAsync(cancellationToken).ConfigureAwait(false);
        State snapshot = await LoadAsync(cancellationToken).ConfigureAwait(false);
        bool snapshotChanged = _lastSnapshotReference != _protector.CurrentReference;
        if (snapshotChanged)
        {
            await CommitAsync(snapshot, cancellationToken).ConfigureAwait(false);
        }

        ValidateStoreFile(BootstrapName);
        ProtectorBootstrapRecord bootstrap = ProtectorBootstrapRecord.Decode(
            await ReadBoundedAsync(BootstrapName, 1024, cancellationToken).ConfigureAwait(false));
        if (bootstrap.StoreInstanceId != _instanceId || !CanReadSnapshotReference(bootstrap.Protector))
        {
            throw new InvalidDataException("Root migration bootstrap changed identity or generation.");
        }

        bool bootstrapChanged = bootstrap.Protector != _protector.CurrentReference;
        if (bootstrapChanged)
        {
            byte[] updated = new ProtectorBootstrapRecord(_instanceId, _protector.CurrentReference).Encode();
            await AtomicWriteAsync(StorePath(BootstrapName), updated, true, cancellationToken)
                .ConfigureAwait(false);
        }

        _migrationRootCompleted = true;
        _lastSnapshotReference = _protector.CurrentReference;
        return snapshotChanged || bootstrapChanged;
    }

    /// <inheritdoc />
    public async ValueTask<KeyStoreEntry?> FindByNameAsync(ProviderId providerId, KeyName name,
        CancellationToken cancellationToken = default)
    {
        if (!providerId.IsDefined || !name.IsDefined)
        {
            throw new ArgumentException("An exact provider and name are required.");
        }

        using FileStream held = await AcquireLockAsync(cancellationToken).ConfigureAwait(false);
        State snapshot = await LoadAsync(cancellationToken).ConfigureAwait(false);
        return snapshot.Names.TryGetValue((providerId, name), out KeyId keyId)
            ? snapshot.Records[(providerId, keyId)].Entry : null;
    }

    /// <inheritdoc />
    public async ValueTask<KeyStoreEntry?> FindByIdAsync(ProviderId providerId, KeyId keyId,
        CancellationToken cancellationToken = default)
    {
        if (!providerId.IsDefined || !keyId.IsDefined)
        {
            throw new ArgumentException("An exact provider and KeyId are required.");
        }

        using FileStream held = await AcquireLockAsync(cancellationToken).ConfigureAwait(false);
        State snapshot = await LoadAsync(cancellationToken).ConfigureAwait(false);
        return snapshot.Records.TryGetValue((providerId, keyId), out Record? record)
            ? record.Entry : null;
    }

    /// <inheritdoc />
    public async ValueTask<KeyStoreMaterialReadResult> ReadMaterialAsync(KeyReference reference,
        KeyStoreRevision expectedRevision, CancellationToken cancellationToken = default)
    {
        if (!reference.IsDefined || !expectedRevision.IsDefined)
        {
            throw new ArgumentException("An exact reference and revision are required.");
        }

        using FileStream held = await AcquireLockAsync(cancellationToken).ConfigureAwait(false);
        State snapshot = await LoadAsync(cancellationToken).ConfigureAwait(false);
        if (!snapshot.Records.TryGetValue((reference.ProviderId, reference.KeyId), out Record? record))
        {
            return KeyStoreMaterialReadResult.Rejected(KeyStoreMaterialReadStatus.NotFound);
        }

        if (record.Entry.Revision != expectedRevision)
        {
            return KeyStoreMaterialReadResult.Rejected(KeyStoreMaterialReadStatus.RevisionMismatch);
        }

        return record.Materials.TryGetValue(reference.Version, out ProtectedStoreEnvelope? material)
            ? KeyStoreMaterialReadResult.Found(material)
            : KeyStoreMaterialReadResult.Rejected(KeyStoreMaterialReadStatus.NotFound);
    }

    /// <inheritdoc />
    public async ValueTask<KeyStoreMutationResult> TryCreateAsync(KeyStoreCreateRequest request,
        CancellationToken cancellationToken = default)
    {
        EnsureWritable();
        ArgumentNullException.ThrowIfNull(request);
        using FileStream held = await AcquireLockAsync(cancellationToken).ConfigureAwait(false);
        State snapshot = await LoadAsync(cancellationToken).ConfigureAwait(false);
        if (snapshot.Names.ContainsKey((request.ProviderId, request.Name)))
        {
            return KeyStoreMutationResult.Rejected(KeyStoreMutationStatus.NameTaken);
        }

        if (snapshot.UsedIds.Contains((request.ProviderId, request.KeyId)))
        {
            return KeyStoreMutationResult.Rejected(KeyStoreMutationStatus.KeyAlreadyExists);
        }

        KeyStoreRevision revision = new(1);
        Dictionary<KeyVersion, ProtectedStoreEnvelope> materials = request.InitialMaterial
            .ToDictionary(item => item.Reference.Version, item => item.Material!);
        KeyStoreEntry entry = new(request.ProviderId, request.KeyId, request.Name, revision, request.ProtectedMetadata);
        snapshot.UsedIds.Add((request.ProviderId, request.KeyId));
        snapshot.Names.Add((request.ProviderId, request.Name), request.KeyId);
        snapshot.Records.Add((request.ProviderId, request.KeyId), new Record(entry, materials));
        await CommitAsync(snapshot, cancellationToken).ConfigureAwait(false);
        return KeyStoreMutationResult.Written(revision);
    }

    /// <inheritdoc />
    public async ValueTask<KeyStoreMutationResult> TryReplaceAsync(KeyStoreReplaceRequest request,
        CancellationToken cancellationToken = default)
    {
        EnsureWritable();
        ArgumentNullException.ThrowIfNull(request);
        using FileStream held = await AcquireLockAsync(cancellationToken).ConfigureAwait(false);
        State snapshot = await LoadAsync(cancellationToken).ConfigureAwait(false);
        if (!snapshot.Records.TryGetValue((request.ProviderId, request.KeyId), out Record? record))
        {
            return KeyStoreMutationResult.Rejected(KeyStoreMutationStatus.NotFound);
        }

        if (record.Entry.Revision != request.ExpectedRevision)
        {
            return KeyStoreMutationResult.Rejected(KeyStoreMutationStatus.RevisionMismatch);
        }

        if (record.Entry.Revision.Value == long.MaxValue)
        {
            throw new InvalidOperationException("Key revision is exhausted.");
        }

        KeyStoreRevision next = new(record.Entry.Revision.Value + 1);
        foreach (KeyStoreMaterialChange change in request.MaterialChanges)
        {
            if (change.IsDelete)
            {
                record.Materials.Remove(change.Reference.Version);
            }
            else
            {
                record.Materials[change.Reference.Version] = change.Material!;
            }
        }

        record.Entry = new KeyStoreEntry(request.ProviderId, request.KeyId, record.Entry.Name,
            next, request.ProtectedMetadata);
        await CommitAsync(snapshot, cancellationToken).ConfigureAwait(false);
        return KeyStoreMutationResult.Written(next);
    }

    /// <inheritdoc />
    public async ValueTask<KeyStoreMutationResult> TryDeleteAsync(ProviderId providerId, KeyId keyId,
        KeyStoreRevision expectedRevision, CancellationToken cancellationToken = default)
    {
        EnsureWritable();
        if (!providerId.IsDefined || !keyId.IsDefined || !expectedRevision.IsDefined)
        {
            throw new ArgumentException("An exact identity and revision are required.");
        }

        using FileStream held = await AcquireLockAsync(cancellationToken).ConfigureAwait(false);
        State snapshot = await LoadAsync(cancellationToken).ConfigureAwait(false);
        if (!snapshot.Records.TryGetValue((providerId, keyId), out Record? record))
        {
            return KeyStoreMutationResult.Rejected(KeyStoreMutationStatus.NotFound);
        }

        if (record.Entry.Revision != expectedRevision)
        {
            return KeyStoreMutationResult.Rejected(KeyStoreMutationStatus.RevisionMismatch);
        }

        snapshot.Records.Remove((providerId, keyId));
        snapshot.Names.Remove((providerId, record.Entry.Name));
        // Do not remove from UsedIds: deleted IDs must never be reassigned.
        await CommitAsync(snapshot, cancellationToken).ConfigureAwait(false);
        return KeyStoreMutationResult.Deleted();
    }

    private async ValueTask InitializeAsync(CancellationToken cancellationToken)
    {
        bool exists = Directory.Exists(_options.RootDirectory);
        if (!exists && !_options.EnableExperimentalWrites)
        {
            throw new InvalidOperationException("Read-only initialization cannot create a new store.");
        }

        if (!exists)
        {
            if (OperatingSystem.IsLinux())
            {
                Directory.CreateDirectory(_options.RootDirectory,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
            else if (OperatingSystem.IsWindows())
            {
                WindowsStorePathGuard.CreateRoot(_options.RootDirectory);
            }
            else
            {
                throw new PlatformNotSupportedException("Filesystem hardening is available on Linux and Windows only.");
            }
        }

        ValidatePath(_options.RootDirectory, true);
        if (OperatingSystem.IsLinux())
        {
            _linuxDirectory = LinuxSecureDirectory.Open(_options.RootDirectory);
        }
        else if (OperatingSystem.IsWindows())
        {
            _windowsDirectory = WindowsSecureDirectory.Open(_options.RootDirectory);
        }
        else
        {
            throw new PlatformNotSupportedException("Filesystem hardening is not available on this OS.");
        }

        using FileStream held = await AcquireLockAsync(cancellationToken).ConfigureAwait(false);
        string bootstrapPath = StorePath(BootstrapName);
        if (!EntryExists(BootstrapName))
        {
            if (_migrationLegacyReference.HasValue || !_options.EnableExperimentalWrites || EntryExists(SnapshotName))
            {
                throw new InvalidDataException("Incomplete or missing store bootstrap.");
            }

            // A crash between these two writes fails closed; never regenerate a half-created store.
            _instanceId = _options.ExpectedStoreInstanceId ?? Guid.NewGuid();
            byte[] bootstrap = new ProtectorBootstrapRecord(_instanceId, _protector.CurrentReference).Encode();
            await AtomicWriteAsync(bootstrapPath, bootstrap, false, cancellationToken).ConfigureAwait(false);
            await CommitAsync(new State(), cancellationToken).ConfigureAwait(false);
        }
        else
        {
            ValidateStoreFile(BootstrapName);
            ProtectorBootstrapRecord bootstrap = ProtectorBootstrapRecord.Decode(
                await ReadBoundedAsync(BootstrapName, 1024, cancellationToken).ConfigureAwait(false));
            _instanceId = bootstrap.StoreInstanceId;
            if ((_options.ExpectedStoreInstanceId is Guid expected && expected != _instanceId) ||
                !CanReadSnapshotReference(bootstrap.Protector))
            {
                throw new InvalidOperationException("Unexpected store identity or root protector generation.");
            }

            await LoadAsync(cancellationToken).ConfigureAwait(false);
            // Read-only opens must not delete uncommitted staging files.
            // Cleanup is a mutation and requires explicit experimental opt-in.
            if (_options.EnableExperimentalWrites)
            {
                CleanupAbandonedTemps();
            }
        }
    }

    private async ValueTask<State> LoadAsync(CancellationToken cancellationToken)
    {
        ValidateStoreFile(SnapshotName);
        byte[] bytes = await ReadBoundedAsync(SnapshotName,
            MaximumBodyLength + ProtectedStoreEnvelope.MaximumEncodedLength + 256, cancellationToken)
            .ConfigureAwait(false);
        (byte[] body, ProtectedStoreEnvelope authentication) = DecodeFile(bytes);
        if (!CanReadSnapshotReference(authentication.Protector))
        {
            throw new InvalidDataException("Unknown snapshot authentication protector.");
        }

        byte[] digest = SHA256.HashData(body);
        try
        {
            using SensitiveMaterialLease verified = await _protector.UnprotectAsync(authentication,
                ProtectionPurpose.Metadata, ManifestContext(), cancellationToken).ConfigureAwait(false);
            bool matches = false;
            verified.UseMaterial(material => matches = material.Length == digest.Length &&
                CryptographicOperations.FixedTimeEquals(material, digest));
            if (!matches)
            {
                throw new InvalidDataException("Snapshot authentication failed.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
        }

        State verifiedState = DecodeBody(body);

        if (_options.RollbackAuthority is not null)
        {
            // Compare the EXACT bytes authenticated above; do not reserialize the model.
            // A missing, foreign or pending authority state is never readable.
            // An authority failure propagates: there is no unprotected fallback.
            RollbackAuthorityState? authority = await _options.RollbackAuthority
                .ReadAsync(_instanceId, cancellationToken).ConfigureAwait(false);
            if (RollbackSnapshotGate.Inspect(_instanceId, bytes, authority) !=
                RollbackSnapshotInspection.CommittedMatch)
            {
                throw new InvalidDataException(
                    "Rollback authority did not confirm this exact committed store snapshot.");
            }
        }

        _lastSnapshotReference = authentication.Protector;
        return verifiedState;
    }

    private bool CanReadSnapshotReference(ProtectorReference reference) =>
        reference == _protector.CurrentReference ||
        (_migrationLegacyReference.HasValue && reference == _migrationLegacyReference.Value);

    private async ValueTask CommitAsync(State state, CancellationToken cancellationToken)
    {
        byte[] body = EncodeBody(state);
        byte[] digest = SHA256.HashData(body);
        ProtectedStoreEnvelope authentication;
        try
        {
            byte[] context = ManifestContext();
            using SensitiveMaterialLease lease = SensitiveMaterialLease.CreateCopy(digest);
            authentication = await _protector.ProtectAsync(lease, ProtectionPurpose.Metadata,
                context, cancellationToken).ConfigureAwait(false);
            using SensitiveMaterialLease verified = await _protector.UnprotectAsync(authentication,
                ProtectionPurpose.Metadata, context, cancellationToken).ConfigureAwait(false);
            bool same = false;
            verified.UseMaterial(bytes => same = bytes.Length == digest.Length &&
                CryptographicOperations.FixedTimeEquals(bytes, digest));
            if (!same)
            {
                throw new CryptographicException("The snapshot protector failed a pre-commit round-trip check.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
        }

        if (authentication.Purpose != ProtectionPurpose.Metadata ||
            authentication.Protector != _protector.CurrentReference)
        {
            throw new InvalidDataException("Protector returned a mismatched snapshot envelope.");
        }

        byte[] snapshot = EncodeFile(body, authentication);
        await AtomicWriteAsync(StorePath(SnapshotName), snapshot, true, cancellationToken).ConfigureAwait(false);
    }

    private byte[] ManifestContext() => Encoding.ASCII.GetBytes(
        $"Laveyana.Security/fs/v1/snapshot/{_instanceId:D}");

    private void EnsureWritable()
    {
        if (!_options.EnableExperimentalWrites)
        {
            throw new InvalidOperationException("Filesystem writes require explicit experimental opt-in.");
        }

        if (!_migrationRootCompleted)
        {
            throw new InvalidOperationException("Migrate the root snapshot before editing key records.");
        }
    }

    private async ValueTask<FileStream> AcquireLockAsync(CancellationToken cancellationToken)
    {
        DateTime deadline = DateTime.UtcNow + _options.LockTimeout;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Linux checks the existing lock entry before flock; Windows verifies the
            // actual opened lock handle. A second Windows handle cannot inspect a lock
            // opened with exclusive sharing, so do not pre-open it here. With writes
            // disabled both backends open the lock without creating it.
            if (_linuxDirectory is not null && EntryExists(LockName))
            {
                ValidateStoreFile(LockName);
            }

            try
            {
                if (_linuxDirectory is not null)
                {
                    FileStream? locked = _linuxDirectory.TryAcquireLock(LockName, _options.EnableExperimentalWrites);
                    if (locked is not null)
                    {
                        return locked;
                    }

                    if (DateTime.UtcNow >= deadline)
                    {
                        throw new TimeoutException("Unable to acquire the store's Linux file lock.");
                    }

                    await Task.Delay(25, cancellationToken).ConfigureAwait(false);
                    continue;
                }

                return _windowsDirectory!.TryAcquireLock(LockName, _options.EnableExperimentalWrites);
            }
            catch (IOException error) when (_linuxDirectory is null && IsWindowsLockContention(error))
            {
                // EXPERIMENTAL / TEST ONLY: retry only genuine OS-level lock contention.
                // An unsafe reparse point, invalid ACL or other I/O failure must fail
                // immediately instead of being hidden behind a misleading timeout.
                if (DateTime.UtcNow >= deadline)
                {
                    throw new TimeoutException("Unable to acquire the store's cooperative interprocess lock.", error);
                }

                await Task.Delay(25, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private static bool IsWindowsLockContention(IOException error)
    {
        // NtCreateFile maps STATUS_SHARING_VIOLATION / STATUS_FILE_LOCK_CONFLICT
        // to Win32 32/33 through an inner Win32Exception. FileStream may instead
        // propagate the corresponding HRESULT directly on its IOException.
        const int sharingViolation = unchecked((int)0x80070020);
        const int lockViolation = unchecked((int)0x80070021);
        return error.HResult is sharingViolation or lockViolation ||
            error.InnerException is Win32Exception { NativeErrorCode: 32 or 33 };
    }

    private async ValueTask AtomicWriteAsync(string destination, byte[] data, bool overwrite,
        CancellationToken cancellationToken)
    {
        string destinationName = Path.GetFileName(destination);
        string temporaryName = $"{PendingPrefix}{Guid.NewGuid():N}{PendingSuffix}";
        try
        {
            using (FileStream stream = _linuxDirectory is not null
                ? _linuxDirectory.CreateTemporary(temporaryName)
                : _windowsDirectory!.CreateTemporary(temporaryName))
            {

                await stream.WriteAsync(data, cancellationToken).ConfigureAwait(false);
                stream.Flush(true);
            }

            byte[] staged = await ReadBoundedAsync(temporaryName, data.Length, cancellationToken)
                .ConfigureAwait(false);
            if (!staged.AsSpan().SequenceEqual(data))
            {
                throw new InvalidDataException("Staged store file differs from the committed candidate.");
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (EntryExists(destinationName))
            {
                ValidateStoreFile(destinationName);
            }

            if (_linuxDirectory is not null)
            {
                _linuxDirectory.Move(temporaryName, destinationName, overwrite);
            }
            else
            {
                if (!OperatingSystem.IsWindows())
                {
                    throw new PlatformNotSupportedException("Unsupported filesystem backend.");
                }

                _windowsDirectory!.Move(temporaryName, destinationName, overwrite);
            }
        }
        finally
        {
            if (_linuxDirectory is not null)
            {
                _linuxDirectory.Remove(temporaryName);
            }
            else
            {
                _windowsDirectory?.Remove(temporaryName);
            }
        }
    }

    private void CleanupAbandonedTemps()
    {
        if (_windowsDirectory is not null)
        {
            foreach (string name in _windowsDirectory.EnumeratePendingNames())
            {
                ValidateStoreFile(name);
                _windowsDirectory.Remove(name);
            }

            return;
        }

        // Linux cleanup is unchanged; individual deletions remain descriptor-relative.
        foreach (string path in Directory.EnumerateFiles(_options.RootDirectory,
            $"{PendingPrefix}*{PendingSuffix}", SearchOption.TopDirectoryOnly))
        {
            string name = Path.GetFileName(path);
            ValidateStoreFile(name);
            _linuxDirectory!.Remove(name);
        }
    }

    private string StorePath(string fileName) => Path.Combine(_options.RootDirectory, fileName);

    private bool EntryExists(string fileName) => _linuxDirectory?.Exists(fileName)
        ?? _windowsDirectory?.Exists(fileName) ?? false;

    private void ValidateStoreFile(string fileName)
    {
        if (!EntryExists(fileName))
        {
            throw new FileNotFoundException("Required store file is missing.", StorePath(fileName));
        }

        if (_linuxDirectory is null)
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException("Unsupported filesystem backend.");
            }

            if (!_windowsDirectory!.Exists(fileName))
            {
                throw new FileNotFoundException("Required store file is missing.", StorePath(fileName));
            }
        }
    }

    private static void ValidatePath(string path, bool directory)
    {
        FileAttributes attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0 ||
            ((attributes & FileAttributes.Directory) != 0) != directory)
        {
            throw new IOException("Store path is redirected or has an unexpected entry type.");
        }
    }

    private async ValueTask<byte[]> ReadBoundedAsync(string fileName, int maximum,
        CancellationToken cancellationToken)
    {
        using FileStream stream = _linuxDirectory is not null
            ? _linuxDirectory.OpenRead(fileName)
            : _windowsDirectory!.OpenRead(fileName);

        if (stream.Length is <= 0 || stream.Length > maximum)
        {
            throw new InvalidDataException("Store file size is outside its allowed bounds.");
        }

        byte[] bytes = new byte[checked((int)stream.Length)];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        return bytes;
    }

    /// <summary>Releases pinned platform directory handles (not a secure erase operation).</summary>
    public void Dispose()
    {
        _linuxDirectory?.Dispose();
        _windowsDirectory?.Dispose();
    }
}
