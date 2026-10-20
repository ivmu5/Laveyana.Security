using System.Security.Cryptography;
using System.Text;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Abstractions.Sensitive;
using static Laveyana.Security.FileSystem.Storage.FileSystemSnapshotCodec;

namespace Laveyana.Security.FileSystem.Storage;

/// <summary>Experimental, store-root-bound staging of exact candidate bytes and authenticated request intent.</summary>
/// <remarks>
/// The caller MUST hold the store's exclusive interprocess lock throughout these methods.
/// This helper never sends authority requests, publishes a snapshot, or performs recovery.
/// Neither Windows namespace power-loss durability nor a protected write profile is established.
/// A partial stage is retained, not silently cleaned or treated as a committed operation.
/// </remarks>
internal static class RollbackCandidateJournal
{
    internal const string CandidateName = ".rollback-candidate.lsfs";
    internal const string IntentName = ".rollback-intent.lsfs";
    private const int MaximumSnapshotLength = MaximumBodyLength + ProtectedStoreEnvelope.MaximumEncodedLength + 256;
    private const int MaximumIntentLength = 4096 + ProtectedStoreEnvelope.MaximumEncodedLength;

    internal static async ValueTask StageAsync(LinuxSecureDirectory? linux, WindowsSecureDirectory? windows,
        IKeyStoreProtector protector, RollbackPreparedWrite write, CancellationToken cancellationToken = default)
    {
        ValidateDirectory(linux, windows);
        ArgumentNullException.ThrowIfNull(protector);
        ArgumentNullException.ThrowIfNull(write);
        if (Exists(linux, windows, CandidateName) || Exists(linux, windows, IntentName))
        {
            throw new InvalidOperationException("An unresolved rollback staging generation already exists.");
        }

        byte[] snapshot = write.ExportCandidateCopy();
        await AuthenticateSnapshotAsync(protector, write.Prepared.StoreInstanceId, snapshot, cancellationToken)
            .ConfigureAwait(false);

        byte[] intent = write.EncodeIntent();
        byte[] digest = SHA256.HashData(intent);
        ProtectedStoreEnvelope signature;
        try
        {
            byte[] context = IntentContext(write.Prepared.StoreInstanceId);
            using SensitiveMaterialLease lease = SensitiveMaterialLease.CreateCopy(digest);
            signature = await protector.ProtectAsync(lease, ProtectionPurpose.Metadata,
                context, cancellationToken).ConfigureAwait(false);
            if (signature.Purpose != ProtectionPurpose.Metadata ||
                signature.Protector != protector.CurrentReference)
            {
                throw new InvalidDataException("Invalid rollback intent protector identity.");
            }

            await VerifyDigestAsync(protector, signature, context, digest, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
        }

        byte[] signedIntent = EncodeFile(intent, signature);
        // Exact candidate must exist before the authenticated request record is made visible.
        // No authority RPC is implemented in this stage, including after an I/O error.
        await WriteNewAsync(linux, windows, CandidateName, snapshot, cancellationToken).ConfigureAwait(false);
        await WriteNewAsync(linux, windows, IntentName, signedIntent, cancellationToken).ConfigureAwait(false);
        RollbackPreparedWrite? persisted = await ReadAsync(linux, windows, protector,
            write.Prepared.StoreInstanceId, cancellationToken).ConfigureAwait(false);
        if (persisted is null || !persisted.Expected.Matches(write.Expected) ||
            !persisted.Prepared.Matches(write.Prepared) ||
            !persisted.PrepareRequestId.Equals(write.PrepareRequestId) ||
            !persisted.FinalizeRequestId.Equals(write.FinalizeRequestId))
        {
            throw new InvalidDataException("Persisted rollback staging generation differs from the candidate.");
        }
    }

    internal static async ValueTask<RollbackPreparedWrite?> ReadAsync(LinuxSecureDirectory? linux,
        WindowsSecureDirectory? windows, IKeyStoreProtector protector, Guid pinnedStoreId,
        CancellationToken cancellationToken = default)
    {
        ValidateDirectory(linux, windows);
        ArgumentNullException.ThrowIfNull(protector);
        if (pinnedStoreId == Guid.Empty)
        {
            throw new ArgumentException("A pinned store identity is required.", nameof(pinnedStoreId));
        }

        bool candidateExists = Exists(linux, windows, CandidateName);
        bool intentExists = Exists(linux, windows, IntentName);
        if (!candidateExists && !intentExists)
        {
            return null;
        }

        if (!candidateExists || !intentExists)
        {
            throw new InvalidDataException("Incomplete rollback staging generation: recovery must fail closed.");
        }

        byte[] signedIntent = await ReadFileAsync(linux, windows, IntentName, MaximumIntentLength,
            cancellationToken).ConfigureAwait(false);
        (byte[] intent, ProtectedStoreEnvelope signature) = DecodeFile(signedIntent);
        if (signature.Protector != protector.CurrentReference)
        {
            throw new InvalidDataException("Unexpected rollback intent protector generation.");
        }

        byte[] digest = SHA256.HashData(intent);
        try
        {
            await VerifyDigestAsync(protector, signature, IntentContext(pinnedStoreId), digest,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
        }

        byte[] candidate = await ReadFileAsync(linux, windows, CandidateName, MaximumSnapshotLength,
            cancellationToken).ConfigureAwait(false);
        RollbackPreparedWrite write;
        try
        {
            write = RollbackPreparedWrite.DecodeIntent(intent, candidate);
        }
        catch (ArgumentException error)
        {
            throw new InvalidDataException("Rollback candidate does not match its authenticated intent.", error);
        }

        if (write.Expected.StoreInstanceId != pinnedStoreId)
        {
            throw new InvalidDataException("Rollback staging UUID does not match the pinned store identity.");
        }

        await AuthenticateSnapshotAsync(protector, pinnedStoreId, candidate, cancellationToken)
            .ConfigureAwait(false);
        return write;
    }

    private static async ValueTask AuthenticateSnapshotAsync(IKeyStoreProtector protector, Guid storeId,
        byte[] snapshot, CancellationToken cancellationToken)
    {
        (byte[] body, ProtectedStoreEnvelope authentication) = DecodeFile(snapshot);
        if (authentication.Protector != protector.CurrentReference)
        {
            throw new InvalidDataException("Unknown rollback candidate snapshot protector.");
        }

        byte[] digest = SHA256.HashData(body);
        try
        {
            byte[] context = Encoding.ASCII.GetBytes($"Laveyana.Security/fs/v1/snapshot/{storeId:D}");
            await VerifyDigestAsync(protector, authentication, context, digest, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    private static async ValueTask VerifyDigestAsync(IKeyStoreProtector protector,
        ProtectedStoreEnvelope envelope, byte[] context, byte[] digest, CancellationToken cancellationToken)
    {
        using SensitiveMaterialLease verified = await protector.UnprotectAsync(envelope,
            ProtectionPurpose.Metadata, context, cancellationToken).ConfigureAwait(false);
        bool matches = false;
        verified.UseMaterial(material => matches = material.Length == digest.Length &&
            CryptographicOperations.FixedTimeEquals(material, digest));
        if (!matches)
        {
            throw new InvalidDataException("Rollback staging authentication failed.");
        }
    }

    private static byte[] IntentContext(Guid storeId) => Encoding.ASCII.GetBytes(
        $"Laveyana.Security/fs/v1/rollback-intent/{storeId:D}");

    private static async ValueTask WriteNewAsync(LinuxSecureDirectory? linux, WindowsSecureDirectory? windows,
        string name, byte[] bytes, CancellationToken cancellationToken)
    {
        string temporaryName = $".pending-{Guid.NewGuid():N}.tmp";
        try
        {
            using (FileStream stream = linux is not null
                ? linux.CreateTemporary(temporaryName)
                : windows!.CreateTemporary(temporaryName))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                stream.Flush(true);
            }

            byte[] staged = await ReadFileAsync(linux, windows, temporaryName, bytes.Length,
                cancellationToken).ConfigureAwait(false);
            if (!staged.AsSpan().SequenceEqual(bytes))
            {
                throw new InvalidDataException("Rollback stage write differs from the candidate.");
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (Exists(linux, windows, name))
            {
                throw new InvalidOperationException("Concurrent rollback staging generation detected.");
            }

            if (linux is not null)
            {
                linux.Move(temporaryName, name, false);
            }
            else
            {
                windows!.Move(temporaryName, name, false);
            }
        }
        finally
        {
            if (linux is not null)
            {
                linux.Remove(temporaryName);
            }
            else
            {
                windows!.Remove(temporaryName);
            }
        }
    }

    private static async ValueTask<byte[]> ReadFileAsync(LinuxSecureDirectory? linux,
        WindowsSecureDirectory? windows, string name, int maximum, CancellationToken cancellationToken)
    {
        using FileStream stream = linux is not null ? linux.OpenRead(name) : windows!.OpenRead(name);
        if (stream.Length is <= 0 || stream.Length > maximum)
        {
            throw new InvalidDataException("Rollback staging file exceeds its bounds.");
        }

        byte[] result = new byte[checked((int)stream.Length)];
        await stream.ReadExactlyAsync(result.AsMemory(), cancellationToken).ConfigureAwait(false);
        return result;
    }

    private static bool Exists(LinuxSecureDirectory? linux, WindowsSecureDirectory? windows, string name) =>
        linux?.Exists(name) ?? windows!.Exists(name);

    private static void ValidateDirectory(LinuxSecureDirectory? linux, WindowsSecureDirectory? windows)
    {
        if ((linux is null) == (windows is null))
        {
            throw new ArgumentException("Exactly one pinned secure directory is required.");
        }
    }
}
