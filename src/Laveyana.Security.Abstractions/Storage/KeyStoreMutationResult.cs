namespace Laveyana.Security.Abstractions.Storage;

/// <summary>One definitive store write outcome, including a new revision for create/replace.</summary>
public readonly record struct KeyStoreMutationResult
{
    private KeyStoreMutationResult(KeyStoreMutationStatus status, KeyStoreRevision? revision)
    {
        Status = status;
        Revision = revision;
    }

    /// <summary>Gets the outcome status, or 0 for an invalid default result.</summary>
    public KeyStoreMutationStatus Status { get; }

    /// <summary>Gets the committed revision after create/replace; null after deletion or non-success.</summary>
    public KeyStoreRevision? Revision { get; }

    /// <summary>Creates a successful create/replace result with an authoritative revision.</summary>
    public static KeyStoreMutationResult Written(KeyStoreRevision revision) => revision.IsDefined
        ? new(KeyStoreMutationStatus.Applied, revision)
        : throw new ArgumentException("Revision is undefined.", nameof(revision));

    /// <summary>Creates a successful delete result after durable name release and material removal.</summary>
    public static KeyStoreMutationResult Deleted() => new(KeyStoreMutationStatus.Applied, null);

    /// <summary>Creates a definitive non-success result without a claimed mutation.</summary>
    public static KeyStoreMutationResult Rejected(KeyStoreMutationStatus status) => status is
        KeyStoreMutationStatus.NameTaken or KeyStoreMutationStatus.KeyAlreadyExists or
        KeyStoreMutationStatus.RevisionMismatch or KeyStoreMutationStatus.NotFound
            ? new(status, null)
            : throw new ArgumentOutOfRangeException(nameof(status));
}
