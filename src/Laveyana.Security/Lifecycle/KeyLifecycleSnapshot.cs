using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;

namespace Laveyana.Security.Lifecycle;

/// <summary>
/// An immutable, pure-domain snapshot, not a durable concurrency token or permission grant.
/// The authoritative store must persist each planned transition atomically with its revision.
/// </summary>
internal sealed class KeyLifecycleSnapshot
{
    private const int MaximumRepresentedVersions = 65_536;

    /// <summary>Creates a validated aggregate and copies its version entries.</summary>
    public KeyLifecycleSnapshot(
        ProviderId providerId,
        KeyId keyId,
        LogicalKeyState state,
        KeyVersion highWaterMark,
        IEnumerable<KeyLifecycleVersion> versions)
    {
        if (!providerId.IsDefined || !keyId.IsDefined || !highWaterMark.IsDefined ||
            !Enum.IsDefined(state) || state == LogicalKeyState.Unspecified)
        {
            throw new ArgumentException("Lifecycle identity, state and high-water mark must be valid.");
        }

        ArgumentNullException.ThrowIfNull(versions);
        KeyLifecycleVersion[] entries = versions.Take(MaximumRepresentedVersions + 1).ToArray();
        if (entries.Length is 0 or > MaximumRepresentedVersions || entries.Any(entry => entry is null))
        {
            throw new ArgumentException("The version history must be nonempty and bounded.", nameof(versions));
        }

        Array.Sort(entries, (left, right) => left.Version.CompareTo(right.Version));
        for (int i = 0; i < entries.Length; i++)
        {
            if (entries[i].Version.Value > highWaterMark.Value ||
                (i > 0 && entries[i - 1].Version == entries[i].Version))
            {
                throw new ArgumentException("Version history contains duplicates or exceeds the high-water mark.", nameof(versions));
            }
        }

        int activeCount = entries.Count(entry => entry.State == KeyVersionState.Active);
        int pendingCount = entries.Count(entry => entry.State == KeyVersionState.Pending);
        if ((state == LogicalKeyState.Active && activeCount != 1) ||
            (state != LogicalKeyState.Active && activeCount != 0) ||
            pendingCount > 1 ||
            (state != LogicalKeyState.Active && pendingCount != 0) ||
            (state == LogicalKeyState.Deleted && entries.Any(entry => entry.State != KeyVersionState.Deleted)))
        {
            throw new ArgumentException("Lifecycle snapshot violates logical/physical state invariants.", nameof(versions));
        }

        ProviderId = providerId;
        KeyId = keyId;
        State = state;
        HighWaterMark = highWaterMark;
        Versions = Array.AsReadOnly(entries);
    }

    /// <summary>Gets the stable owner identity.</summary>
    public ProviderId ProviderId { get; }

    /// <summary>Gets the stable logical generation identity.</summary>
    public KeyId KeyId { get; }

    /// <summary>Gets the logical key state.</summary>
    public LogicalKeyState State { get; }

    /// <summary>Gets the largest ever reserved ordinal, including deleted/pruned versions.</summary>
    public KeyVersion HighWaterMark { get; }

    /// <summary>Gets an immutable, sorted copy of represented version history.</summary>
    public IReadOnlyList<KeyLifecycleVersion> Versions { get; }

    /// <summary>Gets the current version only when the logical generation is Active.</summary>
    public KeyVersion? ActiveVersion => State == LogicalKeyState.Active
        ? Versions.Single(entry => entry.State == KeyVersionState.Active).Version
        : null;

    /// <summary>Gets an entry, or null if the ordinal was not represented.</summary>
    public KeyLifecycleVersion? Find(KeyVersion version) => Versions.FirstOrDefault(entry => entry.Version == version);

    /// <summary>Does not log key identities or lifecycle metadata.</summary>
    public override string ToString() => nameof(KeyLifecycleSnapshot);
}
