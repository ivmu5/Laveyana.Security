using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;

namespace Laveyana.Security.Lifecycle;

/// <summary>Metadata for one permanently reserved version number, including Deleted tombstones.</summary>
internal sealed class KeyLifecycleVersion
{
    /// <summary>Creates a validated, material-free version entry.</summary>
    public KeyLifecycleVersion(KeyVersion version, KeyVersionState state, KeyRetentionConstraint retention = default)
    {
        if (!version.IsDefined || !Enum.IsDefined(state) || state == KeyVersionState.Unspecified)
        {
            throw new ArgumentException("Version and state must be defined.");
        }

        Version = version;
        State = state;
        Retention = retention;
    }

    /// <summary>Gets the never-reusable version ordinal.</summary>
    public KeyVersion Version { get; }

    /// <summary>Gets the lifecycle state of this exact version.</summary>
    public KeyVersionState State { get; }

    /// <summary>Gets the deletion guard recorded for this version.</summary>
    public KeyRetentionConstraint Retention { get; }

    /// <summary>Returns a new entry with the same immutable identity and retention policy.</summary>
    public KeyLifecycleVersion WithState(KeyVersionState state) => new(Version, state, Retention);

    /// <summary>Hides identities and retention metadata in ordinary logs.</summary>
    public override string ToString() => nameof(KeyLifecycleVersion);
}
