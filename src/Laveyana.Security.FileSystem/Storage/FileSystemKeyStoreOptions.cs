using Laveyana.Security.Abstractions.Rollback;

namespace Laveyana.Security.FileSystem.Storage;

/// <summary>Explicit opt-in configuration for the Phase 13 filesystem prototype.</summary>
/// <remarks>
/// Phase 13 remains experimental pending native cross-platform verification and adversarial tests.
/// Production writes MUST remain disabled until the security gate is fully verified.
/// </remarks>
public sealed class FileSystemKeyStoreOptions
{
    // Per-instance test hook; production behavior never reads process environment variables.
    internal Action<StoreWriteBoundary, string>? WriteFault { get; init; }

    /// <summary>Creates options for a fully qualified, isolated directory.</summary>
    public FileSystemKeyStoreOptions(string rootDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootDirectory);
        if (!Path.IsPathFullyQualified(rootDirectory))
        {
            throw new ArgumentException("A fully qualified root path is required.", nameof(rootDirectory));
        }

        RootDirectory = Path.GetFullPath(rootDirectory);
    }

    /// <summary>Gets the store's explicit directory, never a process working directory fallback.</summary>
    public string RootDirectory { get; }

    /// <summary>Enables non-production write experiments only; false by default.</summary>
    /// <remarks>
    /// When disabled, opening an existing store does not create its lock file or
    /// remove pending files. The existing lock must already be present.
    /// This does not prevent OS-managed access-time metadata updates.
    /// </remarks>
    public bool EnableExperimentalWrites { get; init; }

    /// <summary>Optionally pins the expected store UUID against unexpected bootstrap replacement.</summary>
    public Guid? ExpectedStoreInstanceId { get; init; }

    /// <summary>Optional external checkpoint validation on each read (experimental, read-only).</summary>
    /// <remarks>
    /// When provided, requires a pinned ExpectedStoreInstanceId and
    /// EnableExperimentalWrites=false. Every load authenticates the exact persisted bytes
    /// and requires a committed authority match with no pending intent. Missing/failed
    /// authority reads or either local rollback journal entry reject access;
    /// no fallback, cleanup or recovery is attempted.
    /// This is NOT a protected writable profile: the existing ordinary OpenAsync can
    /// still be invoked without this option, so downgrade resistance is not enforced.
    /// Capabilities.ProvidesRollbackProtection remains false. Do not use for real secrets.
    /// </remarks>
    public IKeyStoreRollbackAuthority? RollbackAuthority { get; init; }

    /// <summary>Maximum duration for cooperative interprocess lock acquisition.</summary>
    public TimeSpan LockTimeout { get; init; } = TimeSpan.FromSeconds(15);
}
