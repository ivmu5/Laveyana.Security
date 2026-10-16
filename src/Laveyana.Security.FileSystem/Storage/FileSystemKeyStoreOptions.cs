namespace Laveyana.Security.FileSystem.Storage;

/// <summary>Explicit opt-in configuration for the Phase 13 filesystem prototype.</summary>
/// <remarks>
/// Phase 13 remains experimental pending native cross-platform verification and adversarial tests.
/// Production writes MUST remain disabled until the security gate is fully verified.
/// </remarks>
public sealed class FileSystemKeyStoreOptions
{
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
    public bool EnableExperimentalWrites { get; init; }

    /// <summary>Optionally pins the expected store UUID against unexpected bootstrap replacement.</summary>
    public Guid? ExpectedStoreInstanceId { get; init; }

    /// <summary>Maximum duration for cooperative interprocess lock acquisition.</summary>
    public TimeSpan LockTimeout { get; init; } = TimeSpan.FromSeconds(15);
}
