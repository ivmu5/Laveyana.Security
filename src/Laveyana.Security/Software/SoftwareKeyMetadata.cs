using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Lifecycle;

namespace Laveyana.Security.Software;

/// <summary>Internal immutable persisted aggregate description (never raw key material).</summary>
internal sealed class SoftwareKeyMetadata
{
    public SoftwareKeyMetadata(KeyName name, KeyKind kind, AlgorithmId algorithm,
        IEnumerable<CapabilityId> capabilities, KeyLifecycleSnapshot lifecycle)
    {
        if (!name.IsDefined || !algorithm.IsDefined || !Enum.IsDefined(kind) || kind == KeyKind.Unspecified)
        {
            throw new ArgumentException("Software key metadata is undefined.");
        }

        ArgumentNullException.ThrowIfNull(capabilities);
        ArgumentNullException.ThrowIfNull(lifecycle);
        CapabilityId[] copy = capabilities.Take(65).ToArray();
        if (copy.Length == 0 || copy.Length > 64 || copy.Any(x => !x.IsDefined) ||
            copy.Distinct().Count() != copy.Length)
        {
            throw new ArgumentException("Capabilities must be defined, unique and bounded.", nameof(capabilities));
        }

        Array.Sort(copy, (a, b) => string.CompareOrdinal(a.Value, b.Value));
        Name = name;
        Kind = kind;
        Algorithm = algorithm;
        Capabilities = Array.AsReadOnly(copy);
        Lifecycle = lifecycle;
    }

    public KeyName Name { get; }
    public KeyKind Kind { get; }
    public AlgorithmId Algorithm { get; }
    public IReadOnlyList<CapabilityId> Capabilities { get; }
    public KeyLifecycleSnapshot Lifecycle { get; }

    public SoftwareKeyMetadata WithLifecycle(KeyLifecycleSnapshot lifecycle) =>
        new(Name, Kind, Algorithm, Capabilities, lifecycle);

    public KeyDescriptor Describe() => new(Lifecycle.ProviderId, Lifecycle.KeyId, Name, Kind,
        Lifecycle.State, Lifecycle.ActiveVersion);

    public KeyVersionDescriptor DescribeVersion(KeyVersion version)
    {
        KeyLifecycleVersion entry = Lifecycle.Find(version) ??
            throw new SoftwareKeyConflictException("VersionNotFound");
        return new KeyVersionDescriptor(new KeyReference(Lifecycle.ProviderId, Lifecycle.KeyId, version),
            entry.State, Algorithm, Capabilities);
    }
}
