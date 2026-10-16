using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Abstractions.Models;

/// <summary>
/// An immutable exact-version metadata snapshot. Capability declarations alone do not
/// grant permission to operate; policy and provider support must also be checked.
/// </summary>
public sealed class KeyVersionDescriptor : IEquatable<KeyVersionDescriptor>
{
    /// <summary>
    /// Constructs a snapshot and defensively copies its capabilities.
    /// </summary>
    /// <exception cref="ArgumentException">Metadata or capabilities are invalid or duplicated.</exception>
    public KeyVersionDescriptor(
        KeyReference reference,
        KeyVersionState state,
        AlgorithmId algorithm,
        IEnumerable<CapabilityId> capabilities)
    {
        if (!reference.IsDefined || !algorithm.IsDefined ||
            !Enum.IsDefined(state) || state == KeyVersionState.Unspecified)
        {
            throw new ArgumentException("Version reference, state and algorithm must be defined.");
        }

        ArgumentNullException.ThrowIfNull(capabilities);
        CapabilityId[] entries = capabilities.Take(65).ToArray();
        if (entries.Length > 64)
        {
            throw new ArgumentException("At most 64 capabilities may be declared in one descriptor.", nameof(capabilities));
        }

        if (entries.Any(entry => !entry.IsDefined) || entries.Distinct().Count() != entries.Length)
        {
            throw new ArgumentException("Capabilities must be defined and unique.", nameof(capabilities));
        }

        Array.Sort(entries, (left, right) => StringComparer.Ordinal.Compare(left.Value, right.Value));

        Reference = reference;
        State = state;
        Algorithm = algorithm;
        Capabilities = Array.AsReadOnly(entries);
    }

    /// <summary>Gets the exact provider/key/version identity.</summary>
    public KeyReference Reference { get; }

    /// <summary>Gets the exact material state at capture time.</summary>
    public KeyVersionState State { get; }

    /// <summary>Gets the stable algorithm identity for this version.</summary>
    public AlgorithmId Algorithm { get; }

    /// <summary>Gets an immutable, ordinally sorted snapshot of at most 64 declared capabilities.</summary>
    public IReadOnlyList<CapabilityId> Capabilities { get; }

    /// <summary>
    /// Compares the exact snapshot including the ordered capability sequence.
    /// </summary>
    public bool Equals(KeyVersionDescriptor? other) => other is not null &&
        Reference == other.Reference &&
        State == other.State &&
        Algorithm == other.Algorithm &&
        Capabilities.SequenceEqual(other.Capabilities);

    /// <summary>Compares to another metadata snapshot by value.</summary>
    public override bool Equals(object? obj) => obj is KeyVersionDescriptor other && Equals(other);

    /// <summary>Calculates a deterministic-in-process hash for value-based collections.</summary>
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.Add(Reference);
        hash.Add(State);
        hash.Add(Algorithm);
        foreach (CapabilityId capability in Capabilities)
        {
            hash.Add(capability);
        }

        return hash.ToHashCode();
    }
}
