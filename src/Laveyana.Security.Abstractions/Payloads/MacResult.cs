using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Abstractions.Payloads;

/// <summary>Immutable MAC result that records the exact key version and HMAC algorithm.</summary>
/// <remarks>Construction is not verification; matching must use a policy-aware, fixed-time verifier.</remarks>
public sealed class MacResult
{
    private readonly byte[] _tag;

    /// <summary>Copies a complete HMAC-SHA-256/384/512 tag.</summary>
    public MacResult(KeyReference reference, AlgorithmId algorithm, ReadOnlySpan<byte> tag)
    {
        ManagedPayloadValidation.CheckReference(reference);
        int required = ManagedPayloadValidation.GetMacLength(algorithm);
        if (tag.Length != required)
        {
            throw new ArgumentException("The full HMAC tag length is required.", nameof(tag));
        }

        Reference = reference;
        Algorithm = algorithm;
        _tag = tag.ToArray();
    }

    /// <summary>Current MAC result format version.</summary>
    public ushort FormatVersion => 1;

    /// <summary>Gets the exact key version that produced the MAC.</summary>
    public KeyReference Reference { get; }

    /// <summary>Gets the unambiguous HMAC algorithm.</summary>
    public AlgorithmId Algorithm { get; }

    /// <summary>Returns a caller-owned copy of the MAC tag.</summary>
    public byte[] ExportTagCopy() => (byte[])_tag.Clone();

    /// <summary>Never embeds a MAC tag in logs.</summary>
    public override string ToString() => "MacResult [UNVERIFIED]";
}
