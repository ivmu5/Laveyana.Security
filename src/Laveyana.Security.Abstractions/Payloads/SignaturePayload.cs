using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Abstractions.Payloads;

/// <summary>Immutable exact-key signature value and its stable encoding identifier.</summary>
/// <remarks>Signature authenticity is not established until separately verified by a provider.</remarks>
public sealed class SignaturePayload
{
    private readonly byte[] _signature;

    /// <summary>Constructs a signature with the canonical representation for its scheme.</summary>
    public SignaturePayload(KeyReference reference, AlgorithmId algorithm, ReadOnlySpan<byte> signature)
    {
        ManagedPayloadValidation.CheckReference(reference);
        string encoding = ManagedPayloadValidation.GetSignatureEncoding(algorithm, signature.Length);
        Reference = reference;
        Algorithm = algorithm;
        Encoding = encoding;
        _signature = signature.ToArray();
    }

    /// <summary>Current signature wire format version.</summary>
    public ushort FormatVersion => 1;

    /// <summary>Gets the exact historical signing key identity.</summary>
    public KeyReference Reference { get; }

    /// <summary>Gets the signed-message scheme (e.g. ECDSA P-256 SHA-256).</summary>
    public AlgorithmId Algorithm { get; }

    /// <summary>Gets canonical signature byte encoding: ieee-p1363 or rsa-pss-raw.</summary>
    public string Encoding { get; }

    /// <summary>Returns a copy of the signature bytes.</summary>
    public byte[] ExportSignatureCopy() => (byte[])_signature.Clone();

    /// <summary>Does not print signature bytes.</summary>
    public override string ToString() => "SignaturePayload [UNVERIFIED]";
}
