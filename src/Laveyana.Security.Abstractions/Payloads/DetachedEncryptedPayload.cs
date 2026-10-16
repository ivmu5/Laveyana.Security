using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Abstractions.Payloads;

/// <summary>Immutable AEAD metadata for separately transported ciphertext.</summary>
/// <remarks>The separate ciphertext must be authenticated together with this metadata and external AAD.</remarks>
public sealed class DetachedEncryptedPayload
{
    private readonly byte[] _nonce;
    private readonly byte[] _authenticationTag;

    /// <summary>Copies detached public metadata; does not assert ciphertext authenticity.</summary>
    public DetachedEncryptedPayload(KeyReference reference, AlgorithmId algorithm, ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> authenticationTag, int ciphertextLength)
    {
        ManagedPayloadValidation.CheckEncryption(reference, algorithm, nonce, authenticationTag, ciphertextLength);
        Reference = reference;
        Algorithm = algorithm;
        CiphertextLength = ciphertextLength;
        _nonce = nonce.ToArray();
        _authenticationTag = authenticationTag.ToArray();
    }

    /// <summary>Current wire format version.</summary>
    public ushort FormatVersion => EncryptedPayload.CurrentFormatVersion;

    /// <summary>Gets the exact historical key identity.</summary>
    public KeyReference Reference { get; }

    /// <summary>Gets the encoded AEAD algorithm.</summary>
    public AlgorithmId Algorithm { get; }

    /// <summary>Gets the expected size of separately transported ciphertext.</summary>
    public int CiphertextLength { get; }

    /// <summary>Copies the public nonce.</summary>
    public byte[] ExportNonceCopy() => (byte[])_nonce.Clone();

    /// <summary>Copies the AEAD tag.</summary>
    public byte[] ExportAuthenticationTagCopy() => (byte[])_authenticationTag.Clone();

    /// <summary>Builds the exact associated data required for tag verification.</summary>
    public byte[] BuildAssociatedData(ReadOnlySpan<byte> applicationAad = default) =>
        EncryptedPayloadAssociatedData.Build(Reference, Algorithm, _nonce, CiphertextLength, applicationAad);

    /// <summary>Combines detached data without claiming it has been authenticated.</summary>
    public EncryptedPayload Attach(ReadOnlySpan<byte> ciphertext)
    {
        if (ciphertext.Length != CiphertextLength)
        {
            throw new ArgumentException("Detached ciphertext length does not match metadata.", nameof(ciphertext));
        }

        return new EncryptedPayload(Reference, Algorithm, _nonce, ciphertext, _authenticationTag);
    }

    /// <summary>Does not reveal public cryptographic bytes in incidental logs.</summary>
    public override string ToString() => "DetachedEncryptedPayload [UNVERIFIED]";
}
