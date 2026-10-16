using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Abstractions.Payloads;

/// <summary>
/// Self-describing immutable ciphertext with a fixed historical key identity.
/// Its construction or successful decoding does not prove authenticity: Phase 16 must
/// verify its tag against the exact key and the canonical associated data.
/// </summary>
public sealed class EncryptedPayload
{
    /// <summary>Current stable serialized format version.</summary>
    public const ushort CurrentFormatVersion = 1;

    private readonly byte[] _nonce;
    private readonly byte[] _ciphertext;
    private readonly byte[] _authenticationTag;

    /// <summary>Copies untrusted public metadata and encrypted bytes into owned buffers.</summary>
    public EncryptedPayload(KeyReference reference, AlgorithmId algorithm, ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> authenticationTag)
    {
        ManagedPayloadValidation.CheckEncryption(reference, algorithm, nonce, authenticationTag, ciphertext.Length);
        Reference = reference;
        Algorithm = algorithm;
        _nonce = nonce.ToArray();
        _ciphertext = ciphertext.ToArray();
        _authenticationTag = authenticationTag.ToArray();
    }

    /// <summary>Gets the schema version, not the library assembly version.</summary>
    public ushort FormatVersion => CurrentFormatVersion;

    /// <summary>Gets the exact provider/key/material version used for encryption.</summary>
    public KeyReference Reference { get; }

    /// <summary>Gets the selected, explicitly stored AEAD algorithm identifier.</summary>
    public AlgorithmId Algorithm { get; }

    /// <summary>Gets the length of the ciphertext.</summary>
    public int CiphertextLength => _ciphertext.Length;

    /// <summary>Returns a caller-owned copy of the public nonce.</summary>
    public byte[] ExportNonceCopy() => (byte[])_nonce.Clone();

    /// <summary>Returns a caller-owned copy of the encrypted data.</summary>
    public byte[] ExportCiphertextCopy() => (byte[])_ciphertext.Clone();

    /// <summary>Returns a caller-owned copy of the authentication tag.</summary>
    public byte[] ExportAuthenticationTagCopy() => (byte[])_authenticationTag.Clone();

    /// <summary>
    /// Returns the AEAD associated data to use for tag verification. The caller supplies
    /// the exact external AAD again at decryption; it is not embedded in this value.
    /// </summary>
    public byte[] BuildAssociatedData(ReadOnlySpan<byte> applicationAad = default) =>
        EncryptedPayloadAssociatedData.Build(Reference, Algorithm, _nonce, _ciphertext.Length, applicationAad);

    /// <summary>
    /// Separates the encrypted bytes from their typed metadata; neither output is authenticated
    /// until the matching AEAD operation verifies the tag.
    /// </summary>
    public DetachedEncryptedPayload Detach(out byte[] ciphertext)
    {
        ciphertext = ExportCiphertextCopy();
        return new DetachedEncryptedPayload(Reference, Algorithm, _nonce, _authenticationTag, _ciphertext.Length);
    }

    /// <summary>Does not disclose ciphertext, nonce or tags in incidental logs.</summary>
    public override string ToString() => "EncryptedPayload [UNVERIFIED]";
}
