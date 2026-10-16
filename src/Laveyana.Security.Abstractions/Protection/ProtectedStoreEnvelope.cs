namespace Laveyana.Security.Abstractions.Protection;

/// <summary>An immutable, already authenticated-and-encrypted persisted envelope.</summary>
/// <remarks>
/// Bytes are untrusted until successfully authenticated by a matching protector against
/// the caller-supplied purpose and external associated context. This type does not encrypt.
/// The envelope contains no exported root protection secret or plaintext key material.
/// </remarks>
public sealed class ProtectedStoreEnvelope
{
    /// <summary>Maximum supported serialized envelope size, including authentication data.</summary>
    public const int MaximumEncodedLength = 2 * 1024 * 1024;

    private readonly byte[] _encoded;

    /// <summary>Copies an untrusted encoded envelope into owned immutable storage.</summary>
    public ProtectedStoreEnvelope(ProtectorReference protector, ProtectionPurpose purpose, ReadOnlySpan<byte> encoded)
    {
        if (!protector.IsDefined || !Enum.IsDefined(purpose) || purpose == ProtectionPurpose.Unspecified)
        {
            throw new ArgumentException("Envelope reference and purpose must be defined.");
        }

        if (encoded.Length is < 1 or > MaximumEncodedLength)
        {
            throw new ArgumentOutOfRangeException(nameof(encoded));
        }

        Protector = protector;
        Purpose = purpose;
        _encoded = encoded.ToArray();
    }

    /// <summary>Gets the stable reference required to select an appropriate protector generation.</summary>
    public ProtectorReference Protector { get; }

    /// <summary>Gets the declared cryptographic purpose; it must be authenticated during decryption.</summary>
    public ProtectionPurpose Purpose { get; }

    /// <summary>Gets the encoded length without exposing the backing array.</summary>
    public int EncodedLength => _encoded.Length;

    /// <summary>Returns a caller-owned copy of the protected bytes, never plaintext.</summary>
    public byte[] ExportEncodedCopy() => (byte[])_encoded.Clone();

    /// <summary>Never renders envelope bytes in accidental logs.</summary>
    public override string ToString() => "ProtectedStoreEnvelope [REDACTED]";
}
