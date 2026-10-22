using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Maui.NativeKeys;

/// <summary>Public information for a device-bound ECDSA NIST P-256 signing key.</summary>
public sealed class NativeSigningKeyInfo
{
    private const string NistP256Oid = "1.2.840.10045.3.1.7";
    private readonly byte[] _subjectPublicKeyInfo;

    /// <summary>Validates and owns a canonical NIST P-256 public SubjectPublicKeyInfo.</summary>
    public NativeSigningKeyInfo(ProviderId providerId, KeyId keyId, ReadOnlySpan<byte> subjectPublicKeyInfo)
    {
        if (!providerId.IsDefined || !keyId.IsDefined || subjectPublicKeyInfo.IsEmpty || subjectPublicKeyInfo.Length > 512)
        {
            throw new ArgumentException("Defined provider/key identities and a bounded public key are required.");
        }

        using ECDsa publicKey = ECDsa.Create();
        publicKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out int bytesRead);
        ECParameters parameters = publicKey.ExportParameters(false);
        if (bytesRead != subjectPublicKeyInfo.Length ||
            publicKey.KeySize != 256 ||
            !string.Equals(parameters.Curve.Oid.Value, NistP256Oid, StringComparison.Ordinal) ||
            !publicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(subjectPublicKeyInfo))
        {
            throw new CryptographicException("Expected a canonical ECDSA NIST P-256 public key.");
        }

        ProviderId = providerId;
        KeyId = keyId;
        _subjectPublicKeyInfo = subjectPublicKeyInfo.ToArray();
    }

    /// <summary>Stable owning provider identity, not a runtime alias.</summary>
    public ProviderId ProviderId { get; }

    /// <summary>Exact application-owned key identity within ProviderId.</summary>
    public KeyId KeyId { get; }

    /// <summary>Exports only the public X.509 SubjectPublicKeyInfo.</summary>
    public byte[] ExportSubjectPublicKeyInfo() => (byte[])_subjectPublicKeyInfo.Clone();
}
