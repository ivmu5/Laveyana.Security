using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Capabilities;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Providers;

namespace Laveyana.Security.Agreement;

/// <summary>
/// In-memory P-256 ECDH private-key owner for tests and short-lived applications.
/// It never persists or exports private keys and does not provide cross-process revocation.
/// </summary>
public sealed class EphemeralEcdhKeyOperations : IVersionedKeyAgreementOperations, IDisposable
{
    private readonly object _gate = new();
    private readonly Dictionary<KeyReference, ECDiffieHellman> _keys = [];
    private bool _disposed;

    /// <summary>Takes ownership of the P-256 private key; returns its canonical public SPKI.</summary>
    public byte[] Add(KeyReference reference, ECDiffieHellman ownedPrivateKey)
    {
        ArgumentNullException.ThrowIfNull(ownedPrivateKey);
        if (!reference.IsDefined)
        {
            throw new ArgumentException("Exact key required.", nameof(reference));
        }
        if (!IsP256(ownedPrivateKey))
        {
            throw new ArgumentException("P-256 key required.", nameof(ownedPrivateKey));
        }
        byte[] publicSpki = ownedPrivateKey.ExportSubjectPublicKeyInfo();
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!_keys.TryAdd(reference, ownedPrivateKey))
            {
                throw new ArgumentException("Exact key version is already registered.", nameof(reference));
            }
            return publicSpki;
        }
    }

    /// <summary>Revokes one exact version and destroys its owned private key.</summary>
    public void Revoke(KeyReference reference)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_keys.Remove(reference, out ECDiffieHellman? key))
            {
                key.Dispose();
            }
        }
    }

    /// <summary>Derives P-256 raw agreement internally, immediately HKDF-extracts/expands, then wipes raw bytes.</summary>
    public ValueTask<DerivedKeyLease> AgreeAsync(KeyReference privateKey, AlgorithmId algorithm,
        ReadOnlyMemory<byte> peerPublicKeySpki, DerivationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (!privateKey.IsDefined || algorithm != WellKnownAlgorithms.EcdhP256)
        {
            throw new CryptographicException("Exact P-256 agreement identity and algorithm required.");
        }
        if (peerPublicKeySpki.Length is < 80 or > 512)
        {
            throw new ArgumentException("Invalid P-256 SubjectPublicKeyInfo size.", nameof(peerPublicKeySpki));
        }
        cancellationToken.ThrowIfCancellationRequested();
        using ECDiffieHellman peer = ECDiffieHellman.Create();
        peer.ImportSubjectPublicKeyInfo(peerPublicKeySpki.Span, out int bytesRead);
        if (bytesRead != peerPublicKeySpki.Length || !IsP256(peer))
        {
            throw new CryptographicException("Expected an exact P-256 SubjectPublicKeyInfo.");
        }

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!_keys.TryGetValue(privateKey, out ECDiffieHellman? local))
            {
                throw new CryptographicException("Exact private agreement key unavailable or revoked.");
            }
            cancellationToken.ThrowIfCancellationRequested();
            byte[] localSpki = local.ExportSubjectPublicKeyInfo();
            byte[] peerSpki = peer.ExportSubjectPublicKeyInfo();
            if (localSpki.AsSpan().SequenceEqual(peerSpki))
            {
                throw new CryptographicException("Self-agreement is not supported.");
            }
            byte[] info = context.BuildEcdhInfo(localSpki, peerSpki);
            byte[] salt = SHA256.HashData(info);
            byte[]? raw = null;
            byte[]? derived = null;
            try
            {
                raw = local.DeriveRawSecretAgreement(peer.PublicKey);
                if (raw.Length != 32)
                {
                    throw new CryptographicException("Unexpected P-256 shared secret length.");
                }
                derived = new byte[context.OutputLength];
                HKDF.DeriveKey(HashAlgorithmName.SHA256, raw, derived, salt, info);
                cancellationToken.ThrowIfCancellationRequested();
                DerivedKeyLease lease = new(privateKey, context.Purpose, derived);
                derived = null; // Lease now has exclusive ownership.
                return ValueTask.FromResult(lease);
            }
            finally
            {
                if (raw is not null)
                {
                    CryptographicOperations.ZeroMemory(raw);
                }
                if (derived is not null)
                {
                    CryptographicOperations.ZeroMemory(derived);
                }
                CryptographicOperations.ZeroMemory(info);
                CryptographicOperations.ZeroMemory(salt);
            }
        }
    }

    /// <summary>Destroys all private keys; existing derived leases remain independently owned.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            foreach (ECDiffieHellman key in _keys.Values)
            {
                key.Dispose();
            }
            _keys.Clear();
        }
        GC.SuppressFinalize(this);
    }

    private static bool IsP256(ECDiffieHellman key)
    {
        if (key.KeySize != 256)
        {
            return false;
        }
        ECParameters info = key.ExportParameters(false);
        return info.Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value;
    }
}
