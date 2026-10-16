using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Providers;

namespace Laveyana.Security.Signatures;

/// <summary>
/// Process-local signature executor for tests and ephemeral keys. Never persists private keys.
/// Registered algorithm objects are transferred into this instance and disposed with it.
/// It cannot independently enforce persistent revocation; do not use it as a durable key provider.
/// </summary>
public sealed class EphemeralSignatureKeyOperations : IVersionedSignatureKeyOperations, IDisposable
{
    private readonly object _sync = new();
    private readonly Dictionary<KeyReference, (AlgorithmId Algorithm, AsymmetricAlgorithm Key)> _keys = [];
    private bool _disposed;

    /// <summary>Registers a P-256 private key and transfers ownership on successful registration.</summary>
    public void AddEcdsa(KeyReference reference, ECDsa privateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        if (privateKey.KeySize != 256 || privateKey.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
        {
            throw new ArgumentException("Only NIST P-256 is accepted.", nameof(privateKey));
        }

        Add(reference, WellKnownAlgorithms.EcdsaP256Sha256, privateKey);
    }

    /// <summary>Registers RSA-PSS private key with at least 3072 bits; transfers ownership on success.</summary>
    public void AddRsa(KeyReference reference, RSA privateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        if (privateKey.KeySize is < 3072 or > 8192 || privateKey.KeySize % 8 != 0)
        {
            throw new ArgumentException("RSA signing key size must be 3072-8192 bits.", nameof(privateKey));
        }

        Add(reference, WellKnownAlgorithms.RsaPssSha256, privateKey);
    }

    /// <summary>Signs under the exact registered identity; no implicit version fallback.</summary>
    public ValueTask<byte[]> SignAsync(KeyReference reference, AlgorithmId algorithm, ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            AsymmetricAlgorithm key = Get(reference, algorithm);
            byte[] signature = key switch
            {
                ECDsa ecdsa => ecdsa.SignData(message.Span, HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
                RSA rsa => rsa.SignData(message.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
                _ => throw new CryptographicException("Unsupported signing key type.")
            };
            return ValueTask.FromResult(signature);
        }
    }

    /// <summary>Checks using the matching exact registered key. Invalid data returns false.</summary>
    public ValueTask<bool> VerifyAsync(KeyReference reference, AlgorithmId algorithm, ReadOnlyMemory<byte> message,
        ReadOnlyMemory<byte> signature, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            AsymmetricAlgorithm key = Get(reference, algorithm);
            bool valid = key switch
            {
                ECDsa ecdsa => ecdsa.VerifyData(message.Span, signature.Span, HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
                RSA rsa => rsa.VerifyData(message.Span, signature.Span, HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pss),
                _ => throw new CryptographicException("Unsupported signature key type.")
            };
            return ValueTask.FromResult(valid);
        }
    }

    /// <summary>Destroys all owned ephemeral keys and prevents further operations.</summary>
    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            foreach (var item in _keys.Values)
            {
                item.Key.Dispose();
            }
            _keys.Clear();
        }

        GC.SuppressFinalize(this);
    }

    private void Add(KeyReference reference, AlgorithmId algorithm, AsymmetricAlgorithm key)
    {
        if (!reference.IsDefined)
        {
            throw new ArgumentException("Exact reference required.", nameof(reference));
        }
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!_keys.TryAdd(reference, (algorithm, key)))
            {
                throw new ArgumentException("Exact key version is already registered.", nameof(reference));
            }
        }
    }

    private AsymmetricAlgorithm Get(KeyReference reference, AlgorithmId algorithm)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_keys.TryGetValue(reference, out var entry) || entry.Algorithm != algorithm)
        {
            throw new CryptographicException("Exact signature key version or algorithm is unavailable.");
        }

        return entry.Key;
    }
}
