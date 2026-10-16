using System.Text.Json.Serialization;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Sensitive;

namespace Laveyana.Security.Abstractions.Secrets;

/// <summary>
/// One owned secret read tied to an exact, immutable provider/secret identity.
/// No direct byte-array, string or serializable material accessor is provided.
/// </summary>
/// <remarks>
/// Ownership of the lease transfers to this result after successful construction.
/// The caller must dispose the result; callbacks are synchronous and must not
/// retain borrowed spans. Clearing the buffer cannot erase copies made elsewhere.
/// </remarks>
[JsonConverter(typeof(SecretReadResultJsonConverter))]
public sealed class SecretReadResult : IDisposable
{
    private SensitiveMaterialLease? _material;

    /// <summary>Adopts an existing owned lease for the supplied identity.</summary>
    public SecretReadResult(SecretReference reference, SensitiveMaterialLease material)
    {
        if (!reference.IsDefined)
        {
            throw new ArgumentException("A defined secret reference is required.", nameof(reference));
        }

        ArgumentNullException.ThrowIfNull(material);
        _ = material.Length;
        Reference = reference;
        _material = material;
    }

    /// <summary>Exact stable identity of the borrowed bytes.</summary>
    public SecretReference Reference { get; }

    /// <summary>Grants synchronous, read-only access while the result is alive.</summary>
    public void UseMaterial(SensitiveMaterialAction visitor)
    {
        ArgumentNullException.ThrowIfNull(visitor);
        SensitiveMaterialLease lease = Volatile.Read(ref _material) ??
            throw new ObjectDisposedException(nameof(SecretReadResult));
        lease.UseMaterial(visitor);
    }

    /// <summary>Idempotently disposes and zeroizes the owned lease.</summary>
    public void Dispose()
    {
        Interlocked.Exchange(ref _material, null)?.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <summary>Never includes identity or secret material in diagnostics.</summary>
    public override string ToString() => "SecretReadResult [REDACTED]";
}
