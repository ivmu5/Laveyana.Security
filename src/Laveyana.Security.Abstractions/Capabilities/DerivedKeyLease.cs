using System.Security.Cryptography;
using System.Text.Json.Serialization;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Sensitive;

namespace Laveyana.Security.Abstractions.Capabilities;

/// <summary>Application-owned ephemeral derived key; never returns raw secret bytes by default.</summary>
/// <remarks>Dispose promptly. Disposal wipes only this lease's buffer, not unmanaged or caller-created copies.</remarks>
[JsonConverter(typeof(DerivedKeyLeaseJsonConverter))]
public sealed class DerivedKeyLease : IDisposable
{
    private readonly SensitiveMaterialLease _secret;

    /// <summary>Takes ownership of a derived-only material buffer; caller relinquishes all aliases on success.</summary>
    public DerivedKeyLease(KeyReference source, string purpose, byte[] ownedDerivedMaterial)
    {
        if (!source.IsDefined)
        {
            throw new ArgumentException("Exact source key is required.", nameof(source));
        }
        if (string.IsNullOrWhiteSpace(purpose))
        {
            throw new ArgumentException("Purpose required.", nameof(purpose));
        }
        ArgumentNullException.ThrowIfNull(ownedDerivedMaterial);
        if (ownedDerivedMaterial.Length is < 16 or > 64)
        {
            throw new ArgumentOutOfRangeException(nameof(ownedDerivedMaterial));
        }

        Source = source;
        Purpose = purpose;
        _secret = SensitiveMaterialLease.TakeOwnership(ownedDerivedMaterial);
    }

    /// <summary>Gets the exact provider-owned source key version; not a derived persistent identity.</summary>
    public KeyReference Source { get; }

    /// <summary>Gets the purpose associated with this result.</summary>
    public string Purpose { get; }

    /// <summary>Gets derived material size, provided the lease remains live.</summary>
    public int Length => _secret.Length;

    /// <summary>Runs one synchronous operation using read-only borrowed bytes; the span must not escape.</summary>
    public void UseMaterial(SensitiveMaterialAction visitor) => _secret.UseMaterial(visitor);

    /// <summary>
    /// Explicit materialization escape hatch requiring an application-supplied authorization policy.
    /// Caller owns and MUST dispose/zero returned bytes; default APIs never call this method.
    /// </summary>
    public byte[] ExportMaterialCopy(IDerivedMaterialExportPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        _ = _secret.Length; // Reject use after disposal before policy invocation.
        if (!policy.IsExportAllowed(Source, Purpose))
        {
            throw new CryptographicException("Derived material export was denied by policy.");
        }

        byte[]? result = null;
        _secret.UseMaterial(secret => result = secret.ToArray());
        return result!;
    }

    /// <summary>Destroys managed derived bytes in the owned buffer.</summary>
    public void Dispose() => _secret.Dispose();

    /// <summary>Never renders derived material or identifiers.</summary>
    public override string ToString() => "DerivedKeyLease [REDACTED]";
}
