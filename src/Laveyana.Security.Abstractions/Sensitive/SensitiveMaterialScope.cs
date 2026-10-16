namespace Laveyana.Security.Abstractions.Sensitive;

/// <summary>Executes synchronous visitors with a secret whose lifetime is one call.</summary>
public static class SensitiveMaterialScope
{
    /// <summary>
    /// Copies borrowed bytes once, grants read-only access and clears the private copy
    /// on normal return or exception. Never clears the original caller-owned input.
    /// </summary>
    public static void UseCopy(ReadOnlySpan<byte> material, SensitiveMaterialAction visitor)
    {
        ArgumentNullException.ThrowIfNull(visitor);
        using SensitiveMaterialLease lease = SensitiveMaterialLease.CreateCopy(material);
        lease.UseMaterial(visitor);
    }

    /// <summary>
    /// Takes ownership of a caller-supplied array without a copy and clears that array
    /// on normal return or exception. Validation failure leaves ownership with caller.
    /// </summary>
    public static void UseOwned(byte[] ownedBuffer, SensitiveMaterialAction visitor)
    {
        ArgumentNullException.ThrowIfNull(visitor);
        using SensitiveMaterialLease lease = SensitiveMaterialLease.TakeOwnership(ownedBuffer);
        lease.UseMaterial(visitor);
    }
}
