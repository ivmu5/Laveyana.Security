using System.Security.Cryptography;
using System.Text;

namespace Laveyana.Security.Abstractions.Rollback;

/// <summary>Computes a domain-separated fingerprint of the exact serialized store file.</summary>
public static class RollbackSnapshotDigest
{
    private static readonly byte[] Domain = Encoding.ASCII.GetBytes("Laveyana.Security.RollbackSnapshot.SHA256.v1");

    /// <summary>
    /// Hashes a pinned UUID and exact snapshot bytes, without copying the snapshot buffer.
    /// The caller must also separately authenticate the snapshot and verify its embedded identity.
    /// </summary>
    public static byte[] Compute(Guid storeInstanceId, ReadOnlySpan<byte> snapshot)
    {
        if (storeInstanceId == Guid.Empty)
        {
            throw new ArgumentException("A pinned store UUID is required.", nameof(storeInstanceId));
        }

        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Domain);
        byte[] identity = Encoding.ASCII.GetBytes(storeInstanceId.ToString("D"));
        hash.AppendData(identity);
        hash.AppendData(snapshot);
        return hash.GetHashAndReset();
    }
}
