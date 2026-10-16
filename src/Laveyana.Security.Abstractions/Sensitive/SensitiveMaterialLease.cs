using System.Security.Cryptography;
using System.Text.Json.Serialization;

namespace Laveyana.Security.Abstractions.Sensitive;

/// <summary>
/// Owns one mutable secret buffer and overwrites it on disposal. UseMaterial grants
/// synchronous, read-only borrowed access; material is never returned by a property.
/// </summary>
/// <remarks>
/// TakeOwnership invalidates the caller's right to use or modify its original array,
/// even though .NET cannot revoke existing aliases. CreateCopy leaves its input owned
/// by the caller. Disposal during a callback prevents new access and defers the wipe
/// until the last in-flight callback exits; callbacks never run under an internal lock.
/// Only this lease's buffer is erased, not unrelated runtime, caller or OS copies.
/// Disposal is required: garbage collection does not guarantee timely zeroization.
/// </remarks>
[JsonConverter(typeof(SensitiveMaterialLeaseJsonConverter))]
public sealed class SensitiveMaterialLease : IDisposable
{
    /// <summary>Maximum size in bytes for a single in-memory material lease.</summary>
    public const int MaximumMaterialLength = 1024 * 1024;

    private readonly object _gate = new();
    private byte[]? _ownedBuffer;
    private int _activeReaders;
    private bool _disposed;

    private SensitiveMaterialLease(byte[] ownedBuffer) => _ownedBuffer = ownedBuffer;

    /// <summary>
    /// Copies caller-owned bytes once into an independently owned buffer. The input
    /// is never retained, cleared or modified by this method, including on failure.
    /// </summary>
    public static SensitiveMaterialLease CreateCopy(ReadOnlySpan<byte> material)
    {
        ValidateLength(material.Length, nameof(material));
        return new SensitiveMaterialLease(material.ToArray());
    }

    /// <summary>
    /// Takes exclusive logical ownership of an existing mutable array without copying.
    /// After success the caller MUST NOT read, modify or reuse any alias of that array.
    /// Dispose wipes the same array, observable through any stale aliases.
    /// If validation fails, ownership stays with the caller.
    /// </summary>
    public static SensitiveMaterialLease TakeOwnership(byte[] ownedBuffer)
    {
        ArgumentNullException.ThrowIfNull(ownedBuffer);
        ValidateLength(ownedBuffer.Length, nameof(ownedBuffer));
        return new SensitiveMaterialLease(ownedBuffer);
    }

    /// <summary>Number of secret bytes, available only while not disposed.</summary>
    public int Length
    {
        get
        {
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                return _ownedBuffer!.Length;
            }
        }
    }

    /// <summary>
    /// Invokes a synchronous visitor with borrowed read-only bytes; the visitor
    /// must not retain the span or dispatch work that outlives its invocation.
    /// Concurrent read-only visitors are supported; disposal may be called concurrently.
    /// Copies deliberately made inside the visitor belong to the visitor and are not wiped.
    /// </summary>
    public void UseMaterial(SensitiveMaterialAction visitor)
    {
        ArgumentNullException.ThrowIfNull(visitor);
        byte[] buffer;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            buffer = _ownedBuffer!;
            checked
            {
                _activeReaders++;
            }
        }

        try
        {
            visitor(buffer.AsSpan());
        }
        finally
        {
            lock (_gate)
            {
                _activeReaders--;
                if (_disposed && _activeReaders == 0)
                {
                    ClearOwnedBuffer();
                }
            }
        }
    }

    /// <summary>
    /// Idempotently ends the lease and wipes its entire owned array immediately
    /// unless synchronous readers are in flight, when wiping occurs as they exit.
    /// </summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            if (_activeReaders == 0)
            {
                ClearOwnedBuffer();
            }
        }

        GC.SuppressFinalize(this);
    }

    /// <summary>Always redacts secret bytes and their length.</summary>
    public override string ToString() => "SensitiveMaterialLease [REDACTED]";

    private static void ValidateLength(int length, string parameterName)
    {
        if (length < 1 || length > MaximumMaterialLength)
        {
            throw new ArgumentOutOfRangeException(parameterName,
                $"Material must contain between 1 and {MaximumMaterialLength} bytes.");
        }
    }

    // The caller holds _gate. No user callback runs during this operation.
    private void ClearOwnedBuffer()
    {
        if (_ownedBuffer is byte[] buffer)
        {
            CryptographicOperations.ZeroMemory(buffer);
            _ownedBuffer = null;
        }
    }
}
