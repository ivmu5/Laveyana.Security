using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Abstractions.Sensitive;

namespace Laveyana.Security.Windows.Protection;

/// <summary>
/// Windows DPAPI CurrentUser protector with authenticated, domain-separated store context.
/// The OS owns the protection root. It is never exported or persisted by this component.
/// </summary>
/// <remarks>
/// Only the same Windows user profile can normally decrypt protected data. This is not a
/// machine-wide, remote, portable, rollback-resistant or process-isolation mechanism.
/// Keep the supplied protector identity stable for existing persisted records. Generation
/// changes and recovery of historical envelopes require explicit migration (Phase 14A).
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class WindowsDpapiUserProtector : IKeyStoreProtector
{
    private const int MaxContextLength = 64 * 1024;
    private const int InnerHeaderLength = 40;
    private const int OuterHeaderLength = 9;
    private const byte WireVersion = 1;
    private const int UiForbidden = 0x1;

    private static ReadOnlySpan<byte> OuterMagic => "LSWP"u8;
    private static ReadOnlySpan<byte> InnerMagic => "LWPI"u8;
    private static ReadOnlySpan<byte> EntropyDomain => "Laveyana.Security/windows/dpapi-user/v1"u8;

    /// <summary>
    /// Creates a user-scoped protector. The identity is chosen by the caller and must stay
    /// stable across process restarts and configuration deployments.
    /// </summary>
    public WindowsDpapiUserProtector(ProtectorReference reference)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows DPAPI CurrentUser is available only on Windows.");
        }

        if (!reference.IsDefined)
        {
            throw new ArgumentException("A stable protector reference is required.", nameof(reference));
        }

        CurrentReference = reference;
    }

    /// <inheritdoc />
    public ProtectorReference CurrentReference { get; }

    /// <inheritdoc />
    public ValueTask<ProtectedStoreEnvelope> ProtectAsync(
        SensitiveMaterialLease plaintext,
        ProtectionPurpose purpose,
        ReadOnlyMemory<byte> authenticatedContext,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ValidateRequest(purpose, authenticatedContext.Length);
        cancellationToken.ThrowIfCancellationRequested();

        byte[] entropy = CreateEntropy(CurrentReference, purpose, authenticatedContext.Span);
        byte[]? ciphertext = null;
        try
        {
            plaintext.UseMaterial(material =>
            {
                byte[] inner = BuildInner(material, entropy);
                try
                {
                    ciphertext = InvokeDpapi(inner, entropy, decrypt: false);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(inner);
                }
            });

            cancellationToken.ThrowIfCancellationRequested();
            if (ciphertext is null || ciphertext.Length < 1 ||
                ciphertext.Length > ProtectedStoreEnvelope.MaximumEncodedLength - OuterHeaderLength)
            {
                throw new CryptographicException("DPAPI returned an invalid protected payload size.");
            }

            byte[] encoded = new byte[OuterHeaderLength + ciphertext.Length];
            OuterMagic.CopyTo(encoded);
            encoded[4] = WireVersion;
            BinaryPrimitives.WriteInt32LittleEndian(encoded.AsSpan(5, 4), ciphertext.Length);
            ciphertext.CopyTo(encoded, OuterHeaderLength);
            return ValueTask.FromResult(new ProtectedStoreEnvelope(CurrentReference, purpose, encoded));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(entropy);
        }
    }

    /// <inheritdoc />
    public ValueTask<SensitiveMaterialLease> UnprotectAsync(
        ProtectedStoreEnvelope envelope,
        ProtectionPurpose expectedPurpose,
        ReadOnlyMemory<byte> authenticatedContext,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ValidateRequest(expectedPurpose, authenticatedContext.Length);
        cancellationToken.ThrowIfCancellationRequested();
        if (envelope.Protector != CurrentReference || envelope.Purpose != expectedPurpose)
        {
            throw new CryptographicException("Protector identity or purpose mismatch.");
        }

        byte[] encoded = envelope.ExportEncodedCopy();
        if (encoded.Length < OuterHeaderLength + 1 ||
            !encoded.AsSpan(0, 4).SequenceEqual(OuterMagic) ||
            encoded[4] != WireVersion ||
            BinaryPrimitives.ReadInt32LittleEndian(encoded.AsSpan(5, 4)) != encoded.Length - OuterHeaderLength)
        {
            throw new CryptographicException("Invalid or unsupported DPAPI envelope.");
        }

        byte[] entropy = CreateEntropy(CurrentReference, expectedPurpose, authenticatedContext.Span);
        byte[]? inner = null;
        try
        {
            inner = InvokeDpapi(encoded.AsSpan(OuterHeaderLength).ToArray(), entropy, decrypt: true);
            byte[] plain = ParseInner(inner, entropy);
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                return ValueTask.FromResult(SensitiveMaterialLease.TakeOwnership(plain));
            }
            catch
            {
                CryptographicOperations.ZeroMemory(plain);
                throw;
            }
        }
        finally
        {
            if (inner is not null)
            {
                CryptographicOperations.ZeroMemory(inner);
            }

            CryptographicOperations.ZeroMemory(entropy);
        }
    }

    private static void ValidateRequest(ProtectionPurpose purpose, int contextLength)
    {
        if (!Enum.IsDefined(purpose) || purpose == ProtectionPurpose.Unspecified)
        {
            throw new ArgumentOutOfRangeException(nameof(purpose));
        }

        if (contextLength is < 1 or > MaxContextLength)
        {
            throw new ArgumentOutOfRangeException(nameof(contextLength), "An explicit bounded AAD context is required.");
        }
    }

    private static byte[] CreateEntropy(ProtectorReference reference, ProtectionPurpose purpose, ReadOnlySpan<byte> context)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(EntropyDomain);
        byte[] identity = Encoding.ASCII.GetBytes(reference.ToString());
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(length, identity.Length);
        hash.AppendData(length);
        hash.AppendData(identity);
        Span<byte> purposeByte = stackalloc byte[1] { checked((byte)purpose) };
        hash.AppendData(purposeByte);
        BinaryPrimitives.WriteInt32LittleEndian(length, context.Length);
        hash.AppendData(length);
        hash.AppendData(context);
        return hash.GetHashAndReset();
    }

    private static byte[] BuildInner(ReadOnlySpan<byte> material, ReadOnlySpan<byte> entropy)
    {
        byte[] inner = new byte[InnerHeaderLength + material.Length];
        InnerMagic.CopyTo(inner);
        BinaryPrimitives.WriteInt32LittleEndian(inner.AsSpan(4, 4), material.Length);
        material.CopyTo(inner.AsSpan(InnerHeaderLength));
        WriteDigest(inner, entropy);
        return inner;
    }

    private static void WriteDigest(byte[] inner, ReadOnlySpan<byte> entropy)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(inner.AsSpan(0, 8));
        hash.AppendData(entropy);
        hash.AppendData(inner.AsSpan(InnerHeaderLength));
        byte[] digest = hash.GetHashAndReset();
        try
        {
            digest.CopyTo(inner, 8);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    private static byte[] ParseInner(byte[] inner, ReadOnlySpan<byte> entropy)
    {
        if (inner.Length is < InnerHeaderLength + 1 or > SensitiveMaterialLease.MaximumMaterialLength + InnerHeaderLength ||
            !inner.AsSpan(0, 4).SequenceEqual(InnerMagic) ||
            BinaryPrimitives.ReadInt32LittleEndian(inner.AsSpan(4, 4)) != inner.Length - InnerHeaderLength)
        {
            throw new CryptographicException("Invalid decrypted DPAPI record.");
        }

        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(inner.AsSpan(0, 8));
        hash.AppendData(entropy);
        hash.AppendData(inner.AsSpan(InnerHeaderLength));
        byte[] digest = hash.GetHashAndReset();
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(digest, inner.AsSpan(8, 32)))
            {
                throw new CryptographicException("DPAPI plaintext integrity check failed.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
        }

        return inner.AsSpan(InnerHeaderLength).ToArray();
    }

    private static unsafe byte[] InvokeDpapi(byte[] input, byte[] entropy, bool decrypt)
    {
        GCHandle inputPin = default;
        GCHandle entropyPin = default;
        DataBlob output = default;
        try
        {
            inputPin = GCHandle.Alloc(input, GCHandleType.Pinned);
            entropyPin = GCHandle.Alloc(entropy, GCHandleType.Pinned);
            DataBlob source = new(input.Length, inputPin.AddrOfPinnedObject());
            DataBlob optionalEntropy = new(entropy.Length, entropyPin.AddrOfPinnedObject());
            bool success = decrypt
                ? CryptUnprotectData(ref source, nint.Zero, ref optionalEntropy, nint.Zero, nint.Zero, UiForbidden, out output)
                : CryptProtectData(ref source, null, ref optionalEntropy, nint.Zero, nint.Zero, UiForbidden, out output);
            if (!success)
            {
                int error = Marshal.GetLastPInvokeError();
                throw new CryptographicException("Windows DPAPI could not process the protected record.", new Win32Exception(error));
            }

            int limit = decrypt
                ? SensitiveMaterialLease.MaximumMaterialLength + InnerHeaderLength
                : ProtectedStoreEnvelope.MaximumEncodedLength - OuterHeaderLength;
            if (output.Data == nint.Zero || output.Length is < 1 || output.Length > limit)
            {
                throw new CryptographicException("Windows DPAPI returned an invalid data buffer.");
            }

            byte[] managed = new byte[output.Length];
            Marshal.Copy(output.Data, managed, 0, output.Length);
            return managed;
        }
        finally
        {
            if (output.Data != nint.Zero)
            {
                if (decrypt && output.Length > 0)
                {
                    CryptographicOperations.ZeroMemory(new Span<byte>((void*)output.Data, output.Length));
                }

                _ = LocalFree(output.Data);
            }

            if (entropyPin.IsAllocated)
            {
                entropyPin.Free();
            }

            if (inputPin.IsAllocated)
            {
                inputPin.Free();
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int Length;
        public nint Data;

        public DataBlob(int length, nint data)
        {
            Length = length;
            Data = data;
        }
    }

    [DllImport("crypt32.dll", EntryPoint = "CryptProtectData", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(
        ref DataBlob input,
        string? description,
        ref DataBlob optionalEntropy,
        nint reserved,
        nint prompt,
        int flags,
        out DataBlob output);

    [DllImport("crypt32.dll", EntryPoint = "CryptUnprotectData", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(
        ref DataBlob input,
        nint description,
        ref DataBlob optionalEntropy,
        nint reserved,
        nint prompt,
        int flags,
        out DataBlob output);

    [DllImport("kernel32.dll", EntryPoint = "LocalFree", ExactSpelling = true, SetLastError = true)]
    private static extern nint LocalFree(nint block);
}
