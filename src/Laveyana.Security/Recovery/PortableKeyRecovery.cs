using System.Buffers.Binary;
using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Primitives;

namespace Laveyana.Security.Recovery;

/// <summary>
/// Protects one caller-owned, exportable key material value for cross-device recovery.
/// This codec does not manage storage, backup consistency, hardware keys or key lifecycle.
/// </summary>
/// <remarks>
/// The recovery secret must be 32 cryptographically random bytes, never a user password.
/// Each package derives a fresh AES-256-GCM key from a new random 32-byte salt using HKDF.
/// The exact caller-supplied scope (application, purpose, key identity and version) is
/// authenticated but is not stored in the package; the caller must reproduce it on restore.
/// A previously valid package can be replayed. This is not anti-rollback protection.
/// </remarks>
public static class PortableKeyRecovery
{
    /// <summary>Length of a uniformly random recovery secret, in bytes.</summary>
    public const int RecoverySecretLength = 32;

    /// <summary>Maximum size of one exportable secret/key material value.</summary>
    public const int MaximumMaterialLength = 64 * 1024;

    /// <summary>Maximum length of the caller-supplied stable authenticated scope.</summary>
    public const int MaximumScopeLength = 256;

    private const int HeaderLength = 54;
    private const int TagLength = 16;
    private const int SaltOffset = 10;
    private const int SaltLength = 32;
    private const int NonceOffset = 42;
    private const int NonceLength = 12;

    private static ReadOnlySpan<byte> Magic => "LKR1"u8;
    private static ReadOnlySpan<byte> AssociatedDataDomain => "Laveyana.Security/portable-key-recovery/v1"u8;
    private static ReadOnlySpan<byte> KeyDerivationDomain => "Laveyana.Security/portable-key-recovery/aes-256-gcm/v1"u8;

    /// <summary>
    /// Generates a new 256-bit random recovery secret with disposable ownership.
    /// Show or export it only through a trusted application flow; losing it may make
    /// the protected material irrecoverable.
    /// </summary>
    public static SensitiveMaterialLease GenerateRecoverySecret() =>
        SensitiveMaterialLease.TakeOwnership(RandomNumberGenerator.GetBytes(RecoverySecretLength));

    /// <summary>
    /// Encrypts one exportable key material value. The caller retains ownership of both leases.
    /// A new random salt and nonce are generated for every package, including repeat exports.
    /// </summary>
    /// <param name="material">Exportable key material to protect, never a non-exportable hardware key.</param>
    /// <param name="recoverySecret">Exactly 32 uniformly random bytes, not a password.</param>
    /// <param name="exactScope">Stable cross-device identity, including app, purpose, key ID and version.</param>
    /// <returns>Untrusted-to-readers but authenticated encrypted package bytes.</returns>
    public static byte[] Protect(
        SensitiveMaterialLease material,
        SensitiveMaterialLease recoverySecret,
        ReadOnlyMemory<byte> exactScope)
    {
        ArgumentNullException.ThrowIfNull(material);
        ArgumentNullException.ThrowIfNull(recoverySecret);
        byte[] scope = SnapshotScope(exactScope);
        int length = material.Length;
        if (length > MaximumMaterialLength)
        {
            throw new ArgumentOutOfRangeException(nameof(material), "Recovery material exceeds the supported size.");
        }

        ValidateRecoverySecret(recoverySecret);

        byte[] package = new byte[HeaderLength + length + TagLength];
        Magic.CopyTo(package);
        package[4] = 1;
        package[5] = 0;
        BinaryPrimitives.WriteInt32LittleEndian(package.AsSpan(6, 4), length);
        RandomNumberGenerator.Fill(package.AsSpan(SaltOffset, SaltLength));
        RandomNumberGenerator.Fill(package.AsSpan(NonceOffset, NonceLength));
        byte[] aad = BuildAssociatedData(package.AsSpan(0, HeaderLength), scope);

        recoverySecret.UseMaterial(secret =>
        {
            byte[] derived = new byte[32];
            try
            {
                LocalCryptography.DeriveHkdfSha256(
                    secret, package.AsSpan(SaltOffset, SaltLength), KeyDerivationDomain, derived);
                material.UseMaterial(value =>
                {
                    using AesGcm aes = new(derived, TagLength);
                    aes.Encrypt(
                        package.AsSpan(NonceOffset, NonceLength),
                        value,
                        package.AsSpan(HeaderLength, length),
                        package.AsSpan(HeaderLength + length, TagLength),
                        aad);
                });
            }
            finally
            {
                CryptographicOperations.ZeroMemory(derived);
            }
        });

        return package;
    }

    /// <summary>
    /// Verifies and decrypts a package only for its exact external authenticated scope.
    /// The returned material belongs to the caller and must be disposed. Malformed or
    /// unauthenticated packages never return any plaintext.
    /// </summary>
    /// <param name="encodedPackage">Bytes from untrusted storage or transport.</param>
    /// <param name="recoverySecret">The original, exactly 32-byte random recovery secret.</param>
    /// <param name="exactScope">The exact stable scope used at export, including key identity.</param>
    /// <returns>Disposable owned plaintext material after successful authentication.</returns>
    public static SensitiveMaterialLease Unprotect(
        ReadOnlyMemory<byte> encodedPackage,
        SensitiveMaterialLease recoverySecret,
        ReadOnlyMemory<byte> exactScope)
    {
        ArgumentNullException.ThrowIfNull(recoverySecret);
        byte[] scope = SnapshotScope(exactScope);
        ValidateRecoverySecret(recoverySecret);

        if (encodedPackage.Length < HeaderLength + 1 + TagLength ||
            encodedPackage.Length > HeaderLength + MaximumMaterialLength + TagLength)
        {
            throw new InvalidDataException("Invalid recovery package size.");
        }

        byte[] package = encodedPackage.ToArray();
        if (!package.AsSpan(0, 4).SequenceEqual(Magic) || package[4] != 1 || package[5] != 0)
        {
            throw new InvalidDataException("Invalid or unsupported recovery package header.");
        }

        int length = BinaryPrimitives.ReadInt32LittleEndian(package.AsSpan(6, 4));
        if (length < 1 || length > MaximumMaterialLength ||
            package.Length != HeaderLength + length + TagLength)
        {
            throw new InvalidDataException("Invalid recovery package material length.");
        }

        byte[] aad = BuildAssociatedData(package.AsSpan(0, HeaderLength), scope);
        SensitiveMaterialLease? recovered = null;
        recoverySecret.UseMaterial(secret =>
        {
            byte[] derived = new byte[32];
            byte[]? plaintext = null;
            try
            {
                LocalCryptography.DeriveHkdfSha256(
                    secret, package.AsSpan(SaltOffset, SaltLength), KeyDerivationDomain, derived);
                plaintext = new byte[length];
                using (AesGcm aes = new(derived, TagLength))
                {
                    aes.Decrypt(
                        package.AsSpan(NonceOffset, NonceLength),
                        package.AsSpan(HeaderLength, length),
                        package.AsSpan(HeaderLength + length, TagLength),
                        plaintext,
                        aad);
                }

                recovered = SensitiveMaterialLease.TakeOwnership(plaintext);
                plaintext = null;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(derived);
                if (plaintext is not null)
                {
                    CryptographicOperations.ZeroMemory(plaintext);
                }
            }
        });

        return recovered ?? throw new CryptographicException("Recovery package authentication failed.");
    }

    private static void ValidateRecoverySecret(SensitiveMaterialLease recoverySecret)
    {
        if (recoverySecret.Length != RecoverySecretLength)
        {
            throw new ArgumentException("Recovery requires exactly 32 random secret bytes, not a password.",
                nameof(recoverySecret));
        }
    }

    private static byte[] SnapshotScope(ReadOnlyMemory<byte> exactScope)
    {
        if (exactScope.Length < 1 || exactScope.Length > MaximumScopeLength)
        {
            throw new ArgumentOutOfRangeException(nameof(exactScope), "A bounded stable scope is required.");
        }

        return exactScope.ToArray();
    }

    private static byte[] BuildAssociatedData(ReadOnlySpan<byte> header, ReadOnlySpan<byte> scope)
    {
        byte[] aad = new byte[AssociatedDataDomain.Length + HeaderLength + 2 + scope.Length];
        AssociatedDataDomain.CopyTo(aad);
        header.CopyTo(aad.AsSpan(AssociatedDataDomain.Length, HeaderLength));
        int lengthPosition = AssociatedDataDomain.Length + HeaderLength;
        BinaryPrimitives.WriteUInt16LittleEndian(aad.AsSpan(lengthPosition, 2), checked((ushort)scope.Length));
        scope.CopyTo(aad.AsSpan(lengthPosition + 2));
        return aad;
    }
}
