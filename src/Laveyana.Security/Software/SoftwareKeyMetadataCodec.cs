using System.Security.Cryptography;
using System.Text;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Sensitive;

namespace Laveyana.Security.Software;

/// <summary>Canonical LSMD v2 metadata schema with authenticated-legacy v1 migration support.</summary>
/// <remarks>Only an authenticated store entry can be decoded; this codec does not provide integrity or rollback protection.</remarks>
internal static class SoftwareKeyMetadataCodec
{
    internal const ushort CurrentFormatVersion = 2;
    private const int MaximumVersions = 2048;
    private const int MaximumMetadata = 1024 * 1024;
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly byte[] Header = "LSMD"u8.ToArray();
    private static readonly byte[] LegacyHeader = [0x31, 0x4D, 0x53, 0x4C];

    internal static SensitiveMaterialLease Encode(SoftwareKeyMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        SoftwareKeyPersistedRecord record = SoftwareKeyPersistedRecord.FromDomain(metadata);
        if (record.Versions.Count is 0 or > MaximumVersions || record.Capabilities.Count is 0 or > 64)
        {
            throw new InvalidOperationException("Persisted metadata exceeds supported count bounds.");
        }

        using MemoryStream stream = new();
        try
        {
            using (BinaryWriter writer = new(stream, Utf8, true))
            {
                writer.Write(Header);
                writer.Write(CurrentFormatVersion);
                writer.Write((ushort)0);
                WriteText(writer, record.ProviderId);
                WriteText(writer, record.KeyId);
                WriteText(writer, record.Name);
                WriteText(writer, record.Kind);
                WriteText(writer, record.Algorithm);
                writer.Write((byte)record.Capabilities.Count);
                foreach (string capability in record.Capabilities)
                {
                    WriteText(writer, capability);
                }

                WriteText(writer, record.State);
                writer.Write(record.HighWaterMark);
                writer.Write(record.Versions.Count);
                foreach (SoftwareKeyPersistedVersion version in record.Versions)
                {
                    writer.Write(version.Version);
                    WriteText(writer, version.State);
                    writer.Write((byte)(version.IsOnHold ? 1 : 0));
                    writer.Write(version.RetainUntilTicks);
                }
            }

            if (stream.Length > MaximumMetadata)
            {
                throw new InvalidOperationException("Persisted metadata is too large.");
            }

            return SensitiveMaterialLease.TakeOwnership(stream.ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(stream.GetBuffer().AsSpan(0, (int)stream.Length));
        }
    }

    internal static SoftwareKeyMetadata Decode(SensitiveMaterialLease lease, ProviderId provider, KeyId key,
        KeyName expectedName)
    {
        ArgumentNullException.ThrowIfNull(lease);
        SoftwareKeyMetadata? decoded = null;
        lease.UseMaterial(bytes =>
        {
            if (bytes.Length is < 4 or > MaximumMetadata)
            {
                throw new InvalidOperationException("Invalid metadata length.");
            }

            if (bytes[..4].SequenceEqual(LegacyHeader))
            {
                decoded = LegacySoftwareKeyMetadataV1Codec.Decode(lease, provider, key, expectedName);
                return;
            }

            if (!bytes[..4].SequenceEqual(Header))
            {
                throw new InvalidOperationException("Unknown metadata schema marker.");
            }

            byte[] temporary = bytes.ToArray();
            try
            {
                using MemoryStream stream = new(temporary, false);
                using BinaryReader reader = new(stream, Utf8);
                _ = reader.ReadBytes(4);
                ushort version = reader.ReadUInt16();
                if (version != CurrentFormatVersion)
                {
                    throw new NotSupportedException("Unknown persisted metadata format version.");
                }

                if (reader.ReadUInt16() != 0)
                {
                    throw new InvalidOperationException("Unknown persisted metadata format flags.");
                }

                string providerText = ReadText(reader);
                string keyText = ReadText(reader);
                string name = ReadText(reader);
                string kind = ReadText(reader);
                string algorithm = ReadText(reader);
                int capabilityCount = reader.ReadByte();
                if (capabilityCount is < 1 or > 64)
                {
                    throw new InvalidOperationException("Invalid persisted capability count.");
                }

                string[] capabilities = new string[capabilityCount];
                for (int i = 0; i < capabilityCount; i++)
                {
                    capabilities[i] = ReadText(reader);
                }

                string state = ReadText(reader);
                long highWaterMark = reader.ReadInt64();
                int count = reader.ReadInt32();
                if (count is < 1 or > MaximumVersions)
                {
                    throw new InvalidOperationException("Invalid persisted version count.");
                }

                SoftwareKeyPersistedVersion[] versions = new SoftwareKeyPersistedVersion[count];
                for (int i = 0; i < count; i++)
                {
                    long ordinal = reader.ReadInt64();
                    string versionState = ReadText(reader);
                    byte hold = reader.ReadByte();
                    if (hold > 1)
                    {
                        throw new InvalidOperationException("Invalid persisted hold marker.");
                    }

                    versions[i] = new SoftwareKeyPersistedVersion(ordinal, versionState, hold == 1,
                        reader.ReadInt64());
                }

                if (stream.Position != stream.Length)
                {
                    throw new InvalidOperationException("Trailing bytes in persisted metadata.");
                }

                decoded = new SoftwareKeyPersistedRecord(providerText, keyText, name, kind, algorithm,
                    capabilities, state, highWaterMark, versions).ToDomain(provider, key, expectedName);
                using SensitiveMaterialLease canonical = Encode(decoded);
                bool equal = false;
                canonical.UseMaterial(canonicalBytes => equal = canonicalBytes.SequenceEqual(temporary));
                if (!equal)
                {
                    throw new InvalidOperationException("Metadata is not canonically encoded.");
                }
            }
            catch (Exception ex) when (ex is EndOfStreamException or DecoderFallbackException or FormatException or
                ArgumentException or OverflowException)
            {
                throw new InvalidOperationException("Invalid persisted software metadata.", ex);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(temporary);
            }
        });
        return decoded!;
    }

    /// <summary>Produces current bytes in memory; the caller owns an explicit authenticated CAS commit.</summary>
    internal static SensitiveMaterialLease MigrateToCurrent(SensitiveMaterialLease authenticatedPlaintext,
        ProviderId provider, KeyId key, KeyName name) => Encode(Decode(authenticatedPlaintext, provider, key, name));

    internal static ushort ReadFormatVersion(SensitiveMaterialLease plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ushort result = 0;
        plaintext.UseMaterial(bytes =>
        {
            if (bytes.Length >= 4 && bytes[..4].SequenceEqual(LegacyHeader))
            {
                result = 1;
            }
            else if (bytes.Length >= 6 && bytes[..4].SequenceEqual(Header))
            {
                result = (ushort)(bytes[4] | (bytes[5] << 8));
            }
            else
            {
                throw new InvalidOperationException("Unknown metadata header.");
            }
        });
        return result;
    }

    private static void WriteText(BinaryWriter writer, string value)
    {
        byte[] encoded = Utf8.GetBytes(value);
        if (encoded.Length is < 1 or > 256)
        {
            throw new InvalidOperationException("Persisted token length is invalid.");
        }

        try
        {
            writer.Write((ushort)encoded.Length);
            writer.Write(encoded);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    private static string ReadText(BinaryReader reader)
    {
        int count = reader.ReadUInt16();
        if (count is < 1 or > 256)
        {
            throw new InvalidOperationException("Persisted token length is invalid.");
        }

        byte[] encoded = reader.ReadBytes(count);
        if (encoded.Length != count)
        {
            throw new EndOfStreamException();
        }

        try
        {
            return Utf8.GetString(encoded);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }
}
