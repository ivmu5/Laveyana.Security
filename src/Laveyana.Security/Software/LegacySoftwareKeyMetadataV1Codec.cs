using System.Security.Cryptography;
using System.Text;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Lifecycle;

namespace Laveyana.Security.Software;

/// <summary>Read-only decoder for the authenticated pre-Phase-11 legacy format.</summary>
internal static class LegacySoftwareKeyMetadataV1Codec
{
    private const int Magic = 0x4C534D31; // LSM1
    private const int MaximumVersions = 2048;
    private const int MaximumMetadata = 1024 * 1024;
    private static readonly UTF8Encoding Utf8 = new(false, true);

    internal static SensitiveMaterialLease Encode(SoftwareKeyMetadata metadata)
    {
        using MemoryStream stream = new();
        try
        {
            using (BinaryWriter writer = new(stream, Utf8, true))
            {
                KeyLifecycleSnapshot lifecycle = metadata.Lifecycle;
                if (lifecycle.Versions.Count > MaximumVersions)
                {
                    throw new InvalidOperationException("Version history exceeds the metadata format limit.");
                }

                writer.Write(Magic);
                WriteText(writer, lifecycle.ProviderId.ToString());
                WriteText(writer, lifecycle.KeyId.ToString());
                WriteText(writer, metadata.Name.Value);
                writer.Write((byte)metadata.Kind);
                WriteText(writer, metadata.Algorithm.Value);
                writer.Write((byte)metadata.Capabilities.Count);
                foreach (CapabilityId capability in metadata.Capabilities)
                {
                    WriteText(writer, capability.Value);
                }

                writer.Write((byte)lifecycle.State);
                writer.Write(lifecycle.HighWaterMark.Value);
                writer.Write(lifecycle.Versions.Count);
                foreach (KeyLifecycleVersion version in lifecycle.Versions)
                {
                    writer.Write(version.Version.Value);
                    writer.Write((byte)version.State);
                    writer.Write(version.Retention.IsOnHold);
                    writer.Write(version.Retention.RetainUntilUtc?.UtcTicks ?? 0);
                }
            }

            if (stream.Length > MaximumMetadata)
            {
                throw new InvalidOperationException("Software key metadata exceeds its size limit.");
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
        SoftwareKeyMetadata? result = null;
        lease.UseMaterial(span =>
        {
            if (span.Length > MaximumMetadata)
            {
                throw new InvalidOperationException("Invalid software key metadata size.");
            }

            byte[] temporary = span.ToArray();
            try
            {
                using MemoryStream stream = new(temporary, false);
                using BinaryReader reader = new(stream, Utf8);
                if (reader.ReadInt32() != Magic || ProviderId.Parse(ReadText(reader)) != provider ||
                    KeyId.Parse(ReadText(reader)) != key)
                {
                    throw new InvalidOperationException("Stored key metadata identity is invalid.");
                }

                KeyName name = new(ReadText(reader));
                if (name != expectedName)
                {
                    throw new InvalidOperationException("Stored key name identity is invalid.");
                }

                KeyKind kind = (KeyKind)reader.ReadByte();
                AlgorithmId algorithm = new(ReadText(reader));
                int capabilityCount = reader.ReadByte();
                if (capabilityCount is < 1 or > 64)
                {
                    throw new InvalidOperationException("Stored capability count is invalid.");
                }

                CapabilityId[] capabilities = new CapabilityId[capabilityCount];
                for (int i = 0; i < capabilityCount; i++)
                {
                    capabilities[i] = new CapabilityId(ReadText(reader));
                }

                LogicalKeyState state = (LogicalKeyState)reader.ReadByte();
                KeyVersion highWaterMark = new(reader.ReadInt64());
                int count = reader.ReadInt32();
                if (count is < 1 or > MaximumVersions)
                {
                    throw new InvalidOperationException("Stored version count is invalid.");
                }

                KeyLifecycleVersion[] versions = new KeyLifecycleVersion[count];
                for (int i = 0; i < count; i++)
                {
                    KeyVersion version = new(reader.ReadInt64());
                    KeyVersionState versionState = (KeyVersionState)reader.ReadByte();
                    byte holdValue = reader.ReadByte();
                    if (holdValue > 1)
                    {
                        throw new InvalidOperationException("Invalid retention flag in stored metadata.");
                    }

                    bool hold = holdValue == 1;
                    long ticks = reader.ReadInt64();
                    DateTimeOffset? deadline = ticks == 0 ? null : new DateTimeOffset(ticks, TimeSpan.Zero);
                    versions[i] = new KeyLifecycleVersion(version, versionState,
                        new KeyRetentionConstraint(deadline, hold));
                }

                if (stream.Position != stream.Length)
                {
                    throw new InvalidOperationException("Unexpected data after metadata record.");
                }

                result = new SoftwareKeyMetadata(name, kind, algorithm, capabilities,
                    new KeyLifecycleSnapshot(provider, key, state, highWaterMark, versions));
            }
            catch (Exception ex) when (ex is EndOfStreamException or DecoderFallbackException or FormatException or
                ArgumentException or OverflowException)
            {
                throw new InvalidOperationException("Stored software key metadata is invalid.", ex);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(temporary);
            }
        });

        return result!;
    }

    private static void WriteText(BinaryWriter writer, string value)
    {
        byte[] encoded = Utf8.GetBytes(value);
        if (encoded.Length is < 1 or > 256)
        {
            throw new InvalidOperationException("Metadata token exceeds the permitted length.");
        }

        writer.Write((ushort)encoded.Length);
        writer.Write(encoded);
    }

    private static string ReadText(BinaryReader reader)
    {
        int length = reader.ReadUInt16();
        if (length is < 1 or > 256)
        {
            throw new InvalidOperationException("Invalid metadata token length.");
        }

        byte[] encoded = reader.ReadBytes(length);
        if (encoded.Length != length)
        {
            throw new EndOfStreamException();
        }

        return Utf8.GetString(encoded);
    }
}
