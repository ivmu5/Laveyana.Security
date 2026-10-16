using System.Security.Cryptography;
using System.Text;
using Laveyana.Security.Abstractions.Payloads;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>
/// Deterministic mutation corpus for all four managed wire formats. A syntactically valid
/// ciphertext mutation may decode successfully; authentication belongs to the AEAD operation.
/// </summary>
[TestFixture]
internal sealed class SecurityCodecMutationTests
{
    private static readonly (string File, Func<byte[], byte[]> RoundTrip)[] Cases =
    [
        ("encrypted-payload-v1.hex", bytes => ManagedPayloadCodec.Encode(ManagedPayloadCodec.DecodeEncrypted(bytes))),
        ("detached-payload-v1.hex", bytes => ManagedPayloadCodec.Encode(ManagedPayloadCodec.DecodeDetached(bytes))),
        ("signature-payload-v1.hex", bytes => ManagedPayloadCodec.Encode(ManagedPayloadCodec.DecodeSignature(bytes))),
        ("mac-result-v1.hex", bytes => ManagedPayloadCodec.Encode(ManagedPayloadCodec.DecodeMac(bytes)))
    ];

    [Test]
    public void BoundedSingleByteMutationsEitherFailOrRoundTripCanonically()
    {
        foreach ((string file, Func<byte[], byte[]> roundTrip) in Cases)
        {
            byte[] original = ReadFixture(file);
            Assert.That(roundTrip(original), Is.EqualTo(original), $"Golden frame {file} is not canonical.");
            for (int index = 0; index < original.Length; index++)
            {
                byte[] mutated = (byte[])original.Clone();
                mutated[index] ^= 0x80;
                TryRoundTrip(mutated, roundTrip, file);
            }
        }
    }

    [Test]
    public void DeterministicMalformedFramesDoNotCauseUnhandledRuntimeErrors()
    {
        Random random = new(20261010);
        foreach ((string file, Func<byte[], byte[]> roundTrip) in Cases)
        {
            byte[] original = ReadFixture(file);
            for (int i = 0; i < 128; i++)
            {
                byte[] candidate = new byte[random.Next(0, original.Length + 16)];
                random.NextBytes(candidate);
                if (candidate.Length >= 8 && i % 2 == 0)
                {
                    Array.Copy(original, candidate, Math.Min(8, candidate.Length));
                }
                TryRoundTrip(candidate, roundTrip, file);
            }
        }
    }

    private static void TryRoundTrip(byte[] candidate, Func<byte[], byte[]> roundTrip, string file)
    {
        try
        {
            byte[] canonical = roundTrip(candidate);
            Assert.That(roundTrip(canonical), Is.EqualTo(canonical),
                $"Accepted {file} frame is not stable after canonical encoding.");
        }
        catch (Exception error) when (error is InvalidDataException or ArgumentException or
            NotSupportedException or FormatException or OverflowException or EndOfStreamException or
            InvalidOperationException or DecoderFallbackException or CryptographicException)
        {
            // Rejecting malformed input is the intended outcome.
        }
    }

    private static byte[] ReadFixture(string filename) => Convert.FromHexString(
        File.ReadAllText(Path.Combine(TestContext.CurrentContext.TestDirectory, "Fixtures", filename)).Trim());
}
