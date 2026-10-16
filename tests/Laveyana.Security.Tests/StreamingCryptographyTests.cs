using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Capabilities;
using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Payloads;
using Laveyana.Security.Abstractions.Streaming;
using Laveyana.Security.Providers;
using Laveyana.Security.Software;
using Laveyana.Security.Streaming;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>Phase 20 bounded-memory streaming SHA and managed-key HMAC test cases.</summary>
[TestFixture]
internal sealed class StreamingCryptographyTests
{
    private static readonly ProviderId Provider = ProviderId.Parse("11111111-1111-4111-8111-111111111111");
    private static readonly byte[] Sample = "Streaming authenticated bytes, including boundaries."u8.ToArray();

    [TestCase("sha-256")]
    [TestCase("sha-384")]
    [TestCase("sha-512")]
    public async Task HashMatchesWholeBufferForPartialReadsAndEmptyInput(string name)
    {
        AlgorithmId algorithm = new(name);
        byte[] expected = name switch
        {
            "sha-256" => SHA256.HashData(Sample),
            "sha-384" => SHA384.HashData(Sample),
            _ => SHA512.HashData(Sample),
        };
        using PartialReadStream stream = new(Sample, 3);
        byte[] hash = await StreamingLocalCryptography.HashAsync(stream, algorithm,
            new StreamProcessingOptions(bufferSize: 7, expectedBytes: Sample.Length));
        Assert.That(hash, Is.EqualTo(expected));
        Assert.That(stream.CanRead, Is.True);
        Assert.That(await StreamingLocalCryptography.HashAsync(new MemoryStream(), algorithm),
            Is.EqualTo(name switch
            {
                "sha-256" => SHA256.HashData(Array.Empty<byte>()),
                "sha-384" => SHA384.HashData(Array.Empty<byte>()),
                _ => SHA512.HashData(Array.Empty<byte>()),
            }));
    }

    [Test]
    public async Task LargeStreamUsesOnlyBoundedReadWindows()
    {
        const int total = 6 * 1024 * 1024 + 17;
        using ZeroStream stream = new(total);
        byte[] digest = await StreamingLocalCryptography.HashAsync(stream, WellKnownAlgorithms.Sha256,
            new StreamProcessingOptions(bufferSize: 1024, expectedBytes: total));
        Assert.That(stream.MaximumRequestedRead, Is.LessThanOrEqualTo(1024));
        Assert.That(digest, Is.EqualTo(SHA256.HashData(new byte[total])));
        Assert.That(stream.CanRead, Is.True);
    }

    [Test]
    public void LengthBoundsAndUnsupportedAlgorithmsFailClosed()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new StreamProcessingOptions(bufferSize: 65537));
        Assert.Throws<ArgumentOutOfRangeException>(() => new StreamProcessingOptions(maximumBytes: -1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new StreamProcessingOptions(maximumBytes: 1, expectedBytes: 2));
        Assert.ThrowsAsync<InvalidDataException>(async () => await StreamingLocalCryptography.HashAsync(
            new MemoryStream(Sample), WellKnownAlgorithms.Sha256,
            new StreamProcessingOptions(maximumBytes: Sample.Length - 1)));
        Assert.ThrowsAsync<InvalidDataException>(async () => await StreamingLocalCryptography.HashAsync(
            new MemoryStream(Sample), WellKnownAlgorithms.Sha256,
            new StreamProcessingOptions(expectedBytes: Sample.Length - 1)));
        Assert.ThrowsAsync<EndOfStreamException>(async () => await StreamingLocalCryptography.HashAsync(
            new MemoryStream(Sample), WellKnownAlgorithms.Sha256,
            new StreamProcessingOptions(expectedBytes: Sample.Length + 1)));
        Assert.ThrowsAsync<CryptographicException>(async () => await StreamingLocalCryptography.HashAsync(
            new MemoryStream(Sample), WellKnownAlgorithms.Sha1));
        Assert.ThrowsAsync<CryptographicException>(async () => await StreamingLocalCryptography.HashAsync(
            new MemoryStream(Sample), WellKnownAlgorithms.HmacSha256));
    }

    [Test]
    public void FailureAndCancellationNeverProduceHash()
    {
        using CancellationTokenSource canceled = new();
        canceled.Cancel();
        Assert.ThrowsAsync<OperationCanceledException>(async () => await StreamingLocalCryptography.HashAsync(
            new MemoryStream(Sample), WellKnownAlgorithms.Sha256, cancellationToken: canceled.Token));
        Assert.ThrowsAsync<IOException>(async () => await StreamingLocalCryptography.HashAsync(
            new FaultStream(), WellKnownAlgorithms.Sha256));
    }

    [TestCase("hmac-sha-256", 32)]
    [TestCase("hmac-sha-384", 48)]
    [TestCase("hmac-sha-512", 64)]
    public async Task StreamingMacMatchesWholeBufferAndChecksTampering(string algorithm, int length)
    {
        (SoftwareKeyProviderBackend backend, LogicalKeyHandle handle) = await CreateMacAsync(new AlgorithmId(algorithm));
        using PartialReadStream message = new(Sample, 2);
        MacResult tag = await backend.ComputeMacStreamAsync(handle, message,
            new StreamProcessingOptions(bufferSize: 5, expectedBytes: Sample.Length));
        MacResult single = await backend.ComputeMacAsync(handle, Sample);
        Assert.Multiple(() =>
        {
            Assert.That(tag.Reference, Is.EqualTo(single.Reference));
            Assert.That(tag.ExportTagCopy(), Has.Length.EqualTo(length));
            Assert.That(tag.ExportTagCopy(), Is.EqualTo(single.ExportTagCopy()));
        });
        Assert.That(await backend.VerifyMacStreamAsync(tag, new MemoryStream(Sample)), Is.True);
        Assert.That(await backend.VerifyMacStreamAsync(tag, new MemoryStream("altered"u8.ToArray())), Is.False);
        MacResult corrupted = new(tag.Reference, tag.Algorithm, Corrupt(tag.ExportTagCopy()));
        Assert.That(await backend.VerifyMacStreamAsync(corrupted, new MemoryStream(Sample)), Is.False);
        ProviderRegistry registry = new([new ProviderRegistration(backend)]);
        Assert.That(registry.RouteStreamingMac(handle), Is.SameAs(backend));
        Assert.That(registry.RouteStreamingMac(tag.Reference), Is.SameAs(backend));
        MacKey typed = new(handle, backend);
        Assert.That(await typed.VerifyMacStreamAsync(backend, tag, new MemoryStream(Sample)), Is.True);
    }

    [Test]
    public async Task HistoricalMacAfterRotationAndRevocation()
    {
        (SoftwareKeyProviderBackend backend, LogicalKeyHandle handle) = await CreateMacAsync(WellKnownAlgorithms.HmacSha256);
        MacResult first = await backend.ComputeMacStreamAsync(handle, new MemoryStream(Sample));
        await backend.RotateAsync(handle);
        MacResult second = await backend.ComputeMacStreamAsync(handle, new MemoryStream(Sample));
        Assert.That(first.Reference.Version, Is.EqualTo(new KeyVersion(1)));
        Assert.That(second.Reference.Version, Is.EqualTo(new KeyVersion(2)));
        Assert.That(await backend.VerifyMacStreamAsync(first, new MemoryStream(Sample)), Is.True);
        await backend.RetireAsync(handle);
        Assert.ThrowsAsync<CryptographicException>(async () => await backend.ComputeMacStreamAsync(handle, new MemoryStream(Sample)));
        Assert.That(await backend.VerifyMacStreamAsync(first, new MemoryStream(Sample)), Is.True);
        await backend.DeleteVersionAsync(handle, new KeyVersion(1), DateTimeOffset.UtcNow);
        Assert.ThrowsAsync<CryptographicException>(async () => await backend.VerifyMacStreamAsync(first, new MemoryStream(Sample)));
    }

    [Test]
    public async Task IncompleteMacStreamCannotReturnFalseOrValidTag()
    {
        (SoftwareKeyProviderBackend backend, LogicalKeyHandle handle) = await CreateMacAsync(WellKnownAlgorithms.HmacSha256);
        MacResult tag = await backend.ComputeMacStreamAsync(handle, new MemoryStream(Sample));
        StreamProcessingOptions incomplete = new(expectedBytes: Sample.Length + 1);
        Assert.ThrowsAsync<EndOfStreamException>(async () => await backend.VerifyMacStreamAsync(
            tag, new MemoryStream(Sample), incomplete));
        Assert.ThrowsAsync<InvalidDataException>(async () => await backend.ComputeMacStreamAsync(
            handle, new MemoryStream(Sample), new StreamProcessingOptions(maximumBytes: 1)));
        Assert.ThrowsAsync<IOException>(async () => await backend.VerifyMacStreamAsync(tag, new FaultStream()));
        using CancellationTokenSource canceled = new();
        canceled.Cancel();
        Assert.ThrowsAsync<OperationCanceledException>(async () => await backend.ComputeMacStreamAsync(
            handle, new MemoryStream(Sample), cancellationToken: canceled.Token));
    }

    [Test]
    public async Task ConcurrentRotationInvalidatesInFlightStreamMac()
    {
        (SoftwareKeyProviderBackend backend, LogicalKeyHandle handle) = await CreateMacAsync(WellKnownAlgorithms.HmacSha256);
        using MutationReadStream changing = new(Sample, async () => await backend.RotateAsync(handle));
        Assert.ThrowsAsync<SoftwareKeyConflictException>(async () =>
            await backend.ComputeMacStreamAsync(handle, changing));
        MacResult current = await backend.ComputeMacAsync(handle, Sample);
        using MutationReadStream changingAgain = new(Sample, async () => await backend.RotateAsync(handle));
        Assert.ThrowsAsync<SoftwareKeyConflictException>(async () =>
            await backend.VerifyMacStreamAsync(current, changingAgain));
    }

    [Test]
    public async Task MissingCapabilitiesAreErrorsRatherThanFalse()
    {
        (SoftwareKeyProviderBackend backend, LogicalKeyHandle handle) = await CreateMacAsync(
            WellKnownAlgorithms.HmacSha256, WellKnownCapabilities.Mac);
        MacResult tag = await backend.ComputeMacStreamAsync(handle, new MemoryStream(Sample));
        Assert.ThrowsAsync<CryptographicException>(async () => await backend.VerifyMacStreamAsync(
            tag, new MemoryStream(Sample)));
    }

    private static byte[] Corrupt(byte[] original)
    {
        original[0] ^= 0x40;
        return original;
    }

    private static async Task<(SoftwareKeyProviderBackend Backend, LogicalKeyHandle Handle)> CreateMacAsync(
        AlgorithmId algorithm, params CapabilityId[] capabilities)
    {
        SoftwareKeyProviderBackend backend = new(Provider, new StorageContractsTests.MemoryStore(),
            new SoftwareKeyProviderTests.TestProtector());
        KeyDescriptor descriptor = await backend.CreateAsync(new KeyName("StreamMac"), algorithm,
            capabilities.Length == 0 ? [WellKnownCapabilities.Mac, WellKnownCapabilities.VerifyMac] : capabilities);
        return (backend, new LogicalKeyHandle(descriptor.ProviderId, descriptor.KeyId));
    }

    private sealed class PartialReadStream(byte[] bytes, int chunk) : MemoryStream(bytes, writable: false)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            base.ReadAsync(buffer[..Math.Min(chunk, buffer.Length)], cancellationToken);
    }

    private sealed class MutationReadStream(byte[] bytes, Func<Task> mutation) : MemoryStream(bytes, writable: false)
    {
        private bool _mutated;
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (!_mutated)
            {
                _mutated = true;
                await mutation().ConfigureAwait(false);
            }
            return await base.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        }
    }

    private sealed class FaultStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new IOException("Injected read failure.");
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            ValueTask.FromException<int>(new IOException("Injected read failure."));
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class ZeroStream(long length) : Stream
    {
        private long _remaining = length;
        public int MaximumRequestedRead { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            MaximumRequestedRead = Math.Max(MaximumRequestedRead, buffer.Length);
            int count = (int)Math.Min(_remaining, buffer.Length);
            buffer.Span[..count].Clear();
            _remaining -= count;
            return ValueTask.FromResult(count);
        }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
