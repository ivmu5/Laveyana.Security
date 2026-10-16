using System.Buffers;
using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Streaming;

namespace Laveyana.Security.Streaming;

/// <summary>One-pass bounded-memory read pump; only returns after a verified EOF and size check.</summary>
internal static class StreamHashPump
{
    internal static async Task PumpAsync(Stream message, IncrementalHash accumulator,
        StreamProcessingOptions? options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(accumulator);
        if (!message.CanRead)
        {
            throw new ArgumentException("A readable stream is required.", nameof(message));
        }
        StreamProcessingOptions limits = options ?? new StreamProcessingOptions();
        cancellationToken.ThrowIfCancellationRequested();
        byte[] buffer = ArrayPool<byte>.Shared.Rent(limits.BufferSize);
        long consumed = 0;
        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                // Probe one additional byte at the limit, to distinguish legitimate EOF from oversize input.
                long remaining = limits.MaximumBytes - consumed;
                int readLength = (int)Math.Min(limits.BufferSize, remaining == 0 ? 1 : remaining);
                int read = await message.ReadAsync(buffer.AsMemory(0, readLength), cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }
                try
                {
                    if (read > remaining)
                    {
                        throw new InvalidDataException("Stream exceeds the configured maximum size.");
                    }
                    if (limits.ExpectedBytes.HasValue && read > limits.ExpectedBytes.Value - consumed)
                    {
                        throw new InvalidDataException("Stream exceeds the trusted expected length.");
                    }
                    accumulator.AppendData(buffer.AsSpan(0, read));
                    consumed += read;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(buffer.AsSpan(0, read));
                }
            }
            cancellationToken.ThrowIfCancellationRequested();
            if (limits.ExpectedBytes.HasValue && consumed != limits.ExpectedBytes.Value)
            {
                throw new EndOfStreamException("Stream ended before the trusted expected length.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }
}
