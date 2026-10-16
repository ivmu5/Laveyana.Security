namespace Laveyana.Security.Abstractions.Streaming;

/// <summary>Explicit memory and input-size limits for incremental, read-only stream operations.</summary>
/// <remarks>The trusted expected byte count, when provided, rejects premature EOF and extra input.
/// It does not authenticate length on its own; an attacker must not choose the expected value.</remarks>
public sealed class StreamProcessingOptions
{
    /// <summary>Largest permitted rented read buffer (64 KiB).</summary>
    public const int MaximumBufferSize = 64 * 1024;

    /// <summary>Default maximum bytes processed (1 TiB), independent of stream.Length.</summary>
    public const long DefaultMaximumBytes = 1L << 40;

    /// <summary>Creates immutable read limits, optionally requiring an exact trusted input length.</summary>
    public StreamProcessingOptions(int bufferSize = MaximumBufferSize,
        long maximumBytes = DefaultMaximumBytes, long? expectedBytes = null)
    {
        if (bufferSize is < 1 or > MaximumBufferSize)
        {
            throw new ArgumentOutOfRangeException(nameof(bufferSize));
        }
        if (maximumBytes is < 0 or > DefaultMaximumBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        }
        if (expectedBytes is < 0 || expectedBytes > maximumBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(expectedBytes));
        }
        BufferSize = bufferSize;
        MaximumBytes = maximumBytes;
        ExpectedBytes = expectedBytes;
    }

    /// <summary>Maximum rented buffer length.</summary>
    public int BufferSize { get; }

    /// <summary>Maximum accepted bytes. A stream exceeding it is rejected.</summary>
    public long MaximumBytes { get; }

    /// <summary>Trusted exact size if known; mismatch prevents returning a digest or MAC.</summary>
    public long? ExpectedBytes { get; }
}
