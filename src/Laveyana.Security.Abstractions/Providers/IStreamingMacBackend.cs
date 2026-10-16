using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Payloads;
using Laveyana.Security.Abstractions.Streaming;

namespace Laveyana.Security.Abstractions.Providers;

/// <summary>Optional provider-owned stream HMAC. The stream is borrowed and is never disposed.</summary>
/// <remarks>Successful results mean that EOF and any trusted expected length were observed.
/// False denotes only a mismatching full tag; authorization, I/O, size and cancellation fail by exception.
/// This is not streaming authenticated encryption.</remarks>
public interface IStreamingMacBackend : IManagedMacBackend
{
    /// <summary>Computes a full HMAC using the current Active version without buffering the entire stream.</summary>
    Task<MacResult> ComputeMacStreamAsync(LogicalKeyHandle handle, Stream message,
        StreamProcessingOptions? options = null, CancellationToken cancellationToken = default);

    /// <summary>Verifies a full HMAC using the exact version in the result, after consuming the whole stream.</summary>
    Task<bool> VerifyMacStreamAsync(MacResult result, Stream message,
        StreamProcessingOptions? options = null, CancellationToken cancellationToken = default);
}
