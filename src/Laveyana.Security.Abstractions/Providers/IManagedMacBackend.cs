using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Payloads;

namespace Laveyana.Security.Abstractions.Providers;

/// <summary>Optional provider-owned HMAC boundary; no raw key bytes cross this interface.</summary>
public interface IManagedMacBackend : IKeyProviderBackend
{
    /// <summary>Authenticates a message using the current Active version.</summary>
    ValueTask<MacResult> ComputeMacAsync(LogicalKeyHandle handle, ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken = default);

    /// <summary>Verifies an exact historical result. False means a mismatching tag, not a provider error.</summary>
    ValueTask<bool> VerifyMacAsync(MacResult result, ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken = default);
}
