using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Payloads;

namespace Laveyana.Security.Abstractions.Providers;

/// <summary>Optional versioned provider signing/verification boundary; private material is never returned.</summary>
public interface IManagedSignatureBackend : IKeyProviderBackend
{
    /// <summary>Signs with the current Active private key version.</summary>
    ValueTask<SignaturePayload> SignAsync(LogicalKeyHandle handle, ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken = default);

    /// <summary>Verifies using the exact version recorded in the payload. Invalid signature returns false.</summary>
    ValueTask<bool> VerifySignatureAsync(SignaturePayload signature, ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken = default);
}
