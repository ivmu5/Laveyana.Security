using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Lifecycle;

/// <summary>Failure categories for a rejected pure-domain transition.</summary>
internal enum KeyLifecycleFailure
{
    InvalidState,
    VersionNotFound,
    PendingAlreadyExists,
    RetentionBlocked,
    VersionExhausted,
}
