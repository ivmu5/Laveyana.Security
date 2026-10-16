using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Lifecycle;

/// <summary>The pure-domain operation being planned, not a persisted effect.</summary>
internal enum KeyLifecycleOperation
{
    CreatePendingVersion,
    Activate,
    Rotate,
    RetireKey,
    DiscardPending,
    DeleteVersion,
    ForceDeleteVersion,
    DeleteKey,
    ForceDeleteKey,
}
