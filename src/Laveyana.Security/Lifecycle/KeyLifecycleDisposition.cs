using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Lifecycle;

/// <summary>Identifies whether the requested final state was already reached.</summary>
internal enum KeyLifecycleDisposition
{
    Applied,
    AlreadyApplied,
}
