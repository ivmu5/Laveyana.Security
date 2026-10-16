using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Lifecycle;

namespace Laveyana.Security.Software;

/// <summary>Explicit wire mapping for one lifecycle version and its retention guard.</summary>
internal sealed record SoftwareKeyPersistedVersion(long Version, string State, bool IsOnHold, long RetainUntilTicks);
