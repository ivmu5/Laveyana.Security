namespace Laveyana.Security.Abstractions.Storage;

/// <summary>Explicit durability capabilities; atomic name creation and CAS are mandatory for every store.</summary>
/// <remarks>Authenticated metadata does not imply protection against external snapshot restore.</remarks>
public sealed record KeyStoreCapabilities(bool ProvidesRollbackProtection);
