using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Lifecycle;

namespace Laveyana.Security.Software;

/// <summary>Explicit persisted DTO, separated from runtime lifecycle implementations.</summary>
internal sealed record SoftwareKeyPersistedRecord(
    string ProviderId, string KeyId, string Name, string Kind, string Algorithm,
    IReadOnlyList<string> Capabilities, string State, long HighWaterMark,
    IReadOnlyList<SoftwareKeyPersistedVersion> Versions)
{
    internal static SoftwareKeyPersistedRecord FromDomain(SoftwareKeyMetadata metadata)
    {
        KeyLifecycleSnapshot snapshot = metadata.Lifecycle;
        return new SoftwareKeyPersistedRecord(snapshot.ProviderId.ToString(), snapshot.KeyId.ToString(),
            metadata.Name.Value, metadata.Kind switch
            {
                KeyKind.Symmetric => "symmetric",
                KeyKind.AsymmetricPrivate => "asymmetric-private",
                KeyKind.AsymmetricPublic => "asymmetric-public",
                _ => throw new InvalidOperationException("Unsupported persisted key kind.")
            }, metadata.Algorithm.Value, metadata.Capabilities.Select(x => x.Value).ToArray(),
            snapshot.State switch
            {
                LogicalKeyState.Active => "active",
                LogicalKeyState.Retired => "retired",
                LogicalKeyState.Deleted => "deleted",
                _ => throw new InvalidOperationException("Unsupported persisted logical state.")
            }, snapshot.HighWaterMark.Value,
            snapshot.Versions.Select(x => new SoftwareKeyPersistedVersion(x.Version.Value,
                x.State switch
                {
                    KeyVersionState.Pending => "pending",
                    KeyVersionState.Active => "active",
                    KeyVersionState.Retired => "retired",
                    KeyVersionState.Deleted => "deleted",
                    _ => throw new InvalidOperationException("Unsupported persisted version state.")
                }, x.Retention.IsOnHold, x.Retention.RetainUntilUtc?.UtcTicks ?? 0)).ToArray());
    }

    internal SoftwareKeyMetadata ToDomain(ProviderId provider, KeyId key, KeyName expectedName)
    {
        if (ProviderId != provider.ToString() || KeyId != key.ToString() || Name != expectedName.Value)
        {
            throw new InvalidOperationException("Persisted metadata identity does not match the authenticated entry.");
        }

        KeyKind kind = Kind switch
        {
            "symmetric" => KeyKind.Symmetric,
            "asymmetric-private" => KeyKind.AsymmetricPrivate,
            "asymmetric-public" => KeyKind.AsymmetricPublic,
            _ => throw new InvalidOperationException("Unknown persisted key kind.")
        };
        LogicalKeyState state = State switch
        {
            "active" => LogicalKeyState.Active,
            "retired" => LogicalKeyState.Retired,
            "deleted" => LogicalKeyState.Deleted,
            _ => throw new InvalidOperationException("Unknown persisted logical state.")
        };
        KeyLifecycleVersion[] versions = Versions.Select(x => new KeyLifecycleVersion(new KeyVersion(x.Version),
            x.State switch
            {
                "pending" => KeyVersionState.Pending,
                "active" => KeyVersionState.Active,
                "retired" => KeyVersionState.Retired,
                "deleted" => KeyVersionState.Deleted,
                _ => throw new InvalidOperationException("Unknown persisted version state.")
            }, new KeyRetentionConstraint(x.RetainUntilTicks == 0 ? null :
                new DateTimeOffset(x.RetainUntilTicks, TimeSpan.Zero), x.IsOnHold))).ToArray();
        return new SoftwareKeyMetadata(new KeyName(Name), kind, new AlgorithmId(Algorithm),
            Capabilities.Select(x => new CapabilityId(x)), new KeyLifecycleSnapshot(provider, key, state,
                new KeyVersion(HighWaterMark), versions));
    }
}
