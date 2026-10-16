using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Abstractions.Sensitive;

namespace Laveyana.Security.Protection;

/// <summary>Exact-reference read routing with a single, explicit current-write protector.</summary>
/// <remarks>
/// The caller must keep historical implementations available until all aggregates have been
/// migrated and committed. No fallback, trial decryption, reflection discovery or in-place
/// re-protection occurs. Registration is immutable; a live security incident requires replacing
/// the router or stopping consumers, not mutating its trust status at runtime.
/// </remarks>
public sealed class ProtectorGenerationRouter : IKeyStoreProtector
{
    private readonly IKeyStoreProtector _current;
    private readonly ProtectorReference _currentReference;
    private readonly IReadOnlyDictionary<ProtectorReference, HistoricalProtectorRegistration> _historical;

    /// <summary>Creates a bounded immutable routing table; rejects duplicate generation identities.</summary>
    public ProtectorGenerationRouter(IKeyStoreProtector current,
        IEnumerable<HistoricalProtectorRegistration> historical)
    {
        _current = current ?? throw new ArgumentNullException(nameof(current));
        ArgumentNullException.ThrowIfNull(historical);
        if (!current.CurrentReference.IsDefined)
        {
            throw new ArgumentException("The current protector must have a defined reference.", nameof(current));
        }

        Dictionary<ProtectorReference, HistoricalProtectorRegistration> entries = new();
        foreach (HistoricalProtectorRegistration entry in historical)
        {
            if (entry is null || entries.Count >= 32 || entry.Protector.CurrentReference == current.CurrentReference ||
                !entries.TryAdd(entry.Protector.CurrentReference, entry))
            {
                throw new ArgumentException("Historical references must be non-null, unique and bounded.", nameof(historical));
            }
        }

        _currentReference = current.CurrentReference;
        _historical = new System.Collections.ObjectModel.ReadOnlyDictionary<ProtectorReference,
            HistoricalProtectorRegistration>(entries);
    }

    /// <summary>Gets the only generation permitted to protect new envelopes.</summary>
    public ProtectorReference CurrentReference => _currentReference;

    /// <summary>Classifies an exact reference without attempting to decrypt its data.</summary>
    public ProtectorGenerationClassification Classify(ProtectorReference reference)
    {
        if (!reference.IsDefined)
        {
            return ProtectorGenerationClassification.Unknown;
        }

        if (reference == CurrentReference)
        {
            return ProtectorGenerationClassification.Current;
        }

        if (!_historical.TryGetValue(reference, out HistoricalProtectorRegistration? registration))
        {
            return ProtectorGenerationClassification.Unknown;
        }

        return registration.Status == HistoricalProtectorStatus.Compromised
            ? ProtectorGenerationClassification.Compromised
            : ProtectorGenerationClassification.LegacyReadOnly;
    }

    /// <inheritdoc />
    public async ValueTask<ProtectedStoreEnvelope> ProtectAsync(SensitiveMaterialLease plaintext,
        ProtectionPurpose purpose, ReadOnlyMemory<byte> authenticatedContext,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        cancellationToken.ThrowIfCancellationRequested();
        if (_current.CurrentReference != _currentReference)
        {
            throw new CryptographicException("The current protector changed identity during its lifetime.");
        }

        ProtectedStoreEnvelope envelope = await _current.ProtectAsync(plaintext, purpose,
            authenticatedContext, cancellationToken).ConfigureAwait(false);
        if (envelope is null || envelope.Protector != CurrentReference || envelope.Purpose != purpose)
        {
            throw new CryptographicException("Current protector returned an inconsistent envelope.");
        }

        return envelope;
    }

    /// <inheritdoc />
    public ValueTask<SensitiveMaterialLease> UnprotectAsync(ProtectedStoreEnvelope envelope,
        ProtectionPurpose expectedPurpose, ReadOnlyMemory<byte> authenticatedContext,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        cancellationToken.ThrowIfCancellationRequested();
        if (envelope.Purpose != expectedPurpose || !Enum.IsDefined(expectedPurpose) ||
            expectedPurpose == ProtectionPurpose.Unspecified)
        {
            throw new CryptographicException("Protected envelope purpose mismatch.");
        }

        IKeyStoreProtector reader = Classify(envelope.Protector) switch
        {
            ProtectorGenerationClassification.Current => _current,
            ProtectorGenerationClassification.LegacyReadOnly => _historical[envelope.Protector].Protector,
            ProtectorGenerationClassification.Compromised => throw new CryptographicException(
                "A compromised protector generation requires key compromise assessment and rotation."),
            _ => throw new CryptographicException("Unknown protector generation; no decryption fallback is allowed.")
        };

        if (reader.CurrentReference != envelope.Protector)
        {
            throw new CryptographicException("A registered protector changed its reference.");
        }

        return reader.UnprotectAsync(envelope, expectedPurpose, authenticatedContext, cancellationToken);
    }
}
