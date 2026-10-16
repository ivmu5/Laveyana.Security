using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Algorithms;

/// <summary>Immutable, policy-version-independent metadata for one well-known algorithm.</summary>
public sealed record AlgorithmDescription(
    AlgorithmId Id,
    AlgorithmPurpose Purpose,
    AlgorithmStatus Status,
    bool RequiresPlatformSupport = false);
