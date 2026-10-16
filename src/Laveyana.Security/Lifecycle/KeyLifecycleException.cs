using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Lifecycle;

/// <summary>Does not include sensitive key IDs in its message.</summary>
internal sealed class KeyLifecycleException : InvalidOperationException
{
    public KeyLifecycleException(KeyLifecycleFailure failure) : base($"Key lifecycle transition rejected: {failure}.")
    {
        Failure = failure;
    }

    /// <summary>Gets the deterministic failure category.</summary>
    public KeyLifecycleFailure Failure { get; }
}
