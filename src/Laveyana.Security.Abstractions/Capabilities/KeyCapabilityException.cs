namespace Laveyana.Security.Abstractions.Capabilities;

/// <summary>
/// Reports fail-closed metadata preflight failure without disclosing key identities.
/// </summary>
public sealed class KeyCapabilityException : InvalidOperationException
{
    /// <summary>Creates a categorized, redacted failure.</summary>
    public KeyCapabilityException(KeyCapabilityFailure failure)
        : base(FormatMessage(failure))
    {
        Failure = failure;
    }

    /// <summary>Gets the stable failure category.</summary>
    public KeyCapabilityFailure Failure { get; }

    private static string FormatMessage(KeyCapabilityFailure failure)
    {
        if (failure == KeyCapabilityFailure.None || !Enum.IsDefined(failure))
        {
            throw new ArgumentOutOfRangeException(nameof(failure));
        }

        return $"Key capability resolution failed: {failure}.";
    }
}
