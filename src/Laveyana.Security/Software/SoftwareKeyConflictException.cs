namespace Laveyana.Security.Software;

/// <summary>A definitive naming, state or optimistic concurrency conflict.</summary>
public sealed class SoftwareKeyConflictException : InvalidOperationException
{
    /// <summary>Constructs a redacted failure without key identity or material.</summary>
    public SoftwareKeyConflictException(string reason) : base($"Software key operation rejected: {reason}.") => Reason = reason;

    /// <summary>Gets the stable redacted conflict category.</summary>
    public string Reason { get; }
}
