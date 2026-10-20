namespace Laveyana.Security.Abstractions.Rollback;

/// <summary>Resolution of one exactly identified authority mutation, not overall store health.</summary>
public enum RollbackRequestResolution
{
    /// <summary>
    /// No terminal outcome has been established. A previously sent request may still apply;
    /// the caller MUST preserve recovery evidence and fail closed.
    /// </summary>
    Unresolved = 0,

    /// <summary>
    /// The exact identified mutation was durably applied, even if authority state later advanced.
    /// </summary>
    Applied = 1,

    /// <summary>
    /// The exact identified mutation did not apply and is durably fenced so no delayed delivery
    /// or retry with the same identifier can ever apply it in the future.
    /// </summary>
    NotApplied = 2,
}
