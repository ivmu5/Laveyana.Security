using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace Laveyana.Security.Diagnostics;

/// <summary>Bounded classifications independent of exception messages and provider-specific error codes.</summary>
public enum SecurityOperationOutcome
{
    /// <summary>Indicates that the operation completed successfully.</summary>
    Success,
    /// <summary>Indicates a valid negative verification result.</summary>
    Negative,
    /// <summary>Indicates rejection by a policy or precondition.</summary>
    Rejected,
    /// <summary>Indicates that the operation was canceled.</summary>
    Canceled,
    /// <summary>Indicates that the operation failed with an error.</summary>
    Error
}
