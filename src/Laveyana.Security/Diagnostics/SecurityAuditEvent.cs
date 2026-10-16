using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace Laveyana.Security.Diagnostics;

/// <summary>
/// Deliberately identity-free, non-durable audit notification. The trace ID is suitable for
/// correlation in an application-owned sink but is never emitted as a metric label.
/// </summary>
public sealed record SecurityAuditEvent(
    SecurityOperation Operation,
    SecurityOperationOutcome Outcome,
    DateTimeOffset TimestampUtc,
    string? TraceId);
