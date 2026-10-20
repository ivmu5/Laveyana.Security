using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace Laveyana.Security.Diagnostics;

/// <summary>
/// Optional application-owned best-effort sink. Events are dispatched asynchronously on a bounded
/// process-wide budget and can be dropped. No ordering, delivery, shutdown drain or persistence
/// guarantees are provided. This must not be used as a mandatory compliance audit trail.
/// </summary>
public interface ISecurityAuditSink
{
    /// <summary>
    /// Receives one identity-free event; must not enrich it with plaintext or key material.
    /// Callbacks may overlap. A blocked callback cannot hold the cryptographic operation open.
    /// </summary>
    ValueTask WriteAsync(SecurityAuditEvent auditEvent, CancellationToken cancellationToken = default);
}
