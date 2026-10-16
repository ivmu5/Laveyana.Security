using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace Laveyana.Security.Diagnostics;

/// <summary>Optional application-owned sink; core does not provide audit persistence or delivery guarantees.</summary>
public interface ISecurityAuditSink
{
    /// <summary>Receives one bounded audit event; it must not enrich events with plaintext or key material.</summary>
    ValueTask WriteAsync(SecurityAuditEvent auditEvent, CancellationToken cancellationToken = default);
}
