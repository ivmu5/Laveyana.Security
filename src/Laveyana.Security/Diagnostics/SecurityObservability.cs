using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace Laveyana.Security.Diagnostics;

/// <summary>
/// Opt-in observability boundary for managed operations. It never receives secret bytes, names,
/// provider/key/secret IDs, AAD, or exceptions as diagnostics. Applications own exporters and sinks.
/// </summary>
public sealed class SecurityObservability
{
    /// <summary>ActivitySource name for application-selected trace listeners.</summary>
    public const string ActivitySourceName = "Laveyana.Security";

    /// <summary>Meter name for application-selected metric listeners.</summary>
    public const string MeterName = "Laveyana.Security";

    private static readonly ActivitySource Activities = new(ActivitySourceName);
    private static readonly Meter Metrics = new(MeterName);
    private static readonly Counter<long> Operations = Metrics.CreateCounter<long>(
        "laveyana.security.operations", description: "Completed managed security operations.");
    private static readonly Histogram<double> Duration = Metrics.CreateHistogram<double>(
        "laveyana.security.operation.duration", unit: "ms", description: "Managed operation duration.");
    private static readonly Counter<long> AuditDeliveryFailures = Metrics.CreateCounter<long>(
        "laveyana.security.audit.delivery_failures", description: "Best-effort audit delivery failures.");

    private readonly ILogger<SecurityObservability>? _logger;
    private readonly ISecurityAuditSink? _auditSink;
    private readonly TimeProvider _timeProvider;

    /// <summary>Creates an opt-in telemetry boundary without configuring any exporters or durable audit storage.</summary>
    public SecurityObservability(ILogger<SecurityObservability>? logger = null,
        ISecurityAuditSink? auditSink = null, TimeProvider? timeProvider = null)
    {
        _logger = logger;
        _auditSink = auditSink;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>Observes a non-value operation without manufacturing a public success payload.</summary>
    public async ValueTask ObserveAsync(SecurityOperation operation,
        Func<CancellationToken, ValueTask> action, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(action);
        await ObserveAsync(operation, async ct =>
        {
            await action(ct).ConfigureAwait(false);
            return true;
        }, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Observes one operation. Only the fixed operation and outcome are recorded; payload and exceptions
    /// are never passed to listeners. Audit delivery failure cannot change a committed operation outcome.
    /// </summary>
    public async ValueTask<T> ObserveAsync<T>(SecurityOperation operation,
        Func<CancellationToken, ValueTask<T>> action, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(action);
        if (!Enum.IsDefined(operation))
        {
            throw new ArgumentOutOfRangeException(nameof(operation));
        }

        long start = Stopwatch.GetTimestamp();
        string operationName = operation.ToString();
        Activity? previousActivity = Activity.Current;
        Activity? activity = null;
        try
        {
            // Create first so a throwing ActivityStarted callback cannot hide a started Activity.
            // Sampling, start and tags are all optional, untrusted diagnostic operations.
            activity = Activities.CreateActivity("security.operation", ActivityKind.Internal);
            activity?.Start();
            activity?.SetTag("security.operation", operationName);
        }
        catch (Exception)
        {
            EndActivityBestEffort(activity, previousActivity);
            activity = null;
        }

        SecurityOperationOutcome outcome = SecurityOperationOutcome.Error;
        try
        {
            T value = await action(cancellationToken).ConfigureAwait(false);
            outcome = value is null || (value is bool boolean && !boolean)
                ? SecurityOperationOutcome.Negative
                : SecurityOperationOutcome.Success;
            return value;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            outcome = SecurityOperationOutcome.Canceled;
            throw;
        }
        catch (Exception exception)
        {
            outcome = exception is CryptographicException or UnauthorizedAccessException or
                ArgumentException or NotSupportedException
                ? SecurityOperationOutcome.Rejected : SecurityOperationOutcome.Error;
            throw;
        }
        finally
        {
            try
            {
                string outcomeName = outcome.ToString();
                // Activity tags and the ActivityStopped callback can invoke external instrumentation.
                try { activity?.SetTag("security.outcome", outcomeName); } catch (Exception) { }
                TagList tags = new()
                {
                    { "security.operation", operationName },
                    { "security.outcome", outcomeName }
                };
                // Telemetry sinks are untrusted extensions; neither success nor failures may be rewritten by them.
                try
                {
                    Operations.Add(1, tags);
                    Duration.Record(Stopwatch.GetElapsedTime(start).TotalMilliseconds, tags);
                    _logger?.LogInformation("Security operation {Operation} finished with {Outcome}",
                        operationName, outcomeName);
                }
                catch (Exception)
                {
                    // Optional diagnostics must never change a security operation result.
                }

                if (_auditSink is not null)
                {
                    try
                    {
                        SecurityAuditEvent audit = new(operation, outcome, _timeProvider.GetUtcNow(),
                            activity?.TraceId.ToString());
                        await _auditSink.WriteAsync(audit, CancellationToken.None).ConfigureAwait(false);
                    }
                    catch (Exception)
                    {
                        // Best-effort notification only: do not imply durable auditing or successful delivery.
                        try { AuditDeliveryFailures.Add(1); } catch (Exception) { }
                    }
                }
            }
            finally
            {
                // Dispose invokes ActivityStopped, which may throw before resetting Activity.Current.
                // Never let a tracing listener replace the original action result or exception.
                if (activity is not null)
                {
                    EndActivityBestEffort(activity, previousActivity);
                }
            }
        }
    }

    private static void EndActivityBestEffort(Activity? activity, Activity? previousActivity)
    {
        try
        {
            activity?.Dispose();
        }
        catch (Exception)
        {
            // A listener must not affect the security operation.
        }
        finally
        {
            try
            {
                // Activity.Stop may exit through a listener before restoring the AsyncLocal parent.
                // Restoring Activity.Current may invoke application callbacks, so it is guarded too.
                if (!ReferenceEquals(Activity.Current, previousActivity))
                {
                    Activity.Current = previousActivity;
                }
            }
            catch (Exception)
            {
                // No diagnostic callback may replace an operation result.
            }
        }
    }
}
