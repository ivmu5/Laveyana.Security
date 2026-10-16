using Laveyana.Security.DependencyInjection.Composition;
using Laveyana.Security.Rotation;
using Microsoft.Extensions.Hosting;

namespace Laveyana.Security.DependencyInjection.Rotation;

/// <summary>
/// Explicit opt-in, single-consumer hosted rotation worker. Never retries an uncertain
/// commit or re-delivers a claimed instruction; an exception faults the hosted worker.
/// </summary>
public sealed class RotationWorker : BackgroundService
{
    private readonly IRotationWorkSource _source;
    private readonly RotationEngine _engine;
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _pollInterval;

    /// <summary>Creates a worker using the same validated clock as manual rotation.</summary>
    public RotationWorker(IRotationWorkSource source, RotationEngine engine,
        SecurityCompositionSnapshot composition, TimeSpan pollInterval)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        _timeProvider = (composition ?? throw new ArgumentNullException(nameof(composition))).TimeProvider;
        if (pollInterval < TimeSpan.FromMilliseconds(100) || pollInterval > TimeSpan.FromDays(1))
        {
            throw new ArgumentOutOfRangeException(nameof(pollInterval));
        }

        _pollInterval = pollInterval;
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            RotationAssignment? claimed = await _source.ClaimNextAsync(stoppingToken).ConfigureAwait(false);
            if (claimed is RotationAssignment assignment)
            {
                // If rotation throws (including cancellation or uncertain commit), the durable
                // claim stays blocked and is NEVER blindly retried by this worker.
                RotationAttemptResult result = await _engine.RotateIfDueAsync(assignment, stoppingToken)
                    .ConfigureAwait(false);
                if (result.Status == RotationAttemptStatus.NotDue)
                {
                    throw new InvalidOperationException(
                        "Rotation work was claimed before it was due; reconcile the blocked claim.");
                }

                await _source.RecordResultAsync(assignment, result, stoppingToken).ConfigureAwait(false);
            }

            await Task.Delay(_pollInterval, _timeProvider, stoppingToken).ConfigureAwait(false);
        }
    }
}
