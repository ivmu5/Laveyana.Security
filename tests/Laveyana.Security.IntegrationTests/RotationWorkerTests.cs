using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Providers;
using Laveyana.Security.DependencyInjection.Composition;
using Laveyana.Security.DependencyInjection.Rotation;
using Laveyana.Security.Rotation;
using Laveyana.Security.Software;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NUnit.Framework;

namespace Laveyana.Security.IntegrationTests;

/// <summary>Hosted opt-in, one-time claims and cooperative shutdown tests.</summary>
[TestFixture]
internal sealed class RotationWorkerTests
{
    [Test]
    public void AddSecurityDoesNotStartOrRegisterAnyRotationWorker()
    {
        ServiceCollection services = [];
        services.AddSecurity(_ => { });
        using ServiceProvider provider = services.BuildServiceProvider();
        Assert.That(provider.GetService<RotationWorker>(), Is.Null);
        Assert.That(provider.GetServices<IHostedService>().OfType<RotationWorker>(), Is.Empty);
    }

    [Test]
    public void WorkerOptInRequiresCompositionAndRejectsDuplicates()
    {
        ServiceCollection services = [];
        ClaimedSource source = new();
        Assert.Throws<InvalidOperationException>(() =>
            services.AddSecurityRotationWorker(source, TimeSpan.FromSeconds(1)));
        services.AddSecurity(_ => { });
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            services.AddSecurityRotationWorker(source, TimeSpan.Zero));
        services.AddSecurityRotationWorker(source, TimeSpan.FromSeconds(1));
        Assert.Throws<InvalidOperationException>(() =>
            services.AddSecurityRotationWorker(source, TimeSpan.FromSeconds(1)));
        using ServiceProvider provider = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = true,
            ValidateOnBuild = true
        });
        Assert.That(provider.GetServices<IHostedService>().OfType<RotationWorker>().Count(), Is.EqualTo(1));
    }

    [Test]
    public async Task WorkerRecordsOnlyDefiniteResultAndStopsWithHostCancellation()
    {
        ProviderId id = ProviderId.New();
        LogicalKeyHandle handle = new(id, KeyId.New());
        RotationAssignment assignment = new(handle, new KeyVersion(1),
            new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new RotationPolicy(TimeSpan.FromDays(1)));
        ClaimedSource source = new() { Assignment = assignment };
        StaticBackend backend = new(id, handle.KeyId);
        ServiceCollection services = [];
        services.AddSecurity(builder => builder.UseKeyProvider(backend));
        services.AddSecurityRotationWorker(source, TimeSpan.FromSeconds(1));
        using ServiceProvider provider = services.BuildServiceProvider();
        RotationWorker worker = provider.GetRequiredService<RotationWorker>();
        await worker.StartAsync(CancellationToken.None);
        RotationAttemptResult result = await source.Completed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.That(result.Status, Is.EqualTo(RotationAttemptStatus.Rotated));
        Assert.That(backend.Commits, Is.EqualTo(1));
        await worker.StopAsync(CancellationToken.None);
        Assert.That(source.Claims, Is.EqualTo(1));
    }

    [Test]
    public async Task WorkerStopsWithoutClaimWhenCancelled()
    {
        ServiceCollection services = [];
        ClaimedSource source = new();
        services.AddSecurity(_ => { });
        services.AddSecurityRotationWorker(source, TimeSpan.FromMinutes(1));
        using ServiceProvider provider = services.BuildServiceProvider();
        RotationWorker worker = provider.GetRequiredService<RotationWorker>();
        await worker.StartAsync(CancellationToken.None);
        await worker.StopAsync(CancellationToken.None);
        Assert.That(source.Claims, Is.Zero);
    }

    [Test]
    public async Task WorkerDoesNotRetryAfterUncertainCommit()
    {
        ProviderId id = ProviderId.New();
        LogicalKeyHandle handle = new(id, KeyId.New());
        RotationAssignment assignment = new(handle, new KeyVersion(1),
            new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new RotationPolicy(TimeSpan.FromDays(1)));
        ClaimedSource source = new() { Assignment = assignment };
        StaticBackend backend = new(id, handle.KeyId) { FailAfterCommit = true };
        ServiceCollection services = [];
        services.AddSecurity(builder => builder.UseKeyProvider(backend));
        services.AddSecurityRotationWorker(source, TimeSpan.FromSeconds(1));
        using ServiceProvider provider = services.BuildServiceProvider();
        RotationWorker worker = provider.GetRequiredService<RotationWorker>();
        await worker.StartAsync(CancellationToken.None);
        Assert.That(worker.ExecuteTask, Is.Not.Null);
        try
        {
            await worker.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Fail("The worker must fault after an uncertain commit.");
        }
        catch (SoftwareKeyCommitUncertainException)
        {
            Assert.That(backend.Commits, Is.EqualTo(1));
            Assert.That(source.Claims, Is.EqualTo(1));
            Assert.That(source.Completed.Task.IsCompleted, Is.False);
        }
    }

    [Test]
    public async Task ShutdownCancelsAnInFlightClaimWithoutCompletingIt()
    {
        BlockingSource source = new();
        ServiceCollection services = [];
        services.AddSecurity(_ => { });
        services.AddSecurityRotationWorker(source, TimeSpan.FromMinutes(1));
        using ServiceProvider provider = services.BuildServiceProvider();
        RotationWorker worker = provider.GetRequiredService<RotationWorker>();
        await worker.StartAsync(CancellationToken.None);
        await source.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await worker.StopAsync(CancellationToken.None);
        Assert.That(source.Cancelled, Is.True);
        Assert.That(source.ClaimAttempts, Is.EqualTo(1));
    }

    private sealed class BlockingSource : IRotationWorkSource
    {
        public TaskCompletionSource<bool> Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool Cancelled { get; private set; }
        public int ClaimAttempts { get; private set; }

        public async ValueTask<RotationAssignment?> ClaimNextAsync(CancellationToken cancellationToken = default)
        {
            ClaimAttempts++;
            Started.TrySetResult(true);
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                Cancelled = true;
                throw;
            }

            return null;
        }

        public ValueTask RecordResultAsync(RotationAssignment assignment, RotationAttemptResult result,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("No assignment should be claimed.");
    }

    private sealed class ClaimedSource : IRotationWorkSource
    {
        private int _claims;
        public RotationAssignment? Assignment { get; set; }
        public int Claims => Volatile.Read(ref _claims);
        public TaskCompletionSource<RotationAttemptResult> Completed { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async ValueTask<RotationAssignment?> ClaimNextAsync(CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            cancellationToken.ThrowIfCancellationRequested();
            RotationAssignment? next = Assignment;
            Assignment = null;
            if (next.HasValue)
            {
                Interlocked.Increment(ref _claims);
            }

            return next;
        }

        public ValueTask RecordResultAsync(RotationAssignment assignment, RotationAttemptResult result,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Completed.TrySetResult(result);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class StaticBackend(ProviderId providerId, KeyId keyId) : IConditionalKeyRotationBackend
    {
        private long _activeVersion = 1;
        private int _commits;
        public bool FailAfterCommit { get; set; }
        public ProviderId ProviderId { get; } = providerId;
        public int Commits => Volatile.Read(ref _commits);
        public ValueTask<ProviderCapabilitySnapshot> GetCapabilitiesAsync(CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(new ProviderCapabilitySnapshot(ProviderId, []));
        public ValueTask<KeyDescriptor?> FindLogicalAsync(LogicalKeyHandle handle,
            CancellationToken cancellationToken = default) => ValueTask.FromResult<KeyDescriptor?>(
                new KeyDescriptor(ProviderId, keyId, null, KeyKind.Symmetric,
                    LogicalKeyState.Active, new KeyVersion(Interlocked.Read(ref _activeVersion))));
        public ValueTask<KeyVersionDescriptor?> FindExactAsync(ExactKeyHandle handle,
            CancellationToken cancellationToken = default) => ValueTask.FromResult<KeyVersionDescriptor?>(null);
        public ValueTask<KeyDescriptor> RotateIfCurrentAsync(LogicalKeyHandle handle,
            KeyVersion expectedActiveVersion, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            long next = Interlocked.CompareExchange(ref _activeVersion,
                expectedActiveVersion.Value + 1, expectedActiveVersion.Value);
            if (next != expectedActiveVersion.Value)
            {
                throw new InvalidOperationException("Unexpected concurrent mutation.");
            }

            Interlocked.Increment(ref _commits);
            if (FailAfterCommit)
            {
                throw new SoftwareKeyCommitUncertainException(new IOException("Post-commit failure"));
            }

            return ValueTask.FromResult(new KeyDescriptor(ProviderId, keyId, null,
                KeyKind.Symmetric, LogicalKeyState.Active, new KeyVersion(next + 1)));
        }
    }
}
