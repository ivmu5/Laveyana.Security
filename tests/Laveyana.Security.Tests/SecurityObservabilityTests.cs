using System.Diagnostics;
using System.Threading.Channels;
using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using System.Text;
using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Diagnostics;
using Laveyana.Security.Providers;
using Laveyana.Security.Software;
using Microsoft.Extensions.Logging;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>Phase 25 tracing, low-cardinality metrics, log and non-durable audit privacy gates.</summary>
[TestFixture]
internal sealed class SecurityObservabilityTests
{
    private const string Sentinel = "NEVER_LOG_SECRET_9C36D4";
    private static readonly ProviderId Provider = ProviderId.Parse("11111111-1111-4111-8111-111111111111");

    [Test]
    public async Task LoggerAndAuditNeverReceiveSecretOrExceptionText()
    {
        CaptureLogger logger = new();
        CaptureAudit audit = new();
        SecurityObservability telemetry = new(logger, audit);
        string actual = await telemetry.ObserveAsync(SecurityOperation.Encrypt, _ =>
            ValueTask.FromResult(Sentinel));
        Assert.That(actual, Is.EqualTo(Sentinel));
        Assert.That(logger.Messages, Has.Count.EqualTo(1));
        Assert.That(logger.Messages[0], Does.Not.Contain(Sentinel));
        Assert.That(logger.Messages[0], Does.Contain("Encrypt"));
        SecurityAuditEvent[] delivered = await audit.ReadAsync(1);
        Assert.That(delivered[0].Outcome, Is.EqualTo(SecurityOperationOutcome.Success));
        Assert.That(delivered[0].ToString(), Does.Not.Contain(Sentinel));

        Assert.ThrowsAsync<InvalidOperationException>(async () => await telemetry.ObserveAsync(
            SecurityOperation.Encrypt, _ => throw new InvalidOperationException(Sentinel)));
        Assert.That(logger.Messages[1], Does.Not.Contain(Sentinel));
        Assert.That((await audit.ReadAsync(1))[0].Outcome, Is.EqualTo(SecurityOperationOutcome.Error));
    }

    [Test]
    public async Task NegativeRejectedCanceledAndErrorHaveDistinctBoundedOutcomes()
    {
        CaptureAudit audit = new();
        SecurityObservability telemetry = new(auditSink: audit);
        Assert.That(await telemetry.ObserveAsync(SecurityOperation.VerifyMac, _ => ValueTask.FromResult(false)), Is.False);
        Assert.That(await telemetry.ObserveAsync<string?>(SecurityOperation.TryDecrypt,
            _ => ValueTask.FromResult<string?>(null)), Is.Null);
        Assert.ThrowsAsync<CryptographicException>(async () => await telemetry.ObserveAsync<int>(
            SecurityOperation.Decrypt, _ => throw new CryptographicException(Sentinel)));
        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();
        Assert.ThrowsAsync<OperationCanceledException>(async () => await telemetry.ObserveAsync<int>(
            SecurityOperation.ReadSecret, ct => throw new OperationCanceledException(ct), cancellation.Token));
        Assert.That((await audit.ReadAsync(4)).Select(item => item.Outcome), Is.EquivalentTo(new[]
        {
            SecurityOperationOutcome.Negative, SecurityOperationOutcome.Negative,
            SecurityOperationOutcome.Rejected, SecurityOperationOutcome.Canceled
        }));
    }

    [Test]
    public async Task BrokenDiagnosticsNeverRewriteOperationResults()
    {
        SecurityObservability telemetry = new(new ThrowingLogger(), new ThrowingAudit());
        Assert.That(await telemetry.ObserveAsync(SecurityOperation.CreateKey, _ => ValueTask.FromResult(42)),
            Is.EqualTo(42));
        Assert.ThrowsAsync<InvalidOperationException>(async () => await telemetry.ObserveAsync<int>(
            SecurityOperation.CreateKey, _ => throw new InvalidOperationException(Sentinel)));
    }

    [Test]
    public async Task ThrowingSamplerDoesNotPreventActionOrChangeItsException()
    {
        using Activity parent = new("test.parent");
        parent.Start();
        using ActivityListener listener = new()
        {
            ShouldListenTo = source => source.Name == SecurityObservability.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) =>
                throw new InvalidOperationException(Sentinel)
        };
        ActivitySource.AddActivityListener(listener);

        SecurityObservability telemetry = new();
        int executions = 0;
        int result = await telemetry.ObserveAsync(SecurityOperation.CreateKey, _ =>
        {
            executions++;
            Assert.That(Activity.Current, Is.SameAs(parent));
            return ValueTask.FromResult(17);
        });
        Assert.That(result, Is.EqualTo(17));
        Assert.That(executions, Is.EqualTo(1));
        Assert.That(Activity.Current, Is.SameAs(parent));

        InvalidOperationException original = new("action-failed");
        InvalidOperationException? actual = Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await telemetry.ObserveAsync<int>(SecurityOperation.RotateKey, _ =>
            {
                executions++;
                throw original;
            }));
        Assert.That(actual, Is.SameAs(original));
        Assert.That(executions, Is.EqualTo(2));
        Assert.That(Activity.Current, Is.SameAs(parent));
    }

    [Test]
    public async Task ThrowingActivityStartedDoesNotLeakAmbientTraceOrRerunAction()
    {
        using Activity parent = new("test.parent");
        parent.Start();
        using ActivityListener listener = new()
        {
            ShouldListenTo = source => source.Name == SecurityObservability.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            ActivityStarted = _ => throw new InvalidOperationException(Sentinel)
        };
        ActivitySource.AddActivityListener(listener);

        int executions = 0;
        SecurityObservability telemetry = new();
        int result = await telemetry.ObserveAsync(SecurityOperation.CreateKey, _ =>
        {
            executions++;
            Assert.That(Activity.Current, Is.SameAs(parent));
            return ValueTask.FromResult(27);
        });
        Assert.That(result, Is.EqualTo(27));
        Assert.That(executions, Is.EqualTo(1));
        Assert.That(Activity.Current, Is.SameAs(parent));
    }

    [Test]
    public async Task ThrowingActivityStoppedCannotReplaceCommittedResultOrOriginalFailure()
    {
        using Activity parent = new("test.parent");
        parent.Start();
        using ActivityListener listener = new()
        {
            ShouldListenTo = source => source.Name == SecurityObservability.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            ActivityStopped = _ => throw new InvalidOperationException(Sentinel)
        };
        ActivitySource.AddActivityListener(listener);

        SecurityObservability telemetry = new();
        int executions = 0;
        int result = await telemetry.ObserveAsync(SecurityOperation.CreateKey, _ =>
        {
            executions++;
            return ValueTask.FromResult(37);
        });
        Assert.That(result, Is.EqualTo(37));
        Assert.That(executions, Is.EqualTo(1));
        Assert.That(Activity.Current, Is.SameAs(parent));

        InvalidOperationException original = new("action-failed");
        InvalidOperationException? actual = Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await telemetry.ObserveAsync<int>(SecurityOperation.RotateKey, _ =>
            {
                executions++;
                throw original;
            }));
        Assert.That(actual, Is.SameAs(original));
        Assert.That(executions, Is.EqualTo(2));
        Assert.That(Activity.Current, Is.SameAs(parent));
    }

    [Test]
    public async Task ThrowingStopListenerCannotChangeRealCommittedKeyCreation()
    {
        using ActivityListener listener = new()
        {
            ShouldListenTo = source => source.Name == SecurityObservability.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            ActivityStopped = _ => throw new InvalidOperationException(Sentinel)
        };
        ActivitySource.AddActivityListener(listener);

        Activity? previousActivity = Activity.Current;
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        SoftwareKeyProviderBackend backend = new(Provider, store, protector, observability: new SecurityObservability());
        KeyName name = new("TracingStopCannotInvalidateCommit");
        KeyDescriptor created = await backend.CreateAsync(name, WellKnownAlgorithms.HmacSha256,
            [WellKnownCapabilities.Mac, WellKnownCapabilities.VerifyMac]);

        Assert.That(created.Name, Is.EqualTo(name));
        Assert.That(await backend.FindByNameAsync(name), Is.Not.Null);
        Assert.That(Activity.Current, Is.SameAs(previousActivity));
    }

    [Test]
    public async Task TracesAndMetricLabelsAreBoundedAndContainNoIdentity()
    {
        List<Activity> stopped = [];
        using ActivityListener listener = new();
        listener.ShouldListenTo = source => source.Name == SecurityObservability.ActivitySourceName;
        listener.Sample = (ref ActivityCreationOptions<ActivityContext> options) => ActivitySamplingResult.AllData;
        listener.ActivityStopped = stopped.Add;
        ActivitySource.AddActivityListener(listener);

        List<(string Name, List<KeyValuePair<string, object?>> Tags)> measurements = [];
        using MeterListener meter = new();
        meter.InstrumentPublished = (instrument, active) =>
        {
            if (instrument.Meter.Name == SecurityObservability.MeterName)
            {
                active.EnableMeasurementEvents(instrument);
            }
        };
        meter.SetMeasurementEventCallback<long>((instrument, _, tags, _) =>
            measurements.Add((instrument.Name, tags.ToArray().ToList())));
        meter.SetMeasurementEventCallback<double>((instrument, _, tags, _) =>
            measurements.Add((instrument.Name, tags.ToArray().ToList())));
        meter.Start();

        SecurityObservability telemetry = new();
        await telemetry.ObserveAsync(SecurityOperation.RotateKey, _ => ValueTask.FromResult(Sentinel));
        Assert.That(stopped, Has.Count.EqualTo(1));
        Assert.That(stopped[0].TagObjects.Select(tag => tag.Key),
            Is.EquivalentTo(new[] { "security.operation", "security.outcome" }));
        Assert.That(measurements.Any(item => item.Name == "laveyana.security.operations"), Is.True);
        Assert.That(measurements.Any(item => item.Name == "laveyana.security.operation.duration"), Is.True);
        foreach (var measurement in measurements)
        {
            Assert.That(measurement.Tags.Select(tag => tag.Key),
                Is.EquivalentTo(new[] { "security.operation", "security.outcome" }));
            Assert.That(string.Join("|", measurement.Tags.Select(tag => tag.Value)), Does.Not.Contain(Sentinel));
        }
        Assert.That(stopped[0].Tags.Select(tag => tag.Value), Does.Not.Contain(Sentinel));
    }

    [Test]
    public async Task RealEncryptionEmitsOnlySafeOperationAndOutcome()
    {
        if (!AesGcm.IsSupported)
        {
            Assert.Ignore("AES-GCM is unavailable on this host.");
        }
        CaptureLogger logger = new();
        CaptureAudit audit = new();
        SecurityObservability telemetry = new(logger, audit);
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        SoftwareKeyProviderBackend backend = new(Provider, store, protector, observability: telemetry);
        KeyDescriptor descriptor = await backend.CreateAsync(new KeyName("PrivateIdentity"),
            WellKnownAlgorithms.Aes256Gcm, [WellKnownCapabilities.Encrypt, WellKnownCapabilities.Decrypt]);
        LogicalKeyHandle handle = new(descriptor.ProviderId, descriptor.KeyId);
        ProviderRegistry registry = new([new ProviderRegistration(backend)], telemetry);
        Assert.That(await registry.FindLogicalAsync(handle), Is.Not.Null);
        byte[] plaintext = Encoding.UTF8.GetBytes(Sentinel);
        var payload = await backend.EncryptAsync(handle, plaintext, plaintext);
        Assert.That(await backend.DecryptAsync(payload, plaintext), Is.EqualTo(plaintext));
        Assert.That(await backend.TryDecryptAsync(payload, "bad-aad"u8.ToArray()), Is.Null);
        Assert.That(logger.Messages, Has.Count.EqualTo(5));
        string entireLog = string.Join("|", logger.Messages);
        Assert.That(entireLog, Does.Not.Contain(Sentinel));
        Assert.That(entireLog, Does.Not.Contain("PrivateIdentity"));
        Assert.That(entireLog, Does.Not.Contain(descriptor.KeyId.ToString()));
        SecurityAuditEvent[] delivered = await audit.ReadAsync(5);
        Assert.That(delivered.Single(item => item.Operation == SecurityOperation.TryDecrypt).Outcome,
            Is.EqualTo(SecurityOperationOutcome.Negative));
        Assert.That(delivered.Select(item => item.Operation), Is.EquivalentTo(new[]
        {
            SecurityOperation.CreateKey, SecurityOperation.ReadKey,
            SecurityOperation.Encrypt, SecurityOperation.Decrypt, SecurityOperation.TryDecrypt
        }));
    }

    [Test]
    public async Task NeverCompletingAuditDoesNotDelaySuccessOrReplaceOriginalError()
    {
        StalledAsyncAudit audit = new();
        SecurityObservability telemetry = new(auditSink: audit);
        int executed = 0;
        try
        {
            int result = await telemetry.ObserveAsync(SecurityOperation.CreateKey, _ =>
            {
                executed++;
                return ValueTask.FromResult(91);
            }).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
            Assert.That(result, Is.EqualTo(91));
            await audit.ReadStartedAsync();

            InvalidOperationException expected = new("original-action-error");
            InvalidOperationException? actual = Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await telemetry.ObserveAsync<int>(SecurityOperation.RotateKey, _ =>
                {
                    executed++;
                    throw expected;
                }).AsTask().WaitAsync(TimeSpan.FromSeconds(5)));
            Assert.That(actual, Is.SameAs(expected));
            await audit.ReadStartedAsync();
            Assert.That(executed, Is.EqualTo(2));
        }
        finally
        {
            audit.Release();
        }
    }

    [Test]
    public async Task SynchronouslyBlockingAuditDoesNotBlockCaller()
    {
        using BlockingSynchronousAudit audit = new();
        SecurityObservability telemetry = new(auditSink: audit);
        try
        {
            // Start on a separate thread so a regression to inline dispatch cannot hang NUnit.
            Task<int> operation = Task.Run(async () => await telemetry.ObserveAsync(
                SecurityOperation.CreateKey, _ => ValueTask.FromResult(43)));
            Assert.That(await operation.WaitAsync(TimeSpan.FromSeconds(5)), Is.EqualTo(43));
            Assert.That(audit.Entered.Wait(TimeSpan.FromSeconds(5)), Is.True);
        }
        finally
        {
            audit.Release.Set();
        }
    }

    [Test]
    public async Task StalledAuditConsumesFixedBudgetAndExcessEventsAreDropped()
    {
        StalledAsyncAudit audit = new();
        SecurityObservability telemetry = new(auditSink: audit);
        long failures = 0;
        using MeterListener meter = new();
        meter.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == SecurityObservability.MeterName &&
                instrument.Name == "laveyana.security.audit.delivery_failures")
            {
                listener.EnableMeasurementEvents(instrument);
            }
        };
        meter.SetMeasurementEventCallback<long>((_, value, _, _) => Interlocked.Add(ref failures, value));
        meter.Start();
        try
        {
            for (int i = 0; i < 8; i++)
            {
                Assert.That(await telemetry.ObserveAsync(SecurityOperation.CreateKey,
                    _ => ValueTask.FromResult(i)), Is.EqualTo(i));
            }

            for (int i = 0; i < 8; i++)
            {
                await audit.ReadStartedAsync();
            }

            Assert.That(await telemetry.ObserveAsync(SecurityOperation.CreateKey,
                _ => ValueTask.FromResult(99)), Is.EqualTo(99));
            Assert.That(audit.StartedCount, Is.EqualTo(8));
            Assert.That(Volatile.Read(ref failures), Is.GreaterThanOrEqualTo(1));
        }
        finally
        {
            audit.Release();
            // Let the already-scheduled audit callbacks leave the global budget.
            await Task.Delay(100);
        }
    }

    [Test]
    public async Task AuditWorkerDoesNotInheritCallerAmbientContext()
    {
        AsyncLocal<string?> ambient = new();
        ambient.Value = Sentinel;
        AmbientAudit audit = new(ambient);
        try
        {
            SecurityObservability telemetry = new(auditSink: audit);
            Assert.That(await telemetry.ObserveAsync(SecurityOperation.CreateKey,
                _ => ValueTask.FromResult(63)), Is.EqualTo(63));
            Assert.That(await audit.ReadObservedAsync(), Is.Null);
        }
        finally
        {
            ambient.Value = null;
        }
    }

    [Test]
    public void UndefinedOperationFailsBeforeExecutingCallback()
    {
        bool invoked = false;
        SecurityObservability telemetry = new();
        Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await telemetry.ObserveAsync(
            (SecurityOperation)999, _ =>
            {
                invoked = true;
                return ValueTask.FromResult(0);
            }));
        Assert.That(invoked, Is.False);
    }

    private sealed class CaptureAudit : ISecurityAuditSink
    {
        private readonly Channel<SecurityAuditEvent> _events = Channel.CreateUnbounded<SecurityAuditEvent>();

        internal async Task<SecurityAuditEvent[]> ReadAsync(int count)
        {
            using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
            SecurityAuditEvent[] result = new SecurityAuditEvent[count];
            for (int i = 0; i < count; i++)
            {
                result[i] = await _events.Reader.ReadAsync(timeout.Token);
            }

            return result;
        }

        public ValueTask WriteAsync(SecurityAuditEvent auditEvent, CancellationToken cancellationToken = default)
        {
            _events.Writer.TryWrite(auditEvent);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class StalledAsyncAudit : ISecurityAuditSink
    {
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly Channel<bool> _started = Channel.CreateUnbounded<bool>();
        private int _startedCount;

        internal int StartedCount => Volatile.Read(ref _startedCount);

        internal async Task ReadStartedAsync()
        {
            using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
            await _started.Reader.ReadAsync(timeout.Token);
        }

        internal void Release() => _release.TrySetResult();

        public ValueTask WriteAsync(SecurityAuditEvent auditEvent, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _startedCount);
            _started.Writer.TryWrite(true);
            return new ValueTask(_release.Task);
        }
    }

    private sealed class BlockingSynchronousAudit : ISecurityAuditSink, IDisposable
    {
        internal ManualResetEventSlim Entered { get; } = new(false);
        internal ManualResetEventSlim Release { get; } = new(false);

        public ValueTask WriteAsync(SecurityAuditEvent auditEvent, CancellationToken cancellationToken = default)
        {
            Entered.Set();
            Release.Wait();
            return ValueTask.CompletedTask;
        }

        public void Dispose()
        {
            Release.Set();
            Entered.Dispose();
            Release.Dispose();
        }
    }

    private sealed class AmbientAudit(AsyncLocal<string?> ambient) : ISecurityAuditSink
    {
        private readonly Channel<string?> _observed = Channel.CreateUnbounded<string?>();

        internal async Task<string?> ReadObservedAsync()
        {
            using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
            return await _observed.Reader.ReadAsync(timeout.Token);
        }

        public ValueTask WriteAsync(SecurityAuditEvent auditEvent, CancellationToken cancellationToken = default)
        {
            _observed.Writer.TryWrite(ambient.Value);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class ThrowingAudit : ISecurityAuditSink
    {
        public ValueTask WriteAsync(SecurityAuditEvent auditEvent, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException(Sentinel);
    }

    private sealed class CaptureLogger : ILogger<SecurityObservability>
    {
        internal List<string> Messages { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => Messages.Add(formatter(state, exception));
    }

    private sealed class ThrowingLogger : ILogger<SecurityObservability>
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => throw new InvalidOperationException(Sentinel);
    }
}
