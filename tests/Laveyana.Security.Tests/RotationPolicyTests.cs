using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Providers;
using Laveyana.Security.Rotation;
using Laveyana.Security.Software;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>Clock, version-fence, CAS and manual/automatic consistency tests.</summary>
[TestFixture]
internal sealed class RotationPolicyTests
{
    private static readonly ProviderId Provider = ProviderId.Parse("11111111-1111-4111-8111-111111111111");
    private static readonly DateTimeOffset Activated = new(2026, 10, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly CapabilityId[] Capabilities =
        [WellKnownCapabilities.Mac, WellKnownCapabilities.VerifyMac];

    [Test]
    public void StrictPolicyRejectsMissingOrUntrustedTime()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new RotationPolicy(TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => new RotationPolicy(TimeSpan.FromDays(3651)));
        RotationPolicy policy = new(TimeSpan.FromDays(30));
        Assert.Throws<ArgumentException>(() => policy.DueAtUtc(default));
        Assert.Throws<ArgumentException>(() => policy.DueAtUtc(Activated.ToOffset(TimeSpan.FromHours(1))));
        Assert.Throws<ArgumentException>(() => new RotationAssignment(default, new KeyVersion(1), Activated, policy));
        Assert.That(policy.DueAtUtc(Activated), Is.EqualTo(Activated.AddDays(30)));
    }

    [Test]
    public async Task DueOverdueAndManualUseOneVersionFencedEngine()
    {
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        SoftwareKeyProviderBackend backend = new(Provider, store, protector);
        KeyDescriptor created = await backend.CreateAsync(new KeyName("rotation"),
            WellKnownAlgorithms.HmacSha256, Capabilities);
        LogicalKeyHandle handle = new(created.ProviderId, created.KeyId);
        MutableClock clock = new(Activated.AddDays(10));
        RotationEngine engine = new(new ProviderRegistry([new ProviderRegistration(backend)]), clock);
        RotationAssignment assignment = new(handle, new KeyVersion(1), Activated,
            new RotationPolicy(TimeSpan.FromDays(30)));

        Assert.That(engine.IsDue(assignment), Is.False);
        Assert.That((await engine.RotateIfDueAsync(assignment)).Status, Is.EqualTo(RotationAttemptStatus.NotDue));
        clock.UtcNow = Activated.AddDays(30);
        Assert.That(engine.IsDue(assignment), Is.True);
        RotationAttemptResult changed = await engine.RotateIfDueAsync(assignment);
        Assert.That(changed.Status, Is.EqualTo(RotationAttemptStatus.Rotated));
        Assert.That(changed.Descriptor!.ActiveVersion, Is.EqualTo(new KeyVersion(2)));
        clock.UtcNow = Activated.AddDays(999);
        Assert.That((await engine.RotateIfDueAsync(assignment)).Status,
            Is.EqualTo(RotationAttemptStatus.VersionChanged));
        Assert.That((await backend.FindLogicalAsync(handle))!.ActiveVersion, Is.EqualTo(new KeyVersion(2)));

        RotationAssignment next = new(handle, new KeyVersion(2), Activated.AddDays(30),
            new RotationPolicy(TimeSpan.FromDays(30)));
        Assert.That((await engine.RotateNowAsync(next)).Descriptor!.ActiveVersion, Is.EqualTo(new KeyVersion(3)));
    }

    [Test]
    public async Task TwoIndependentEnginesCannotDoubleRotateExpectedVersion()
    {
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        SoftwareKeyProviderBackend first = new(Provider, store, protector);
        SoftwareKeyProviderBackend second = new(Provider, store, protector);
        KeyDescriptor created = await first.CreateAsync(new KeyName("shared"),
            WellKnownAlgorithms.HmacSha256, Capabilities);
        RotationAssignment assignment = new(new LogicalKeyHandle(Provider, created.KeyId),
            new KeyVersion(1), Activated, new RotationPolicy(TimeSpan.FromDays(1)));
        MutableClock clock = new(Activated.AddDays(3));
        RotationEngine[] engines =
        [
            new(new ProviderRegistry([new ProviderRegistration(first)]), clock),
            new(new ProviderRegistry([new ProviderRegistration(second)]), clock)
        ];

        RotationAttemptResult[] results = await Task.WhenAll(engines.Select(engine => Task.Run(async () =>
            await engine.RotateIfDueAsync(assignment))));
        Assert.That(results.Count(x => x.Status == RotationAttemptStatus.Rotated), Is.EqualTo(1));
        Assert.That(results.All(x => x.Status is RotationAttemptStatus.Rotated or
            RotationAttemptStatus.VersionChanged or RotationAttemptStatus.Conflict), Is.True);
        Assert.That((await first.FindLogicalAsync(assignment.Handle))!.ActiveVersion,
            Is.EqualTo(new KeyVersion(2)));
    }

    [Test]
    public async Task AmbiguousPostCommitResultIsNeverClassifiedAsDefiniteConflict()
    {
        StorageContractsTests.MemoryStore memory = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        SoftwareKeyProviderTests.BarrierStore store = new(memory);
        SoftwareKeyProviderBackend backend = new(Provider, store, protector);
        KeyDescriptor created = await backend.CreateAsync(new KeyName("uncertain"),
            WellKnownAlgorithms.HmacSha256, Capabilities);
        RotationAssignment assignment = new(new LogicalKeyHandle(Provider, created.KeyId),
            new KeyVersion(1), Activated, new RotationPolicy(TimeSpan.FromDays(1)));
        RotationEngine engine = new(new ProviderRegistry([new ProviderRegistration(backend)]),
            new MutableClock(Activated.AddDays(3)));
        store.ThrowAfterNextReplace = true;
        Assert.ThrowsAsync<SoftwareKeyCommitUncertainException>(async () =>
            await engine.RotateIfDueAsync(assignment));
        Assert.That((await backend.FindLogicalAsync(assignment.Handle))!.ActiveVersion,
            Is.EqualTo(new KeyVersion(2)));
        Assert.That((await engine.RotateIfDueAsync(assignment)).Status,
            Is.EqualTo(RotationAttemptStatus.VersionChanged));
        Assert.That((await backend.FindLogicalAsync(assignment.Handle))!.ActiveVersion,
            Is.EqualTo(new KeyVersion(2)));
    }

    [Test]
    public async Task CancelledAttemptNeverCreatesAnotherVersion()
    {
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        SoftwareKeyProviderBackend backend = new(Provider, store, protector);
        KeyDescriptor created = await backend.CreateAsync(new KeyName("cancel"),
            WellKnownAlgorithms.HmacSha256, Capabilities);
        RotationEngine engine = new(new ProviderRegistry([new ProviderRegistration(backend)]),
            new MutableClock(Activated.AddDays(3)));
        RotationAssignment assignment = new(new LogicalKeyHandle(Provider, created.KeyId),
            new KeyVersion(1), Activated, new RotationPolicy(TimeSpan.FromDays(1)));
        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();
        Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await engine.RotateIfDueAsync(assignment, cancellation.Token));
        Assert.That((await backend.FindLogicalAsync(assignment.Handle))!.ActiveVersion,
            Is.EqualTo(new KeyVersion(1)));
    }

    private sealed class MutableClock(DateTimeOffset initial) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = initial;
        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
}
