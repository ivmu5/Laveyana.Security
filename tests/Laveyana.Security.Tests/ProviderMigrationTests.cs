using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Migration;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Migration;
using Laveyana.Security.Providers;
using Laveyana.Security.Software;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>Provider migration exact-identity, coexistence, guard and recovery tests.</summary>
[TestFixture]
internal sealed class ProviderMigrationTests
{
    private static readonly ProviderId First = ProviderId.Parse("11111111-1111-4111-8111-111111111111");
    private static readonly ProviderId Second = ProviderId.Parse("22222222-2222-4222-8222-222222222222");
    private static readonly CapabilityId[] Abilities =
        [WellKnownCapabilities.Mac, WellKnownCapabilities.VerifyMac];

    [Test]
    public void MigrationRequestRejectsIdentityAndCapabilityErrors()
    {
        KeyReference source = new(First, KeyId.New(), new KeyVersion(1));
        Assert.Throws<ArgumentException>(() => new ProviderMigrationRequest(Guid.Empty, source,
            Second, new KeyName("target"), ProviderMigrationMode.Regenerate, Abilities));
        Assert.Throws<ArgumentException>(() => new ProviderMigrationRequest(Guid.NewGuid(), source,
            First, new KeyName("target"), ProviderMigrationMode.Regenerate, Abilities));
        Assert.Throws<ArgumentException>(() => new ProviderMigrationRequest(Guid.NewGuid(), source,
            Second, new KeyName("target"), ProviderMigrationMode.Regenerate, []));
        Assert.Throws<ArgumentException>(() => new ProviderMigrationRequest(Guid.NewGuid(), source,
            Second, new KeyName("target"), ProviderMigrationMode.Regenerate, [Abilities[0], Abilities[0]]));
        Assert.Throws<ArgumentException>(() => new ProviderMigrationRequest(Guid.NewGuid(), source,
            Second, new KeyName("target"), (ProviderMigrationMode)777, Abilities));
    }

    [Test]
    public async Task RegenerateValidateActivateCutoverNeverRedirectsOriginalReference()
    {
        StorageContractsTests.MemoryStore firstStore = new();
        StorageContractsTests.MemoryStore secondStore = new();
        using SoftwareKeyProviderTests.TestProtector sourceProtector = new();
        using SoftwareKeyProviderTests.TestProtector destinationProtector = new();
        SoftwareKeyProviderBackend source = new(First, firstStore, sourceProtector);
        SoftwareKeyProviderBackend destination = new(Second, secondStore, destinationProtector);
        KeyDescriptor created = await source.CreateAsync(new KeyName("original"),
            WellKnownAlgorithms.HmacSha256, Abilities);
        KeyReference oldReference = new(First, created.KeyId, created.ActiveVersion!.Value);
        ProviderMigrationRequest request = NewRequest(oldReference);
        ProviderRegistry registry = new([new ProviderRegistration(source), new ProviderRegistration(destination)]);
        ProviderMigrationOrchestrator service = new(registry, [new SoftwareMigrationDestination(destination)]);

        ProviderMigrationCheckpoint planned = await service.PlanAsync(request);
        Assert.That(planned.Stage, Is.EqualTo(ProviderMigrationStage.Planned));
        Assert.That(planned.Destination, Is.Null);
        ProviderMigrationCheckpoint prepared = await service.PrepareAsync(planned);
        Assert.That(prepared.Stage, Is.EqualTo(ProviderMigrationStage.Prepared));
        Assert.That(prepared.Destination!.Value.ProviderId, Is.EqualTo(Second));
        Assert.That(prepared.Destination!.Value.KeyId, Is.Not.EqualTo(oldReference.KeyId));
        Assert.That((await source.FindExactAsync(new ExactKeyHandle(oldReference)))!.State,
            Is.EqualTo(KeyVersionState.Active));
        Assert.That((await registry.FindExactAsync(new ExactKeyHandle(oldReference)))!.Reference,
            Is.EqualTo(oldReference));

        ProviderMigrationCheckpoint validated = await service.ValidateAsync(prepared);
        ProviderMigrationCheckpoint activated = await service.ActivateAsync(validated);
        MigrationCutoverReceipt receipt = new(request.MigrationId, oldReference, activated.Destination!.Value,
            "external-cas-committed-1");
        ProviderMigrationCheckpoint completed = service.ConfirmApplicationCutover(activated, receipt);
        Assert.That(completed.Stage, Is.EqualTo(ProviderMigrationStage.ApplicationCutoverConfirmed));
        Assert.That((await source.FindExactAsync(new ExactKeyHandle(oldReference)))!.Reference,
            Is.EqualTo(oldReference));
        Assert.That((await registry.FindExactAsync(new ExactKeyHandle(completed.Destination!.Value)))!.State,
            Is.EqualTo(KeyVersionState.Active));
        Assert.ThrowsAsync<NotSupportedException>(async () => await service.RetireSourceAsync(completed));
    }

    [Test]
    public async Task NativeTransferCannotSilentlyFallbackToRegeneration()
    {
        using SoftwareKeyProviderTests.TestProtector p1 = new();
        using SoftwareKeyProviderTests.TestProtector p2 = new();
        SoftwareKeyProviderBackend source = new(First, new StorageContractsTests.MemoryStore(), p1);
        SoftwareKeyProviderBackend destination = new(Second, new StorageContractsTests.MemoryStore(), p2);
        KeyDescriptor created = await source.CreateAsync(new KeyName("native-source"),
            WellKnownAlgorithms.HmacSha256, Abilities);
        KeyReference reference = new(First, created.KeyId, created.ActiveVersion!.Value);
        ProviderRegistry registry = new([new ProviderRegistration(source), new ProviderRegistration(destination)]);
        ProviderMigrationOrchestrator orchestrator = new(registry, [new SoftwareMigrationDestination(destination)]);
        ProviderMigrationCheckpoint checkpoint = await orchestrator.PlanAsync(NewRequest(reference,
            ProviderMigrationMode.ProviderNativeTransfer));
        Assert.ThrowsAsync<NotSupportedException>(async () => await orchestrator.PrepareAsync(checkpoint));
        Assert.That(await destination.FindByNameAsync(new KeyName("migrated")), Is.Null);
    }

    [Test]
    public async Task StaleSourceVersionCannotBePrepared()
    {
        using SoftwareKeyProviderTests.TestProtector p1 = new();
        using SoftwareKeyProviderTests.TestProtector p2 = new();
        SoftwareKeyProviderBackend source = new(First, new StorageContractsTests.MemoryStore(), p1);
        SoftwareKeyProviderBackend destination = new(Second, new StorageContractsTests.MemoryStore(), p2);
        KeyDescriptor created = await source.CreateAsync(new KeyName("rotate-source"),
            WellKnownAlgorithms.HmacSha256, Abilities);
        ProviderMigrationOrchestrator orchestrator = new(new ProviderRegistry(
            [new ProviderRegistration(source), new ProviderRegistration(destination)]),
            [new SoftwareMigrationDestination(destination)]);
        KeyReference original = new(First, created.KeyId, created.ActiveVersion!.Value);
        ProviderMigrationCheckpoint planned = await orchestrator.PlanAsync(NewRequest(original));
        await source.RotateAsync(new LogicalKeyHandle(First, created.KeyId));
        Assert.ThrowsAsync<InvalidOperationException>(async () => await orchestrator.PrepareAsync(planned));
        Assert.That(await destination.FindByNameAsync(new KeyName("migrated")), Is.Null);
    }

    [Test]
    public async Task CutoverRequiresAnExactApplicationReceiptAndCorrectSequence()
    {
        using SoftwareKeyProviderTests.TestProtector p1 = new();
        using SoftwareKeyProviderTests.TestProtector p2 = new();
        SoftwareKeyProviderBackend source = new(First, new StorageContractsTests.MemoryStore(), p1);
        SoftwareKeyProviderBackend destination = new(Second, new StorageContractsTests.MemoryStore(), p2);
        KeyDescriptor created = await source.CreateAsync(new KeyName("receipt-source"),
            WellKnownAlgorithms.HmacSha256, Abilities);
        KeyReference original = new(First, created.KeyId, created.ActiveVersion!.Value);
        ProviderMigrationOrchestrator service = new(new ProviderRegistry(
            [new ProviderRegistration(source), new ProviderRegistration(destination)]),
            [new SoftwareMigrationDestination(destination)]);
        ProviderMigrationCheckpoint planned = await service.PlanAsync(NewRequest(original));
        Assert.ThrowsAsync<InvalidOperationException>(async () => await service.ValidateAsync(planned));
        ProviderMigrationCheckpoint prepared = await service.PrepareAsync(planned);
        Assert.ThrowsAsync<InvalidOperationException>(async () => await service.PrepareAsync(prepared));
        ProviderMigrationCheckpoint validated = await service.ValidateAsync(prepared);
        ProviderMigrationCheckpoint activated = await service.ActivateAsync(validated);
        MigrationCutoverReceipt wrong = new(Guid.NewGuid(), original, activated.Destination!.Value, "tx-1");
        Assert.Throws<InvalidOperationException>(() => service.ConfirmApplicationCutover(activated, wrong));
        Assert.Throws<ArgumentException>(() => new MigrationCutoverReceipt(planned.Request.MigrationId,
            original, activated.Destination!.Value, " "));
        Assert.ThrowsAsync<InvalidOperationException>(async () => await service.DeleteSourceAsync(activated));
    }

    [Test]
    public async Task UnknownPrepareCommitRequiresReconciliationInsteadOfBlindRetry()
    {
        using SoftwareKeyProviderTests.TestProtector p1 = new();
        using SoftwareKeyProviderTests.TestProtector p2 = new();
        SoftwareKeyProviderBackend source = new(First, new StorageContractsTests.MemoryStore(), p1);
        SoftwareKeyProviderTests.BarrierStore faulted = new(new StorageContractsTests.MemoryStore());
        SoftwareKeyProviderBackend destination = new(Second, faulted, p2);
        KeyDescriptor created = await source.CreateAsync(new KeyName("uncertain-source"),
            WellKnownAlgorithms.HmacSha256, Abilities);
        ProviderMigrationOrchestrator service = new(new ProviderRegistry(
            [new ProviderRegistration(source), new ProviderRegistration(destination)]),
            [new SoftwareMigrationDestination(destination)]);
        ProviderMigrationCheckpoint planned = await service.PlanAsync(NewRequest(
            new KeyReference(First, created.KeyId, created.ActiveVersion!.Value)));
        faulted.ThrowAfterNextCreate = true;
        Assert.ThrowsAsync<SoftwareKeyCommitUncertainException>(async () => await service.PrepareAsync(planned));
        KeyDescriptor? exists = await destination.FindByNameAsync(new KeyName("migrated"));
        Assert.That(exists, Is.Not.Null);
        Assert.That(exists!.KeyId, Is.Not.EqualTo(created.KeyId));
        Assert.That(planned.Stage, Is.EqualTo(ProviderMigrationStage.Planned));
        // The application must reconcile this orphaned generation, not call PrepareAsync again.
    }

    [Test]
    public void AuthenticatedJournalRestoreRequiresCoherentStageAndTarget()
    {
        KeyReference source = new(First, KeyId.New(), new KeyVersion(1));
        ProviderMigrationRequest request = NewRequest(source);
        KeyReference target = new(Second, KeyId.New(), new KeyVersion(1));
        Assert.Throws<ArgumentException>(() => ProviderMigrationCheckpoint.Restore(request,
            WellKnownAlgorithms.HmacSha256, KeyKind.Symmetric, ProviderMigrationStage.Prepared, null));
        Assert.Throws<ArgumentException>(() => ProviderMigrationCheckpoint.Restore(request,
            WellKnownAlgorithms.HmacSha256, KeyKind.Symmetric, ProviderMigrationStage.Planned, target));
        Assert.Throws<ArgumentException>(() => ProviderMigrationCheckpoint.Restore(request,
            WellKnownAlgorithms.HmacSha256, KeyKind.Symmetric, ProviderMigrationStage.Validated, source));
        ProviderMigrationCheckpoint valid = ProviderMigrationCheckpoint.Restore(request,
            WellKnownAlgorithms.HmacSha256, KeyKind.Symmetric, ProviderMigrationStage.Validated, target);
        Assert.That(valid.Destination, Is.EqualTo(target));
    }

    [Test]
    public async Task MismatchingDestinationCapabilitiesRejectPlanningWithoutSideEffects()
    {
        using SoftwareKeyProviderTests.TestProtector p1 = new();
        using SoftwareKeyProviderTests.TestProtector p2 = new();
        SoftwareKeyProviderBackend source = new(First, new StorageContractsTests.MemoryStore(), p1);
        SoftwareKeyProviderBackend destination = new(Second, new StorageContractsTests.MemoryStore(), p2);
        KeyDescriptor created = await source.CreateAsync(new KeyName("cap-source"),
            WellKnownAlgorithms.HmacSha256, Abilities);
        KeyReference reference = new(First, created.KeyId, created.ActiveVersion!.Value);
        ProviderMigrationOrchestrator orchestrator = new(new ProviderRegistry(
            [new ProviderRegistration(source), new ProviderRegistration(destination)]),
            [new SoftwareMigrationDestination(destination)]);
        ProviderMigrationRequest request = new(Guid.NewGuid(), reference, Second, new KeyName("migrated"),
            ProviderMigrationMode.Regenerate, [WellKnownCapabilities.Sign]);
        Assert.ThrowsAsync<InvalidOperationException>(async () => await orchestrator.PlanAsync(request));
        Assert.That(await destination.FindByNameAsync(new KeyName("migrated")), Is.Null);
    }

    private static ProviderMigrationRequest NewRequest(KeyReference source,
        ProviderMigrationMode mode = ProviderMigrationMode.Regenerate) =>
        new(Guid.NewGuid(), source, Second, new KeyName("migrated"), mode, Abilities);
}
