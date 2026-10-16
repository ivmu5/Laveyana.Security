using System.Text.Json;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Primitives;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>Guards buffer ownership, zeroization, scopes and non-disclosure.</summary>
[TestFixture]
internal sealed class SensitiveMaterialTests
{
    [Test]
    public void CreateCopyRetainsNeitherInputOwnershipNorInputAliasing()
    {
        byte[] source = [11, 22, 33, 44];
        using SensitiveMaterialLease lease = SensitiveMaterialLease.CreateCopy(source);
        source[0] = 99;

        lease.UseMaterial(span =>
        {
            Assert.That(span.SequenceEqual(new byte[] { 11, 22, 33, 44 }), Is.True);
            Assert.That(span.Overlaps(source.AsSpan()), Is.False);
        });

        Assert.That(lease.Length, Is.EqualTo(4));
        lease.Dispose();
        Assert.That(source, Is.EqualTo(new byte[] { 99, 22, 33, 44 }));
        Assert.Throws<ObjectDisposedException>(() => lease.UseMaterial(_ => { }));
        Assert.Throws<ObjectDisposedException>(() => { _ = lease.Length; });
    }

    [Test]
    public void TakeOwnershipDoesNotCopyAndDisposeZeroesExactTransferredArray()
    {
        byte[] owned = [21, 22, 23, 24];
        SensitiveMaterialLease lease = SensitiveMaterialLease.TakeOwnership(owned);
        lease.UseMaterial(span => Assert.That(span.Overlaps(owned.AsSpan()), Is.True));
        Assert.That(owned, Is.EqualTo(new byte[] { 21, 22, 23, 24 }));

        lease.Dispose();
        lease.Dispose();
        Assert.That(owned, Is.EqualTo(new byte[4]));
    }

    [Test]
    public void CallbackExceptionDoesNotSkipDisposalForTransferredBuffer()
    {
        byte[] owned = [101, 102, 103];
        Assert.Throws<InvalidOperationException>(() => SensitiveMaterialScope.UseOwned(
            owned, _ => throw new InvalidOperationException("Visitor failed.")));
        Assert.That(owned, Is.EqualTo(new byte[3]));
    }

    [Test]
    public void ScopedCopyOnExceptionNeverModifiesBorrowedInput()
    {
        byte[] original = [1, 2, 3];
        Assert.Throws<InvalidOperationException>(() => SensitiveMaterialScope.UseCopy(
            original, _ => throw new InvalidOperationException("Visitor failed.")));
        Assert.That(original, Is.EqualTo(new byte[] { 1, 2, 3 }));
    }

    [Test]
    public void DisposeInsideCallbackDefersWipeUntilVisitorReturns()
    {
        byte[] owned = [7, 8, 9];
        using SensitiveMaterialLease lease = SensitiveMaterialLease.TakeOwnership(owned);
        lease.UseMaterial(span =>
        {
            lease.Dispose();
            Assert.That(span.SequenceEqual(new byte[] { 7, 8, 9 }), Is.True);
            Assert.Throws<ObjectDisposedException>(() => lease.UseMaterial(_ => { }));
        });
        Assert.That(owned, Is.EqualTo(new byte[3]));
    }

    [Test]
    public void NestedReadOnlyVisitorsAreValidUntilOuterScopeExits()
    {
        byte[] owned = [10, 20];
        using SensitiveMaterialLease lease = SensitiveMaterialLease.TakeOwnership(owned);
        lease.UseMaterial(first =>
        {
            lease.UseMaterial(second => Assert.That(second.SequenceEqual(new byte[] { 10, 20 }), Is.True));
            Assert.That(first.SequenceEqual(new byte[] { 10, 20 }), Is.True);
        });
        lease.Dispose();
        Assert.That(owned, Is.EqualTo(new byte[2]));
    }

    [Test]
    public void DisposeDuringConcurrentVisitorWaitsToWipeUntilVisitorCompletes()
    {
        byte[] owned = [5, 6, 7];
        using SensitiveMaterialLease lease = SensitiveMaterialLease.TakeOwnership(owned);
        using ManualResetEventSlim entered = new(false);
        using ManualResetEventSlim exit = new(false);

        Task worker = Task.Run(() => lease.UseMaterial(span =>
        {
            entered.Set();
            if (!exit.Wait(TimeSpan.FromSeconds(10)))
            {
                throw new TimeoutException("Visitor was not released.");
            }

            Assert.That(span.SequenceEqual(new byte[] { 5, 6, 7 }), Is.True);
        }));

        try
        {
            Assert.That(entered.Wait(TimeSpan.FromSeconds(10)), Is.True);
            lease.Dispose();
            Assert.That(owned, Is.EqualTo(new byte[] { 5, 6, 7 }));
            Assert.Throws<ObjectDisposedException>(() => lease.UseMaterial(_ => { }));
        }
        finally
        {
            exit.Set();
            worker.GetAwaiter().GetResult();
        }

        Assert.That(owned, Is.EqualTo(new byte[3]));
    }

    [Test]
    public void LeaseFeedsHmacWithoutExportingKeyArray()
    {
        byte[] keyBytes = new byte[32];
        Array.Fill(keyBytes, (byte)0x5a);
        byte[]? tag = null;
        SensitiveMaterialScope.UseOwned(keyBytes, key =>
        {
            tag = LocalCryptography.HmacSha256(key, "payload"u8);
        });

        Assert.That(tag, Has.Length.EqualTo(32));
        Assert.That(keyBytes, Is.EqualTo(new byte[32]));
    }

    [Test]
    public void RejectionBeforeTransferLeavesInputInCallerOwnership()
    {
        byte[] empty = [];
        byte[] oversized = new byte[SensitiveMaterialLease.MaximumMaterialLength + 1];
        Assert.Multiple(() =>
        {
            Assert.Throws<ArgumentNullException>(() => SensitiveMaterialLease.TakeOwnership(null!));
            Assert.Throws<ArgumentOutOfRangeException>(() => SensitiveMaterialLease.TakeOwnership(empty));
            Assert.Throws<ArgumentOutOfRangeException>(() => SensitiveMaterialLease.TakeOwnership(oversized));
            Assert.Throws<ArgumentOutOfRangeException>(() => SensitiveMaterialLease.CreateCopy(empty));
            Assert.Throws<ArgumentNullException>(() => SensitiveMaterialScope.UseOwned([1, 2], null!));
        });
        Assert.That(oversized.Length, Is.EqualTo(SensitiveMaterialLease.MaximumMaterialLength + 1));
    }

    [Test]
    public void SerializedAndLoggedRepresentationsNeverExposeMaterial()
    {
        using SensitiveMaterialLease lease = SensitiveMaterialLease.TakeOwnership([65, 66, 67]);
        Assert.That(lease.ToString(), Is.EqualTo("SensitiveMaterialLease [REDACTED]"));
        Assert.Throws<NotSupportedException>(() => JsonSerializer.Serialize(lease));
        Assert.Throws<NotSupportedException>(() => JsonSerializer.Serialize(new { Material = lease }));
        Assert.Throws<NotSupportedException>(() => JsonSerializer.Deserialize<SensitiveMaterialLease>("{}"));
    }
}
