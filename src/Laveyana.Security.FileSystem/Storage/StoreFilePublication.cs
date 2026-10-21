namespace Laveyana.Security.FileSystem.Storage;

/// <summary>Publishes exact staged bytes without replacing directory-pinned I/O with paths.</summary>
/// <remarks>
/// A successful Windows rename is NOT a namespace power-loss durability barrier.
/// Linux Move performs fsync on the pinned parent, subject to the filesystem/storage contract.
/// This helper does not authorize protected writes, authority RPCs or recovery.
/// </remarks>
internal static class StoreFilePublication
{
    internal static async ValueTask WriteAsync(LinuxSecureDirectory? linux, WindowsSecureDirectory? windows,
        string destinationName, byte[] data, bool overwrite, CancellationToken cancellationToken,
        Action<StoreWriteBoundary, string>? fault = null)
    {
        if ((linux is null) == (windows is null))
        {
            throw new ArgumentException("Exactly one pinned secure directory is required.");
        }

        string temporaryName = $".pending-{Guid.NewGuid():N}.tmp";
        bool publicationStarted = false;
        Exception? originalFailure = null;
        try
        {
            using (FileStream stream = linux is not null
                ? linux.CreateTemporary(temporaryName) : windows!.CreateTemporary(temporaryName))
            {
                fault?.Invoke(StoreWriteBoundary.TemporaryCreated, destinationName);
                await stream.WriteAsync(data, cancellationToken).ConfigureAwait(false);
                fault?.Invoke(StoreWriteBoundary.DataWritten, destinationName);
                stream.Flush(true);
                fault?.Invoke(StoreWriteBoundary.FileFlushed, destinationName);
            }

            using (FileStream staged = linux is not null
                ? linux.OpenRead(temporaryName) : windows!.OpenRead(temporaryName))
            {
                if (staged.Length != data.Length)
                {
                    throw new InvalidDataException("Staged store file has an unexpected length.");
                }

                byte[] persisted = new byte[data.Length];
                await staged.ReadExactlyAsync(persisted.AsMemory(), cancellationToken).ConfigureAwait(false);
                if (!persisted.AsSpan().SequenceEqual(data))
                {
                    throw new InvalidDataException("Staged store file differs from the exact candidate.");
                }
            }

            cancellationToken.ThrowIfCancellationRequested();
            fault?.Invoke(StoreWriteBoundary.BeforeRename, destinationName);
            // Once native publication begins, an exception is not evidence of rollback.
            publicationStarted = true;
            if (linux is not null)
            {
                linux.MoveWithFault(temporaryName, destinationName, overwrite, fault);
            }
            else
            {
                windows!.MoveWithFault(temporaryName, destinationName, overwrite, fault);
            }

            fault?.Invoke(StoreWriteBoundary.Published, destinationName);
        }
        catch (Exception error)
        {
            originalFailure = error;
            if (publicationStarted)
            {
                throw new IOException(
                    "Store publication may have committed. Reconcile persisted state; do not blindly retry the mutation.", error);
            }

            throw;
        }
        finally
        {
            try
            {
                if (linux is not null)
                {
                    linux.Remove(temporaryName);
                }
                else
                {
                    windows!.Remove(temporaryName);
                }
            }
            catch (Exception cleanupError)
            {
                if (originalFailure is not null)
                {
                    originalFailure.Data["TemporaryCleanupFailure"] = cleanupError;
                }
                else
                {
                    throw new IOException(
                        "Store publication completed but temporary cleanup failed; reconcile before retrying.", cleanupError);
                }
            }
        }
    }
}
