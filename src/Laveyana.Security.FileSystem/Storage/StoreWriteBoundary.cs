namespace Laveyana.Security.FileSystem.Storage;

/// <summary>Observable test boundaries in the real handle-relative publication path.</summary>
internal enum StoreWriteBoundary
{
    TemporaryCreated,
    DataWritten,
    FileFlushed,
    BeforeRename,
    AfterRename,
    DirectoryFlushed,
    Published,
}
