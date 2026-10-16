using Laveyana.Security.Abstractions.Protection;

namespace Laveyana.Security.Abstractions.Storage;

/// <summary>Revision-consistent outcomes for reads of independently protected material.</summary>
public enum KeyStoreMaterialReadStatus
{
    /// <summary>Indicates that protected material was found for the requested revision.</summary>
    Found = 1,
    /// <summary>Indicates that no material exists for the requested version.</summary>
    NotFound = 2,
    /// <summary>Indicates that the expected store revision no longer matches.</summary>
    RevisionMismatch = 3
}
