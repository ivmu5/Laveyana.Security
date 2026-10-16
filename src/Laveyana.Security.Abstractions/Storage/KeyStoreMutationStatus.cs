namespace Laveyana.Security.Abstractions.Storage;

/// <summary>Definitive conditional-write outcomes; exceptions/cancellation may mean an unknown commit.</summary>
public enum KeyStoreMutationStatus
{
    /// <summary>Indicates that the conditional mutation was committed.</summary>
    Applied = 1,
    /// <summary>Indicates that another key already claims the requested name.</summary>
    NameTaken = 2,
    /// <summary>Indicates that the requested key identity already exists.</summary>
    KeyAlreadyExists = 3,
    /// <summary>Indicates that the expected revision did not match.</summary>
    RevisionMismatch = 4,
    /// <summary>Indicates that the requested key was not found.</summary>
    NotFound = 5
}
