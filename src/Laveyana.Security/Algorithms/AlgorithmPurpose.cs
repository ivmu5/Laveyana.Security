namespace Laveyana.Security.Algorithms;

/// <summary>Identifies the kind of cryptographic operation for which a policy applies.</summary>
public enum AlgorithmPurpose
{
    /// <summary>Identifies one-way hash algorithms.</summary>
    Hash = 0,
    /// <summary>Identifies message authentication code algorithms.</summary>
    Mac = 1,
    /// <summary>Identifies general-purpose key derivation algorithms.</summary>
    GeneralKdf = 2,
    /// <summary>Identifies password-based key derivation algorithms.</summary>
    PasswordKdf = 3,
    /// <summary>Identifies authenticated encryption algorithms.</summary>
    AuthenticatedEncryption = 4,
    /// <summary>Identifies digital signature algorithms.</summary>
    Signature = 5,
    /// <summary>Identifies key agreement algorithms.</summary>
    KeyAgreement = 6,
}
