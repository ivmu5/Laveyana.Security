using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace Laveyana.Security.Diagnostics;

/// <summary>Fixed, bounded names for diagnostic operations. Never use key or tenant identifiers as operations.</summary>
public enum SecurityOperation
{
    /// <summary>Identifies an encryption operation.</summary>
    Encrypt,
    /// <summary>Identifies a decryption operation.</summary>
    Decrypt,
    /// <summary>Identifies a non-throwing authentication verification attempt.</summary>
    TryDecrypt,
    /// <summary>Identifies creation of a message authentication code.</summary>
    ComputeMac,
    /// <summary>Identifies verification of a message authentication code.</summary>
    VerifyMac,
    /// <summary>Identifies creation of a key.</summary>
    CreateKey,
    /// <summary>Identifies rotation of a key.</summary>
    RotateKey,
    /// <summary>Identifies reading a secret.</summary>
    ReadSecret,
    /// <summary>Identifies reading key metadata.</summary>
    ReadKey,
    /// <summary>Identifies retirement of a key.</summary>
    RetireKey,
    /// <summary>Identifies deletion of a key.</summary>
    DeleteKey
}
