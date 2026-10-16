namespace Laveyana.Security.Algorithms;

/// <summary>Classifies algorithm suitability for new operations and historical interoperability.</summary>
public enum AlgorithmStatus
{
    /// <summary>Indicates that an algorithm is recommended for its permitted uses.</summary>
    Recommended = 0,
    /// <summary>Indicates that an algorithm is supported subject to policy.</summary>
    Supported = 1,
    /// <summary>Indicates that an algorithm is restricted to historical verification.</summary>
    LegacyReadOnly = 2,
}
