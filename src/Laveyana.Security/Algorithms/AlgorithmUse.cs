namespace Laveyana.Security.Algorithms;

/// <summary>Distinguishes the creation of new protected values from verification of historical data.</summary>
public enum AlgorithmUse
{
    /// <summary>Indicates creation of new cryptographic output.</summary>
    NewOperation = 0,
    /// <summary>Indicates verification of previously created output.</summary>
    HistoricalVerification = 1,
}
