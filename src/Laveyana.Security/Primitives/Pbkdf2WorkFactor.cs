namespace Laveyana.Security.Primitives;

/// <summary>
/// Explicit versioned work factor for new PBKDF2-HMAC-SHA-256 values. Persist both
/// the policy version and iteration count alongside the salt and derived-key length.
/// </summary>
public readonly record struct Pbkdf2WorkFactor
{
    /// <summary>Generation 1 minimum iterations for newly derived values.</summary>
    public const int Generation1MinimumIterations = 600_000;

    /// <summary>Generation 1 default iterations for newly derived values.</summary>
    public const int Generation1DefaultIterations = 600_000;

    /// <summary>Maximum accepted iterations to bound attacker-controlled work.</summary>
    public const int MaximumIterations = 10_000_000;

    /// <summary>Constructs an explicit versioned work factor for new values.</summary>
    public Pbkdf2WorkFactor(int policyVersion, int iterations)
    {
        if (policyVersion != 1)
        {
            throw new ArgumentOutOfRangeException(nameof(policyVersion), "Unsupported PBKDF2 policy version.");
        }

        if (iterations < Generation1MinimumIterations || iterations > MaximumIterations)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations), "Work factor is outside Generation 1 bounds.");
        }

        PolicyVersion = policyVersion;
        Iterations = iterations;
    }

    /// <summary>Identifies the versioned requirements used when the value was created.</summary>
    public int PolicyVersion { get; }

    /// <summary>Gets the number of PBKDF2 iterations.</summary>
    public int Iterations { get; }

    /// <summary>Gets the Generation 1 default for new derivations.</summary>
    public static Pbkdf2WorkFactor Generation1Default { get; } =
        new(1, Generation1DefaultIterations);

    /// <summary>Rejects zero-initialized structures before cryptographic use.</summary>
    public void Validate()
    {
        if (PolicyVersion != 1 || Iterations < Generation1MinimumIterations || Iterations > MaximumIterations)
        {
            throw new ArgumentException("PBKDF2 work factor is not a valid Generation 1 policy value.", nameof(Pbkdf2WorkFactor));
        }
    }
}
