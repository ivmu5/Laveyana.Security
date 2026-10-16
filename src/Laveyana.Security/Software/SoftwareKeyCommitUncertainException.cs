namespace Laveyana.Security.Software;

/// <summary>A storage write may have committed despite throwing; do not blindly retry.</summary>
public sealed class SoftwareKeyCommitUncertainException : InvalidOperationException
{
    /// <summary>Constructs a redacted exception for a possibly committed mutation.</summary>
    public SoftwareKeyCommitUncertainException(Exception innerException)
        : base("Software key commit outcome is unknown. Reconcile against authoritative storage before retrying.", innerException) { }
}
