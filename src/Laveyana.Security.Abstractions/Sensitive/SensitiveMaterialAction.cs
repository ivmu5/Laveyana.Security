namespace Laveyana.Security.Abstractions.Sensitive;

/// <summary>
/// Synchronously examines sensitive material. The span is borrowed for the duration
/// of the call and must not be retained, copied to persistent storage or logged.
/// </summary>
/// <param name="material">Read-only access to a temporary, borrowed secret.</param>
public delegate void SensitiveMaterialAction(ReadOnlySpan<byte> material);
