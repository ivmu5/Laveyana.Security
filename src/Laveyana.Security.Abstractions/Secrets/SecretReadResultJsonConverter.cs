using System.Text.Json;
using System.Text.Json.Serialization;

namespace Laveyana.Security.Abstractions.Secrets;

/// <summary>Prevents automatic import or export of secret material through JSON.</summary>
public sealed class SecretReadResultJsonConverter : JsonConverter<SecretReadResult>
{
    /// <inheritdoc />
    public override SecretReadResult Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        throw new NotSupportedException("Secret read results cannot be deserialized.");

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, SecretReadResult value, JsonSerializerOptions options) =>
        throw new NotSupportedException("Secret read results cannot be serialized.");
}
