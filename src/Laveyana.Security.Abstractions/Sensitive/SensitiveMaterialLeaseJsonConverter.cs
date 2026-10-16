using System.Text.Json;
using System.Text.Json.Serialization;

namespace Laveyana.Security.Abstractions.Sensitive;

/// <summary>Prevents built-in JSON serialization or deserialization of sensitive leases.</summary>
public sealed class SensitiveMaterialLeaseJsonConverter : JsonConverter<SensitiveMaterialLease>
{
    /// <inheritdoc />
    public override SensitiveMaterialLease Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        throw new NotSupportedException("A sensitive material lease cannot be deserialized.");

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, SensitiveMaterialLease value, JsonSerializerOptions options) =>
        throw new NotSupportedException("A sensitive material lease cannot be serialized.");
}
