using System.Text.Json;
using System.Text.Json.Serialization;

namespace Laveyana.Security.Abstractions.Capabilities;

/// <summary>Always rejects serialization/deserialization of derived secret material.</summary>
public sealed class DerivedKeyLeaseJsonConverter : JsonConverter<DerivedKeyLease>
{
    /// <inheritdoc/>
    public override DerivedKeyLease Read(ref Utf8JsonReader reader, Type typeToConvert,
        JsonSerializerOptions options) => throw new NotSupportedException("Derived material cannot be deserialized.");

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, DerivedKeyLease value,
        JsonSerializerOptions options) => throw new NotSupportedException("Derived material cannot be serialized.");
}
