using System.Reflection;
using System.Security.Cryptography;
using Laveyana.Security.Primitives;

namespace Laveyana.Security.App.LibraryWorkbench.Services;

public static class SafeMethodRegistry
{
    // Explicit allowlist: no arbitrary reflection invocation is permitted.
    public static bool CanExecute(MethodInfo method) =>
        method.DeclaringType == typeof(LocalCryptography) &&
        method.Name == nameof(LocalCryptography.GenerateRandomBytes) &&
        method.GetParameters().Length == 1 && method.GetParameters()[0].ParameterType == typeof(int);

    public static string Execute(MethodInfo method, IReadOnlyDictionary<string, object?> parameters)
    {
        if (!CanExecute(method))
        {
            throw new InvalidOperationException("The method is not registered for safe execution.");
        }

        if (!parameters.TryGetValue("byteCount", out object? value) || value is not int count || count < 1 || count > 256)
        {
            throw new ArgumentOutOfRangeException(nameof(parameters), "This example accepts from 1 to 256 bytes.");
        }

        byte[] random = LocalCryptography.GenerateRandomBytes(count);
        try
        {
            // Only show the length; do not log or export generated key-like bytes.
            return $"Generated {random.Length} synthetic random bytes using the library RNG. Output was zeroed.";
        }
        finally
        {
            CryptographicOperations.ZeroMemory(random);
        }
    }
}
