using System.Reflection;
using Laveyana.Security.Algorithms;
using Laveyana.Security.FileSystem.Storage;
using Laveyana.Security.Primitives;
using Laveyana.Security.DependencyInjection.Composition;
using Laveyana.Security.Windows.Protection;
using Laveyana.Security.Abstractions.Storage;

namespace Laveyana.Security.App.LibraryWorkbench.Discovery;

public sealed record TypeItem(Type Type, string DisplayName, string Group, string Kind, string FullName);

public sealed class TypeCatalog
{
    public IReadOnlyList<TypeItem> Read()
    {
        Assembly[] assemblies =
        [
            typeof(IKeyStore).Assembly,
            typeof(LocalCryptography).Assembly,
            typeof(FileSystemKeyStore).Assembly,
            typeof(AlgorithmPolicy).Assembly,
            typeof(WindowsDpapiUserProtector).Assembly,
            typeof(SecurityServiceCollectionExtensions).Assembly
        ];

        return assemblies.Distinct().SelectMany(SafeTypes)
            .Where(type => type.IsPublic || type.IsNestedPublic)
            .Where(type => !type.IsCompilerGenerated())
            .Select(type => new TypeItem(type, type.Name, type.Assembly.GetName().Name ?? "Unknown",
                type.IsInterface ? "Interface" : type.IsEnum ? "Enum" : type.IsValueType ? "Struct" : "Class",
                type.FullName ?? type.Name))
            .OrderBy(item => item.Group).ThenBy(item => item.DisplayName)
            .ToArray();
    }

    private static IEnumerable<Type> SafeTypes(Assembly assembly)
    {
        try
        {
            return assembly.GetExportedTypes();
        }
        catch (ReflectionTypeLoadException error)
        {
            return error.Types.OfType<Type>();
        }
    }
}

internal static class TypeMetadataExtensions
{
    public static bool IsCompilerGenerated(this Type type) =>
        type.IsDefined(typeof(System.Runtime.CompilerServices.CompilerGeneratedAttribute), false);
}
