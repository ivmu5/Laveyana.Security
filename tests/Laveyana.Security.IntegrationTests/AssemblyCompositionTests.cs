using System.Reflection;
using NUnit.Framework;

namespace Laveyana.Security.IntegrationTests;

/// <summary>
/// Guards independent storage and composition assembly boundaries.
/// </summary>
[TestFixture]
internal sealed class AssemblyCompositionTests
{
    /// <summary>
    /// Ensures that FileSystem does not acquire a core or DI dependency.
    /// </summary>
    [Test]
    public void FileSystemDoesNotReferenceCoreOrComposition()
    {
        Assembly assembly = Assembly.Load("Laveyana.Security.FileSystem");
        string?[] references = assembly.GetReferencedAssemblies()
            .Select(reference => reference.Name)
            .ToArray();

        Assert.That(references, Does.Not.Contain("Laveyana.Security"));
        Assert.That(references, Does.Not.Contain("Laveyana.Security.DependencyInjection"));
    }

    /// <summary>
    /// Ensures every production assembly retains its assigned family identity.
    /// </summary>
    [Test]
    public void ProductionAssembliesUseLaveyanaFamilyIdentity()
    {
        string[] names =
        [
            "Laveyana.Security.Abstractions",
            "Laveyana.Security",
            "Laveyana.Security.FileSystem",
            "Laveyana.Security.DependencyInjection"
        ];

        foreach (string name in names)
        {
            Assembly assembly = Assembly.Load(name);
            Assert.That(assembly.GetName().Name, Is.EqualTo(name));
        }
    }
}
