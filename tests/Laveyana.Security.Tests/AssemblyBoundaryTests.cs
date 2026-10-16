using System.Reflection;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>
/// Guards the runtime assembly boundaries of the foundational projects.
/// </summary>
[TestFixture]
internal sealed class AssemblyBoundaryTests
{
    /// <summary>
    /// Ensures that the contract assembly cannot depend on implementation assemblies.
    /// </summary>
    [Test]
    public void AbstractionsDoesNotReferenceConcreteAssemblies()
    {
        Assembly assembly = Assembly.Load("Laveyana.Security.Abstractions");
        string?[] references = assembly.GetReferencedAssemblies()
            .Select(reference => reference.Name)
            .ToArray();

        Assert.That(references, Does.Not.Contain("Laveyana.Security"));
        Assert.That(references, Does.Not.Contain("Laveyana.Security.FileSystem"));
        Assert.That(references, Does.Not.Contain("Laveyana.Security.DependencyInjection"));
    }

    /// <summary>
    /// Ensures that the core implementation does not depend on storage or composition.
    /// </summary>
    [Test]
    public void CoreDoesNotReferenceFilesystemOrComposition()
    {
        Assembly assembly = Assembly.Load("Laveyana.Security");
        string?[] references = assembly.GetReferencedAssemblies()
            .Select(reference => reference.Name)
            .ToArray();

        Assert.That(references, Does.Not.Contain("Laveyana.Security.FileSystem"));
        Assert.That(references, Does.Not.Contain("Laveyana.Security.DependencyInjection"));
    }
}
