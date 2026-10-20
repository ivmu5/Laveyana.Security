using System.IO;
using System.Diagnostics;

namespace Laveyana.Security.App.LibraryWorkbench.Services;

public sealed class SourceLocator
{
    public string? FindRepositoryRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        for (int depth = 0; current is not null && depth < 12; current = current.Parent, depth++)
        {
            if (File.Exists(Path.Combine(current.FullName, "Laveyana.Security.sln")) &&
                Directory.Exists(Path.Combine(current.FullName, "src")))
            {
                return current.FullName;
            }
        }

        return null;
    }

    public string? FindSource(Type type)
    {
        string? root = FindRepositoryRoot();
        if (root is null)
        {
            return null;
        }

        string assembly = type.Assembly.GetName().Name ?? "";
        string directory = Path.Combine(root, "src", assembly);
        if (!Directory.Exists(directory))
        {
            return null;
        }

        return Directory.EnumerateFiles(directory, type.Name.Split('`')[0] + ".cs", SearchOption.AllDirectories)
            .FirstOrDefault() ?? Directory.EnumerateFiles(directory, "*.cs", SearchOption.AllDirectories)
            .FirstOrDefault(file => Path.GetFileName(file).StartsWith(type.Name.Split('`')[0] + ".", StringComparison.Ordinal));
    }

    public string OpenSource(Type type)
    {
        string? source = FindSource(type);
        if (source is null)
        {
            return "Source file was not found. Open the repository root in Visual Studio.";
        }

        try
        {
            using Process? _ = Process.Start(new ProcessStartInfo
            {
                FileName = source,
                UseShellExecute = true
            });
            return "Opened source: " + source;
        }
        catch (Exception error)
        {
            return $"Unable to open source ({error.GetType().Name}). File: {source}";
        }
    }
}
