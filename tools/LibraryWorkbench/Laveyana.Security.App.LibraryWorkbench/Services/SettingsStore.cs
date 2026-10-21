using System.IO;
using System.Text.Json;

namespace Laveyana.Security.App.LibraryWorkbench.Services;

public sealed class WorkbenchSettings
{
    public bool LightTheme { get; set; }
    public string LastType { get; set; } = "";
    public double WindowWidth { get; set; } = 1280;
    public double WindowHeight { get; set; } = 820;
}

public sealed class SettingsStore
{
    private readonly string _path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Laveyana", "Security", "LibraryWorkbench", "settings.json");

    public WorkbenchSettings Load()
    {
        try
        {
            return File.Exists(_path)
                ? JsonSerializer.Deserialize<WorkbenchSettings>(File.ReadAllText(_path)) ?? new WorkbenchSettings()
                : new WorkbenchSettings();
        }
        catch (Exception)
        {
            return new WorkbenchSettings();
        }
    }

    public void Save(WorkbenchSettings settings)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        File.WriteAllText(_path, JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true }));
    }
}
