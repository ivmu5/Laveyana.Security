using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows.Interop;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Laveyana.Security.App.LibraryWorkbench.Discovery;
using Laveyana.Security.App.LibraryWorkbench.Services;
using Laveyana.Security.App.LibraryWorkbench.ViewModels;
using Laveyana.Security.App.LibraryWorkbench.Views;
using Microsoft.Win32;

namespace Laveyana.Security.App.LibraryWorkbench;

public partial class MainWindow : Window
{
    private readonly MainViewModel _model;
    private readonly SourceLocator _sources = new();
    private readonly WorkerRunner _worker = new();
    private readonly SettingsStore _settingsStore = new();
    private readonly WorkbenchSettings _settings;
    private readonly Dictionary<string, Func<object?>> _editors = [];

    public MainWindow()
    {
        InitializeComponent();
        _settings = _settingsStore.Load();
        _model = new MainViewModel(new TypeCatalog());
        DataContext = _model;
        Width = Math.Clamp(_settings.WindowWidth, MinWidth, 1900);
        Height = Math.Clamp(_settings.WindowHeight, MinHeight, 1300);
        ApplyTheme(_settings.LightTheme);
        SourceInitialized += (_, _) => ApplyTitleBarTheme(_settings.LightTheme);
        TypeItem? selected = _model.FilteredTypes.FirstOrDefault(item => item.FullName == _settings.LastType);
        if (selected is not null)
        {
            _model.SelectedType = selected;
        }

        UpdateCustomView();
        _model.Log("READY", $"Found {_model.FilteredTypes.Count} public types. Production data is prohibited.");
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        try
        {
            _settings.LastType = _model.SelectedType?.FullName ?? "";
            _settings.WindowWidth = RestoreBounds.Width;
            _settings.WindowHeight = RestoreBounds.Height;
            _settingsStore.Save(_settings);
        }
        catch (Exception error)
        {
            _model.Log("WARN", "Failed to save window settings: " + error.GetType().Name);
        }

        base.OnClosing(e);
    }

    private void TypeSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_model is null)
        {
            return;
        }

        UpdateCustomView();
        MethodList.SelectedIndex = -1;
        MethodTitle.Text = "Select a method from the list.";
        GeneratedParameterPanel.Children.Clear();
        MethodHint.Text = "";
        ExecuteMethodButton.IsEnabled = false;
        MethodOutput.Text = "";
    }

    private void UpdateCustomView()
    {
        if (_model.IsCryptoView)
        {
            LocalCryptographyView view = new();
            view.ScenarioCompleted += message => _model.Log("DEMO", message);
            CustomViewHost.Content = view;
        }
        else
        {
            TextBlock fallbackMessage = new()
            {
                Text = "No custom view is registered for this type. Open the Methods tab: "
                    + "parameter editors and execution restrictions are generated automatically. "
                    + "New classes appear here without manual registration.",
                Margin = new Thickness(8),
                TextWrapping = TextWrapping.Wrap
            };
            fallbackMessage.SetResourceReference(TextBlock.ForegroundProperty, "MutedBrush");
            CustomViewHost.Content = fallbackMessage;
        }
    }

    private void MethodSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (GeneratedParameterPanel is null || MethodList.SelectedItem is not MethodItem row)
        {
            return;
        }

        _editors.Clear();
        GeneratedParameterPanel.Children.Clear();
        MethodTitle.Text = row.Signature;
        MethodOutput.Text = "";
        bool supported = true;
        foreach (ParameterInfo parameter in row.Method.GetParameters())
        {
            string name = parameter.Name ?? "arg" + parameter.Position.ToString(CultureInfo.InvariantCulture);
            GeneratedParameterPanel.Children.Add(new TextBlock
            {
                Text = name + "  (" + parameter.ParameterType.Name + ")",
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 8, 0, 5)
            });
            if (parameter.ParameterType == typeof(bool))
            {
                CheckBox box = new() { IsChecked = false, Content = "True / False" };
                GeneratedParameterPanel.Children.Add(box);
                _editors[name] = () => box.IsChecked == true;
            }
            else if (parameter.ParameterType.IsEnum)
            {
                ComboBox combo = new() { ItemsSource = Enum.GetValues(parameter.ParameterType), SelectedIndex = 0,
                    Width = 270, HorizontalAlignment = HorizontalAlignment.Left };
                GeneratedParameterPanel.Children.Add(combo);
                _editors[name] = () => combo.SelectedItem;
            }
            else if (parameter.ParameterType == typeof(DateTime))
            {
                DatePicker picker = new() { SelectedDate = DateTime.Today, Width = 220,
                    HorizontalAlignment = HorizontalAlignment.Left };
                GeneratedParameterPanel.Children.Add(picker);
                _editors[name] = () => picker.SelectedDate ?? throw new FormatException("Choose a date.");
            }
            else if (parameter.ParameterType == typeof(string) || parameter.ParameterType == typeof(int)
                     || parameter.ParameterType == typeof(double) || parameter.ParameterType == typeof(Guid))
            {
                TextBox input = new() { Text = parameter.ParameterType == typeof(int) ? "32" : "",
                    Width = 290, HorizontalAlignment = HorizontalAlignment.Left };
                GeneratedParameterPanel.Children.Add(input);
                _editors[name] = () => ConvertParameter(input.Text, parameter.ParameterType);
            }
            else
            {
                supported = false;
                TextBlock unsupportedHint = new()
                {
                    Text = "No editor for this parameter type; its signature is still available."
                };
                unsupportedHint.SetResourceReference(TextBlock.ForegroundProperty, "MutedBrush");
                GeneratedParameterPanel.Children.Add(unsupportedHint);
            }
        }

        bool executable = supported && SafeMethodRegistry.CanExecute(row.Method);
        ExecuteMethodButton.IsEnabled = executable;
        MethodHint.Text = executable
            ? "Allowlisted typed scenario with validated limits. MethodInfo.Invoke is never used."
            : "Execution is disabled by default. Register a safe scenario in SafeMethodRegistry.";
    }

    private static object? ConvertParameter(string text, Type type)
    {
        if (type == typeof(int))
        {
            return int.Parse(text, CultureInfo.InvariantCulture);
        }

        if (type == typeof(double))
        {
            return double.Parse(text, CultureInfo.InvariantCulture);
        }

        if (type == typeof(Guid))
        {
            return Guid.Parse(text);
        }

        return text;
    }

    private void ExecuteMethodClick(object sender, RoutedEventArgs e)
    {
        if (MethodList.SelectedItem is not MethodItem row || !SafeMethodRegistry.CanExecute(row.Method))
        {
            return;
        }

        try
        {
            Dictionary<string, object?> values = _editors.ToDictionary(item => item.Key, item => item.Value());
            string message = SafeMethodRegistry.Execute(row.Method, values);
            MethodOutput.Text = message;
            _model.Log("DEMO", row.Name + " executed through its allowlisted adapter.");
        }
        catch (Exception error)
        {
            MethodOutput.Text = $"{error.GetType().Name}: {error.Message}";
            _model.Log("ERROR", "Generated method scenario failed: " + error.GetType().Name);
        }
    }

    private void OpenSourceClick(object sender, RoutedEventArgs e)
    {
        if (_model.SelectedType is not null)
        {
            string result = _sources.OpenSource(_model.SelectedType.Type);
            _model.Log("SOURCE", result);
        }
    }

    private async void WorkerCryptoClick(object sender, RoutedEventArgs e) =>
        await RunWorkerAsync(sender, "worker-crypto");

    private async void WorkerFileClick(object sender, RoutedEventArgs e) =>
        await RunWorkerAsync(sender, "temp-file-roundtrip");

    private async Task RunWorkerAsync(object sender, string scenario)
    {
        if (sender is not Button button)
        {
            return;
        }

        button.IsEnabled = false;
        WorkerResult.Text = "Starting worker...";
        try
        {
            var result = await _worker.ExecuteAsync(scenario);
            WorkerResult.Text = result.Message + $" ({result.ElapsedMilliseconds} ms)";
            _model.Log(result.Succeeded ? "WORKER" : "ERROR",
                $"{scenario}: {(result.Succeeded ? "completed" : "failed")}, {result.ElapsedMilliseconds} ms");
        }
        catch (Exception error)
        {
            WorkerResult.Text = $"{error.GetType().Name}: {error.Message}";
            _model.Log("ERROR", "Worker scenario failed: " + error.GetType().Name);
        }
        finally
        {
            button.IsEnabled = true;
        }
    }

    private void ThemeClick(object sender, RoutedEventArgs e)
    {
        _settings.LightTheme = !_settings.LightTheme;
        ApplyTheme(_settings.LightTheme);
        _model.Log("UI", _settings.LightTheme ? "Light theme enabled." : "Dark theme enabled.");
    }

    private void ApplyTheme(bool light)
    {
        Dictionary<string, string> colors = light
            ? new()
            {
                ["PageBrush"] = "#F1F5FA", ["PanelBrush"] = "#FFFFFF", ["CardBrush"] = "#F6F9FC",
                ["InputBrush"] = "#FFFFFF", ["TextBrush"] = "#17283A", ["MutedBrush"] = "#54687E",
                ["AccentBrush"] = "#167B79", ["AccentTextBrush"] = "#FFFFFF",
                ["AccentHoverBrush"] = "#1B9692", ["AccentPressedBrush"] = "#105C5B",
                ["BorderBrush"] = "#CBD6E2", ["HoverBorderBrush"] = "#6D909B",
                ["HoverBrush"] = "#E5F1F2", ["SelectedBrush"] = "#D7EBEB",
                ["DisabledBrush"] = "#E9EEF3", ["DisabledTextBrush"] = "#8794A3",
                ["ReadOnlyBrush"] = "#F1F5F8", ["ScrollTrackBrush"] = "#F1F5FA",
                ["ScrollThumbBrush"] = "#B3C2D0"
            }
            : new()
            {
                ["PageBrush"] = "#101722", ["PanelBrush"] = "#192536", ["CardBrush"] = "#223146",
                ["InputBrush"] = "#121E2D", ["TextBrush"] = "#EDF4FC", ["MutedBrush"] = "#A3B6CC",
                ["AccentBrush"] = "#59C3B5", ["AccentTextBrush"] = "#09261F",
                ["AccentHoverBrush"] = "#7ADBCF", ["AccentPressedBrush"] = "#41A99D",
                ["BorderBrush"] = "#34485F", ["HoverBorderBrush"] = "#6587A1",
                ["HoverBrush"] = "#30445E", ["SelectedBrush"] = "#274957",
                ["DisabledBrush"] = "#1A2533", ["DisabledTextBrush"] = "#6F8296",
                ["ReadOnlyBrush"] = "#1D2B3C", ["ScrollTrackBrush"] = "#192536",
                ["ScrollThumbBrush"] = "#4E657D"
            };

        ResourceDictionary resources = Application.Current.Resources;
        foreach (KeyValuePair<string, string> entry in colors)
        {
            Color color = (Color)ColorConverter.ConvertFromString(entry.Value);
            // WPF may freeze resource brushes. Replacement also updates DynamicResource consumers.
            resources[entry.Key] = new SolidColorBrush(color);
        }

        ThemeButton.Content = light ? "Тёмная тема" : "Светлая тема";
        ApplyTitleBarTheme(light);
    }

    // Windows 11 supports caption colors; older Windows versions may ignore them.
    // Failure is cosmetic and must not interrupt the application.
    private void ApplyTitleBarTheme(bool light)
    {
        nint handle = new WindowInteropHelper(this).Handle;
        if (handle == 0)
        {
            return;
        }

        try
        {
            int darkMode = light ? 0 : 1;
            _ = DwmSetWindowAttribute(handle, 20, ref darkMode, sizeof(int));

            int caption = ToColorRef(light ? "#F1F5FA" : "#101722");
            int captionText = ToColorRef(light ? "#17283A" : "#EDF4FC");
            _ = DwmSetWindowAttribute(handle, 35, ref caption, sizeof(int));
            _ = DwmSetWindowAttribute(handle, 36, ref captionText, sizeof(int));
        }
        catch (DllNotFoundException)
        {
            // Non-Windows execution is not supported, but the UI should fail gracefully.
        }
        catch (EntryPointNotFoundException)
        {
            // The installed Windows build does not support this decoration.
        }
    }

    private static int ToColorRef(string hex)
    {
        Color color = (Color)ColorConverter.ConvertFromString(hex);
        return color.R | (color.G << 8) | (color.B << 16);
    }

    [DllImport("dwmapi.dll", ExactSpelling = true)]
    private static extern int DwmSetWindowAttribute(nint hwnd, int attribute, ref int value, int size);

    private void SaveLogClick(object sender, RoutedEventArgs e)
    {
        SaveFileDialog dialog = new()
        {
            Title = "Save LibraryWorkbench log",
            FileName = "LibraryWorkbench-log.txt",
            Filter = "Text files (*.txt)|*.txt"
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        try
        {
            File.WriteAllLines(dialog.FileName,
                _model.Logs.Reverse().Select(line => $"{line.Time} [{line.Level}] {line.Message}"));
            _model.Log("UI", "Journal saved. Never enter secrets into test examples.");
        }
        catch (Exception error)
        {
            _model.Log("ERROR", "Failed to save log: " + error.GetType().Name);
        }
    }
}
