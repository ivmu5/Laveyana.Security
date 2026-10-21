using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Reflection;
using System.Runtime.CompilerServices;
using Laveyana.Security.App.LibraryWorkbench.Discovery;

namespace Laveyana.Security.App.LibraryWorkbench.ViewModels;

public sealed class MainViewModel : INotifyPropertyChanged
{
    private readonly IReadOnlyList<TypeItem> _allTypes;
    private string _filter = string.Empty;
    private TypeItem? _selected;
    private string _status = "Ready. Experimental/test-only library; use synthetic data.";

    public MainViewModel(TypeCatalog catalog)
    {
        _allTypes = catalog.Read();
        RebuildSearch();
        SelectedType = FilteredTypes.FirstOrDefault(item => item.Type.Name == "LocalCryptography")
            ?? FilteredTypes.FirstOrDefault();
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public ObservableCollection<TypeItem> FilteredTypes { get; } = [];
    public ObservableCollection<MethodItem> Methods { get; } = [];
    public ObservableCollection<LogLine> Logs { get; } = [];

    public string SearchText
    {
        get => _filter;
        set
        {
            if (_filter == value)
            {
                return;
            }

            _filter = value;
            Raise();
            RebuildSearch();
        }
    }

    public TypeItem? SelectedType
    {
        get => _selected;
        set
        {
            if (_selected == value)
            {
                return;
            }

            _selected = value;
            Raise();
            Raise(nameof(SelectedTitle));
            Raise(nameof(SelectedSubtitle));
            Raise(nameof(SelectedDescription));
            Raise(nameof(Relationships));
            Raise(nameof(IsCryptoView));
            Methods.Clear();
            if (value is not null)
            {
                foreach (MethodInfo method in value.Type.GetMethods(BindingFlags.Public | BindingFlags.Static |
                             BindingFlags.Instance | BindingFlags.DeclaredOnly)
                             .Where(method => !method.IsSpecialName)
                             .OrderBy(method => method.Name))
                {
                    Methods.Add(new MethodItem(method));
                }
            }
        }
    }

    public string SelectedTitle => _selected?.DisplayName ?? "Select a type";
    public string SelectedSubtitle => _selected is null ? "" : $"{_selected.Kind}  |  {_selected.Group}";
    public string SelectedDescription => _selected?.FullName ?? "Select a class or interface on the left.";
    public bool IsCryptoView => _selected?.Type.FullName == "Laveyana.Security.Primitives.LocalCryptography";

    public string Relationships
    {
        get
        {
            Type? type = _selected?.Type;
            if (type is null)
            {
                return string.Empty;
            }

            string interfaces = type.GetInterfaces().Length == 0
                ? "No implemented interfaces"
                : string.Join(Environment.NewLine, type.GetInterfaces().Select(item => "  " + item.FullName));
            string implementations = "";
            if (type.IsInterface)
            {
                Type[] matches = _allTypes.Where(item => item.Type.IsClass && type.IsAssignableFrom(item.Type))
                    .Select(item => item.Type).Take(100).ToArray();
                implementations = matches.Length == 0 ? "No public implementations discovered in scanned assemblies"
                    : string.Join(Environment.NewLine, matches.Select(item => "  " + item.FullName));
            }

            string constructors = type.GetConstructors().Length == 0
                ? "  No public constructors"
                : string.Join(Environment.NewLine, type.GetConstructors().Select(ctor =>
                    "  " + type.Name + "(" + string.Join(", ", ctor.GetParameters().Select(parameter =>
                        parameter.ParameterType.Name + " " + parameter.Name)) + ")"));
            return $"Assembly: {type.Assembly.GetName().Name}{Environment.NewLine}"
                + $"Base type: {type.BaseType?.FullName ?? "(none)"}{Environment.NewLine}"
                + $"Interfaces:{Environment.NewLine}{interfaces}{Environment.NewLine}"
                + (type.IsInterface ? $"Implementations:{Environment.NewLine}{implementations}{Environment.NewLine}" : "")
                + $"Public constructors / dependencies:{Environment.NewLine}{constructors}{Environment.NewLine}"
                + $"Public properties: {type.GetProperties(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance).Length}";
        }
    }

    public string StatusText
    {
        get => _status;
        set { _status = value; Raise(); }
    }

    public void Log(string level, string message)
    {
        Logs.Insert(0, new LogLine(DateTimeOffset.Now.ToString("HH:mm:ss"), level, message));
        if (Logs.Count > 300)
        {
            Logs.RemoveAt(Logs.Count - 1);
        }

        StatusText = message;
    }

    private void RebuildSearch()
    {
        string search = _filter.Trim();
        TypeItem? previous = _selected;
        FilteredTypes.Clear();
        foreach (TypeItem item in _allTypes.Where(item => string.IsNullOrEmpty(search)
                     || item.FullName.Contains(search, StringComparison.OrdinalIgnoreCase)
                     || item.Group.Contains(search, StringComparison.OrdinalIgnoreCase)
                     || item.Kind.Contains(search, StringComparison.OrdinalIgnoreCase)))
        {
            FilteredTypes.Add(item);
        }

        if (previous is not null && !FilteredTypes.Contains(previous))
        {
            SelectedType = FilteredTypes.FirstOrDefault();
        }
    }

    private void Raise([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

public sealed record MethodItem(MethodInfo Method)
{
    public string Name => Method.Name;
    public string Signature => $"{Friendly(Method.ReturnType)} {Method.Name}("
        + string.Join(", ", Method.GetParameters().Select(parameter =>
            $"{Friendly(parameter.ParameterType)} {parameter.Name}")) + ")";

    private static string Friendly(Type type)
    {
        if (type == typeof(void))
        {
            return "void";
        }

        if (type == typeof(int))
        {
            return "int";
        }

        if (type == typeof(bool))
        {
            return "bool";
        }

        if (type == typeof(string))
        {
            return "string";
        }

        return type.Name;
    }
}

public sealed record LogLine(string Time, string Level, string Message);
