using System.Diagnostics;
using System.IO.Pipes;
using System.IO;
using System.Text;
using System.Text.Json;
using Laveyana.Security.App.LibraryWorkbench.Contracts;

namespace Laveyana.Security.App.LibraryWorkbench.Services;

public sealed class WorkerRunner
{
    private static readonly HashSet<string> AllowedScenarios = ["temp-file-roundtrip", "worker-crypto"];

    public async Task<ScenarioResponse> ExecuteAsync(string scenarioId, CancellationToken cancellationToken = default)
    {
        if (!AllowedScenarios.Contains(scenarioId))
        {
            throw new InvalidOperationException("Scenario not in the allowlist.");
        }

        string directory = Path.Combine(AppContext.BaseDirectory, "worker");
        string executable = Path.Combine(directory, "Laveyana.Security.App.LibraryWorkbench.Worker.exe");
        string dll = Path.Combine(directory, "Laveyana.Security.App.LibraryWorkbench.Worker.dll");
        if (!File.Exists(executable) && !File.Exists(dll))
        {
            throw new FileNotFoundException("Worker not built. Build the LibraryWorkbench solution first.", executable);
        }

        string pipeName = "laveyana-workbench-" + Guid.NewGuid().ToString("N");
        string requestId = Guid.NewGuid().ToString("N");
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(12));
        using NamedPipeServerStream server = new(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        ProcessStartInfo start = new()
        {
            FileName = File.Exists(executable) ? executable : "dotnet",
            WorkingDirectory = directory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true
        };
        if (!File.Exists(executable))
        {
            start.ArgumentList.Add(dll);
        }

        start.ArgumentList.Add("--pipe");
        start.ArgumentList.Add(pipeName);
        using Process child = Process.Start(start) ?? throw new IOException("Unable to start worker.");
        try
        {
            await server.WaitForConnectionAsync(timeout.Token);
            using StreamReader reader = new(server, Encoding.UTF8, leaveOpen: true);
            using StreamWriter writer = new(server, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };
            await writer.WriteLineAsync(JsonSerializer.Serialize(new ScenarioRequest(requestId, scenarioId)).AsMemory(),
                timeout.Token);
            string? reply = await reader.ReadLineAsync(timeout.Token);
            ScenarioResponse response = reply is null
                ? throw new InvalidDataException("Worker ended without a response.")
                : JsonSerializer.Deserialize<ScenarioResponse>(reply)
                    ?? throw new InvalidDataException("Worker returned invalid JSON.");
            if (response.RequestId != requestId)
            {
                throw new InvalidDataException("Worker response correlation failed.");
            }

            await child.WaitForExitAsync(timeout.Token);
            if (child.ExitCode != 0)
            {
                throw new IOException($"Worker exited with code {child.ExitCode}.");
            }

            return response;
        }
        finally
        {
            if (!child.HasExited)
            {
                child.Kill(entireProcessTree: true);
            }
        }
    }
}
