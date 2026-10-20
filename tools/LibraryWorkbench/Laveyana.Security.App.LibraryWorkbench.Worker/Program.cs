using System.Diagnostics;
using System.IO.Pipes;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Laveyana.Security.App.LibraryWorkbench.Contracts;
using Laveyana.Security.Primitives;

if (args.Length != 2 || args[0] != "--pipe" || string.IsNullOrWhiteSpace(args[1]) || args[1].Length > 180)
{
    Environment.ExitCode = 2;
    return;
}

try
{
    using NamedPipeClientStream client = new(".", args[1], PipeDirection.InOut, PipeOptions.Asynchronous);
    using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(15));
    await client.ConnectAsync(timeout.Token);
    using StreamReader reader = new(client, Encoding.UTF8, leaveOpen: true);
    using StreamWriter writer = new(client, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };
    string? line = await reader.ReadLineAsync(timeout.Token);
    ScenarioRequest? request = line is null ? null : JsonSerializer.Deserialize<ScenarioRequest>(line);
    if (request is null || string.IsNullOrEmpty(request.RequestId))
    {
        Environment.ExitCode = 3;
        return;
    }

    Stopwatch watch = Stopwatch.StartNew();
    ScenarioResponse response;
    try
    {
        string message = request.ScenarioId switch
        {
            "temp-file-roundtrip" => await TemporaryRoundtripAsync(timeout.Token),
            "worker-crypto" => WorkerCrypto(),
            _ => throw new InvalidOperationException("The scenario is not registered in the worker allowlist.")
        };
        response = new ScenarioResponse(request.RequestId, true, message, watch.ElapsedMilliseconds);
    }
    catch (Exception error)
    {
        response = new ScenarioResponse(request.RequestId, false, $"{error.GetType().Name}: {error.Message}", watch.ElapsedMilliseconds);
    }

    await writer.WriteLineAsync(JsonSerializer.Serialize(response).AsMemory(), timeout.Token);
}
catch (Exception error)
{
    Console.Error.WriteLine($"Worker communication failed: {error.GetType().Name}");
    Environment.ExitCode = 4;
}

static string WorkerCrypto()
{
    byte[] input = Encoding.UTF8.GetBytes("Laveyana.Security.LibraryWorkbench / synthetic worker test");
    byte[] digest = LocalCryptography.Sha256(input);
    try
    {
        return $"Library SHA-256 successfully processed {input.Length} synthetic bytes. Digest prefix: {Convert.ToHexString(digest.AsSpan(0, 8))}";
    }
    finally
    {
        CryptographicOperations.ZeroMemory(input);
        CryptographicOperations.ZeroMemory(digest);
    }
}

static async Task<string> TemporaryRoundtripAsync(CancellationToken cancellationToken)
{
    string root = Path.Combine(Path.GetTempPath(), "Laveyana.LibraryWorkbench", "run-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(root);
    try
    {
        string file = Path.Combine(root, "synthetic-snapshot.bin");
        byte[] bytes = Encoding.UTF8.GetBytes("SYNTHETIC WORKBENCH DATA: not a real key");
        try
        {
            await File.WriteAllBytesAsync(file, bytes, cancellationToken);
            byte[] loaded = await File.ReadAllBytesAsync(file, cancellationToken);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(bytes, loaded))
                {
                    throw new InvalidDataException("Synthetic data changed during the roundtrip.");
                }

                byte[] hash = LocalCryptography.Sha256(loaded);
                try
                {
                    return $"Temporary roundtrip succeeded: {loaded.Length} bytes; SHA-256 prefix {Convert.ToHexString(hash.AsSpan(0, 8))}. Temporary files will be removed.";
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(hash);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(loaded);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }
    finally
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, true);
        }
    }
}
