namespace Laveyana.Security.App.LibraryWorkbench.Contracts;

public sealed record ScenarioRequest(string RequestId, string ScenarioId);
public sealed record ScenarioResponse(string RequestId, bool Succeeded, string Message, long ElapsedMilliseconds);
