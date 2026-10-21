# Laveyana.Security LibraryWorkbench

Internal Windows WPF/.NET 10 learning and debugging application. **EXPERIMENTAL / TEST ONLY**; do not use with production data or actual secrets.

Open `tools/LibraryWorkbench/Laveyana.Security.LibraryWorkbench.sln` in Visual Studio 2022 (.NET 10 workload), set `Laveyana.Security.App.LibraryWorkbench` as startup project, select Debug and press F5. This Windows-only solution is separate from the cross-platform root solution. Worker output is built and copied to the WPF output `worker` folder automatically.

Explore public types with Reflection, inspect interfaces, methods and parameter editors; the unknown method execution policy is **deny by default**. `LocalCryptography` has a custom working view for SHA-256 and HMAC; an allowlisted, constrained `GenerateRandomBytes(int)` has a safe typed invocation adapter. The separate worker process supports two synthetic examples through named pipes. Source navigation and text-only logging are included. Settings are local per-user.

For a complete capability matrix, configuration and security limitations see [README.ru.md](README.ru.md).

Windows build/run is not verified in this environment; the delivered ZIP is source code and a Visual Studio solution, not a precompiled executable.
