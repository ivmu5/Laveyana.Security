# H01 — первый запуск на Windows (пошагово)

Этот архив основан на Phase 27 Partial Audit. **Сборка и тесты пока не подтверждены; не использовать библиотеку с настоящими секретами.** Изменены только конфигурация разработки, CI и платформенная маркировка тестов. Публикация в NuGet отключена (`IsPackable=false`).

## Что уже подготовлено

- .NET 10 SDK: `global.json` закреплён за feature band `10.0.400` с `latestPatch` (установленный у владельца `10.0.401` подходит).
- NUnit + VSTest сохранены.
- Включена генерация настоящих `packages.lock.json` при `dotnet restore`.
- Проверка NuGet `--locked-mode` при каждом Push и Pull Request.
- Проверки Windows и Linux в GitHub Actions, TRX и требование успешного выполнения ключевых платформенных тестов (не просто обнаружения/пропуска).
- Отдельный ночной workflow: три последовательных запуска обеих тестовых сборок на Windows и Linux. Это повторные регрессионные проверки, **ещё не полноценный долгосрочный stress/fault-injection test suite**.
- Неявно успешные проверки DPAPI на Linux заменены явным `Assert.Ignore` и категориями NUnit.

## Первый запуск — один шаг за раз

1. Распакуйте ZIP в обычную рабочую папку, например `C:\Projects\Laveyana.Security`. Архив **не содержит `.git`**.
2. Откройте PowerShell/Терминал **в папке, где лежит `Laveyana.Security.sln`**.
3. Проверьте SDK: `dotnet --version`. Ожидается `10.0.401` или другая `10.0.4xx`.
4. **До первого Git push** создайте настоящие lock-файлы одной командой:

   ```powershell
   .\scripts\Initialize-LockFiles.ps1
   ```

   Скрипт запустит `dotnet restore --force-evaluate`, проверит наличие lock-файлов всех проектов с прямыми NuGet-зависимостями и проверит `dotnet restore --locked-mode`. Нужен доступ к NuGet-источникам. Если политика PowerShell запрещает запуск сценария, можно выполнить команды вручную:

   ```powershell
   dotnet restore .\Laveyana.Security.sln --force-evaluate
   dotnet restore .\Laveyana.Security.sln --locked-mode
   ```

   **Нельзя создавать или исправлять `packages.lock.json` вручную.** Они не вложены в архив, потому что здесь недоступны .NET SDK и проверенный NuGet restore. CI намеренно не пройдёт без настоящих закоммиченных lock-файлов.
5. При успешном restore проверьте компиляцию:

   ```powershell
   dotnet build .\Laveyana.Security.sln -c Release --no-restore -warnaserror
   ```

   Ошибки компиляции возможны и должны быть исправлены до закрытия H01. Зелёный CI пока **не подтверждён**.
6. Затем запустите тесты:

   ```powershell
   dotnet test .\Laveyana.Security.sln -c Release --no-build --no-restore
   ```

7. Создавайте локальный Git-репозиторий и репозиторий GitHub **после** проверки восстановленных зависимостей; в первый commit включите все созданные `packages.lock.json`, исходники и `.github/workflows`.
8. После первого Push откройте GitHub → вкладка **Actions**. При нормальной работе появятся jobs `Source & docs`, `Build & NUnit (ubuntu-latest)` и `Build & NUnit (windows-latest)`. Каждый job должен пройти. Архивы TRX доступны в отчётах workflow.
9. После появления успешных проверок настройте Settings → Rules → Rulesets (или Branches → Branch protection) для `main`: Require a pull request before merging, Require status checks, Require branches to be up to date, Block force pushes, и ограничьте bypass/прямой Push. Эти права нельзя безопасно «прописать в ZIP» — они устанавливаются в настройках конкретного GitHub-репозитория. Обязательные проверки: `Source & docs` и обе `Build & NUnit` (их отображаемые имена уточняйте после первого запуска).

## Ограничения

- Git и GitHub **не создавались** и публикация на NuGet **не включена**.
- Статическая корректность workflow не равна успешному выполнению на GitHub-hosted runner.
- Нельзя утверждать, что H01 закрыт до реальной сборки и NUnit на Windows/Linux.
- Для старта не нужно создавать API-токены и не нужно публиковать NuGet-пакеты.
- Вариант с требованием PR и проверок зависит от настроек и возможностей конкретного GitHub-репозитория; после первого Push настроим его вместе.
