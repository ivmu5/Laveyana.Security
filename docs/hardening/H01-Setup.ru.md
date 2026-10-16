# H01 — сборка, CI и защита ветки

[English](H01-Setup.md) | **Русский**

**Статус на 16 октября 2026 года:** инфраструктура проверки работает. Workflow `Verify` успешно завершился на Windows и Ubuntu, включая проверки исходников/документации и обе группы NUnit. Репозиторий пока не выпущен; **аудит безопасности Phase 27 не завершён**.

## Воспроизводимая локальная проверка

- .NET SDK закреплён в [`global.json`](../../global.json): `10.0.400` и `latestPatch` в feature band 10.0.4xx.
- Версии пакетов централизованы в [`Directory.Packages.props`](../../Directory.Packages.props); созданные `packages.lock.json` хранятся в Git. Зависимости восстанавливаются в locked mode.
- Сохранены NUnit 4 + NUnit3TestAdapter + VSTest. Платформенные тесты пропускаются явно только на ОС, где они не применимы.
- Предупреждения компилятора считаются ошибками. XML-документация обязательна для исходников поставляемых библиотек, но не для методов test fixtures.

Из корня репозитория:

```sh
dotnet --version
dotnet restore Laveyana.Security.sln --locked-mode
python tools/verify_repository.py
python tools/verify_api_layout.py
python tools/verify_documentation.py
python tools/verify_documentation.py --self-test
dotnet build Laveyana.Security.sln --no-restore -c Release -warnaserror
dotnet test Laveyana.Security.sln --no-build --no-restore -c Release
```

После изменения зависимостей перегенерируйте lock-файлы скриптом [`scripts/Initialize-LockFiles.ps1`](../../scripts/Initialize-LockFiles.ps1) на доверенном компьютере с .NET SDK, проверьте изменения и закоммитьте. Нельзя редактировать lock-файлы вручную ради прохождения CI.

## GitHub Actions

Workflow `Verify` запускается для каждого Pull Request и при Push в `master` (включая Push после слияния). Отдельные Push в рабочие ветки не запускают `Verify`, чтобы избежать дублирования проверок открытых Pull Request. Обязательные имена проверок:

1. `Source & docs`
2. `Build & NUnit (ubuntu-latest)`
3. `Build & NUnit (windows-latest)`

Матрица использует Release-сборку и locked restore, сохраняет TRX и проверяет, что нужные платформенные NUnit-тесты действительно выполнялись.

Отдельный workflow [`Extended Regression`](../../.github/workflows/nightly.yml) запускается **1-го числа каждого месяца в 02:17 UTC** из основной ветки либо вручную через **Actions → Extended Regression → Run workflow**. Прежнее имя файла `nightly.yml` сохранено, чтобы не создавать дублирующий workflow. На `ubuntu-latest` и `windows-latest` выполняются однократные locked restore и Release-сборка, после чего **оба полных NUnit-проекта запускаются последовательно по пять раз**. Для каждого повтора сохраняются отдельные unit/integration TRX; `tools/check_trx.py` проверяет **каждый повтор независимо**, включая обязательные платформенные тесты. Ошибка любого теста или проверки TRX приводит к провалу соответствующего задания. Отчёты хранятся как artifacts 14 дней; лимит времени каждого задания — 90 минут.

`Extended Regression` **не** входит в обязательные status checks для `Protect master`: быстрым шлюзом Pull Request остаётся `Verify`. [Первый ручной запуск](https://github.com/ivmu5/Laveyana.Security/actions/runs/38908695165) на `master` завершился успешно 16 октября 2026 года на Windows и Ubuntu. Повторные успешные тесты помогают искать нестабильные регрессии, но не заменяют adversarial-тестирование по модели угроз, проверку конфликтов между процессами или имитацию внезапного отключения питания. В публичных репозиториях GitHub автоматически отключает проверки по расписанию после **60 дней без активности**; при необходимости включите workflow заново через Actions.

Активный GitHub ruleset `Protect master` защищает ветку по умолчанию (`master` на 16 октября 2026 года): обязательны Pull Request, все три успешные проверки и актуальность ветки относительно `master`. Запрещены force push и удаление ветки. Требуемое число одобрений пока равно нулю. Не обходите CI ради ускорения выпуска.

## Обычный процесс внесения изменений

```text
master (защищена)
  -> создать рабочую ветку
  -> изменить файлы, проверить локально, сделать commit
  -> отправить рабочую ветку
  -> создать Pull Request в master
  -> дождаться Windows + Ubuntu + source/docs checks
  -> выполнить merge при соблюдении требований
  -> синхронизировать локальную master
```

Пустая рабочая ветка не даст содержательного Pull Request; нужен реальный, проверяемый commit с документацией или исходниками.

## Границы подтверждённой проверки

- Зелёный CI означает, что тестируемая сборка и тесты проходят на CI runners. Это **не** независимый security audit и не доказательство безопасного production-хранилища.
- CI не подтверждает защиту от гонок замены Windows-путей, воспроизведения старого аутентичного snapshot, рисков nonce при backup/restore или потерь при внезапном отключении питания.
- GitHub rulesets находятся в настройках репозитория, а не внутри экспорта исходников. Для нового репозитория защиту ветки и обязательные проверки нужно настроить заново.
- Автоматическая публикация в NuGet отсутствует; в проектах установлено `IsPackable=false`.

Оставшиеся blockers: [отчёт по безопасности](../audit/Laveyana.Security.Phase27.SecurityAudit.ru.md). История компиляторных изменений, позволивших получить зелёный CI: [H01 Compilation Repair](H01-CompilationRepair.ru.md).
