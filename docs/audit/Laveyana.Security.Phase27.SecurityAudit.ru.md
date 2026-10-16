# Laveyana.Security — Phase 27: отчёт о проверке безопасности

[English](Laveyana.Security.Phase27.SecurityAudit.md) | **Русский**

**Дата:** 2026-10-10  
**База:** архив `Laveyana.Security_Phase26_2026-10-10.zip`  
**Статус:** **PARTIAL / RELEASE BLOCKED**. Этот документ фиксирует выполненный статический review и внесённые исправления, **не** удостоверяет полную приёмку Phase 27.

## Объём и метод

Проверены границы семи проектов, исходники провайдеров AES-GCM/HMAC/ECDH/подписи, nonce engine, protected storage, Linux/Windows path guards, Windows DPAPI, sensitive memory, audit и API ввода/вывода, а также имеющиеся тестовые контракты и CI. Выполнены `tools/verify_repository.py` и `tools/verify_documentation.py` с самопроверками. Просмотрены пути исполнения и обработки исключений, повторные обращения к историческим версиям, ограничения размера, копирование входных массивов, очистка секретных буферов. Добавлены тесты мутаций четырёх сериализованных форматов и инъекции ожидания I/O.

**Не выполнялись:** `dotnet restore`, `dotnet build`, NUnit, Windows DPAPI, межпроцессные гонки, тесты с подменой reparse points, реальная аварийная потеря питания, fuzzing работающего C#-декодера. В текущей среде нет .NET SDK. Наличие NUnit-тестов и CI-конфигурации не засчитывается как их успешный запуск.

## Реестр выводов по критичности

| ID | Приоритет | Место / подтверждение | Наблюдение и последствия | Статус |
| --- | --- | --- | --- | --- |
| SA-01 | **BLOCKER** | `global.json`, `.github/workflows/verify.yml` | Нет подтверждённой сборки и фактического запуска unit/integration tests под .NET 10; состояние компиляции и поведения неизвестно. | **Открыто** |
| SA-02 | **HIGH** | `FileSystemKeyStore.cs`: `AtomicWriteAsync`, `ReadBoundedAsync`; `WindowsStorePathGuard.cs` | Windows проверяет путь до/после файловых операций, но открытие и замена используют имена. TOCTOU при изменении пути между проверкой и I/O не исключён. | **Открыто**; `EnableExperimentalWrites` обязателен |
| SA-03 | **HIGH** | `FileSystemKeyStore.cs`: `Capabilities = new(false)`, `LoadAsync` | Аутентификация snapshot не обеспечивает защиту от восстановления **старого корректного** файла. Возможен возврат состояний ключей, прежних ревизий и tombstones; нет внешнего монотонного authority. | **Открыто**, требуется независимая rollback-resistant граница |
| SA-04 | **HIGH / RELEASE GATE** | `AeadNoncePolicyEngine.cs`: `RandomBudgets`, `MaxRandomizedInvocationsPerProcessKey` | Случайный nonce и счётчик действуют только в процессе: они не являются независимой гарантией на всю жизнь материала после restart/restore/нескольких процессов. Детерминированный allocator зависит от внешнего достоверного механизма. | **Открыто** как инфраструктурная гарантия |
| SA-05 | **MEDIUM** | `SecurityObservability.cs`: `await _auditSink.WriteAsync(... CancellationToken.None)` | Необязательный sink может зависнуть без ограничений и отложить завершение уже исполненной операции; аварийный повтор клиентом повышает неопределённость. Исключения sink подавляются, но бесконечное ожидание — нет. | **Открыто**; ограничить время доставки / изолировать выполнение |
| SA-06 | **MEDIUM** | `SoftwareKeyProviderBackend.Aead.cs` | Mutable AAD из `ReadOnlyMemory<byte>` мог измениться во время ожидания I/O и поменять криптографический контекст операции. | **Исправлено в исходниках**, тесты добавлены, **не запущены** |
| SA-07 | **MEDIUM** | `ManagedSignatureBackend.cs` | Mutable message копировалось лишь после асинхронной проверки метаданных; содержимое подписи могло не соответствовать состоянию на момент вызова. | **Исправлено в исходниках**, тест добавлен, **не запущен** |
| SA-08 | **RELEASE GATE** | `FileSystemKeyStore.cs`, `LinuxSecureDirectory.cs`, `WindowsDpapiUserProtector.cs` | Проверки владельцев/прав, descriptor-relative I/O, recovery, durability и P/Invoke требуют тестов на целевых Windows/Linux и при adversarial concurrency. | **Открыто** |
| SA-09 | **LIMITATION** | `EphemeralSignatureKeyOperations.cs`, `EphemeralEcdhKeyOperations.cs` | Текущие асимметричные исполнители — временные in-process; постоянный отзыв и protected asymmetric keystore не реализованы. | Документировано, не маркировать как production-провайдер |

### Замечания об области применимости

- HPKE `Seal/Open` и streaming AEAD **не поддерживаются**: отсутствие API безопаснее неподтверждённой реализации.
- Secret provider обязан сам выполнять авторизацию; библиотека не объявляет универсальную политику доступа.
- `SensitiveMaterialLease` стирает только собственные managed-буферы; память OS/runtime, копии в callback и удалённые дисковые блоки не охватываются.
- Защита от rollback и nonce uniqueness при нескольких процессах не может быть удостоверена одной локальной статической проверкой.
- Дефектов критичности `CRITICAL` с доказанной эксплуатацией по результатам этого **неполного** review не подтверждено. Это не означает отсутствие таких дефектов.

## Фактически внесённые изменения

1. `SoftwareKeyProviderBackend.Aead.cs`: снимок AAD до первого асинхронного ожидания, ограничение длины **до копирования**, очистка снимка при любом завершении.
2. `ManagedSignatureBackend.cs`: аналогичный снимок входного сообщения до lookup, очистка временного массива при исключении и отмене.
3. `SoftwareAeadEncryptionTests.cs`: два теста на изменение AAD при остановленном metadata lookup.
4. `ManagedMacSignatureTests.cs`: один тест на изменение сообщения в signing/verify при остановленном metadata lookup.
5. `SecurityCodecMutationTests.cs`: детерминированные single-byte mutations и мусорный corpus для `LEP1`, `LDP1`, `LSP1`, `LMR1`; декодирование **не** считается подтверждением аутентичности.

Публичные интерфейсы и сериализованные wire-форматы намеренно не менялись. Два исправления требуют компиляции и проверки совместимости, прежде чем их можно считать принятыми.

## Обязательная release-gate матрица

| Проверка | Среда | Требование |
| --- | --- | --- |
| Restore / Release build / warnings as errors | Windows + Linux, .NET SDK из `global.json` | Успешно без исключений |
| Полный unit + integration NUnit | Windows + Linux | Все тесты проходят без Skip, кроме объяснённых feature gates |
| Codec fuzz & cross-version golden files | .NET исполнение, обе платформы | Бounded parser, deterministic round trips, unknown-version rejection |
| Windows ACL, symlink/junction/reparse races | Windows, несколько процессов, adversarial mutation | Не удаётся перенаправить запись/чтение за закреплённый доверенный каталог |
| Linux openat/statx/flock/rename/fsync | Linux, несколько процессов и controlled crash | Отсутствие race, ACL bypass и неконсистентных транзакций |
| Rollback restore / nonce budget across processes | Реальное выбранное хранилище и allocator | Никакого повторного nonce для одной версии ключа, отказ при откате |
| DPAPI current user / wrong user / profile unavailable | Windows | Fail-closed, отсутствие plaintext fallback |
| Key lifecycle + CAS + uncertain commit + rotation/migration | Fault-injection, concurrent hosts | Нет повторного использования версий и автоматического повтора неопределённых commit |
| Public API / nullable / package-vulnerability / dependency review | CI и ручной diff | Нет неподтверждённых breaking changes или известных опасных зависимостей |
| Внешний security review | Независимый специалист | Зафиксировано и согласовано решение по остаточным рискам |

## Решение по выпуску

**NO-GO** для production и реальных секретов. Текущий этап Phase 27 **не закрыт**. Первоначально планировались сборка и запуск NUnit в .NET 10 (позднее выполнены в H01 CI); затем остаётся устранить SA-02/SA-03/SA-04, проводятся платформенные adversarial tests и повторный полный аудит. Положительный результат статических проверок не заменяет эти требования.

## Дополнение по проверкам H01 — 16 октября 2026 года

Этот раздел обновляет *доказательства*, но не подменяет исторический объём статического анализа Phase 27 или принятые архитектурные решения.

- SA-01 (отсутствие подтверждённой сборки/NUnit): **подтверждение получено.** GitHub Actions `Verify` успешно прошёл проверку исходников/документации и Release + NUnit на Ubuntu и Windows.
- В ходе последующих CI-исправлений учтены различия владельцев Windows ACL (token owner и current user), Linux native-descriptor stream и тест небезопасных прав родительского каталога с учётом `umask`. Сами по себе они не снимают остальные риски FileSystem.
- Активный ruleset `Protect master` требует PR и три проверки. Это защита процесса разработки, а не криптографическая сертификация.
- SA-02 (Windows TOCTOU), SA-03 (rollback), SA-04 (долговременные ограничения nonce), SA-05 (время доставки best-effort аудита), SA-08 (adversarial platform tests) и другие условия Phase 27 **остаются открытыми**. Зелёный CI не доказывает отсутствие неохваченных уязвимостей.

**Решение о релизе — NO-GO** до выполнения оставшихся security gates. Воспроизводимые команды: [H01](../hardening/H01-Setup.ru.md).
