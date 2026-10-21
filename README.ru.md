# Laveyana.Security

[English](README.md) | **Русский**

[![Verify](https://github.com/ivmu5/Laveyana.Security/actions/workflows/verify.yml/badge.svg)](https://github.com/ivmu5/Laveyana.Security/actions/workflows/verify.yml)

`Laveyana.Security` — набор библиотек .NET 10 для криптографических примитивов, версионированного жизненного цикла ключей, типизированных возможностей провайдеров и явно защищённого постоянного хранения ключей. Основная логика и платформенные интеграции разделены по сборкам. Репозиторий находится **до публичного релиза**; файловое хранилище остаётся **экспериментальным и не одобрено для production-секретов**.

**Историческая база CI (16 октября 2026 года):** приложенная документация фиксирует успешные Release-проверки Windows/Ubuntu. Позднее SA-02 получил ограниченное закрытие. **Текущая сводная проверка (21 октября 2026 года): SA-03/SA-04/SA-08 OPEN; Phase 27 NO-GO.** Новый Linux-прогон описан в `VERIFICATION_REPORT.ru.md` комплекта исправлений; Windows и реальная потеря питания для этого комплекта не проверялись. См. [отчёт по безопасности](docs/audit/Laveyana.Security.Phase27.SecurityAudit.ru.md).

## Содержание

- [Возможности](#возможности)
- [Архитектура и точки входа](#архитектура-и-точки-входа)
- [Быстрый старт](#быстрый-старт)
- [Проверки](#проверки)
- [Границы безопасности и жизненного цикла](#границы-безопасности-и-жизненного-цикла)
- [Документация](#документация)

## Возможности

- Локальные RNG, SHA-2, HMAC, HKDF и PBKDF2, программные криптографические операции с явной политикой алгоритмов.
- Непрозрачные идентификаторы провайдеров и ключей, точные версии, операции через capabilities и переходы жизненного цикла.
- Контракты управляемого AEAD-шифрования, MAC, подписи/проверки и derivation с явным владением чувствительной памятью.
- Версионированные форматы хранения, программный key provider, необязательный контракт rollback-protected nonce allocator и явные операции миграции провайдеров.
- Экспериментальное файловое `IKeyStore`, Windows DPAPI CurrentUser protector, DI, опциональный worker ротации и телеметрия без секретных данных.

**Не реализовано:** публичное HPKE `Seal`/`Open`, шифрование потоков через AEAD, универсальный постоянный исполнитель асимметричных приватных ключей и встроенный постоянный generic secret backend. Наличие соседних интерфейсов и проектных документов не означает поддержки этих возможностей.

## Архитектура и точки входа

| Сборка | Назначение и ключевые точки входа |
| --- | --- |
| `Laveyana.Security.Abstractions` | [Идентификаторы ключей](src/Laveyana.Security.Abstractions/Identifiers/KeyReference.cs), [типизированные capabilities](src/Laveyana.Security.Abstractions/Capabilities/EncryptionKey.cs), [контракт хранилища](src/Laveyana.Security.Abstractions/Storage/IKeyStore.cs), [контракт protector](src/Laveyana.Security.Abstractions/Protection/IKeyStoreProtector.cs). |
| `Laveyana.Security` | [LocalCryptography](src/Laveyana.Security/Primitives/LocalCryptography.cs), [SoftwareKeyProviderBackend](src/Laveyana.Security/Software/SoftwareKeyProviderBackend.cs), [ProviderRegistry](src/Laveyana.Security/Providers/ProviderRegistry.cs), lifecycle, migration, observability. |
| `Laveyana.Security.FileSystem` | [FileSystemKeyStore](src/Laveyana.Security.FileSystem/Storage/FileSystemKeyStore.cs), [опции](src/Laveyana.Security.FileSystem/Storage/FileSystemKeyStoreOptions.cs), проверки Windows ACL и Linux-путей через дескрипторы. **Экспериментально.** |
| `Laveyana.Security.Windows` | [WindowsDpapiUserProtector](src/Laveyana.Security.Windows/Protection/WindowsDpapiUserProtector.cs), выбирается явно, работает только на Windows. |
| `Laveyana.Security.DependencyInjection` | [AddSecurity / AddSecurityDefaults](src/Laveyana.Security.DependencyInjection/Composition/SecurityServiceCollectionExtensions.cs), [composition builder](src/Laveyana.Security.DependencyInjection/Composition/SecurityCompositionBuilder.cs), необязательный worker ротации. |

```text
Приложение
  -> Laveyana.Security.DependencyInjection (необязательная явная композиция)
  -> Laveyana.Security + Laveyana.Security.Abstractions
                  -> контракты provider / store / protector
                  -> необязательные FileSystem store и Windows protector
```

В solution также есть `Laveyana.Security.Tests` (модульные и контрактные тесты) и `Laveyana.Security.IntegrationTests` (платформенные, файловые, DI и worker-сценарии). Публичные контракты не зависят от конкретного пути на диске или Windows-protector.

## Быстрый старт

Для локальных операций с памятью, которой владеет вызывающий код, подключите `Laveyana.Security` и используйте существующий публичный API:

```csharp
using System.Security.Cryptography;
using Laveyana.Security.Primitives;

byte[] key = LocalCryptography.GenerateRandomBytes(32);
try
{
    byte[] message = "example"u8.ToArray();
    byte[] tag = LocalCryptography.HmacSha256(key, message);
    bool verified = LocalCryptography.VerifyHmacSha256(key, message, tag);
    // Use verified for application logic; do not log the key.
}
finally
{
    CryptographicOperations.ZeroMemory(key);
}
```

Это пример локального примитива, **а не** протокол аутентификации или полноценного управления ключами. Для управляемых ключей приложение явно выбирает backend и доверенные `IKeyStore` / `IKeyStoreProtector` и использует контракты провайдера. `AddSecurityDefaults` **не** генерирует ключи, не выбирает незащищённое хранилище, не создаёт файловый store и не запускает worker автоматически.

<details>
<summary>Композиция провайдеров и ограничения файловых записей</summary>

[`SecurityCompositionBuilder`](src/Laveyana.Security.DependencyInjection/Composition/SecurityCompositionBuilder.cs) поддерживает явную регистрацию провайдеров ключей, провайдеров секретов, protector, store, nonce allocator и observability. Композиция регистрируется однократно; несовместимые регистрации приводят к ошибке, а не к незаметному переопределению. Backend обязан проверять права на выполнение операции, а не только во время metadata preflight.

[`FileSystemKeyStoreOptions`](src/Laveyana.Security.FileSystem/Storage/FileSystemKeyStoreOptions.cs) требует абсолютный путь корневого каталога. `EnableExperimentalWrites` по умолчанию `false`; включение допускается **только для экспериментов вне production**. Даже корректно работающий DPAPI не делает файловое хранилище одобренным для production. Приложение отвечает за доверенные идентификаторы процессов, изоляцию каталога, резервное копирование и независимую защиту от rollback, если она нужна.

</details>

## Проверки

В приложенном экспорте нет файлов `.github/workflows`. Описание CI ниже относится к исторической конфигурации проекта, а не к новой проверке удалённых workflows; они не изменялись и не воссоздавались. Политика ежемесячного/ручного расширенного прогона сохранена.

Установите SDK, указанный в [`global.json`](global.json) (.NET SDK `10.0.400` с `latestPatch` в линейке 10.0.4xx). NuGet lock-файлы уже фиксируются в Git; CI восстанавливает зависимости в locked mode.

```sh
python tools/verify_repository.py
python tools/verify_api_layout.py
python tools/verify_documentation.py
python tools/verify_documentation.py --self-test
dotnet restore Laveyana.Security.sln --locked-mode
dotnet build Laveyana.Security.sln -c Release --no-restore -warnaserror
dotnet test Laveyana.Security.sln -c Release --no-build --no-restore
```

GitHub Actions запускает `Source & docs`, `Build & NUnit (ubuntu-latest)` и `Build & NUnit (windows-latest)` для каждого Pull Request и после Push в `master` (без дублирующих проверок при Push в рабочие ветки) с TRX-отчётами. Активный ruleset `Protect master` защищает ветку по умолчанию: обязателен Pull Request и все три проверки, запрещены force push и удаление. Текущая основная ветка — `master`. Отдельный [workflow Extended Regression](https://github.com/ivmu5/Laveyana.Security/blob/master/.github/workflows/nightly.yml) выполняет пять повторов полного NUnit-набора на каждой ОС **1-го числа каждого месяца в 02:17 UTC** либо вручную через GitHub Actions. Первый ручной запуск на `master` успешно прошёл 16 октября 2026 года (Windows и Ubuntu). Успешная локальная сборка не заменяет платформенную проверку и security-приёмку. Подробнее: [проверки H01](docs/hardening/H01-Setup.ru.md).

## Границы безопасности и жизненного цикла

- FileSystem остаётся **экспериментальным**: обычные записи требуют opt-in, rollback/crash/durability gates открыты. Ограниченное закрытие SA-02 по изоляции путей сохраняется; backend не предназначен для production-секретов.
- Аутентификация сохранённых данных сама по себе **не** предотвращает восстановление ранее действительного snapshot. Для rollback-sensitive задач необходимо независимое доверенное состояние.
- Управляемое randomized AES-GCM шифрование разрешено только для материала, **созданного тем же экземпляром `SoftwareKeyProviderBackend`**, максимум `2^20` выданных nonce за поддерживаемый срок жизни материала. Новый backend, перезапуск, импорт или открытие сохранённого ключа не восстанавливают бюджет и происхождение: для нового шифрования нужна явная ротация на свежий материал. Историческое расшифрование доступно. Nonce вероятностные; строгая уникальность не заявляется. Клонирование памяти процесса/VM не входит в поддерживаемую модель срока жизни.
- Встроенный software backend **отклоняет детерминированные allocator**, даже при заявленной rollback-защите хранилища. Интерфейс не доказывает независимость резервирования для всего ключа. ProviderManaged AEAD исполняется внутри отдельно доверенного провайдера и не получает локальный nonce.
- Идентификатор protector должен быть стабильным. Смена или ротация protector **не** равнозначна ротации ключа. DPAPI CurrentUser привязан к профилю Windows-пользователя, а не обеспечивает переносимое шифрование на всей машине.
- Владение секретным материалом задаётся явно через lease. Массивы вызывающего кода не очищаются автоматически. Отмена операции после durable commit не гарантирует откат.
- `SecurityObservability` подключается отдельно и не передаёт секретные входные данные; доставка audit events — best-effort, а не транзакционный журнал.
- Проекты сейчас ориентированы на `net10.0`, имеют `IsPackable=false` и не публикуются из этого репозитория в NuGet.

## Документация

| Документ | Основная ответственность |
| --- | --- |
| [Technical Specification](docs/design/Laveyana.Security.TechnicalSpecification.ru.md) | Внешние контракты, инварианты и acceptance criteria. |
| [Architecture](docs/design/Laveyana.Security.Architecture.ru.md) | Внутренние границы, ownership и компоненты. |
| [Decision Log](docs/design/Laveyana.Security.DecisionLog.ru.md) | Принятые архитектурные решения (исторические DXX сохраняются). |
| [Roadmap](docs/design/Laveyana.Security.Roadmap.ru.md) | Этапы работ и незакрытые условия релиза. |
| [HPKE gate](docs/design/Laveyana.Security.HpkeGate.ru.md) · [Streaming gate](docs/design/Laveyana.Security.StreamingGate.ru.md) | Отложенные протокольные возможности и условия их появления. |
| [Security review Phase 27](docs/audit/Laveyana.Security.Phase27.SecurityAudit.ru.md) | Результаты статического аудита, последующая проверка H01 и оставшиеся риски. |
| [Проверки H01](docs/hardening/H01-Setup.ru.md) · [История исправлений компиляции](docs/hardening/H01-CompilationRepair.ru.md) | Воспроизводимый CI и история компиляторных исправлений. |
| [CHANGELOG](CHANGELOG.ru.md) | Изменения в ходе разработки и история релизов (выпуска пока нет). |

Документация поддерживается равнозначными версиями `*.md` (English) и `*.ru.md` (Russian). Репозиторий распространяется под лицензией [MIT](LICENSE.txt). Лицензии сторонних зависимостей нужно проверить отдельно до распространения; версии находятся в [`Directory.Packages.props`](Directory.Packages.props).
