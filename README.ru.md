# Laveyana.Security

[English](README.md) | **Русский**

Модульная библиотека .NET 10 для управления жизненным циклом ключей, криптографических операций, интеграции с поставщиками секретов и явной композиции провайдеров. **Это предварительная реализация, не одобренная для production.** Исходники проходили статические проверки репозитория, однако успешная сборка .NET 10, запуск NUnit, межпроцессные испытания и платформенный аудит безопасности **не подтверждены** в текущем окружении.

> **Текущая точка:** Phase 27 — предварительный security review исходников Phase 26 (2026-10-10). Внесены исправления асинхронного захвата AAD/сообщений и подготовлены регрессионные тесты. **Аудит и production release gate остаются открытыми**: сборка, NUnit и платформенные сценарии не выполнены. См. [отчёт Phase 27](docs/audit/Laveyana.Security.Phase27.SecurityAudit.ru.md).

**Исправления H01:** [устранение ошибок первой компиляции и правила размещения типов](docs/hardening/H01-CompilationRepair.ru.md). Перед заменой распакованного проекта используйте чистую папку, сохранив NuGet lock-файлы из старой копии.

**Новое:** [Подготовка первого запуска H01](docs/hardening/H01-Setup.ru.md). Сначала создайте и зафиксируйте настоящие NuGet lock-файлы на компьютере с .NET SDK 10.0.4xx.

## Сборки

| Проект | Назначение |
| --- | --- |
| `Laveyana.Security.Abstractions` | Стабильные идентификаторы, типизированные дескрипторы, неизменяемые результаты, контракты расширения, владение секретной памятью. |
| `Laveyana.Security` | Примитивы, жизненный цикл ключей, программный провайдер, AEAD, MAC, derivation, маршрутизация, ротация, миграция, диагностика. |
| `Laveyana.Security.FileSystem` | Экспериментальный защищённый `IKeyStore`; меры защиты Linux/Windows не прошли production-приёмку. |
| `Laveyana.Security.Windows` | Явно выбираемый Windows DPAPI CurrentUser `IKeyStoreProtector` (платформенные тесты ещё не подтверждены). |
| `Laveyana.Security.DependencyInjection` | Явная композиция `AddSecurity`/`AddSecurityDefaults` и необязательный worker ротации. |
| `Laveyana.Security.Tests` | Модульные и контрактные тесты NUnit. |
| `Laveyana.Security.IntegrationTests` | Интеграционные сценарии NUnit для DI, FileSystem, Windows и worker. |

Публичные контракты расширения находятся в Abstractions. Можно создавать компоненты вручную без DI. Автоматического plaintext fallback, выбора protector, создания файлового хранилища или запуска worker нет.

## Статус реализации

| Подсистема / этапы | Состояние исходников | Существенное ограничение |
| --- | --- | --- |
| Идентификаторы, примитивы, защищённая память, дескрипторы, lifecycle, registry (1–7) | Реализовано | Предварительная проверка capability работает только с метаданными; авторизация обязательна при выполнении операции. |
| Контракты хранилища, software lifecycle, nonce policy, схемы данных (8–11) | Реализовано | Гарантии атомарности и защиты от rollback зависят от реального хранилища и независимого механизма. |
| FileSystem и платформенное усиление (12–13) | **Экспериментально** | Требуется явное включение экспериментальной записи; Windows TOCTOU, durability и rollback gates открыты. |
| Windows DPAPI и миграция protector (14, 14A) | Реализовано в исходниках | Тесты Windows и восстановления не подтверждены; повторная защита не означает ротацию рабочего ключа. |
| Результаты, AES-256-GCM, HMAC, временные ECDSA/RSA-PSS и ECDH/HKDF (15–18) | Реализовано в исходниках | Нет долговременного управления приватными асимметричными ключами и полноценного межпроцессного отзыва. |
| HPKE `Seal`/`Open` (19) | **Отложено / не поддерживается** | Эталонные векторы RFC 9180 не подтверждают .NET-реализацию HPKE. Публичного HPKE API нет. |
| Потоковые SHA-2 и HMAC (20) | Реализовано в исходниках | **Потоковое AEAD отложено / не поддерживается** до отдельного security gate. |
| Secrets, DI, worker ротации, миграция провайдеров, диагностика (21–25) | Реализовано в исходниках | Авторизация провайдера, долговечная очередь, журнал переключения и обязательный аудит остаются ответственностью приложения/провайдера. |
| Синхронизация документации (26) | Подготовлена | Не закрывает предыдущие проверки сборки и безопасности. |
| Полный аудит (27) | **Частично выполнен — не принят** | Проведён статический review и исправлены два дефекта; .NET/NUnit, rollback и platform gates открыты. |

Другие отсутствующие гарантии: нет стандартного rollback-resistant nonce allocator, встроенного постоянного хранилища произвольных секретов, неявного экспорта non-exportable ключей и гарантированного стирания сторонних копий в памяти или удалённых блоков на диске.

## Пример локальных криптографических примитивов

```csharp
using System.Security.Cryptography;
using Laveyana.Security.Primitives;

byte[] key = LocalCryptography.GenerateRandomBytes(32);
byte[] message = "message"u8.ToArray();
try
{
    byte[] tag = LocalCryptography.HmacSha256(key, message);
    bool matches = LocalCryptography.VerifyHmacSha256(key, message, tag);
    // Обработайте результат, не записывая ключ в журнал.
}
finally
{
    CryptographicOperations.ZeroMemory(key);
}
```

Это локальный примитив, **не** управляемый сервис ключей и не механизм авторизации. Для использования с реальными секретами необходимо самостоятельно оценить создание и хранение ключей, владение памятью, правила провайдера и модель угроз.

## Проверки

Установите .NET SDK, указанный в [`global.json`](global.json) (10.0.x), затем выполните:

```sh
python tools/verify_repository.py
python tools/verify_repository.py --self-test
python tools/verify_documentation.py
python tools/verify_documentation.py --self-test
dotnet restore Laveyana.Security.sln
dotnet build Laveyana.Security.sln -c Release --no-restore -warnaserror
dotnet test Laveyana.Security.sln -c Release --no-build --no-restore
```

GitHub Actions настроен на проверку, сборку и тесты на Windows и Ubuntu **при фактическом запуске CI**. Само наличие workflow не доказывает успешного прохождения. До реальной записи секретов требуются испытания прав доступа, файловой системы, нескольких процессов, аварийного восстановления и возврата старого снимка.

## Документация

| Документ | Назначение |
| --- | --- |
| [Техническая спецификация](docs/design/Laveyana.Security.TechnicalSpecification.ru.md) | Контракты API, форматы, инварианты и требования безопасности. |
| [Архитектура](docs/design/Laveyana.Security.Architecture.ru.md) | Сборки, жизненный цикл, провайдеры, хранилище и границы доверия. |
| [Roadmap](docs/design/Laveyana.Security.Roadmap.ru.md) | Критерии приёмки по этапам и release gates. |
| [Журнал решений](docs/design/Laveyana.Security.DecisionLog.ru.md) | Решения D04–D57 с намеренными пропусками номеров; см. примечание в журнале. |
| [HPKE gate](docs/design/Laveyana.Security.HpkeGate.ru.md) | Причины отложенной реализации HPKE. |
| [Streaming gate](docs/design/Laveyana.Security.StreamingGate.ru.md) | Границы SHA/HMAC и отложенного AEAD. |
| [Отчёт Phase 27](docs/audit/Laveyana.Security.Phase27.SecurityAudit.ru.md) | Findings, исправления и обязательные release-gate проверки. |
| [CHANGELOG](CHANGELOG.ru.md) | История неопубликованных этапов, не сообщение о релизе. |
| [Мастер-промпт](Laveyana.Security.MasterImplementationPrompt.ru.md) | Общие требования Generation 1 и указания для продолжения разработки. |

У базовых проектных документов есть англоязычные пары `*.md`, а также [English README](README.md) и [English CHANGELOG](CHANGELOG.md).

## Условия выпуска

Phase 27 обязателен. До заявления о production-готовности требуются сборка и тесты, проверенные свойства FileSystem и protector на Windows/Linux, разрешение рисков rollback/nonce и конкурентных операций и отдельный аудит безопасности. HPKE и потоковое AEAD могут оставаться явно неподдерживаемыми. Лицензии в репозитории нет: её выбор и добавление требуют решения владельца проекта.
