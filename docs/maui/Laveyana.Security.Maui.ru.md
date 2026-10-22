# Laveyana.Security.Maui — адаптер SecureStorage (кандидат)

[English](Laveyana.Security.Maui.md) | **Русский**

**Статус (22 октября 2026):** общая библиотека собрана и переносимые NUnit-тесты пройдены на Windows/Linux; Android/Apple проекты скомпилированы через GitHub Actions. Аппаратные тесты на устройствах ещё не выполнялись. Только экспериментальное использование.

## Назначение и ограничения

`MauiSecureStorageSecretProvider` реализует существующий контракт `ISecretManagementProvider` поверх `Microsoft.Maui.Storage.ISecureStorage` (либо MAUI `SecureStorage.Default`). Он намеренно **не** является `IKeyStore` или `IKeyStoreProtector`: платформенное хранилище «ключ — значение» не предоставляет обязательных атомарных долговечных CAS-транзакций, управления nonce на уровне ключа, защиты от rollback, аутентификации назначений конверта и внешнего контекста, межпроцессной координации и crash recovery.

Что реализовано:

- Адресация по стабильным `ProviderId`/`SecretId`, собственное пространство имён и версионированный формат с повторной проверкой идентичности сохранённой записи.
- `FindAsync`, `GetAsync` (секрет в принадлежащем вызывающему коду `SensitiveMaterialLease`), `SetAsync`, `DeleteAsync` через общие интерфейсы библиотеки.
- Ограничение **2048 байт** исходных данных. В MAUI данные передаются как Base64-строки. При чтении формат и идентичность проверяются строго.
- Повреждённые записи и ошибки, реально переданные `ISecureStorage`, отклоняются. Проверка точным чтением сразу после `SetAsync` выявляет пропущенную или несовпавшую запись. Сам адаптер не вызывает `RemoveAll`, не повторяет операции и не делает fallback. При этом Android backend MAUI может скрывать ошибки или очищать preferences внутри себя.
- Явная регистрация в DI; для unit-тестов можно передать поддельный `ISecureStorage`.

**Не гарантируются:** разграничение доступа внутри процесса приложения, авторизация отдельных пользователей, очистка всех копий `string` в управляемой памяти, транзакции между процессами, наличие аппаратного хранилища на каждом устройстве, переносимость между устройствами, сохранность при потере питания, anti-rollback, физическое удаление информации и безопасность постоянного AES-GCM master key.

## Подключение к MAUI-приложению

В MAUI уже есть `SecureStorage.Default`. Регистрировать адаптер следует **до** существующего `AddSecurity`. `ProviderId` и `SecretId` должны быть постоянными идентификаторами, а не новыми GUID при каждом запуске:

```csharp
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.DependencyInjection.Composition;
using Laveyana.Security.Maui.Composition;
using Laveyana.Security.Maui.Storage;

ProviderId providerId = ProviderId.Parse("11111111-1111-4111-8111-111111111111"); // Заменить и сохранить.
builder.Services.AddLaveyanaMauiSecureStorage(providerId);
builder.Services.AddSecurity(security =>
    security.UseSecretProvider<MauiSecureStorageSecretProvider>(providerId));
```

Пример чтения и записи в приложении:

```csharp
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Secrets;
using Laveyana.Security.Abstractions.Sensitive;

SecretReference secret = new(providerId, SecretId.Parse("22222222-2222-4222-8222-222222222222"));
using SensitiveMaterialLease value = SensitiveMaterialLease.CreateCopy("test-token"u8);
await provider.SetAsync(secret, value);

using SecretReadResult? result = await provider.GetAsync(secret);
result?.UseMaterial(bytes =>
{
    // Работать с байтами синхронно; не сохранять span и не логировать секрет.
});
```

Здесь `provider` — внедрённый `MauiSecureStorageSecretProvider` либо `ISecretManagementProvider`. Типы `SensitiveMaterialLease`, `SecretReference`, `SecretReadResult` находятся в `Laveyana.Security.Abstractions` (`Sensitive`, `Identifiers`, `Secrets`).

`ISecureStorage` не принимает `CancellationToken`: отмена проверяется **до** операции платформы, но не прерывает её. При исключении во время `SetAsync` результат записи может быть неопределённым. Удаление не обещает физической очистки блоков или синхронизированных копий.

## Платформенные особенности

- **Android:** зашифрованные Preferences используют платформенный ключ. При сбое восстановления `SecureStorage.Default` может **очистить несколько записей или вернуть `null` вместо исключения**; иногда запись завершается без фактического сохранения. Немедленная проверка чтением обнаруживает отсутствие/несовпадение только что записанного значения, но не гарантирует долговечность, не предотвращает скрытую очистку и не различает последующий скрытый сбой от реального отсутствия. Исключайте preferences из backup или предусматривайте повторную авторизацию. **Нельзя пересоздавать незаменимый корневой секрет только по результату `GetAsync == null`.**
- **iOS / Mac Catalyst:** записи Keychain могут пережить удаление приложения; в некоторых конфигурациях возможно iCloud Keychain sync. Политику очистки при первом запуске и смене пользователя должно определять приложение: адаптер намеренно не вызывает `RemoveAll`.
- **Windows:** MAUI использует DataProtectionProvider. Для упакованных приложений существует ограничение размера значений; лимит 2048 байт снижает риск переполнения. У упакованных и неупакованных приложений разные механизмы сохранения.

См. [официальную документацию Microsoft SecureStorage](https://learn.microsoft.com/en-us/dotnet/maui/platform-integration/storage/secure-storage?view=net-maui-10.0).

## Проверка перед выпуском

- Общий MAUI-проект уже включён в решение и переносимые NUnit-тесты; версия `Microsoft.Maui.Essentials` задана централизованно. Для Android и Apple существуют отдельные workload-проекты и CI.
- **Новая зависимость требует обновления NuGet lock-файлов** на машине с .NET 10 SDK до проверки `--locked-mode`. Использовать имеющийся проектный `scripts/Initialize-LockFiles.ps1`, не изменять lock-файлы вручную.
- Выполнить проверки структуры, Release build и NUnit; отдельно проверить MAUI на Android/iOS/Mac Catalyst/Windows перед заявлениями о полноценной поддержке этих платформ.
- `IsPackable=false` сохраняется. Публикация этого модуля в NuGet откладывается до успешных интеграционных испытаний.

## Экспериментальная аппаратная подпись — Windows TPM

Необязательный низкоуровневый `INativeSigningKeyService` поддерживает
создание, поиск и удаление постоянных именованных ключей ECDSA NIST P-256
через **Microsoft Platform Crypto Provider (TPM)** на совместимых устройствах
Windows. Подпись — SHA-256, формат IEEE P1363, 64 байта; экспортируется
только **публичный** ключ SubjectPublicKeyInfo. Экспорт закрытого ключа и
автоматическое переключение на программные ключи не предусмотрены.

Регистрация явная: `services.AddLaveyanaWindowsTpmSigning(providerId)`.
Приложение сохраняет постоянные ID, не переиспользует удалённые ID и
обрабатывает неопределённый исход создания/удаления. При аварийном
завершении ключ может остаться в TPM. Удаление не гарантирует физическое
стирание. Это НЕ реализация `IKeyProviderBackend` или
`IManagedSignatureBackend`: отсутствуют версии ключей, attestation,
биометрия, защита от rollback и межпроцессный CAS.

Обычные NUnit/CI проверяют переносимые сценарии и валидацию публичных
ключей. Для реального теста Windows TPM требуется явное включение
`LAVEYANA_RUN_TPM_TESTS=1` на совместимом Windows-ПК. Тест по умолчанию
пропущен; при аварийном завершении может остаться постоянный ключ.
**Успешный CI не доказывает работу TPM на оборудовании.**

Android Keystore и Apple Secure Enclave имеют отдельные **экспериментальные реализации**, но ещё не прошли испытаний на физических устройствах.
Модуль экспериментальный, не допущен к production-секретам и стабильной
публикации NuGet; SA-03/04/08 остаются открытыми.

## Экспериментальный Android Keystore (отдельная сборка)

**Экспериментальная** сборка `platforms/android/Laveyana.Security.Maui.Android`
реализует тот же `INativeSigningKeyService` через Android Keystore
(Android 12+, API 31+). По результату проверки уровня защиты принимаются
только TEE/StrongBox. Используются ECDSA P-256/SHA-256 и подпись IEEE P1363
размером 64 байта.

Модуль не входит в основное решение, не работает на Windows/Linux и ещё
не прошёл испытания на устройствах. Компиляцию проверяет отдельный CI.
Подробнее: [модуль Android](../../platforms/android/README.ru.md).
Аттестация, биометрия, CAS и защита от rollback не гарантируются.

## Apple Secure Enclave — экспериментальная реализация

Отдельный проект iOS/Mac Catalyst
`platforms/apple/Laveyana.Security.Maui.Apple` использует
`INativeSigningKeyService`: аппаратные ключи P-256 (обязательный
`SecTokenID.SecureEnclave`, режим `WhenUnlockedThisDeviceOnly`),
публичные ключи SPKI и подписи IEEE P1363. Программного fallback нет.

Платформенный проект **не входит** в основное решение. Проверки на реальном
устройстве, аппаратная аттестация, авторизация пользователя,
межпроцессный CAS и защищённый жизненный цикл **отсутствуют**.
См. [модуль Apple](../../platforms/apple/README.ru.md).
