# Laveyana.Security.Maui — адаптер SecureStorage (кандидат)

[English](Laveyana.Security.Maui.md) | **Русский**

**Статус:** исходный вариант для ревью, сборка и платформенные испытания НЕ выполнены. Это не допуск к защите production-секретов.

## Назначение и ограничения

`MauiSecureStorageSecretProvider` реализует существующий контракт `ISecretManagementProvider` поверх `Microsoft.Maui.Storage.ISecureStorage` (либо MAUI `SecureStorage.Default`). Он намеренно **не** является `IKeyStore` или `IKeyStoreProtector`: платформенное хранилище «ключ — значение» не предоставляет обязательных атомарных долговечных CAS-транзакций, управления nonce на уровне ключа, защиты от rollback, аутентификации назначений конверта и внешнего контекста, межпроцессной координации и crash recovery.

Что реализовано:

- Адресация по стабильным `ProviderId`/`SecretId`, собственное пространство имён и версионированный формат с повторной проверкой идентичности сохранённой записи.
- `FindAsync`, `GetAsync` (секрет в принадлежащем вызывающему коду `SensitiveMaterialLease`), `SetAsync`, `DeleteAsync` через общие интерфейсы библиотеки.
- Ограничение **2048 байт** исходных данных. В MAUI данные передаются как Base64-строки. При чтении формат и идентичность проверяются строго.
- Ошибки не скрываются; нет автоматического `RemoveAll`, миграции, восстановления, повторов, запасного небезопасного хранилища или перечисления секретов.
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

- **Android:** зашифрованные Preferences используют ключи платформы. Android Auto Backup может восстановить ciphertext без исходного ключа устройства; чтение тогда может завершиться ошибкой либо MAUI удалит проблемное значение. Следует исключить SecureStorage из резервного копирования или предусмотреть повторную авторизацию.
- **iOS / Mac Catalyst:** записи Keychain могут пережить удаление приложения; в некоторых конфигурациях возможно iCloud Keychain sync. Политику очистки при первом запуске и смене пользователя должно определять приложение: адаптер намеренно не вызывает `RemoveAll`.
- **Windows:** MAUI использует DataProtectionProvider. Для упакованных приложений существует ограничение размера значений; лимит 2048 байт снижает риск переполнения. У упакованных и неупакованных приложений разные механизмы сохранения.

См. [официальную документацию Microsoft SecureStorage](https://learn.microsoft.com/en-us/dotnet/maui/platform-integration/storage/secure-storage?view=net-maui-10.0).

## Проверка перед выпуском

- Добавить проект в `Laveyana.Security.sln`, пакет `Microsoft.Maui.Essentials` — в `Directory.Packages.props`, а ссылку из тестов — в `Laveyana.Security.Tests.csproj`.
- **Новая зависимость требует обновления NuGet lock-файлов** на машине с .NET 10 SDK до проверки `--locked-mode`. Использовать имеющийся проектный `scripts/Initialize-LockFiles.ps1`, не изменять lock-файлы вручную.
- Выполнить проверки структуры, Release build и NUnit; отдельно проверить MAUI на Android/iOS/Mac Catalyst/Windows перед заявлениями о полноценной поддержке этих платформ.
- `IsPackable=false` сохраняется. Публикация этого модуля в NuGet откладывается до успешных интеграционных испытаний.
