# Laveyana.Security.Maui.Apple — экспериментальная подпись Secure Enclave

**Статус:** черновой кандидат; не допущен к production и публикации NuGet.
Отдельный проект для iOS и Mac Catalyst, не включённый в обычное решение
`net10.0`. Использует общий `INativeSigningKeyService`.

Создание, поиск, подпись и удаление постоянных ключей NIST P-256 через Apple
Security framework. При создании обязательно запрашивается
**SecTokenID.SecureEnclave**, режим **WhenUnlockedThisDeviceOnly** и флаг
**PrivateKeyUsage**. Программного fallback нет. Закрытый ключ не экспортируется.
Публичный ключ X9.63 преобразуется в SPKI, подпись DER — в IEEE P1363 (64 байта).

Регистрация: `AddLaveyanaAppleSecureEnclaveSigning(providerId)`.
ID провайдера и ключа должны сохраняться приложением. На неподдерживаемом
устройстве операции должны завершаться ошибкой. Биометрия и подтверждение
присутствия пользователя **не включены**.

## Ограничения

- Нет атомарного CAS при создании: другой процесс может успеть создать
  ключ с тем же тегом между проверкой и записью.
- Нет аппаратной аттестации, версий и ротации ключей, защиты от rollback,
  доказательства физического стирания и биометрической авторизации.
- Записи Keychain могут переживать переустановку приложения. После сбоев
  при создании/удалении нужно сверять реальное состояние.
- Ключи ThisDeviceOnly нельзя перенести на другое устройство или
  восстановить из резервной копии.
- Симулятор не подтверждает работу реального Secure Enclave.
- Успешная компиляция не доказывает работоспособность на устройстве.

## Сборка

Нужны macOS, Xcode и workload iOS/Mac Catalyst .NET 10:

```sh
dotnet workload install ios maccatalyst
dotnet restore platforms/apple/Laveyana.Security.Maui.Apple/Laveyana.Security.Maui.Apple.csproj --force-evaluate
dotnet build platforms/apple/Laveyana.Security.Maui.Apple/Laveyana.Security.Maui.Apple.csproj -c Release --no-restore
```

Обязательный Verify условно проверяет компиляцию Apple-проекта при соответствующих изменениях; отдельный workflow запускается вручную. Перед релизом необходимо
проверить создание и подпись на реальном iOS-устройстве и Mac, зафиксировать
настоящие lock-файлы и выполнить необходимые security-gate проверки.
