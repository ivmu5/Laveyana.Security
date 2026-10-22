# Laveyana.Security.Maui.Android — экспериментальная аппаратная подпись

Проект **не включён** в основное решение и не публикуется в NuGet.
Он зависит от общего `INativeSigningKeyService` из PR с Windows TPM и
проверяется отдельной сборкой с Android workload.

Требуется Android API 31+. Постоянные ключи ECDSA P-256 создаются через
`AndroidKeyStore`; при создании, поиске и подписи проверяется фактический
`KeyInfo.SecurityLevel`. Принимаются только TEE или StrongBox.
Переход к программной реализации запрещён. Подписи SHA-256 преобразуются
из DER в IEEE P1363 (64 байта). Экспортируется только публичный ключ SPKI.

Пока отсутствуют: биометрия, аппаратная аттестация, гарантии стирания,
межпроцессный атомарный захват имени ключа, версии/ротация и защита от
rollback. При гонке создания Android может заменить ключ с тем же alias;
аварийное завершение может оставить постоянный ключ с неизвестным исходом.
Приложение должно сохранять ID и восстанавливать состояние после сбоя.
Нельзя использовать для невосстановимых ключей шифрования.

Для сборки нужен Android workload .NET 10:

```powershell
dotnet workload install android
dotnet restore platforms/android/Laveyana.Security.Maui.Android/Laveyana.Security.Maui.Android.csproj --force-evaluate
dotnet build platforms/android/Laveyana.Security.Maui.Android/Laveyana.Security.Maui.Android.csproj -c Release --no-restore
```

Обязательный Verify условно компилирует Android-проект при изменении
его зависимостей; отдельный workflow запускается вручную. Перед релизом нужно зафиксировать
настоящий NuGet lock-файл платформенного проекта и проверять locked restore.
Также необходимы проверки на устройствах.

**Статус:** черновой кандидат, не production и не готов к NuGet.

## Необязательный fail-closed backend Android (эксперимент)

`Storage.AndroidFailClosedSecureStorage` — отдельная явно подключаемая
реализация `ISecureStorage`. Это **не** `IKeyStore`, не полноценный
менеджер ключей и не долговечная БД. Только небольшие восстанавливаемые
секреты.

В отличие от стандартной реализации MAUI, этот адаптер непосредственно
открывает изолированное AndroidX `EncryptedSharedPreferences`, не подавляет
ошибки и не удаляет повреждённые данные. Для записи используется синхронный
`Commit()` вместо `Apply()`, отрицательный результат вызывает исключение.
Существующий `MauiSecureStorageSecretProvider` отдельно перепроверяет
значение чтением. `RemoveAll()` запрещён. **Это не** гарантия отсутствия
rollback, транзакционного CAS или сохранности при отключении питания.

AndroidX `EncryptedSharedPreferences` **устарел (deprecated)**. Мы
переиспользуем существующее шифрование AndroidX, а не создаём самодельный
AES-протокол. Это **не** подтверждение аппаратной защиты AES на любом Android
и **не** готовое production-хранилище.

В MAUI Android:
```csharp
builder.Services.AddLaveyanaAndroidFailClosedSecureStorage(stableProviderId);
builder.Services.AddSecurity(security =>
    security.UseSecretProvider<MauiSecureStorageSecretProvider>(stableProviderId));
```

Используется **новый изолированный** файл encrypted preferences. Существующие
значения `SecureStorage.Default` туда автоматически **не переносятся**.
Не включайте две реализации одновременно. Нужно исключить файл из Android
Auto Backup и проверить на устройстве потери ключей, backup/restore, сбои
`Commit`, завершение процесса и переустановку. CI проверяет **компиляцию**,
а не работу на телефоне.
