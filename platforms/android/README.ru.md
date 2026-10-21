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

Отдельный GitHub Actions проверяет компиляцию Android-проекта. Обычный
CI Windows/Linux его **не компилирует**. Перед релизом нужно зафиксировать
настоящий NuGet lock-файл платформенного проекта и проверять locked restore.
Также необходимы проверки на устройствах.

**Статус:** черновой кандидат, не production и не готов к NuGet.
