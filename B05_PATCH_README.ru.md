# SA-08 B-05 — закреплённое перечисление временных файлов Linux

**Назначение:** устранить расхождение между перечислением `.pending-*.tmp` по изменяемому строковому пути и удалением через удерживаемый дескриптор каталога.

**Исходная база:** `Laveyana_2026-10-21_11-35-57.zip`. Это overlay-патч: распаковать в корень копии этого проекта с заменой совпадающих файлов. Не заменять им весь репозиторий.

## Изменения

- `LinuxSecureDirectory.EnumeratePendingNames()` перечисляет записи через `openat(rootFd, ".")` / `fdopendir` / `readdir`; дескриптор опирается на закреплённый root и имеет независимую позицию перечисления.
- `FileSystemKeyStore.CleanupAbandonedTemps()` использует это перечисление. Проверка файлов и удаление по-прежнему выполняются через тот же закреплённый Linux root.
- `FileSystemKeyStoreTests.LinuxCleanupRootRelocation.cs` воспроизводит подмену строкового пути во время LoadAsync: ожидается очистка старого каталога без изменения decoy.
- `tools/check_trx.py` требует успешного выполнения нового теста на Linux.
- Обновлён CHANGELOG на двух языках.

## Проверки, которые реально проведены при подготовке

- `tools/verify_repository.py` — PASS.
- `tools/verify_api_layout.py` — PASS.
- `tools/verify_documentation.py` — PASS.
- 13 self-tests `tools/test_check_trx.py` — PASS.
- Отдельная native Linux проверка ABI `dirent` и закреплённого дескриптора при переименовании root — PASS. **Это не выполнение кода Laveyana.Security!**

**Не выполнялись:** .NET Release build, NUnit, Windows/Linux CI. На данной машине не установлен .NET SDK. Изменения — кандидат до проверки тестами.

## Действия в Visual Studio

1. Обновить `master` через Pull и создать ветку `security/sa08-linux-pinned-cleanup`.
2. Распаковать overlay в корень репозитория.
3. Выполнить Release rebuild; запустить все тесты. На Windows новый Linux-only тест ожидаемо пропускается.
4. Пришлите ZIP результатов Windows. После этого — PR и обязательный Linux/Windows CI. **Не выполнять merge до нашей проверки**.

**Ограничения:** не создаёт новых гарантий устойчивости к power loss, не меняет protected-write profile, nonce, rollback authority или capabilities. SA-03/SA-04/SA-08 OPEN, Phase 27 NO-GO.
