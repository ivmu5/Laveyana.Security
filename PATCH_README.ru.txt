Laveyana.Security — SA-03 Stage 2B1 (2026-10-20)

Небольшой промежуточный патч: экспериментальная проверка rollback-authority
при чтении FileSystemKeyStore. Полноценный защищённый режим НЕ реализован.

Установка:
1. Убедитесь, что SA-03 Stage 2A и исправление CS4007 уже слиты в master.
2. В Visual Studio: Git Repository → master → Pull, затем создайте
   отдельную ветку security/sa03-read-gate.
3. Распакуйте ZIP в КОРЕНЬ репозитория с заменой файлов.
4. Через Test Explorer выполните полный прогон тестов Windows.
5. Запушьте ветку и проверьте Windows/Linux GitHub CI.

Изменения:
- FileSystemKeyStoreOptions.RollbackAuthority — необязательная внешняя
  проверка ТОЛЬКО для чтения; UUID должен быть закреплён, writes=false.
- Каждый LoadAsync сверяет аутентифицированные байты файла с authority;
  при missing/pending/foreign/mismatch или ошибке соединения — отказ.
- 7 интеграционных тестов с authority-имитатором, 3 новых обязательных
  теста в tools/check_trx.py, документация EN/RU и CHANGELOG.

ОГРАНИЧЕНИЯ:
- Позволяет тестировать Stage 1 на настоящем FileSystem-снимке;
  не защищает от downgrade, потому что OpenAsync без этой опции сохраняется.
- В этом режиме запрещены запись и root migration.
- Нет enrolment, prepare/finalize, crash recovery, durable staging,
  удалённого провайдера или доказанной OS power-loss durability.
- ProvidesRollbackProtection=false, SA-03/SA-04/SA-08 OPEN,
  Phase 27 NO-GO для production/реальных секретов.
- В среде подготовки отсутствует .NET SDK: C# компиляция не проверена.

Примечание: verify_documentation.py на исходном Source-экспорте сообщает
о четырёх старых ссылках .github/workflows/nightly.yml: каталог .github
не попал в архив экспорта. В этом патче эти ссылки не изменены.
