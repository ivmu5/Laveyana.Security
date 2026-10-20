SA-03 Stage 2A — CS4007 test compilation fix

Распакуйте архив в корень репозитория Laveyana.Security с заменой одного файла:
tests/Laveyana.Security.Tests/RollbackRequestAuthorityContractTests.cs

Изменение только в тесте LostPrepareReplyIsResolvedFromTheOriginalRequestWithoutAnotherMutation:
await fake.ReadAsync(Store) выполняется до синхронного вызова RollbackSnapshotGate.Inspect.
Контракты, рабочий код и другие тесты не изменены.

Перезапустите полный набор тестов через Visual Studio.
До повторного прогона успешность unit-тестов не подтверждена.
