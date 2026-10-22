# Laveyana.Security — предварительные пакеты NuGet

**Предварительный выпуск для разработки и контролируемых внутренних экспериментов.** Набор библиотек .NET 10 в целом не допущен к production-хранению важных секретов.

Публикуются отдельные пакеты для контрактов, криптографических примитивов, DI, MAUI, Windows DPAPI и экспериментального файлового хранилища.

Файловый backend — **EXPERIMENTAL / TEST ONLY**, НЕ предназначен для ценных ключей и production-секретов. `Laveyana.Security.DependencyInjection` зависит от этого пакета, но зависимость не подтверждает его production-пригодность.

**Открытые ограничения:** SA-03 (откат снимков), SA-04 (история AES-GCM nonce при повторном открытии/импорте/восстановлении), SA-08 (долговечность файлового хранилища). Восстановленный материал ключа нельзя автоматически применять для нового AES-GCM шифрования. Нативное поведение MAUI на физических устройствах пока не подтверждено.

Документация: [README](https://github.com/ivmu5/Laveyana.Security/blob/master/README.ru.md), [ограничения](https://github.com/ivmu5/Laveyana.Security/blob/master/docs/audit/Laveyana.Security.KnownLimitations.ru.md).

Исходники: https://github.com/ivmu5/Laveyana.Security

Лицензия MIT. Факт публикации предварительных пакетов не означает стабильность API или production-допуск.
