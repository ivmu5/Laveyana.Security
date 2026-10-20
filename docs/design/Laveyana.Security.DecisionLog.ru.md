# Laveyana.Security — Журнал архитектурных решений

[English](Laveyana.Security.DecisionLog.md) | **Русский**

> Состав: самостоятельные security-specific развилки Generation 1. Записи, целиком повторяющие общий стандарт Laveyana, исключены с сохранением исходных DXX идентификаторов для трассируемости.

Новый DXX нужен лишь при существенном архитектурном выборе в безопасности, совместимости, lifecycle, persistent formats или границах provider/store. Детали реализации отдельного DXX не требуют. Все приведённые решения остаются утверждёнными до обоснованного пересмотра.

---

## D04. High-Level и Advanced остаются в одной domain assembly

**Решение**

Сохранять safe High-Level API и explicit Advanced/interoperability API в основной Security domain, пока реальная boundary не потребует отдельного package.

**Обоснование**

Не дробит packages и сохраняет dangerous operations явными.

---

## D05. Logical и exact-version handles разделены

**Решение**

Logical handles привязаны к ProviderId+KeyId и resolve current Active для forward use; exact handles привязаны к ProviderId+KeyId+KeyVersion и никогда не переключаются автоматически.

**Обоснование**

Rotation не может незаметно изменить historical identity semantics.

---

## D06. KeyVersion необратимо выделяется внутри authoritative history

**Решение**

Discarded/deleted version numbers не переиспользуются в represented authoritative history; gaps допустимы.

**Обоснование**

Persistent references остаются однозначными после failed/discarded version creation.

---

## D07. Discard заканчивается Deleted, отдельного public state нет

**Решение**

Discard Pending уничтожает never-activated material и даёт public Deleted; internal terminal reason может сохраняться для diagnostics.

**Обоснование**

Сохраняет lifecycle компактным без потери internal recovery/audit context.

---

## D08. KeyName unique внутри provider scope

**Решение**

Generation 1 uniqueness: (ProviderId, KeyName) -> KeyId, без global cross-provider namespace.

**Обоснование**

Исключает hidden coordination между independent providers.

---

## D09. GetOrCreate требует store-level atomic name claim

**Решение**

Local keyed lock — только optimization; correctness обеспечивает atomic store claim/create unique name binding и aggregate.

**Обоснование**

Не позволяет независимым process создать два KeyId для одного provider/name.

---

## D10. ProviderId persistent, ProviderAlias runtime-only

**Решение**

Persistent references хранят stable ProviderId. Alias mapping — runtime configuration, duplicate ids/aliases являются failures.

**Обоснование**

Configuration refactoring не меняет смысл сохранённой cryptographic reference.

---

## D11. Provider migration создаёт новый KeyId

**Решение**

Migration к другому provider создаёт новую ProviderId/KeyId generation; existing KeyId не переносится, redirect registry не меняет old references.

**Обоснование**

Historical references остаются immutable, source/destination могут сосуществовать.

---

## D12. Provider capabilities granular

**Решение**

Не требовать один giant backend interface; operation требует одновременно key policy permission и provider capability.

**Обоснование**

Честно поддерживает software, OS-backed, HSM, remote и non-exportable keys.

---

## D13. IKeyStore принадлежит Abstractions

**Решение**

IKeyStore — public software-storage extension boundary; domain lifecycle logic остаётся в core Security.

**Обоснование**

Custom stores не требуют dependency на concrete Security и не становятся владельцами lifecycle rules.

---

## D14. IKeyStoreProtector определяется до FileSystem

**Решение**

Protected FileSystem storage с первой реализации строится на opaque protection contract; temporary plaintext persistence path запрещён.

**Обоснование**

At-rest security является частью architecture, а не future retrofit.

---

## D15. Default FileSystem rollback-unprotected

**Решение**

Обычный FileSystem объявляет ProvidesRollbackProtection=false, пока не добавлена independent rollback-resistant authority.

**Обоснование**

Old valid authenticated snapshot нельзя считать monotonic current state.

---

## D16. AEAD nonce strategy capability-driven

**Решение**

Managed AES-GCM использует Randomized, RollbackProtectedDeterministic или ProviderManaged. Deterministic allocation запрещена на rollback-unprotected state.

**Обоснование**

Nonce safety соответствует declared threat model и не перекладывается на ordinary consumer.

---

## D17. Imported AES material с unknown nonce history ограничен

**Решение**

Unknown prior nonce history блокирует ordinary managed forward encryption без explicit safe provider/policy.

**Обоснование**

Новый KeyId вокруг того же raw material не отменяет prior (key, nonce) use.

---

## D18. Managed crypto results фиксируют exact historical identity

**Решение**

EncryptedPayload, SignaturePayload и MacResult фиксируют exact KeyReference, использованный managed forward operation.

**Обоснование**

Historical decrypt/verify остаётся deterministic после rotation.

---

## D19. Security-critical payload metadata аутентифицируется внутри

**Решение**

Format, algorithm, exact key reference, critical flags и semantic parameters криптографически связываются где применимо; application AAD — отдельный external context.

**Обоснование**

Предотвращает metadata tampering без связи Security с domain-specific meanings.

---

## D20. Sensitive material использует scoped access и leases

**Решение**

Opaque handles — default; raw material access использует callback scopes или disposable SensitiveMaterialLease с zeroization owned buffer.

**Обоснование**

Уменьшает accidental long-lived byte[]/string exposure и сохраняет interoperability.

---

## D21. Seal/Open проходит standardized HPKE gate

**Решение**

High-level asymmetric confidentiality откладывается до выбора analyzed standardized HPKE-compatible implementation strategy, vectors, limits, encoding и focused review.

**Обоснование**

Не допускает custom hybrid cryptographic protocol ради формального feature.

---

## D22. Streaming AEAD требует protocol gate

**Решение**

Encrypted streaming требует analyzed segmented construction или отдельно specified/reviewed protocol с position/stream binding, truncation/splice protection, limits и vectors.

**Обоснование**

Делает framing и nonce semantics явными и тестируемыми.

---

## D23. Generic defaults требуют safe protector

**Решение**

AddSecurityDefaults() не угадывает platform protector и не имеет plaintext fallback; platform packages владеют platform-safe presets.

**Обоснование**

Cross-platform defaults остаются честными и fail-fast при отсутствии protection.

---

## D24. Automatic rotation — explicit opt-in

**Решение**

Core содержит rotation policy/engine, но не запускает hidden loop; optional hosted automation использует тот же engine и Generic Host lifecycle.

**Обоснование**

Сохраняет lifecycle ownership явным и тестируемым.

---

## D25. Persistent formats versioned независимо

**Решение**

Runtime models отображаются в versioned persisted DTO; metadata, protected envelope, encrypted payload, streaming format и package version эволюционируют независимо.

**Обоснование**

Позволяет controlled migrations и fail-closed handling unknown newer formats.

---

## D27. Delete не означает forensic secure erase

**Решение**

Normal delete означает, что material больше недоступен через provider. Strong physical erase заявляет только backend, способный это гарантировать.

**Обоснование**

Соответствует SSD/COW/snapshot/journal realities и исключает false security claims.

---

## D31. Re-protection не равен ротации криптографического ключа

**Решение**

Замена `IKeyStoreProtector` / at-rest envelopes сохраняет `KeyReference` и cryptographic material. Это отдельный recoverable workflow; compromised key material требует настоящей key rotation.

**Обоснование**

Разделяет различные риски и исключает ложные заявления о rotation при перешифровании хранилища.

---

## D32. Known external restore требует reconciliation

**Решение**

После известного restore rollback-unprotected state unsafe forward use блокируется до явного reconciliation; типовой безопасный путь — historical-only для restored keys и новые `KeyId`/material для forward use. Подлинность старого snapshot сама по себе не позволяет обнаружить неизвестный rollback.

**Обоснование**

Исключает повтор nonce, revisions и lifecycle state после restore без обещания недоступного rollback detection.

---

## D33. Canonical stable identity encoding для Generation 1

**Решение**

Принять непустые lowercase UUID (`D`) как stable ProviderId/KeyId/SecretId, положительный Int64 decimal как KeyVersion и фиксированные `provider/key/version` / `provider/secret` как exact references. Application aliases не участвуют в persistent identity. Algorithm/Capability identifiers — stable lowercase tokens, CLR enums не сохраняются по ordinal. Ограничения имён и полная грамматика определены в TechnicalSpecification §7.1.

**Обоснование**

Переименование aliases и CLR-типа, изменение текущей культуры, восстановление старого snapshot и обновление реализаций не должны менять meaning уже сохранённых references. Это решение определяет только identity encoding; versioned persistent envelope и codecs проектируются в соответствующих будущих этапах.

---

## D34. Policy-gated local primitives и history-only compatibility

**Решение**

Внутри Security domain применять явную классификацию алгоритмов с проверкой назначения. SHA-1/HMAC-SHA-1 доступны только при явном `HistoricalVerification`; ни один неизвестный или недоступный алгоритм не заменяется fallback. Новые PBKDF2 derivations принимают только версионированный Generation 1 work factor с нижней границей 600 000 итераций, а восстановление более старых значений вынесено в именованный historical API. CSPRNG, HKDF и HMAC в safe-default и Advanced API разделяются требованиями к параметрам; эти операции не представляют собой управление ключами.

**Обоснование**

Позволяет воспроизводить historical значения без неявного ослабления новых операций и сохраняет совместимость будущих версий политики без переписывания lifecycle/key references.

---

## D35. Владение sensitive-массивом и конкурентный Dispose

**Решение**

Sensitive lease поддерживает `CreateCopy` (чужой вход, caller остаётся owner) и `TakeOwnership` (существующий массив, без копирования, явная логическая передача). По умолчанию доступ предоставляется синхронному read-only callback. `Dispose` не очищает массив посреди выполняющегося callback: новые callbacks отклоняются, owned bytes очищаются после выхода последнего reader. Стандартная JSON-сериализация явно отклоняется; `ToString` никогда не содержит секрет.

**Обоснование**

Задаёт точную границу zeroization, предотвращает очистку памяти во время использования callback и случайный export через обычный API. Существующие aliases, намеренные копии и снимки runtime/OS нельзя принудительно отозвать средствами управляемого кода.

---

## D36. Phase 5: capability resolution — только метаданные

**Решение**

Разделить stable logical и exact handles; типизированные key views работают через `IKeyMetadataResolver`, возвращающий актуальные неизменяемые snapshots. При каждой forward-проверке заново определять Active, исторические проверки выполнять только по exact version. Несовпадения identity, lifecycle, kind или capability отклонять. Результат — лишь metadata preflight, а не авторизация, material lease, nonce reservation или подтверждение поддержки алгоритма провайдером. Реальный provider обязан повторно проверить policy и capabilities при dispatch.

**Причина**

Разделяем discovery и реальные меры безопасности провайдера, исключаем кэширование Active и ложные гарантии авторизации при TOCTOU до появления backend contracts.

---

## D37. Чистое планирование lifecycle, tombstones и retention

**Решение**

В Generation 1 state machine реализуется как **внутренняя, чистая, неизменяемая** модель планирования в core `Laveyana.Security`, а не как публичный provider/store контракт. Каждый снимок содержит стабильные ProviderId/KeyId, logical state, монотонный high-water mark версий и записи версий, включая Deleted tombstones. `CreatePendingVersion`, `Activate`, `Rotate`, `RetireKey`, `DiscardPending`, `DeleteVersion`, `ForceDeleteVersion`, `DeleteKey` и `ForceDeleteKey` применяют transition matrix и invariant Active. Активация заменяет состояния старой и новой версий одним планом. Обычное удаление требует явное UTC-время и соблюдение retention каждой версии. Опасное force-удаление явно обходит retention, но `ForceDeleteVersion` никогда не удаляет current Active. CreatePendingVersion и Rotate неидемпотентны; no-op классификация не разрешает слепой повтор после неопределённого commit.

Authoritative backend следующих этапов обязан проверять revisions и достоверность retention, атомарно фиксировать state и material-effects, защищать high-water mark в пределах возможностей persistence/restore и освобождать KeyName только после durable deletion. Чистый план **не является транзакцией, записью на диск или авторизацией**. Уплотнять history можно только с сохранением high-water; старые снапшоты rollback-unprotected хранилища не гарантируют глобального non-reuse.

**Обоснование**

Позволяет тестировать критические инварианты без I/O, разделяет domain policy и durable provider mechanics и не фиксирует нестабильный internal API как публичный extension boundary.

---

## D38. Immutable provider registry и metadata-only backend discovery

**Решение**

Разместить `IKeyProviderBackend` и immutable provider capability declarations в Abstractions, без зависимостей от concrete Security и `IKeyStore`. В Phase 7 интерфейс обслуживает identity/metadata/capability discovery, а не crypto dispatch. При сборке immutable registry отклонять duplicate ProviderId/ProviderAlias и изменение идентичности реализации. Exact routing всегда использует persisted ProviderId, не перебирает остальные backends и валидирует ответы. Не считать provider-wide capability или metadata preflight подтверждением разрешения на операцию.

**Обоснование**

Позволяет подключать OS/HSM/remote adapters без расширения зависимостей, сохраняет смысл уже записанных KeyReference, не маскирует нарушения маршрутизации и оставляет атомарные security checks на границе исполнения следующих фаз.

---

## D39. Atomic aggregate storage и независимые контракты protector/nonce

**Решение**

Все три extension boundaries Phase 8 находятся исключительно в Abstractions. `IKeyStore` обязан обеспечивать единую durable точку коммита для захвата имени вместе с созданием агрегата, обновления метаданных и versioned protected material под CAS, удаления агрегата, всего material и освобождения имени. Ревизии начинаются с 1, увеличиваются на единицу на каждом успешном replace и не переполняются в authoritative history; удалённые KeyId остаются зарезервированы. Явный отказ не имеет побочных эффектов, но отмена/исключение рядом с commit требуют сверки состояния. Чтение material обязательно проверяет expected revision. Store не принимает plaintext, а создание envelope само по себе не подтверждает аутентичность.

`IKeyStoreProtector` аутентифицирует identity, purpose и versioned AAD с устойчивым `ProtectorReference`, не экспортируя root material. `IRollbackProtectedNonceAllocator` независим и optional, с сильными гарантиями против внешнего restore; обычный FileSystem counter не годится в качестве такой реализации.

**Обоснование**

Обеспечивает уникальность имени между процессами, исключает частичную фиксацию metadata/material, предотвращает ложные гарантии rollback/nonce и сохраняет расширяемость custom store/protector без ослабления безопасного поведения по умолчанию.

---

## D40. Software lifecycle orchestration и строгая обработка commit

**Решение**

Использовать чистую Phase 6 state machine как единственный источник допустимых lifecycle-переходов, а Phase 8 store — как единственный источник commit, уникальности имён и их освобождения. `SoftwareKeyProviderBackend` создаёт новый симметричный материал и связывает защищённые метаданные строго со следующей ревизией (`1` при create, `expected+1` при replace). Однозначный CAS-конфликт завершает операцию без автоматического повтора. Исключение во время store commit трактуется как неопределённый исход; перед новой командой требуется reconciliation. `GetOrCreate` после definite name conflict проверяет identity, algorithm, capabilities и retention победителя. Предварительный ограниченный формат `LSM1` защищён криптографически, но не объявлен финальной схемой хранения. До реализации crypto dispatch backend не декларирует исполняемые возможности.

**Обоснование**

Сохраняются уникальность имени, история версий, согласованность metadata/material; устраняются небезопасные повторные ротации и ложные declarations. Межпроцессная долговечность и защита от внешнего rollback зависят от будущих внешних реализаций и на Phase 9 не гарантируются.

---

## D41. Внутренняя AEAD nonce policy и строгая привязка к версии

**Решение**

Для AES-256-GCM добавить внутренний policy engine, выбирающий ProviderManaged только при подтверждённой гарантии провайдера; RollbackProtectedDeterministic — только при *одновременном* наличии независимого rollback-resistant allocator и объявленной store rollback protection; иначе для собственного свежего material — Randomized CSPRNG. В deterministic выдавать диапазоны по 64, привязывать к `KeyReference`, сжигать неизрасходованные значения при завершении и блокировать сессию при неизвестном исходе reservation. В randomized применять процессный бюджет 2²⁰ на точную версию и обеспечить ограничение реального срока использования ключа в будущей оркестрации. Известный rollback требует invalidate/reconciliation/new KeyId, а импорт с неизвестной историей nonce запрещён для managed encryption. Engine не выполняет AES и не заменяет авторизацию.

**Обоснование**

Разделяет nonce policy, independent durable authority и будущий криптографический dispatch. Не приписывает локальному счётчику кросс-процессную стойкость к restore и не маскирует сбой deterministic authority случайными nonce.

---

## D42. Канонические версии метаданных и контролируемая миграция

**Решение**

Новые software metadata используют схему `LSMD` v2 с независимыми от CLR enum wire-токенами и детерминированной сериализацией. Унаследованный `LSM1` допускается только для чтения аутентифицированных записей. Миграция создаёт новые bytes в памяти; запись требует отдельного CAS и новой revision-bound protection. `LSPB` bootstrap и `LSNC` nonce checkpoint — явные независимые wire-контракты, но не доказательства аутентичности или rollback protection. Неизвестные версии и некорректные записи отклоняются.

**Обоснование**

Снимает зависимость persisted-контракта от CLR-реализации, сохраняет history/high-water и исключает тихую подмену защитного authority либо nonce-state после restore. Долговечность и crash recovery принадлежат конкретному store следующего этапа.

---

## Сопровождение журнала

**Проверка нумерации Phase 26 (2026-10-10):** В журнале **50 самостоятельных решений** с идентификаторами D04–D57. Намеренные пропуски D01–D03, D26 и D28–D30 дублировали общие правила экосистемы, уже включённые в самостоятельный мастер-промпт; это **не потерянные решения**. Придумывать или перенумеровывать их нельзя. Наборы номеров в EN/RU совпадают. Последнее решение — D57; синхронизация документации не требует D58. Наличие решений **не доказывает приёмку безопасности**; аудит Phase 27 остаётся открытым.

## D43. Единый аутентифицированный файловый снимок с явным security gate

**Решение**

Phase 12 использует одну согласованную, версионированную запись `LSFS/LSFB`, аутентифицированный SHA-256-манифест через предоставленный `IKeyStoreProtector`, эксклюзивный межпроцессный lock и atomic file replacement. Сохранённые tombstones исключают повторное использование KeyId в доступной истории. Bootstrap не поставляет root secret, отсутствует plaintext fallback. Включение записи требует явного `EnableExperimentalWrites`; до завершения Phase 13 она не годится для production. `ProvidesRollbackProtection=false`, достоверное обнаружение restore и directory fsync не заявляются.

**Обоснование**

Один снимок сводит имя, CAS, metadata/material и used-ID к одной точке замены, а внешний protector защищает целостность маршрутизации без собственного корневого секрета в файловом хранилище. Отдельный security gate не маскирует отсутствие platform hardening и rollback authority.

## D44. Платформенные проверки без снятия экспериментального ограничения

**Решение**

Linux закрепляет проверенный приватный каталог `0700` дескриптором, выполняет операции относительно него без следования ссылкам, проверяет владельцев, права и типы через `statx`, использует `flock` и `fsync` каталога после атомарной замены. Небезопасные права уже существующих каталогов и файлов отклоняются без скрытого `chmod`. Windows создаёт изолированный ACL и проверяет владельца, DACL, предков и reparse points. Остальные ОС отклоняются.

**Ограничения**

На Windows запись всё ещё основана на строковых путях: необходимы защита от конкурентной подмены и настоящие тесты. Требуется проверить Linux и Windows на .NET 10. Это решение **не** разрешает production-запись, не вводит platform protector и не обеспечивает rollback protection. `EnableExperimentalWrites` остаётся режимом только для тестов.


## D45. Windows DPAPI CurrentUser — конкретный platform protector без fallback

**Решение.** `IKeyStoreProtector` в `Laveyana.Security.Windows` использует DPAPI CurrentUser (не LocalMachine): `LSWP` v1, domain binding `ProtectorReference`/purpose/AAD, проверку версии и дополнительный plaintext checksum. Корневой секрет остаётся у ОС; приложение передаёт стабильное поколение, менять которое без миграции нельзя. Native plaintext очищается. На других ОС — явный отказ, без plaintext fallback и assembly scanning.

**Ограничения.** DPAPI не изолирует приложения одного пользователя, не предотвращает rollback и не даёт универсального кросс-платформенного default. FileSystem TOCTOU и реальные .NET/Windows тесты остаются открытыми. Phase 14A отвечает за re-protection.


## D46. Re-protection — явный CAS всего агрегата, а не ротация ключа

**Решение.** Прошлые поколения `ProtectorReference` читаются только через явно
зарегистрированную ограниченную неизменяемую таблицу с exact routing; для записи есть
ровно один текущий protector. Для конкретного ключа сначала аутентифицируем метаданные
и все неудалённые версии материала, затем одним CAS заменяем метаданные с AAD следующей
ревизии и все historical envelopes. Неизвестные и скомпрометированные поколения
отклоняются: новая упаковка не устраняет компрометацию реального key material.
Запрещены fallback, частичные миграции и автоматический повтор неизвестного commit.
Лимит — 128 живых версий для единой транзакции, при превышении — явный отказ.

**Компромиссы.** Старые readers нужны до завершения миграции/проверки резервных копий.
Статус поколения — конфигурация, не защищённый журнал отзывов. `AlreadyCurrent` —
аутентифицированное наблюдение, но не линеаризуемое чтение. Смена DPAPI reference
не обязательно меняет root DPAPI. Тесты на сбои написаны, но .NET build, NUnit,
Windows DPAPI и production-gate FileSystem остаются открытыми.

**Дополнение для FileSystem.** Внешний snapshot защищён отдельно: его необходимо
явно перевести на current protector до миграции внутренних записей. Для
`OpenForMigrationAsync` нужны закреплённый UUID, точный legacy reference и experimental
write opt-in. Две атомарные замены файлов (snapshot, затем bootstrap) **не образуют
одной транзакции**: смешанное состояние исправляется повторным открытием в migration
mode, проверкой аутентичности и повтором идемпотентной операции. Обычный OpenAsync
отклоняет старый bootstrap. Пока миграция корня не завершена, обычные изменения
запрещены. Это не решает rollback старого корректного снимка и Windows TOCTOU.

**Дополнительная проверка Phase 14A:** новые protected envelopes и внешний snapshot проходят проверку расшифровки и точного равенства plaintext **до** попытки фиксации. Это не заменяет независимую реализацию, audit protector и проверки Windows/Linux на реальной .NET сборке.

## D47. Exact-reference результаты и криптографическая привязка метаданных AEAD

**Решение.** Четыре неизменяемых типа и канонических версионированных кодека (`LEP1`, `LDP1`, `LSP1`, `LMR1`) находятся в Abstractions, не зависят от провайдеров и копируют входные/выходные массивы. Неизвестные версии/флаги/алгоритмы отвергаются; detached ciphertext имеет зафиксированную длину. AEAD должен аутентифицировать versioned domain-separated контекст из точного `KeyReference`, алгоритма, nonce, размеров tag/ciphertext и внешнего application AAD. Сам external AAD не хранится в payload. Конструктор и кодек **не доказывают подлинность**.

**Причина и ограничения.** Ротация logical key не должна менять версию, которой шифровалось старое сообщение. Неканонический AAD создаёт риск неоднозначной интерпретации полей. Реальная проверка tag, политика провайдера, разрешение Active version, nonce policy и MAC/signature выполнение — отдельные будущие этапы. До реальной сборки и тестов .NET 10 форматы остаются предварительными и не должны использоваться как production interoperability contract.


## D48. AEAD выполняется провайдером: exact Active и TryDecrypt только для неверного tag

**Решение.** Whole-buffer AES-256-GCM реализован в `SoftwareKeyProviderBackend`; опциональный контракт `IAuthenticatedEncryptionBackend` находится в Abstractions, `ProviderRegistry.RouteAead` маршрутизирует по постоянному ProviderId. После проверки аутентифицированных метаданных выбирается текущая Active версия и материал читается условно по той же ревизии агрегата. Шифровать может только Active; расшифрование использует exact KeyReference (Active/Retired) из payload. Повторно применяется канонический AAD Phase 15 и nonce policy Phase 10; нет nonce из пользовательского ввода, silent downgrade и экспорта ключей.

**Ошибки и ограничения.** `TryDecrypt` перехватывает только `AuthenticationTagMismatchException` (неверный tag); конфликты стора, protector, политики, cancellation и форматов остаются ошибками. Временный plaintext очищается; лимит данных — 16 МиБ, внешний AAD — 64 КиБ. Пока исполняется только AES-256-GCM: ChaCha20-Poly1305 deferred до отдельной проверки nonce policy. Randomized лимит локален процессу, не гарантирует уникальность между перезапусками. Опциональный allocator требует независимо подтверждённой rollback protection. Файловый слой и Windows TOCTOU не прошли production gate; реальные .NET/NUnit тесты не запускались.

## D49. HMAC на защищённом software-хранилище, подписи через независимый versioned executor

**Решение.** Существующий симметричный `SoftwareKeyProviderBackend` исполняет HMAC-SHA-256/384/512 без экспорта исходного материала. Создание MAC выбирает Active, проверка использует точную Active/Retired версию, сравнение полного тега — fixed-time. Отдельные capability `Mac` и `VerifyMac` обязательны. `IManagedMacBackend` живёт в Abstractions, маршрутизация использует постоянный `ProviderId`.

**Асимметричная граница.** `IManagedSignatureBackend` и `IVersionedSignatureKeyOperations` позволяют доверенному исполнителю создавать ECDSA P-256 SHA-256 или RSA-PSS SHA-256 без изменения схемы симметричных ключей. Адаптер проверяет provider capabilities, свежие метаданные, точную версию, kind, состояние и алгоритм; фактические права и отзыв **обязательно** повторно проверяются исполнителем в момент криптографической операции. `EphemeralSignatureKeyOperations` выполняет реальные .NET подписи с передачей владения ключом, но хранит их только в процессе и **не** является durable backend.

**Семантика ошибок и открытые критерии.** Неверный MAC/подпись — `false`; отсутствие ключа, запрет capabilities, удаление, ошибки провайдера и отмена — исключения. Историческая проверка никогда не переключается на новую версию автоматически. Постоянное хранилище асимметричных ключей, отзыв в нескольких процессах, реальная .NET 10 сборка/NUnit, rollback и Windows TOCTOU остаются открытыми. Phase 18 отвечает за agreement и derivation.

## D50. ECDH P-256 + mandatory HKDF and explicit ephemeral derived capabilities

**Решение.** P-256 ECDH проводится только за доверенной versioned границей. Для ключа по metadata выбирается текущая Active private версия; потом trusted executor повторно проверяет право доступа. Raw shared secret не выдаётся API и очищается после HKDF-SHA-256. Контекст v1 с purpose, app context, длиной и двумя каноническими публичными SPKI обеспечивает domain separation, `salt=SHA256(info)`. Для симметричных HKDF-ключей используется защищённый материал с Active и expected revision, а транскрипт привязан к exact KeyReference. Произвольный выбор алгоритма, legacy fallback и default raw export запрещены.

**Компромиссы.** `DerivedKeyLease` владеет буфером, предоставляет только sync scoped visitor и стирает его при Dispose; явный export требует внешнюю `IDerivedMaterialExportPolicy`, что не отменяет обязанности стереть копии. Ephemeral executor — не durable, не защищает от другого процесса или MITM. Вектор ECDH/HKDF сверяется независимо, но .NET 10 сборка/NUnit и platform/security gates остаются открытыми. PQC KEM не включён.


## D51. Phase 19 HPKE остаётся deferred до .NET-conformance и доверенного private-key execution

**Решение.** Официальный эталон RFC 9180 Appendix A.3.1: Base, P-256/HKDF-SHA256/AES-128-GCM; он не меняет AES-256-GCM default обычного API. Подтверждаем независимым тестовым Python-движком открытый RFC vector. Нельзя подменять RFC-9180 HKDF собственной derivation Phase 18 и публиковать `Seal`, `Open`, `SealedPayload`, capabilities и стабильный wire-формат до выбора production suite, проверенного .NET провайдера, C# тестов/независимого interop, проверок точного приватного ключа и его отзыва, info/AAD/identity binding и focused security review.

**Ограничение.** Тестовый эталон успешно проверен (6 последовательностей и 14 отрицательных проверок), но .NET 10/NUnit, производственный private-key custody, независимое interop и security review **не выполнены**. Возможность остаётся UNSUPPORTED/DEFERRED согласно D21 и release-optional Roadmap. Подробности: `Laveyana.Security.HpkeGate.ru.md`.

## D52. Потоковые SHA/HMAC независимы от отдельного AEAD security gate

**Решение.** Поставлять SHA-2 и полноразмерный HMAC под управлением провайдера с однопроходным буфером ограниченного размера, максимальным числом байтов, необязательной доверенной длиной, без владения входным потоком, с точной версией ключа и повторной проверкой ревизии по завершении. Проверка MAC возвращает `false` только при несовпадении тега, а не при неполном чтении или сбое провайдера. `IStreamingMacBackend` — необязательный точечно маршрутизируемый контракт. Публичный API AEAD streaming запрещён без отдельного рецензируемого протокола, аутентифицированного завершения и независимых тестов.

**Ограничения.** Недоверенная ожидаемая длина не защищает от обрезки; неизменяемость источника обеспечивает приложение. Сборка .NET, NUnit и platform security review остаются открытыми. См. `Laveyana.Security.StreamingGate.ru.md`.


## D53. Secrets по умолчанию read-only, exact-ID routing и scoped владение

**Решение.** Базовый `ISecretProvider` содержит только `FindAsync` и `GetAsync`. Идентификатор — `(ProviderId, SecretId)` без универсальной версии. `SecretReadResult` владеет очищаемым lease; `SecretHandle` предоставляет callback-доступ с проверкой идентичности. Отдельный неизменяемый `SecretProviderRegistry` маршрутизирует по точному ID; alias — только runtime. `ISecretManagementProvider` необязателен и запрашивается явно. Возможности open/export разделены, по умолчанию false и не являются разрешением доступа.

**Обоснование.** Не дублируем Key Lifecycle, не требуем управление от read-only провайдера, не держим долгоживущие копии plaintext и не перенаправляем сохранённые ссылки после изменения alias. Авторизация проверяется провайдером при каждой операции.

**Ограничения.** Borrowed span нельзя физически защитить от намеренной копии; отмена не прерывает уже работающий синхронный callback. Нет встроенного persistent secret provider, гарантированного отзыва во всех процессах и подтверждённой сборки/NUnit.



## D54. DI формирует неизменяемую конфигурацию без владения криптографическими правилами

**Решение.** `AddSecurity` и `AddSecurityDefaults` собирают строго явный снимок
`SecurityCompositionSnapshot` в отдельной сборке DI. Структурные ошибки конфигурации
отклоняются при регистрации/разрешении, а требуемые объявленные capabilities проверяются
при старте Host через `IHostedService` либо явно в non-host приложениях. Реестры
сохраняют точные `ProviderId`, alias не подменяют persistent identity. Внешние типы должны
предоставляться уже зарегистрированными singleton; смешение alias ключей и секретов
в одной композиции запрещено.

**Обоснование и компромиссы.** Синхронный DI container не должен блокировать
асинхронное открытие стора, поэтому FileSystem открывает приложение до композиции.
Регистрация не инициирует network I/O, файловый bootstrap, silent platform probing,
фоновые задания или выдачу plaintext. `AddSecurityDefaults` без protector отклоняется;
автоматический выбор Windows DPAPI не делается. При динамическом изменении capabilities
и отзыве ключей права перепроверяются при криптографической операции. Для non-host
контейнеров startup-валидация динамических capabilities должна вызываться явно.

**Открытые требования.** Windows-specific convenience preset, .NET build/NUnit и проверка
реального DI host integration, а также предыдущие FileSystem/platform security gates.


## D55. Условная ротация с явным расписанием и optional worker

**Решение.** Ручной и плановый вызовы объединены в `RotationEngine` с обязательным
для автоматической операции контрактом `IConditionalKeyRotationBackend`: ожидаемая
Active-версия проверяется backend внутри той же CAS-транзакции. Время вычисляется
через `TimeProvider` и доверенную UTC-метку активации, переданную приложением.
Worker никогда не регистрируется по умолчанию; его включают только явным вызовом
DI с `IRotationWorkSource`, атомарно и долговечно закрепляющим задание до выполнения.
При неизвестном исходе commit автоматического повтора нет.

**Компромиссы и ограничения.** Persistent расписание и ручная сверка сомнительных
результатов остаются ответственностью приложения. Сбой после claim может оставить
задание заблокированным, чтобы исключить повтор неидемпотентной операции. Worker
не обеспечит safety, если source нарушает контракт. Авторизация и допустимость
удаления старых ключей проверяются отдельно. Сборка .NET, NUnit, реальное
межпроцессное исполнение пока не подтверждены.


## D56. Явная поэтапная миграция без перенаправления KeyReference

**Решение.** Перенос использует отдельные неизменяемые ProviderId/KeyId, точную
версию Active источника и `ProviderMigrationOrchestrator` с контрольными точками.
Software destination создаёт независимый материал; защищённый native transfer
требует отдельных контрактов и реальных проверок доверия/канала провайдерами.
Открытого API экспорта исходного ключа нет. Подготовка нового ключа и проверка
не означают переключение приложения: необходим точный receipt после долговечного
переноса данных и ссылок. Старый `KeyReference` не перенаправляется.
Retirement/delete исходного ключа требуют отдельного lifecycle-контракта самого
провайдера; принудительного удаления здесь нет.

**Ограничения.** Авторизация и CAS-сохранение checkpoint, восстановление после
неопределённого commit и сверка состояний принадлежат приложению. Готовых native
transfer и долговечного журнала нет. Реальные сборка/NUnit, security review и
предыдущие platform/rollback security gates не подтверждены.

## D57. Наблюдаемость opt-in, с фиксированными кодами событий и необязательным audit sink

**Решение.** `SecurityObservability` в основной сборке использует стандартные
`ILogger<SecurityObservability>`, `ActivitySource` и `System.Diagnostics.Metrics`.
Доступны только фиксированные значения `SecurityOperation` и `SecurityOperationOutcome`.
Логи содержат `{Operation}` / `{Outcome}`, Activity и метрики — только теги
`security.operation` и `security.outcome`; histogram длительности выражен в миллисекундах.
Нет меток ProviderId/KeyId/SecretId, имени, версии, AAD, размера секретного материала,
сообщений исключений, payload, plaintext или ciphertext. Ошибки классифицируются
без сериализации исходного исключения. `false` для проверки MAC и `null` для
`TryDecrypt` дают `Negative`, а техническая ошибка не превращается в отрицательный ответ.

**Интеграция.** Наблюдатель передаётся в `SoftwareKeyProviderBackend`,
`ProviderRegistry` и `SecretProviderRegistry` явно. DI имеет опциональный
`WithObservability`; ручная композиция остаётся равноправной. Нет глобальной
перенастраиваемой конфигурации, не вводится backend экспортирования. Для Activity
корреляция использует стандартный trace ID и не добавляется в labels метрик.
Существующие прямые обходы реестра и сторонние провайдеры не инструментируются
автоматически: им требуется собственное внедрение наблюдателя.

**Audit.** `ISecurityAuditSink` принимает bounded `SecurityAuditEvent` с операцией,
исходом, UTC временем и необязательным trace ID. Это необязательная best-effort
notification, а **не** compliance/audit trail: нет durable storage, гарантии доставки,
идемпотентности и подтверждённой атомарности относительно commit. Ошибки telemetry
или sink не меняют уже совершённую криптографическую операцию, а потеря audit
учитывается отдельным счётчиком. Приложение должно само реализовать долговечный
аудит с нужными SLA и контролем доступа; audit sink не должен блокировать вызов.

**Открытые проверки.** Добавлены тесты на отсутствие чувствительных данных,
bounded dimensions, Activity/correlation, real AES-GCM outcome и сбои sink. До
компиляции .NET 10 и выполнения NUnit, включая тесты на реальных Windows/Linux,
формальная приёмка Phase 25 открыта. Вся библиотека остаётся неготовой к production.


---

## D58. SA-03: независимое состояние всего хранилища и отказ при неопределённости (2026-10-20)

**Решение**

Добавить необязательный контракт внешнего authority в Abstractions с привязкой к закреплённому UUID, монотонной последовательности **целого снимка** и его отпечатку. Использовать долговечные CAS-переходы «подготовлено / подтверждено»; запретить автоматическую регистрацию при первом открытии существующего хранилища, обычное чтение при pending и сброс к старому checkpoint. Возможность `ProvidesRollbackProtection` остаётся `false` до реализации и проверки независимого authority и восстановления.

**Обоснование**

Исторический корректно аутентифицированный файл можно повторно подставить. Ревизии отдельных ключей и MAC внутри файла не способны выявить откат без независимого доверенного состояния. Подробнее в [контракте SA-03](Laveyana.Security.RollbackAuthorityContract.ru.md). **Только этап контракта; SA-03 открыта.**
