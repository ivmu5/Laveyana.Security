# Laveyana.Security — Архитектура

[English](Laveyana.Security.Architecture.md) | **Русский**

> Статус: **final architecture baseline Generation 1**.
>
> Реализация обязана сохранять boundaries и invariants этого документа. Возврат к закрытому решению требует новой технической причины и новой записи Decision Log.


> **Точка реализации и верификации (2026-10-16; H01):** Исходники семи проектов и публичные API существуют. Проверки `Source & docs`, Release-сборка и NUnit успешно прошли на Windows и Ubuntu в GitHub Actions. Это закрывает прежнее отсутствие проверенной сборки, но не завершает adversarial-аудит Phase 27. `FileSystem` остаётся экспериментальным; HPKE `Seal/Open` и потоковое AEAD не поддерживаются. Исторические замечания об отсутствии выполненных тестов в описаниях отдельных фаз относятся к тем этапам, а не к текущему CI. См. [README](../../README.ru.md), [Roadmap](Laveyana.Security.Roadmap.ru.md) и [CHANGELOG](../../CHANGELOG.ru.md).

## 1. Архитектурная модель

`Laveyana.Security` разделяет четыре уровня ответственности:

```text
Consumer contracts / stable values
        ↓
Domain orchestration / policy / lifecycle
        ↓
Provider and storage extension boundaries
        ↓
Concrete software/platform/HSM/remote implementations
```

Обычный consumer работает с capability-oriented high-level API и не управляет опасными cryptographic details вручную.

## 2. Dependency graph

```text
Laveyana.Security.DependencyInjection
        ├───────────────┐
        v               v
Laveyana.Security   Laveyana.Security.FileSystem
        │               │
        └───────┬───────┘
                v
Laveyana.Security.Abstractions
```

Platform/provider packages также зависят вниз от `Laveyana.Security.Abstractions`. Platform package при необходимости может дополнительно использовать DI/FileSystem для собственного safe preset, но cross-platform core никогда не зависит от platform package.

Запрещённые направления:

- `Abstractions → Security/FileSystem/platform`;
- `FileSystem → Security` только ради получения `IKeyStore`;
- provider package → `Security` только ради backend contracts;
- циклические `ProjectReference` graphs.

## 3. Logical modules

Основная assembly остаётся одной technical unit, но логически делится на:

```text
Laveyana.Security.Cryptography
Laveyana.Security.Keys
Laveyana.Security.Secrets
```

Отдельный `.csproj` не создаётся только потому, что появился namespace.

### Cryptography

Algorithm policy, safe defaults, local primitives, high-level payload semantics, validation, dispatch и provider-backed operations.

### Keys

Key identity, typed capabilities, lifecycle, provider registry, rotation, retention, delete, provider migration и software-provider orchestration.

### Secrets

Read-oriented secret providers, opaque secret handles и controlled material access.

## 4. Public API layers

### Consumer-facing abstractions

`Laveyana.Security.Abstractions` содержит все типы, необходимые в ordinary consumer-facing signatures, включая:

- stable identifiers и references;
- descriptors и lifecycle/capability values;
- logical и exact-version capability contracts;
- high-level cryptographic service contracts;
- high-level key/secret management contracts;
- `EncryptedPayload`, `SignaturePayload`, `MacResult`;
- typed result/status values и contract exceptions.

### Extensibility-facing abstractions

В той же assembly, но в отдельных namespaces, находятся deliberate cross-assembly extension points:

- `IKeyProviderBackend`;
- `IKeyStore`;
- `IKeyStoreProtector`;
- optional rollback-protected AEAD nonce-state contract;
- только минимальные supporting contexts/results/capabilities, необходимые external implementations.

Serializers, locks, journals, internal state machines, orchestration helpers и implementation-only validators остаются internal.

## 5. Key aggregate

Conceptual logical-key aggregate:

```text
LogicalKey
├── ProviderId
├── KeyId
├── KeyName?               # runtime/application alias
├── KeyKind / capabilities
├── LogicalState
├── NextVersion / HighWaterMark
└── Versions[]
    ├── KeyVersion
    ├── Algorithm + parameters
    ├── VersionState
    ├── timestamps
    └── provider-owned material reference/capability
```

Слово `material` не означает, что raw bytes обязаны существовать в process memory. HSM, OS-backed, remote и non-exportable implementations могут держать private material полностью opaque.

## 6. Logical vs exact capabilities

Forward-use capability:

```text
EncryptionKey (ProviderId + KeyId)
        ↓ resolve current Active version
Exact version (ProviderId + KeyId + KeyVersion)
        ↓ dispatch
Encrypt
        ↓
EncryptedPayload фиксирует exact KeyReference
```

Historical-use capability:

```text
EncryptedPayload / SignaturePayload / MacResult
        ↓ exact KeyReference
resolve exact historical provider/key/version
        ↓
decrypt / verify
```

Rotation изменяет будущий forward resolution, но никогда не меняет смысл уже сохранённых historical references.

Logical handles не кэшируют Active version через rotation. Exact handles никогда не переключаются автоматически.

## 7. Lifecycle state machine

### Logical key

```text
Create
  ↓
Active ──RetireKey──> Retired ──DeleteKey──> Deleted
  │
  └── ForceDeleteKey (Advanced destructive path) ───> Deleted
```

### KeyVersion

```text
CreateVersion
   ↓
Pending ──Activate──> Active ──replacement / RetireKey──> Retired ──DeleteVersion──> Deleted
   │                    │
   └── Discard ────────>Deleted
                        └── ordinary delete forbidden while current Active
```

Activation replacement — один atomic/recoverable domain transition:

```text
old Active → Retired
new Pending → Active
```

Standalone `RetireVersion(current Active)` не может оставить logical `Active` без Active version. Consumer должен использовать replacement activation или `RetireKey`.

## 8. KeyVersion reservation

Version identity необратимо выделяется внутри represented authoritative history:

```text
v1 created
v2 created
v2 discarded
v3 created
next version = v4
```

Aggregate/store сохраняет достаточный high-water state, чтобы исключить reuse при normal operation и supported crash recovery.

Гарантия явно ограничена rollback characteristics: restore старой valid snapshot rollback-unprotected store может откатить high-water state.

### Phase 6: граница чистого lifecycle planning

Внутренний `Laveyana.Security.Lifecycle.KeyLifecyclePlanner` работает с валидированными неизменяемыми snapshots и возвращает неизменяемые планы. Он не зависит от storage, системных часов и provider dispatch. Замена состояний атомарна **только как расчёт domain state**. Provider orchestration (Phase 9) должен атомарно фиксировать планы и material effects с optimistic revision checks в надёжном authoritative store (Phase 8). Неопределённый commit требует reconciliation перед retry; no-op доменной модели не является межпроцессным idempotency key. Текущий Active запрещено удалять через `ForceDeleteVersion`, а явный `ForceDeleteKey` каскадно удаляет агрегат. Retention берётся из authoritative состояния; запись high-water mark и освобождение имени — ответственность store. Restore rollback-unprotected backup не обеспечивает глобальной монотонности.

## 9. Provider registry и routing

Runtime composition создаёт immutable registry:

```text
ProviderAlias ──resolve──> ProviderId ──route──> IKeyProviderBackend
```

Правила:

- alias и id независимо unique;
- duplicates — startup/configuration errors;
- `KeyReference` route напрямую по stable `ProviderId`;
- scan-all-providers lookup отсутствует;
- изменение alias mapping не меняет смысл persisted references.

Provider capabilities granular. Cryptographic operation допустима только когда:

```text
key policy allows operation
AND
provider declares required capability
```

## 10. Provider migration

Provider migration создаёт новую cryptographic generation:

```text
Source ProviderId A / KeyId A
        ↓
Destination ProviderId B / KeyId B
```

Существующий KeyId никогда не переносится между providers. Old references остаются immutable и могут сосуществовать с destination references во время migration.

Если source material non-exportable, migration может требовать application data re-cryptography или provider-native transfer capability вместо raw material export.

## 11. Software provider boundary

```text
Laveyana.Security orchestration
        ↓
SoftwareKeyProviderBackend
        ↓
IKeyStore
        ↓
FileSystem or custom software store
```

Store владеет persistence/consistency mechanics; Security владеет lifecycle validity и cryptographic policy.

Correctness `GetOrCreate` обеспечивается на boundary unique `(ProviderId, KeyName)` binding/aggregate creation. Гонка случайных KeyId недостаточна.

## 12. Protected FileSystem architecture

```text
Laveyana.Security.FileSystem
        ↓ uses
IKeyStoreProtector
        ↓ implemented by
platform/custom protector
```

FileSystem conceptually сохраняет:

```text
minimal bootstrap/routing header
protected metadata envelope
protected key-material envelope(s)
recovery/journal state where required
```

Bootstrap fields, необходимые для выбора `ProtectorReference`/envelope version, могут оставаться cleartext, но обязаны быть cryptographically bound как authenticated context.

Metadata и material protection используют разные domain-separated purposes. `master.key` рядом с encrypted keys не является acceptable secure default, если этот master key сам не защищён independent security boundary.

## 13. FileSystem safety

**Граница готовности:** пока проверки owner/permissions/path safety не реализованы и не проверены на целевой платформе, FileSystem store нельзя считать безопасным writable key store для production. Основа FileSystem и platform hardening образуют единый security release gate.


Initialization behavior:

- если root отсутствует, создать его, выставить restrictive permissions, проверить результат и только затем писать sensitive files;
- если root существует, проверить owner, ACL/mode, inheritance, entry type и reparse/symlink behavior;
- unsafe или unverifiable state → fail closed.

Unix baseline:

```text
directory → 0700
secret file → 0600
```

Windows использует ACL/ownership validation согласно deployment model и проверяет итоговый ACL.

Normal filesystem delete означает, что material больше недоступен через provider; forensic secure erase не обещается.

## 14. Crash recovery vs external rollback

Существуют два разных recovery class.

### Crash recovery

Текущая authoritative history существует, но write/workflow прерван. Recovery может использовать temp files, journal, checkpoint, transaction-equivalent replacement, resume или rollback незавершённой operation.

### External rollback / restore

Current valid store заменён более старой, но всё ещё valid/authenticated snapshot. Rollback-unprotected store может быть неспособен обнаружить событие.

Поэтому authenticated metadata **не равна** rollback protection. Lifecycle state, version high-water marks, name bindings, usage counters и deterministic nonce state могут откатиться.

Если external restore известен, forward cryptographic use входит в explicit reconciliation. Safe default:

```text
restored generation → historical/read-only where possible
fresh forward use   → new KeyId + fresh material
```

Deployment, где требуется malicious-rollback detection, обязан использовать independent rollback-protected authority/backend.

## 15. AEAD nonce architecture

Strategy selection capability-driven:

```text
provider safely owns AEAD nonce lifecycle
        → ProviderManaged

rollback-protected monotonic state exists
        → RollbackProtectedDeterministic

software key + rollback-unprotected store
        → Randomized

no safe strategy available
        → managed AES-GCM Encrypt unsupported
```

Deterministic allocator — отдельный optional contract и никогда не является обязательной частью `IKeyStore` CRUD.

### Randomized

Использует fresh 96-bit CSPRNG nonce. Это default для ordinary FileSystem storage, потому что strategy не зависит от rollback-able FileSystem counter.

### RollbackProtectedDeterministic

Требует rollback protection и atomic monotonic reservation capability, привязанную к exact `KeyReference`. Committed unused ranges после crash сгорают.

### ProviderManaged

Backend владеет safe nonce semantics и возвращает public metadata, необходимые managed payload.

## 16. Payload architecture

Managed encryption result:

```text
EncryptedPayload
├── FormatVersion
├── AlgorithmId + public parameters
├── Nonce
├── Ciphertext
├── AuthenticationTag
└── exact KeyReference
```

Managed signature/MAC results аналогично содержат exact historical identity:

```text
SignaturePayload
MacResult
```

Security-critical fields immutable и, где применимо, аутентифицируются как internal metadata.

Application-provided AAD — отдельный external context. Security аутентифицирует его, но не интерпретирует domain meaning и не сохраняет автоматически.

## 17. Persistent schema architecture

Runtime/domain classes не являются permanent schemas.

```text
Domain model
    ↓ mapping
Persisted Vn DTO
    ↓ codec
Protected envelope
```

Migration chain:

```text
V1 → V2 → V3 → ...
```

Migration выполняет strict old-version parse, validation, in-memory conversion, current-version validation и safe persistence.

Stable persisted identifiers никогда не зависят от CLR type names, assembly-qualified names или enum declaration ordering.

Unknown newer format → fail closed.

## 18. Secrets architecture

```text
SecretHandle (opaque)
        ↓
ISecretProvider
        ↓
UseMaterial(callback)
        or
SensitiveMaterialLease
```

Base secret model read-oriented. Universal `SecretVersion` намеренно отсутствует; provider-specific versioning может быть optional capability.

`SensitiveMaterialLease` владеет mutable memory, очищает owned memory при dispose, не сериализуется/не логируется, не имеет meaningful `ToString` и implicit conversion в `byte[]`.

## 19. DI composition architecture

Manual construction остаётся supported scenario.

DI composition:

```text
method-based settings DSL
        ↓ validation
immutable composition snapshot
        ↓
provider/protector registries
        ↓
thread-safe shared services
```

`AddSecurityDefaults()` — common preset поверх той же model. Он требует pre-registered safe protector и никогда не угадывает platform implementation через assembly scanning/reflection.

Platform packages могут предоставлять safe platform presets. Core/default composition не запускает hidden background worker.

Optional automatic rotation использует Generic Host lifecycle и тот же rotation engine, что manual path.

## 20. Integration boundary

`Laveyana.Security` предоставляет capabilities. Domain libraries владеют domain semantics.

Пример:

```text
Laveyana.Persistence.Security
├── decides what data is encrypted
├── constructs persistence-specific AAD
├── tracks data references
└── migrates/re-encrypts dependent data
        ↓
Laveyana.Security
└── crypto/key capabilities
```

Independent domains не изображают общую transaction, если реальной общей transaction нет. Cross-domain workflows используют application-owned retry, compensation, journal, checkpoint или recovery state.

## 21. Deliberate design gates

Две feature намеренно gated и не являются незакрытой архитектурой.

### Seal/Open

High-level asymmetric confidentiality публикуется только после выбора standardized/analyzed HPKE-compatible construction, exact suites/encoding/info/AAD/limits, authoritative vectors и focused security review. Если gate не пройден, feature остаётся unsupported/deferred.

### Streaming AEAD

Encrypted streaming требует analyzed segmented construction или отдельно specified/reviewed protocol с nonce derivation, position binding, stream identity, splice/reorder/truncation protection, limits, vectors и focused review.

Custom protocol не создаётся только ради закрытия checklist.

## 22. Обязательные инварианты

Все externally observable invariants и условия допуска к релизу нормативно определены в [TechnicalSpecification](Laveyana.Security.TechnicalSpecification.ru.md). Этот документ описывает механизмы и границы ответственности, а не дублирует требования.

### Phase 5 — граница metadata-only resolution

Типизированные views (`EncryptionKey`, `MacKey`, `DerivationKey`, `AsymmetricPublicKey`, `AsymmetricPrivateKey`) используют `IKeyMetadataResolver`, возвращающий отдельные неизменяемые logical/exact metadata snapshots. Они проверяют декларации capabilities, соответствие версий и тип ключа только для preflight; не возвращают material и не выдают разрешения на его использование. Resolution **не** является авторизацией: при выполнении операции backend должен повторно проверить актуальное состояние, политику, provider capability и algorithm policy. Устаревший результат не может считаться разрешением на операцию.

### Phase 7 — контракты provider и композиционный registry

`IKeyProviderBackend` и immutable `ProviderCapabilitySnapshot` находятся в `Laveyana.Security.Abstractions.Providers`. Внешняя реализация может подключаться без ссылки на concrete Security/FileSystem/DI. Интерфейс расширяет `IKeyMetadataResolver`; это **metadata-discovery boundary**, не монолитный интерфейс crypto operations. Его договорённость по `ProviderId` требует сохранения одной persistent identity на lifetime инстанса.

`Laveyana.Security.Providers.ProviderRegistry` захватывает `ProviderRegistration` в приватный snapshot: lookup по ProviderId и опционально alias-to-ProviderId. Duplicate registry entries/alias запрещены. `Route` и методы `IKeyMetadataResolver` направляют вызов только в конкретный backend из ProviderId; ответы с иной identity и смена заявленной backend identity отклоняются. `ProviderCapabilitySnapshot` является read-only копией объявленных capabilities, но **не** подтверждает разрешение policy и не резервирует ресурс. Registry не делает автоматического поиска подходящего backend и не исполняет криптографию; software adapter и durable workflow появятся позднее.

### Phase 8 — атомарность store и граница protector

`Laveyana.Security.Abstractions.Storage.IKeyStore` — расширяемый контракт долговечного software-хранилища, отдельный от provider discovery. Create атомарно связывает `(ProviderId, KeyName)` с encrypted metadata и initial material; CAS replace фиксирует новую ревизию и всю группу material upsert/deletion одной транзакцией; conditional delete каскадно уничтожает материал и только тогда освобождает имя. `ReadMaterialAsync` проверяет конкретную ревизию агрегата, не позволяя прочитать материал под неподходящим снимком метаданных. Ревизии монотонны в пределах authoritative history; повторное использование удалённого KeyId запрещено и требует долговечной отметки used identity. Допустимость lifecycle-переходов определяет planner и provider orchestration, а не store. Исключения/отмена рядом с commit требуют reconciliation по authoritative состоянию.

`Laveyana.Security.Abstractions.Protection.IKeyStoreProtector` отдельно аутентифицирует и шифрует metadata и key material с разными purpose и стабильными поколениями `ProtectorReference`. AAD привязывает точную key identity и metadata revision либо exact material version. Envelope — только неизменяемый контейнер ciphertext, **не** доказательство подлинности. Root-ключ защиты никогда не экспортируется; plaintext передаётся в явных `SensitiveMaterialLease`. Никакого fallback на plaintext или слабую защиту. Для детерминированного nonce предусмотрен **необязательный** и независимый `IRollbackProtectedNonceAllocator`; обычный FileSystem не объявляется rollback-protected. Реальная at-rest защита, permissions и crash recovery будут реализованы позже.

## Реализация Phase 9: software lifecycle с защищённым хранилищем

`Laveyana.Security.Software.SoftwareKeyProviderBackend` реализует `IKeyProviderBackend`, используя внешние контракты `IKeyStore` и `IKeyStoreProtector` из Abstractions. Все изменения проходят внутренний `KeyLifecyclePlanner`; adapter проверяет provider/name/key, аутентифицирует метаданные `LSM1` с контекстом ревизии и записывает новое состояние вместе с изменениями material одной CAS-транзакцией. При создании происходит атомарный захват provider/name с ревизией 1; замена использует строго `expected + 1` для предварительной аутентификации записи. Plaintext material не сохраняется и не возвращается вызывающему коду.

`GetOrCreate` возвращает найденное поколение только при совпадении алгоритма, capabilities и initial retention. Проигравший создатель освобождает временный секретный буфер; отказ store не должен давать побочных эффектов. При определённом конфликте ревизий операция прекращается. Неопределённый commit вызывает `SoftwareKeyCommitUncertainException`; автоматический retry отсутствует. Имя освобождается только после фиксации полного удаления. Retention и high-water mark живут в защищённых метаданных; возврат старого снимка нельзя обнаружить без внешнего authority. Исполняемые capabilities backend пока не объявляет. Формат метаданных предварителен и требует отдельной проверки миграций в Phase 11.

## Phase 10 — реализация nonce policy

В `Laveyana.Security.Nonce` добавлена внутренняя политика для будущих provider operation paths; все расширяемые контракты по-прежнему в Abstractions. Выбор осуществляется один раз по проверенным метаданным конкретной версии, а операция дополнительно проверяет актуальность lifecycle и статус restore. `Randomized` использует CSPRNG и локальный по процессу лимит; `RollbackProtectedDeterministic` — только внешний durable rollback-resistant allocator, который атомарно и навсегда резервирует интервалы; `ProviderManaged` не выдаёт nonce для локального шифрования. Каждый deterministic session сериализует выдачу, отвергает неправильные ответы и не повторяет неопределённый commit. После известного восстановления старой версии требуется новая `KeyId`. Функциональный AES-GCM dispatch будет на следующих этапах.

## Phase 11 — границы persistent схем

Runtime state machine сохраняет семантику lifecycle, а внутренний `SoftwareKeyPersistedRecord` отвечает за переход к стабильным wire-значениям. `SoftwareKeyMetadataCodec` создаёт `LSMD` v2 и читает ранее аутентифицированный `LSM1`; никаких неявных on-read mutations. В `Abstractions.Persistence` размещены переносимые, независимые от FileSystem схемы `LSPB`/`LSNC`; FileSystem, корневой protector и независимый monotonic allocator остаются на своих границах ответственности.

## Phase 12 — реализация FileSystem boundary

`FileSystemKeyStore` работает только через интерфейсы `Abstractions` и обязательный внешний `IKeyStoreProtector`. Авторитетная транзакция — единый снапшот, lock распространяется на весь цикл read/modify/write, `KeyId` tombstones не удаляются. `LSPB` bootstrap — лишь маршрутизирующая подсказка; за доверие отвечает configured protector и его проверка AAD манифеста. Не путать проверяемую целостность текущей записи с защитой от внешнего возврата к старому состоянию. Внешнее хранилище не получает полномочий изменять lifecycle без orchestrator.

До Phase 13 не устраняются symlink/reparse и path component гонки, и не заявляется production гарантия directory fsync. Письмо закрыто по умолчанию с исключительно экспериментальным opt-in.

## Phase 13 — платформа и изоляция файлового хранилища

На Linux каталог хранилища закрепляется проверенным дескриптором. Файлы открываются относительно него, без следования символическим ссылкам; контролируются тип, владелец, режим, `flock` и атомарная замена с `fsync` каталога. Опасные предки пути отклоняются. На Windows проверяются владелец, DACL и reparse points; новый каталог создаётся с изолированным ACL, однако операции по строковым путям сохраняют риск TOCTOU. Экспериментальный opt-in и ограничение rollback не сняты.


### Phase 14 — модель доверия DPAPI CurrentUser на Windows

Платформенная сборка зависит только от `Abstractions`. Выбор protector делает приложение, не `FileSystem`/DI через reflection. DPAPI CurrentUser защищает текущий профиль и криптографически связывает identity/purpose/AAD посредством domain-separated optional entropy. Успешная расшифровка не гарантирует rollback-resistance, отсутствие файловых TOCTOU или изоляцию приложений одного пользователя. `LSWP` v1 и его поколение стабильны; migration только в Phase 14A. При отсутствии DPAPI — fail closed без plaintext fallback.


### Phase 14A — маршрутизация и атомарная повторная защита

`ProtectorGenerationRouter` находится в реализации, а сторонним protector/store достаточно
`Abstractions`. Неизменяемая таблица по точным historical reference разрешает только
аутентифицированное чтение; для новой записи используется исключительно current protector.
Неизвестные или скомпрометированные поколения блокируются без fallback. Явный
`SoftwareKeyReprotectionService` проверяет метаданные и каждый существующий материал,
затем одним CAS переводит метаданные и historical material на текущую защиту с новой
ревизией. Удалённые версии сохраняются как tombstones без материала. Нет автоматического
обхода всех ключей, скрытых повторов или частичной миграции, нет смены KeyId/key material.
Неизвестный результат commit требует сверки состояния. Реальная атомарность хранилища
и security-gate ОС остаются независимыми условиями.


**Экспериментальная миграция корня FileSystem:** хранилище отдельно аутентифицирует
весь снимок `LSFS`, поэтому миграции одних key material envelopes недостаточно.
Существующее хранилище нужно открыть через
`FileSystemKeyStore.OpenForMigrationAsync(options, router, legacyReference)` с
`EnableExperimentalWrites = true` и **закреплённым непустым**
`ExpectedStoreInstanceId`. Обычный `OpenAsync` не разрешает старое поколение.
Явный `ReprotectRootAsync()` сначала заменяет снимок с защитой нового поколения,
потом обновляет публичный `LSPB` bootstrap. Это **две отдельные файловые операции**,
не общая транзакция: при сбое между ними возможно промежуточное смешанное состояние.
Для восстановления повторно открыть в migration mode с теми же UUID и доверенным
legacy reader, проверить аутентичность снимка и повторить идемпотентную миграцию корня.
Пока миграция корня не завершена, обычные изменения записей в этой сессии запрещены.
Затем разрешена per-key миграция через `SoftwareKeyReprotectionService`. После
миграции **всех** сохранённых ключей хранилище должно открываться только с current
protector. Миграция корня не переписывает сами key envelopes и не обеспечивает
rollback protection.

### Phase 15 — владение результатами, проверка и managed AAD

`Laveyana.Security.Abstractions.Payloads` содержит ciphertext, detached metadata, signature и MAC значения без зависимости от реализации криптографических провайдеров. Буферы возвращаются лишь через `Export*Copy()`, backing arrays недоступны для изменения. Обязателен сохранённый exact `KeyReference`, а не alias или logical handle. Четыре раздельных формата v1 (`LEP1`/`LDP1`/`LSP1`/`LMR1`) исключают смешение классов записей; неизвестные версии отвергаются. Detached metadata аутентифицируемо привязана к длине ciphertext.

`EncryptedPayloadAssociatedData` формирует domain-separated AEAD внутренние метаданные и ограниченный внешний AAD приложения. Отправитель и получатель обязаны использовать одинаковый набор байтов при **реальном** AEAD. Создание объекта и парсинг не дают гарантий подлинности. Выбор exact active version и шифрование — Phase 16, MAC/подписи исполняются через отдельные контракты Phase 17; их приёмка .NET пока не выполнена. Поля непроверенного payload не предоставляют полномочий доступа, экспорт или выбор провайдера.


### Phase 16 — аутентифицированный dispatch и согласованность ревизий

`IAuthenticatedEncryptionBackend` — необязательный контракт в Abstractions. Реестр маршрутизирует по стабильному ProviderId, не передавая ключевой материал и не используя runtime alias. `SoftwareKeyProviderBackend` обеспечивает проверку возможностей и состояния, выбор Active-версии, согласованное по ревизии чтение защищённого материала, AES-GCM и точное историческое расшифрование. Форматы Phase 15 остаются независимыми от выполнения операций. Nonce policy вызывается после проверки материала; randomized и внешний независимо проверенный allocator не смешиваются через silent fallback. ChaCha20-Poly1305 пока deferred; TryDecrypt нормализует только неверный tag. Production gate FileSystem/платформ остаётся открытым.

### Phase 17 — границы исполнения MAC и цифровых подписей

В `Abstractions` добавлены независимые `IManagedMacBackend`, `IManagedSignatureBackend` и `IVersionedSignatureKeyOperations`. `ProviderRegistry` предоставляет `RouteMac(logical/exact)` и `RouteSignature(logical/exact)` без fallback, alias-поиска и перебора провайдеров. Симметричный backend аутентифицирует метаданные, выбирает точную версию, условно читает материал по ревизии стора, выполняет HMAC-SHA-2 и сравнивает полный тег через `FixedTimeEquals`. Существующая схема защищённого симметричного хранилища не расширяется непроверенным форматом приватных асимметричных ключей.

`ManagedSignatureBackend` объединяет metadata backend и доверенный исполнитель. Для Sign нужны Active, AsymmetricPrivate и capability; для Verify — точная версия Active/Retired и VerifySignature. Проверка объявленных возможностей провайдера не является достаточной авторизацией: **исполнитель** обязан заново проверить точный ключ и отзыв в момент исполнения. `EphemeralSignatureKeyOperations` обеспечивает операции ECDSA/RSA на .NET для временных ключей, но не поддерживает постоянное состояние и отзыв между процессами. Production-интеграция потребует постоянного/HSM-исполнителя и реальных .NET-тестов.

### Phase 18 — граница ECDH/HKDF

Abstractions: `IManagedKeyAgreementBackend`, `IVersionedKeyAgreementOperations`, `IManagedDerivationBackend`, `DerivationContext`, `DerivedKeyLease` и `IDerivedMaterialExportPolicy`. Security: `ManagedKeyAgreementBackend`, `EphemeralEcdhKeyOperations` и `SoftwareKeyProviderBackend.DeriveAsync`. Registry — маршрутизация только по ProviderId. Связь metadata/executor строго разделена; preflight не выдаёт право на private-key usage. Исполнитель обязан проверять авторизацию и отзыв в момент ECDH. Только HKDF-derived (не ECDH raw) выходит из executor; `DerivedKeyLease` ограничен временем жизни и не сериализуется. Нет автоматического `Materialize` и нет неаутентифицированного peer trust.


### Phase 19 — граница HPKE без публичного API

RFC 9180 — отдельное расширение после security gate, а не композиция собственного ECDH HKDF Phase 18 и AES-GCM Phase 16. До подтверждения exact-suite interoperability, авторизации получателя и private key при использовании, binding info/AAD и независимого review **не добавляем** `Seal`, `Open`, `SealedPayload`, контракт маршрутизации и постоянный бинарный envelope. Подготовительный тестовый Python reference и официальный fixture находятся в `tests/hpke-gate`; полный gate — `Laveyana.Security.HpkeGate.ru.md`. Публичная архитектура не изменена; Phase 19 deferred.

### Phase 20 — архитектурная граница потокового SHA/HMAC

`StreamingLocalCryptography` и внутренний `StreamHashPump` размещаются в Security; `StreamProcessingOptions` и необязательный `IStreamingMacBackend` — в Abstractions. `SoftwareKeyProviderBackend` инициализирует `IncrementalHash` из синхронного защищённого lease и освобождает lease до асинхронного чтения. По EOF повторно проверяется ревизия, чтобы изменение ключа аннулировало операцию. `ProviderRegistry` маршрутизирует потоковый MAC по постоянному `ProviderId`. Сегментированное AEAD остаётся unsupported: см. `Laveyana.Security.StreamingGate.ru.md`.


### Phase 21 — read-oriented Secrets

`ISecretProvider` размещён в Abstractions и требует только `FindAsync` (метаданные) и `GetAsync` (владение `SecretReadResult`, обязательный `Dispose`). `SecretReference` остаётся `(ProviderId, SecretId)` — без общей `SecretVersion`, автоматического перечисления секретов или копирования Key Lifecycle. `SecretDescriptor.CanOpenMaterial` и `CanExportMaterial` — независимые **заявляемые** возможности, обе false по умолчанию; они не разрешают доступ. Провайдер обязан проверять актуальные права непосредственно в `GetAsync`.

`SecretHandle.UseMaterialAsync` получает материал, сверяет identity и ProviderId после await, исполняет синхронный callback с заимствованным span и освобождает секрет при успехе, отмене и исключении. Отсутствие секретов возвращает `false`; отказ в доступе и ошибка провайдера — исключения. Callback может намеренно скопировать материал — технически запретить это внутри процесса нельзя. `SecretReadResult` запрещает сериализацию в JSON и скрывает данные в `ToString`.

`SecretProviderRegistry` хранит неизменяемый снимок регистраций и alias (регистрозависимых) и маршрутизирует только по точному ID. `ISecretManagementProvider` необязателен и запрашивается явно, без скрытых записей. Настоящий provider хранения, межпроцессный отзыв, разрешения на стороне backend и platform tests остаются вне Phase 21. C# сборка/NUnit в окружении не выполнялись.



## Реализация Phase 22 — DI и композиция (2026-10-09)

`Laveyana.Security.DependencyInjection` предоставляет `AddSecurity(Action<SecurityCompositionBuilder>)`,
`AddSecurityDefaults(...)`, `SecurityCompositionSnapshot`, явное подключение key/secret providers,
`IKeyStore`, `IKeyStoreProtector`, необязательного nonce allocator и `TimeProvider`.
По умолчанию файловое хранилище и программные ключи не создаются, worker не запускается.
`AddSecurityDefaults` без выбранного protector отклоняется. Программный backend требует
оба явных компонента: store и protector; никакого plaintext fallback нет.

Реестр и конфигурация замораживаются один раз. Дублирующиеся provider identities,
пересекающиеся alias, зависимости с не-singleton временем жизни, неизвестные требования
capabilities и повторный вызов `AddSecurity` отклоняются. Типизированная регистрация
использует только ранее зарегистрированный singleton; прямые экземпляры остаются
доступными через независимый API без DI. Требуемые динамические capability snapshots
проверяются при старте .NET Host через `IHostedService` или явным вызовом
`SecurityCompositionSnapshot.ValidateCapabilitiesAsync` в non-host приложениях.
Отдельный hosted worker для ротации не регистрируется.

**Ограничения:** объявленные capabilities не являются разрешением на операцию. Сервисы,
созданные внешними DI-фабриками, должны дополнительно проверяться средствами host
(`ValidateScopes`, `ValidateOnBuild`), а нестандартные контейнеры могут обходить проверку
transitive captive dependencies. Инициализация FileSystem асинхронна: вызов
`FileSystemKeyStore.OpenAsync` выполняется явно до composition; синхронная блокировка
асинхронных операций не допускается. Platform-specific preset в Windows-пакете
пока не добавлен, вместо него можно явно передать `WindowsDpapiUserProtector`.
.NET SDK / NUnit в рабочем окружении недоступны. FileSystem security gate и общая
production acceptance остаются открытыми.


## Phase 23 — явная политика ротации и необязательный worker (2026-10-09)

В основном модуле добавлены `RotationPolicy`, `RotationAssignment`,
`RotationEngine`. Расписание получает от приложения доверенную UTC-дату последней
активации и **ожидаемую Active-версию**. Срок наступления ротации определяется через
переданный `TimeProvider`: библиотека не выдумывает timestamp по номеру версии и
не перечисляет все ключи. Ручной `RotateNowAsync` и плановый `RotateIfDueAsync`
используют один и тот же исполнитель. Контракт `IConditionalKeyRotationBackend`
обязывает backend сравнить ожидаемую версию **атомарно с обновлением**. Программный
backend проверяет её на том же снимке состояния, по которому выполняет CAS в store;
две конкурирующие операции не могут успешно обновить одну исходную версию дважды.

`AddSecurity` и `AddSecurityDefaults` не создают фоновых задач. Только явный вызов
`AddSecurityRotationWorker(IRotationWorkSource, pollInterval)` подключает
`RotationWorker`. Источник заданий предоставляет приложение; он должен **надёжно и
атомарно закреплять только наступившие задания до выдачи и никогда не переотдавать его
автоматически** при ошибке или перезапуске. Очередь в оперативной памяти для
production не подходит. Успех фиксируется через `RecordResultAsync`, ошибки worker
останавливают его для ручной сверки исхода. Для следующей версии приложение отдельно
создаёт новое задание. Отмена Host передаётся в операции; основной engine не
владеет жизненным циклом worker. Политика не заменяет авторизацию: права проверяют
приложение, источник расписаний и backend.

```csharp
using Laveyana.Security.Rotation;
using Laveyana.Security.DependencyInjection.Rotation;

// Доверенные дата активации и ожидаемая версия сохраняются приложением.
RotationAssignment assignment = new(handle, activeVersion, activatedAtUtc,
    new RotationPolicy(TimeSpan.FromDays(30)));
RotationAttemptResult outcome = await rotationEngine.RotateIfDueAsync(assignment, cancellationToken);

// Только явное подключение с надёжным источником:
services.AddSecurityRotationWorker(durableRotationSource, TimeSpan.FromMinutes(1));
```

**Открытые ограничения:** готовой production-реализации durable schedule source нет;
неопределённый исход commit требует отдельной сверки, а не повтора. Доверенность
времени, расписания и его авторизация обеспечиваются приложением. Ротация не
доказывает возможность удалить предыдущие ключи без потери доступа к данным.
Сборка .NET 10, NUnit, multi-host и platform security gates остаются неподтверждёнными.


## Phase 24 — явные границы миграции провайдеров

`ProviderMigrationRequest` закрепляет точный **Active** `KeyReference` источника,
другой `ProviderId`, новое имя, необходимые capabilities и режим переноса.
`ProviderMigrationOrchestrator` выполняет `PlanAsync` → `PrepareAsync` →
`ValidateAsync` → `ActivateAsync` → `ConfirmApplicationCutover`, возвращая
неизменяемые `ProviderMigrationCheckpoint`. Контрольные точки не содержат
секретных байтов; приложение обязано аутентифицировать источник checkpoint и
долговечно сохранять его порядок. `ProviderMigrationCheckpoint.Restore` проверяет
структуру, но не достоверность журнала. Для software-провайдера новый ключ уже
Active при подготовке; `ActivateAsync` лишь проверяет конкретную версию, но не
выполняет переключение приложения.

`SoftwareMigrationDestination` поддерживает только **новую генерацию** с другим
`KeyId` и независимым материалом. Native transfer допускается лишь через
`IProviderNativeMigrationSource` и `IProviderNativeMigrationDestination`, без
публичного экспорта plaintext. Проверка доверия, защищённый канал, авторизация,
атомарность и replay protection — обязанности реализаций провайдеров. Готовых
реализаций такого переноса нет. Оркестратор повторно сверяет ID, вид ключа,
алгоритм и capabilities, но предварительные проверки не заменяют атомарные
проверки внутри backend.

Переключение **не переписывает** старые `KeyReference` или ciphertext.
`MigrationCutoverReceipt` должен соответствовать точной паре ссылок после
долговечного переноса зависимых данных приложением. Удаление/retirement источника
возможно только через `IProviderMigrationSourceLifecycle` с собственной проверкой
retention, версии, авторизации и зависимых данных. Software backend его не
реализует; force-delete fallback отсутствует.

До каждого меняющего состояния вызова приложение долговечно фиксирует намерение
в CAS-журнале и после успеха сохраняет новый checkpoint. При неизвестном исходе
операции или записи checkpoint автоматический повтор запрещён: требуется сверка
журнала и состояний обоих провайдеров. В библиотеке нет общей транзакции между
провайдерами, распределённой блокировки, миграции приложенческих данных и готового
rollback-resistant журнала. Компиляция/NUnit и production security gates открыты.

## Phase 25 — Диагностическая граница

Основная сборка содержит независимый optional `Diagnostics.SecurityObservability`
с `ActivitySource`/`Meter`/`ILogger`; внешний collector или durable audit database
не входит в dependency graph библиотеки. `SecurityObservability` доступен без DI,
а `WithObservability` только проводит тот же экземпляр в программный backend и
реестры. Audit sink получает только фиксированные код операции и результат,
UTC-время и необязательный trace ID, но не чувствительные или identity поля.
Прямые вызовы сторонних providers не могут считаться автоматически покрытыми аудитом.

## Сводное ограничение режимов — 21 октября 2026 года

`StoreFilePublication` — единый внутренний путь staging для обычных snapshot/bootstrap и экспериментального rollback-журнала. Сохраняются закреплённые Windows handles / Linux descriptors, эксклюзивное создание временного файла, проверка точных байтов, file flush и относительное нативное rename. Linux дополнительно вызывает fsync закреплённого каталога. Внутренние fault callbacks задаются для операции/экземпляра и по умолчанию отсутствуют; production-код не читает переменные окружения тестового worker. Исключения после начала нативной публикации означают неопределённость, включая cancellation; ошибка cleanup не скрывает исходную ошибку. Удаление временного файла не является долговечным решением о восстановлении.

**Защищённого записываемого FileSystem-профиля нет**: не реализованы аутентифицированная привязка authority, enrollment/миграция в такой профиль и автоматическое восстановление. `RollbackAuthority` остаётся read-only inspection. Теперь он отклоняет наличие любого файла rollback-журнала до обращения к authority и сохраняет неполные/неоднозначные свидетельства. Обычный v1 Open остаётся экспериментальным и не защищённым от rollback; пропуск настройки не называется безопасным. На обеих платформах `ProvidesRollbackProtection=false`.

Software AES-GCM требует живой записи происхождения материала от создавшего его экземпляра backend. Приватный SHA-256 fingerprint материала и точный `KeyReference` выбирают общий атомарный бюджет `2^20` операций. Генерация кандидата не сбрасывает уже существующий совпадающий бюджет. Чтение импортированного/повторно открытого материала не регистрирует его заново; новый срок жизни начинается при явном создании/ротации свежей версии, а не при re-protection. Это намеренно ограничивает новое шифрование после пересоздания backend; историческое расшифрование сохранено. Fingerprint и бюджет не журналируются и не сохраняются. Поддерживаемый срок жизни исключает копирование/восстановление памяти работающего процесса/VM и выдачу того же материала другим генераторам nonce.

Детерминированная выдача сохранена как внутренняя **модельная операция** для регрессий резервирования, переполнения и cancellation; policy запрещает выбирать её даже при allocator и флаге `ProvidesRollbackProtection`. `ProviderManaged` не выдаёт локальный nonce. Соответствие независимого authority/provider контракту, защита от downgrade и физическая долговечность остаются внешними условиями, а не следствием наличия интерфейсов.
