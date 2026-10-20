# Laveyana.Security — Техническая спецификация

[English](Laveyana.Security.TechnicalSpecification.md) | **Русский**

> Статус: **архитектурный baseline Generation 1 завершён**.
>
> Target framework: `.NET 10` (`net10.0` для cross-platform assemblies).
>
> Версионирование пакетов: `X.YYMM.R`.


> **Точка реализации и верификации (2026-10-16; H01):** Исходники семи проектов и публичные API существуют. Проверки `Source & docs`, Release-сборка и NUnit успешно прошли на Windows и Ubuntu в GitHub Actions. Это закрывает прежнее отсутствие проверенной сборки, но не завершает adversarial-аудит Phase 27. `FileSystem` остаётся экспериментальным; HPKE `Seal/Open` и потоковое AEAD не поддерживаются. Исторические замечания об отсутствии выполненных тестов в описаниях отдельных фаз относятся к тем этапам, а не к текущему CI. См. [README](../../README.ru.md), [Roadmap](Laveyana.Security.Roadmap.ru.md) и [CHANGELOG](../../CHANGELOG.ru.md).

## 1. Назначение

`Laveyana.Security` — переиспользуемая security-область экосистемы Laveyana. Она предоставляет безопасные high-level cryptographic operations, управление lifecycle ключей и доступ к секретам, сохраняя explicit Advanced/interoperability surface для осознанного low-level использования.

Обычный consumer должен настроить safe provider, получить opaque capabilities и вызывать операции вроде `Encrypt`, `Decrypt`, `Sign`, `Verify` или `Derive`. Сложность lifecycle, routing, storage protection, persistent identity, recovery и cryptographic policy остаётся внутри библиотеки.

Существующий `CryptoKit` рассматривается как прототип и источник полезных идей, кода и тестов. Backward compatibility с его public API не требуется.

## 2. Scope

### 2.1. Входит в scope

- secure random generation;
- hashing и fixed-time comparison;
- HMAC;
- HKDF и password-based KDF primitive;
- authenticated symmetric encryption/decryption;
- asymmetric signing/verification;
- key agreement с последующим обязательным KDF;
- conditional `Seal/Open` после отдельного HPKE design/security gate;
- key identities, descriptors, typed capabilities, versions, rotation, retirement и deletion;
- software, OS-backed, HSM, remote и non-exportable providers;
- software storage contracts и стандартный protected FileSystem store;
- safe temporary access к secret/key material;
- versioned cryptographic payloads и persistent metadata;
- safe streaming primitives после отдельного streaming-protocol gate;
- logging/metrics/tracing/audit hooks без утечки sensitive data.

### 2.2. Не входит в scope

- authentication, authorization, JWT, user management;
- password login/reset workflows и credential databases;
- TLS/transport-security replacement;
- database-specific encryption policy и решение, какие application data шифровать;
- certificate/X.509 management в Generation 1;
- generic plugin scanning;
- global event bus;
- hidden background runtime;
- custom ad-hoc HPKE-like или streaming encryption protocols.

Application/domain workflows принадлежат integration layer, например `Laveyana.Persistence.Security`.

## 3. Repository и assemblies

Обязательный baseline:

```text
Laveyana.Security/
├── src/
│   ├── Laveyana.Security.Abstractions/
│   ├── Laveyana.Security/
│   ├── Laveyana.Security.FileSystem/
│   └── Laveyana.Security.DependencyInjection/
├── tests/
│   ├── Laveyana.Security.Tests/
│   └── Laveyana.Security.IntegrationTests/
└── docs/
```

Responsibilities:

| Assembly | Responsibility |
|---|---|
| `Laveyana.Security.Abstractions` | Stable consumer contracts, identifiers/value objects, result types и реальные cross-assembly extension boundaries. |
| `Laveyana.Security` | Domain rules, orchestration, standard concrete crypto implementations, validators, codecs, locking/workflow mechanics, Advanced implementation surface. |
| `Laveyana.Security.FileSystem` | Standard software `IKeyStore` implementation с protected persistence, recovery и filesystem safety. |
| `Laveyana.Security.DependencyInjection` | `IServiceCollection` composition, method-based configuration DSL, validation, lifetimes, optional hosted integration. |
| Platform/provider package | Добавляется только при реальной platform/dependency/provider boundary. |

`Laveyana.Security.Abstractions` — стабильный нижний слой и никогда не зависит от concrete Security/FileSystem/platform assemblies.

## 4. Обязательные общие нормы

Обязательные общие требования: единые имена `Laveyana.*`, `.NET 10`, контролируемые dependencies, версии и документация по стадиям; читаемый C# с file-scoped namespaces, nullable/analyzers/XML-doc, English-only source comments, корректные async/cancellation и ownership, явные AOT/trimming guarantees и безопасная observability. Полные нормы включены в самодостаточный мастер-промпт реализации библиотеки.

Специфические усиления Security: чувствительный материал не раскрывается по умолчанию, небезопасные алгоритмы/конфигурации не используются с fallback, а persistent и cryptographic state не считается rollback-protected без доказуемой capability.

## 5. Public API model

Public surface делится по semantics, а не по лишним packages.

### High-Level API

Обязан предоставлять:

- safe defaults;
- минимальный выбор cryptographic parameters;
- opaque key/secret capabilities;
- immutable self-describing managed result values;
- отсутствие ручного nonce/tag management у обычного consumer;
- fail-closed behavior, если требуемая security capability недоступна.

### Advanced API

Используется осознанно для:

- raw/interoperability primitives;
- explicit import/export;
- explicit material leases;
- algorithm/parameter selection;
- destructive lifecycle operations;
- protocol-level integrations.

## 6. Algorithm policy

Generation 1 high-level defaults:

| Capability | Default |
|---|---|
| Random | `RandomNumberGenerator` |
| Hash | SHA-256 |
| MAC | HMAC-SHA-256 |
| Authenticated encryption | AES-256-GCM |
| General KDF | HKDF-SHA-256 |
| Password KDF primitive | PBKDF2-HMAC-SHA-256 с explicit work factor/policy version |
| Signature | ECDSA P-256 + SHA-256 |
| Signature alternative | RSA-PSS; новые RSA keys >= 3072 bit |
| Key agreement | ECDH P-256 с последующим обязательным KDF |

Supported hash/MAC alternatives: SHA/HMAC SHA-384 и SHA-512. ChaCha20-Poly1305 допускается только после подтверждения runtime/platform capability.

Algorithm catalog states:

```text
Recommended
Supported
LegacyReadOnly
```

Silent downgrade запрещён. Если explicitly required/preferred algorithm недоступен, validation/configuration/operation завершается ошибкой.

PQC должна позже добавляться без переделки `KeyId`, lifecycle и provider boundaries, но не является default Generation 1.

## 7. Key identity и capabilities

Различаются три identity:

```text
KeyName    → consumer/application alias
KeyId      → immutable cryptographic-generation identity
KeyVersion → exact material-version identity внутри одного KeyId
```

Persistent managed reference:

```text
KeyReference = ProviderId + KeyId + KeyVersion
```

`KeyName` и `ProviderAlias` не являются persistent cryptographic identity.

`KeyVersion` выделяется необратимо внутри текущей authoritative history. Deleted/discarded version numbers не переиспользуются; gaps допустимы. Cross-snapshot monotonicity не обещается для rollback-unprotected external restore.

Logical и exact handles — разные понятия:

```text
logical capability   = ProviderId + KeyId
exact-version handle = ProviderId + KeyId + KeyVersion
```

Logical capability resolve current `Active` перед каждой forward operation. Exact handle сам никогда не переключается.

Typed capability views:

```text
EncryptionKey
MacKey
DerivationKey
AsymmetricPublicKey
AsymmetricPrivateKey
```

Algorithm — metadata exact version, а не тип ключа.


### 7.1. Canonical Generation 1 identity text

- `ProviderId`, `KeyId`, `SecretId` — непустые UUID, строго lowercase `8-4-4-4-12` (`D`, например `12345678-1234-4234-8234-123456789abc`). `default` value struct недействителен. Новый `ProviderId` сохраняется при provisioning и переиспользуется при рестартах; случайная генерация при каждом startup запрещена.
- `KeyVersion` — положительный `Int64` с текстом invariant decimal, без ведущих нулей и знаков. Генерация чисел и high-water mark принадлежат authoritative lifecycle/store, а не самому value object.
- `KeyReference` = `provider-uuid/key-uuid/version`; `SecretReference` = `provider-uuid/secret-uuid`. Никакие alias, CLR names или случайные `enum` ordinals в точные ссылки не входят.
- `ProviderAlias`, `KeyName` — case-sensitive ordinal ASCII имена длиной 1–128, начинающиеся с буквы, затем допустимы буквы, цифры, `.`, `_`, `-`; никакого trimming, case-folding или path interpretation. Их нельзя сохранять вместо persistent identity.
- `AlgorithmId`, `CapabilityId` — lowercase ASCII tokens длиной 1–128, начинающиеся с буквы, допускающие цифры и одиночные внутренние разделители `.`, `_`, `-`. Token обозначает identity, но сам по себе не подтверждает поддержку, разрешение или криптостойкость алгоритма.
- Преобразования `ToString`/`Parse` для этих конкретных value objects **явно определены** как canonical text. Будущие metadata/envelope codecs обязаны самостоятельно задавать версию схемы и кодировать состояния/варианты по стабильным именам; нельзя автоматически превращать порядок/значения CLR-enums или reflection type names в persisted contract.
- `KeyDescriptor`, `KeyVersionDescriptor`, `SecretDescriptor` — только immutable metadata snapshots, не I/O и не lifetime/authorization handles. `Active` logical descriptor содержит active version, `Retired`/`Deleted` — нет. Capabilities в version descriptor defensive-copy и сортируются ordinal; наличие capability не заменяет policy/provider checks.

## 8. Key lifecycle

Logical states:

```text
Active
Retired
Deleted
```

Version states:

```text
Pending
Active
Retired
Deleted
```

`Discarded` не является public state. Discard never-activated `Pending` version уничтожает material и переводит её в `Deleted`, при этом `KeyVersion` навсегда остаётся зарезервированной внутри authoritative history.

Stable invariants:

- logical `Active` имеет ровно одну Active version;
- default lifecycle имеет не более одной Pending version;
- logical `Retired` не имеет Active или Pending version;
- current Active version нельзя удалить через normal `DeleteVersion` или `ForceDeleteVersion`;
- normal destructive path: `Active → Retired → Deleted`;
- `KeyName` освобождается только после durable completion `DeleteKey`;
- retired logical generation не re-activate в Generation 1.

Activation replacement — единый atomic/recoverable domain transition: previous Active → Retired и target Pending → Active.

## 9. Create/Get/Find/GetOrCreate и concurrency

- `Create`: создаёт новый logical generation и initial Active version; занятый name → conflict.
- `Get`: существование ожидается; absence → exception.
- `Find`: absence — normal outcome.
- `GetOrCreate`: возвращает existing или атомарно создаёт new logical generation.

Generation 1 name scope:

```text
(ProviderId, KeyName) → KeyId
```

Correct concurrent `GetOrCreate` требует два уровня:

1. local per-name keyed lock для уменьшения лишней работы;
2. store-level atomic claim/create unique name binding и aggregate как окончательную coordination point между instances/processes.

`Find → Create` никогда не считается atomic.

### 9.1. Операции управления и защита удаления

- Rotation поддерживает immediate путь и staged `CreateVersion(Pending) → Activate` с атомарным переключением версии. `Retired` сохраняет material для разрешённых исторических decrypt/verify и отличается от `Deleted`.
- `DeleteKey` выполняет recoverable cascade только после проверки состояния всех версий/retention; `Deletable` не означает, что у приложения отсутствуют historical references.
- Явные Advanced `ForceDeleteKey`/`ForceDeleteVersion` имеют опасную семантику; удалять текущую `Active` версию отдельно нельзя. При `ForceDeleteKey` агрегат удаляется согласованно, но historical data могут стать недоступны.
- Конкурентные переходы используют expected revision / conditional replace; retries для неидемпотентных операций не являются неограниченными/неявными.

## 10. Provider architecture

Каждый persistent provider имеет stable immutable `ProviderId`. `ProviderAlias` — runtime/configuration convenience, разрешаемая в один `ProviderId` внутри immutable composition snapshot.

Правила:

- `ProviderId` unique;
- `ProviderAlias` unique;
- duplicate registration → startup/configuration failure;
- exact reference routing идёт прямо по `ProviderId`;
- scan-all-providers lookup запрещён;
- alias remapping не меняет смысл persisted references.

Backend boundary:

```text
High-Level Security
        ↓
Crypto / Key Orchestration
        ↓
IKeyProviderBackend
├── Software
├── OS-backed
├── HSM
└── Remote/custom
```

Capabilities granular. Операция допустима только если её одновременно разрешают key policy и provider capability.

Provider migration создаёт **новый** ProviderId/KeyId generation; существующий KeyId не переносится между providers, redirect registry не меняет old references.

## 11. Software storage и protection

`IKeyStore` принадлежит `Laveyana.Security.Abstractions`. Он предоставляет persistence/consistency primitives для software-managed providers, а не lifecycle policy.

Conceptual responsibilities:

- find/load;
- atomic name claim/create;
- conditional replace с expected revision;
- delete;
- material read/write/destroy;
- capability declaration.

AEAD deterministic nonce allocation **не является** обязательной частью `IKeyStore`.

`IKeyStoreProtector` также является extension boundary в Abstractions и определяется до concrete FileSystem implementation. Он обязан сохранять root protection secret opaque и предоставлять stable/versioned `ProtectorReference` плюс domain-separated purposes минимум `Metadata` и `KeyMaterial`.

Standard FileSystem store не имеет secure-default raw-material persistence path и plaintext fallback.

## 12. FileSystem и rollback model

Standard FileSystem store:

- создаёт/проверяет isolated root;
- проверяет ACL/Unix permissions и ownership assumptions;
- отклоняет unsafe symlink/reparse redirection;
- хранит protected metadata/material envelopes;
- использует atomic/conditional write patterns и recoverable temp/journal/checkpoint workflows;
- fail closed при corrupted/tampered protected state;
- не обещает forensic secure erase;
- объявляет `ProvidesRollbackProtection = false`, пока нет independent rollback-resistant authority.

Unix baseline: directory `0700`, secret file `0600` или строже. Windows использует ACL/ownership validation и post-configuration verification.

Crash recovery и external rollback — разные классы:

- **CrashRecovery:** interrupted operation внутри current authoritative history; journal/temp/checkpoint может resume или rollback незавершённую operation.
- **ExternalRollback/Restore:** valid current store заменён более старой, но authentic snapshot; rollback-unprotected store может быть неспособен это обнаружить.

Known restore требует explicit reconciliation до unsafe forward operations. Safe default: old restored generation становится historical/read-only где возможно; новый forward use создаёт новый `KeyId` и fresh material.

## 13. AEAD nonce policy

Обычный consumer никогда не передаёт nonce в high-level API.

Managed AES-GCM поддерживает три strategy:

```text
Randomized
RollbackProtectedDeterministic
ProviderManaged
```

### Randomized

- 96-bit nonce из CSPRNG;
- default для rollback-unprotected software storage;
- probabilistic uniqueness;
- CSPRNG state не должен быть rollback-able FileSystem counter state;
- invocation/data bounds enforce; exhaustion → fail closed/re-key.

### RollbackProtectedDeterministic

Разрешён только при:

```text
ProvidesRollbackProtection = true
+
IAeadNonceStateStore (или эквивалент)
```

State привязан к exact `KeyReference`. Reserved but unused values после crash сгорают и не выдаются повторно.

### ProviderManaged

Provider владеет AEAD execution и safe nonce lifecycle и возвращает нужные public operation metadata.

Deterministic allocation на default rollback-unprotected FileSystem запрещён.

Imported AES raw material с неизвестной prior nonce history не допускается в ordinary managed forward encryption без explicit safe policy/provider mechanism.

## 14. Payloads, formats, AAD и outcomes

Managed results — self-describing immutable values:

```text
EncryptedPayload  → exact KeyReference + algorithm/public parameters + nonce + ciphertext + tag + format version
SignaturePayload  → exact KeyReference + signature scheme/public parameters + format version
MacResult         → exact KeyReference + algorithm/public parameters + format version
```

Security-critical encrypted-payload metadata криптографически связывается internal authenticated metadata.

Optional application AAD — external input: аутентифицируется, не шифруется и автоматически в payload не сохраняется.

Persistent/runtime versions независимы:

```text
LibraryVersion
MetadataFormatVersion
ProtectedMaterialEnvelopeVersion
EncryptedPayloadFormatVersion
StreamingFormatVersion
```

Runtime/domain objects не являются permanent persistence schemas. Unknown newer formats → fail closed.

Invalid signature/MAC — normal negative result. `TryDecrypt` нормализует только authentication failure; provider/configuration/format/cancellation/programming failures остаются видимыми.

### Phase 15 — конкретные модели и бинарные форматы (предварительно)

`Laveyana.Security.Abstractions.Payloads` содержит неизменяемые значения с копированием всех входных байтов. `EncryptedPayload` сохраняет exact `KeyReference`, алгоритм, 12-байтный AEAD nonce, 16-байтный authentication tag и ciphertext 0–16 MiB. `DetachedEncryptedPayload` хранит те же критические метаданные и точную длину передаваемого отдельно ciphertext. Поддержаны представления AES-256-GCM и ChaCha20-Poly1305; фактическую доступность определит провайдер. `SignaturePayload` допускает ECDSA-P256-SHA256 IEEE P1363 (64 байта) и RSA-PSS-SHA256 raw (256–1024 байта). `MacResult` принимает только полные HMAC-SHA256/384/512; legacy HMAC-SHA1 и усечённые теги в безопасный API не входят. Наружу возвращаются только копии байтов. Создание и парсинг не подтверждают подлинность.

Бинарные канонические форматы little-endian: `LEP1`, `LDP1`, `LSP1`, `LMR1`, `UInt16 version=1`, `UInt16 flags=0`, строгие UTF-8 token поля с `UInt16` длиной и ограниченные байтовые поля с `UInt32` длиной. Для подписи явно кодируется проверяемый encoding token; detached-формат фиксирует размер отдельного ciphertext. Отвергаются неизвестные версии/флаги, неканонические идентификаторы, неверные алгоритмы, лишние байты и выход за лимит 16 MiB + 4 KiB.

`EncryptedPayloadAssociatedData.Build` создаёт канонический AAD с разделением доменов `Laveyana.Security/managed-aead/v1`, exact KeyReference, алгоритмом, nonce, длиной tag/ciphertext и отдельным переданным приложением AAD (до 64 KiB). External AAD **не записывается** в payload. Encrypt и Decrypt обязаны применять **точно этот же AAD**, иначе метаданные не получают криптографическую аутентификацию. Кодек не выполняет криптографию, поиск ключа, key rotation или проверку MAC/подписи. Phase 16 записывает действительно выбранную Active версию в exact reference AES-GCM; Phase 17 реализует HMAC и versioned-адаптеры подписи; их компиляция и тестирование пока не подтверждены. Форматы предварительные до выполнения .NET 10 compatibility tests.

## 15. Secrets и sensitive material

Secrets используют read-oriented model:

```text
SecretId
SecretReference = ProviderId + SecretId
SecretDescriptor
SecretHandle
ISecretProvider
```

Base secret provider требует только `Get/Find`; management — optional separate capability.

Default access не возвращает долгоживущий `string`/`byte[]`. Controlled access использует:

- scoped callback access;
- disposable `SensitiveMaterialLease` поверх owned mutable memory.

Lease zeroize только memory, которой владеет, и не обещает стирание unrelated managed/native/OS copies.

`CanOpenMaterial` и `CanExportMaterial` — разные capabilities.

### 15.1. Export/import и representation

- Import в Advanced API явно задаёт provider, key kind/algorithm/capabilities, exportability и ownership; caller-owned input material по умолчанию не уничтожается библиотекой. Явный transfer ownership — отдельный контракт.
- `CanOpenMaterial` не тождественно `CanExportMaterial`; non-exportable provider не обязан раскрывать private material в процессе.
- Стандартный public asymmetric export — `SubjectPublicKeyInfo`; private import/export — `PKCS#8`, только при разрешающей policy. Не создавать proprietary private key format без реальной причины.
- Результат key agreement по умолчанию проходит KDF с каноническим domain-separated context, не возвращает raw shared secret. Streaming encrypted protocol остаётся gated; streaming hash/MAC может поставляться отдельно.

## 16. DI, async, time и observability

Core остаётся usable без DI.

`Laveyana.Security.DependencyInjection` предоставляет method-based configuration:

```csharp
services.AddSecurity(settings =>
{
    settings
        .Use...
        .Enable...
        .With...;
});
```

`AddSecurityDefaults()` — preset поверх той же composition model. Он требует уже выбранный safe protector, не делает hidden assembly scanning/platform guessing, не имеет plaintext fallback и fail-fast при invalid composition. Platform packages могут предоставлять platform-safe presets вроде `AddSecurityWindowsDefaults()`.

Pure local CPU primitives могут быть synchronous. Provider/storage/lifecycle I/O — asynchronous. Fake async запрещён. `CancellationToken` последний там, где operation реально cancellable. Cancellation после durable commit не откатывает committed effect.

Shared/DI services thread-safe; предпочтительна narrow per-key/per-name synchronization. Time-dependent policy использует `TimeProvider`.

Observability использует standard .NET logging/metrics/tracing. Sensitive payload/material никогда не логируется. High-cardinality `KeyId`/`KeyName`/`SecretId` не являются default metric labels. Core может эмитить audit events, но не владеет durable audit persistence.

## 17. Версии и документация

- Версия выпуска соответствует общему контракту `X.YYMM.R` (`R` — последовательный стабильный релиз в месяце для пары `(X, YYMM)`, начиная с `0`), а prerelease имеет SemVer-compatible suffix. Не использовать прежнее `X.YY.MM.DD`.
- Версии `.NET`-пакета, persisted metadata, protected envelope, encrypted payload и stream format независимы.
- Design-документы поддерживаются как `TechnicalSpecification`, `Architecture`, `DecisionLog`, `Roadmap` в эквивалентных EN/RU парах. На pre-implementation этапе не создавать README, CHANGELOG или placeholder LICENSE. После появления реального кода и на release lifecycle действуют требования встроенного мастер-промпта библиотеки.
- Поддержка поколений, API compatibility gate и deprecation регламентированы встроенным мастер-промптом; опасные security API могут выводиться из поддержки раньше обычного срока по обоснованной причине.

## 18. Testing и architecture gate

Required test categories:

- happy path и expected negatives;
- invalid configuration и dependency failure;
- cancellation и idempotency;
- concurrency и cross-process coordination;
- migrations/recovery/failure injection;
- corruption/tampering/unknown future formats;
- provider capability mismatch;
- filesystem permissions и symlink/reparse attacks;
- randomized и deterministic AEAD nonce semantics;
- imported-key unknown nonce-history rejection;
- external rollback/restore reconciliation;
- known-answer crypto vectors;
- codec/parser fuzzing.

Архитектурный этап завершён, потому что purpose/scope, dependency boundaries, public/extensibility surfaces, identity/lifecycle, provider/store/protector boundaries, AEAD nonce policy, persistence/recovery, DI/defaults, versioning/support, testing и security gates зафиксированы.

**Среди ранее зафиксированных DXX нет открытых пунктов, блокирующих Phase 1.** Новые факты реализации могут потребовать пересмотра только с техническим обоснованием. Concrete method signatures, exact stable identifier encodings, serializer choice, internal type/folder names и точные mechanics platform protector остаются implementation-level choices, пока они сохраняют frozen invariants.

## 19. Нормативные ориентиры и уровень доказательств

- AEAD/nonce model: RFC 5116 и применимая редакция NIST SP 800-38D (перепроверить перед релизом).
- Условный HPKE `Seal/Open`: RFC 9180; необходимы выбранная suite, проверенная implementation, interop vectors и отдельный security review.
- Streaming AEAD: анализируемая стандартизованная/reviewed конструкция (например, model Google Tink Streaming AEAD) плюс точный protocol/security gate.
- Внешние стандарты — ориентир для review, а не доказательство безопасности произвольной реализации.

## 20. Generation 1 release acceptance summary

Generation 1 допускается к release только когда implementation подтверждает всё следующее:

- ordinary encryption/signing/MAC/KDF usage не требует dangerous parameter management;
- default API не раскрывает raw key/secret material;
- software, OS-backed, HSM, remote и non-exportable providers входят в одну capability model;
- `KeyReference` стабилен, historical operations остаются valid после rotation;
- concurrent `GetOrCreate` не может создать двух winners для одного provider/name;
- lifecycle отклоняет unsafe transitions и не переиспользует discarded/deleted KeyVersion identities внутри authoritative history;
- FileSystem fail closed при unsafe permissions и не хранит raw material как secure default;
- security-critical metadata имеет integrity protection, но integrity не выдаётся за rollback protection;
- protector re-protection отделена от cryptographic key rotation;
- persistent formats эволюционируют независимо и reject unknown newer versions;
- cancellation semantics не создают иллюзию rollback после durable commit;
- secrets по умолчанию не превращаются в бессрочные string/byte[];
- observability не раскрывает sensitive payload/material;
- default configuration не делает silent algorithm/security downgrade;
- managed AES-GCM имеет explicit capability-driven nonce allocation;
- known external rollback rollback-unprotected state требует reconciliation до unsafe forward use;
- HPKE и encrypted streaming либо проходят обязательные security gates, либо явно остаются unsupported/deferred;
- implementation, integration, concurrency, corruption, recovery, permission, negative-crypto и fuzz tests проходят;
- финальная EN/RU documentation соответствует реализованным public API и lifecycle.

## 6.1 Phase 3 — границы реализации local primitives

Реализация Phase 3 в `Laveyana.Security` (namespace `Algorithms`, `Primitives`) содержит:

- `AlgorithmPolicy`: каталог известных `AlgorithmId`, назначение, классификация `Recommended`/`Supported`/`LegacyReadOnly`, запрет неизвестных ID, неверного назначения и silent downgrade. Для AES-GCM и ChaCha20-Poly1305 runtime availability проверяется через `.IsSupported`; доступность provider/key проверяется на последующих этапах. Каталог не означает, что операция шифрования или подписи уже реализована.
- `LocalCryptography`: безопасный default CSPRNG, SHA-256, HMAC-SHA-256 (новые ключи от 32 байт), fixed-time compare, HKDF-SHA-256 (непустой контекст и соль от 16 байт), PBKDF2-HMAC-SHA-256 (соль от 16 байт, версионированный work factor, 16–1024 байт выхода).
- `AdvancedLocalPrimitives`: явный выбор SHA-256/384/512 и HMAC-SHA-256/384/512; HKDF по RFC 5869, включая пустую соль/info; отдельные методы для исторических PBKDF2 и SHA-1/HMAC-SHA-1 только с `AlgorithmUse.HistoricalVerification`. Последние нельзя применять к созданию новых значений.
- `Pbkdf2WorkFactor`: Generation 1, policy version 1, default/minimum **600 000** итераций, maximum **10 000 000** для новых derivations. Конкретный count, version, соль и длина должны сохраняться вместе с данными, которые требуется воспроизводить. Более старые count допускаются исключительно через явный метод historical verification. Профиль может измениться в будущих версиях policy.

Ограничения: `FixedTimeEquals` скрывает содержимое, но не длину при сравнении буферов разных размеров. HKDF не повышает энтропию слабого исходного материала. PBKDF2 primitive не является готовой подсистемой password storage/verification и не подменяет password hashing policy приложения. Входные и выходные Span/byte[] базовых примитивов по-прежнему принадлежат вызывающему коду, пока не переданы в Phase 4 lease явно. Ввод пароля в форме bytes исключает неявную нормализацию Unicode и кодирование со стороны API. Не использовать high-level primitives как готовую библиотеку шифрования до соответствующих следующих этапов.

Тестовые источники: [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231), [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869), SHA-2 standard digests, опубликованные PBKDF2-HMAC-SHA-256 vectors. Сборка и тесты должны выполняться под .NET 10 до закрытия security gate Phase 3.

## 6.2 Phase 4 — границы реализации sensitive memory

`Laveyana.Security.Abstractions.Sensitive` содержит `SensitiveMaterialLease` (один изменяемый байтовый буфер, размер 1–1 048 576 байт) и `SensitiveMaterialScope` для синхронного scoped-доступа. `CreateCopy` копирует вход однократно и не меняет память вызывающего кода; `TakeOwnership(byte[])` передаёт **логическое** владение без копирования, поэтому вызывающий код после успеха обязан отказаться от всех aliases. При ошибке валидации до передачи владение остаётся у caller. Scope-методы всегда вызывают `Dispose`, включая путь с исключением callback.

`UseMaterial` принимает синхронный delegate с `ReadOnlySpan<byte>`; публичного getter секретов, implicit `byte[]`, асинхронного callback или автоматического экспорта нет. Callback не выполняется под внутренней блокировкой. Читатели, начавшие работу до `Dispose`, могут завершиться, затем owned buffer очищается. Новое чтение после начала disposal запрещено, повторный `Dispose` безопасен. `ToString()` скрывает содержимое; штатная сериализация/десериализация `System.Text.Json` запрещена. Явные копии callback, сторонняя reflection-сериализация/логирование и копии ОС/runtime находятся вне контроля. Чужие буферы не очищаются без явной передачи исходного массива. Своевременная очистка требует `Dispose`, finalizer-гарантии и принудительного timeout у callback нет.

**Gate проверки:** собрать шесть проектов на .NET 10, выполнить NUnit по освобождению, исключениям, aliases, конкурирующим reader/dispose, JSON и валидации. Одни статические проверки Phase 4 не закрывают.

## 6.3 Phase 5 — logical/exact handles и проверка capability по метаданным

`Laveyana.Security.Abstractions.Handles` содержит неизменяемые `LogicalKeyHandle` (`ProviderId + KeyId`) и `ExactKeyHandle` (`KeyReference`). Exact handle навсегда привязан к указанной версии; logical handle не хранит состояние Active. При создании отклоняются неопределённые идентификаторы, обычный `ToString()` скрывает идентификаторы. Для исторических данных сохраняется явный стабильный `KeyReference`.

`Laveyana.Security.Abstractions.Capabilities` содержит типизированные metadata views `EncryptionKey`, `MacKey`, `DerivationKey`, `AsymmetricPublicKey`, `AsymmetricPrivateKey`. Каждая forward-проверка заново читает logical snapshot, требует Active, затем проверяет соответствующую exact-версию, тип ключа и объявленную capability. Historical-проверка принимает exact handle того же логического ключа, никогда не заменяет версию, отклоняет Pending/Deleted version и Deleted logical key. Exact Active/Retired допускается только при согласованных metadata. Отсутствие, ошибки идентификаторов, kind/capability mismatch и запрещённые состояния приводят к fail-closed отказу.

**Граница безопасности:** `KeyCapabilityResolution` — **лишь проверка метаданных, а не авторизация, lease, reservation или криптографическая операция**. `KeyVersionDescriptor.Capabilities` показывает декларации, не разрешение политики. Между preflight и использованием возможны rotation, revocation, изменение policy или состояния provider. Реальный backend ОБЯЗАН при выполнении операции независимо (и атомарно, если необходимо) проверять key policy, provider capability, lifecycle state и algorithm policy у конкретного используемого material. Результат preflight может устареть немедленно. Provider-backed криптография и постоянное состояние lifecycle относятся к дальнейшим фазам.

**Gate проверки:** скомпилировать .NET 10 и выполнить unit-тесты rotation, pin исторических ссылок, проверки capabilities/kinds, несовместимых snapshots, cancellation и lifecycle. Структурная проверка не закрывает Phase 5.

## 6.4 Phase 6 — границы реализации чистого lifecycle planner

`Laveyana.Security.Lifecycle` в Generation 1 остаётся **внутренней частью core Security**; публичный provider contract пока отсутствует. `KeyLifecycleSnapshot` проверяет стабильную identity, согласованность logical/version states (ровно один Active только при logical Active; не более одного Pending; отсутствие Pending для Retired/Deleted) и ограниченную, неизменяемую, отсортированную историю версий. `HighWaterMark` хранится отдельно от записей, переживает discard/delete и допустимое уплотнение tombstones. При исчерпании `long.MaxValue` резервирование отклоняется.

Чистые методы `KeyLifecyclePlanner` возвращают неизменяемый план `KeyLifecycleTransition`: `Create` создаёт Active v1; `CreatePendingVersion` резервирует Pending; `Activate` одним доменным переходом переводит старую Active → Retired и Pending → Active; `Rotate` сразу резервирует и активирует новую версию; `RetireKey` отклоняет неразрешённый Pending и навсегда прекращает forward-use; `DiscardPending` оставляет Deleted tombstone. `DeleteVersion` удаляет только Retired после проверки retention; `ForceDeleteVersion` позволяет удалить Retired/Pending, но **никогда** current Active. `DeleteKey` требует Retired и проверяет retention всех оставшихся версий; `ForceDeleteKey` оформляет единый разрушительный каскад до Deleted, в том числе из Active. Retired/Deleted logical generations нельзя активировать повторно.

Каждая версия может иметь срок удержания и hold. Обычное удаление принимает явно заданное UTC-время и не использует системные часы/I/O. Force операции обходят retention и способны уничтожить доступ к историческим данным. Планы различают `Applied` и `AlreadyApplied`; CreatePendingVersion/Rotate неидемпотентны. Даже `AlreadyApplied` **не доказывает**, что предыдущая попытка была надёжно зафиксирована: authoritative store обязан проверять revisions, координировать claims и операции с материалом, а перед повтором выяснять исход неопределённого commit. `KeyName` освобождается исключительно после durable DeleteKey/ForceDeleteKey в будущих фазах. Монотонность high-water гарантируется в represented/authoritative history, но не после незамеченного отката rollback-unprotected store.

**Gate проверки:** .NET 10 build и фактический запуск NUnit на transition matrix, Active invariant, монотонность/исчерпание версий, Pending/discard/activation, retention/force deletion, идемпотентность, неизменяемость и псевдослучайные последовательности. Одной статической проверки недостаточно.

## 6.5 Phase 7 — provider contracts и exact routing

Внешний `IKeyProviderBackend` принадлежит `Laveyana.Security.Abstractions.Providers` и расширяет `IKeyMetadataResolver`. Контракт содержит только stable immutable `ProviderId`, выборку exact logical/version metadata и метод `GetCapabilitiesAsync`, возвращающий immutable `ProviderCapabilitySnapshot` (не более 64 уникальных `CapabilityId`). Это provider-wide декларации; per-key capability, policy, lifecycle и algorithm должны независимо проверяться при реальном dispatch. Данные из API discovery не могут служить authorization token, а API пока не выполняет cryptographic operations и не экспортирует material.

Core `ProviderRegistry` принимает полный набор `ProviderRegistration` при инициализации (0–1024 провайдера), копирует mappings в приватные коллекции, отклоняет duplicate `ProviderId` или `ProviderAlias`, неопределённые идентификаторы, null и изменение provider identity. Aliases сравниваются ordinal/case-sensitive и используются только для явного `ResolveAlias`; никакой persisted reference не переадресуется. `GetRequired`, `Route`, `FindLogicalAsync` и `FindExactAsync` маршрутизируют **строго по ProviderId** без fallback/перебора остальных зарегистрированных провайдеров. Открытый exact `KeyReference` нельзя заменить runtime alias.

Реестр проверяет идентичность logical/exact metadata и provider-wide capability snapshot, а также ProviderId backend до и после await. Несовпадение идентичности — fail-closed ошибка, отсутствие ключа у правильного провайдера возвращает null. Cancellation проверяется до и после await и передаётся backend. Snapshot composition фиксирует состав и aliases, но не замораживает remote backend availability/capability; объявление capability может устареть между чтением и crypto dispatch. В Phase 7 отсутствуют `IKeyStore`, persistence, software adapter, DI registration и atomic cryptographic operations. Gate: собрать .NET 10, выполнить NUnit tests для дубликатов, отсутствующих идентификаторов, невалидных answers, capability, cancellation, alias remap и отсутствия scan-all-provider.

## 6.6 Phase 8 — контракты software-хранилища и защиты данных

`IKeyStore`, `IKeyStoreProtector` и optional `IRollbackProtectedNonceAllocator` принадлежат исключительно Abstractions. Каждая реализация store должна честно объявлять `KeyStoreCapabilities.ProvidesRollbackProtection` и обеспечивать durable межпроцессную атомарность: захват имени при создании, CAS-замену метаданных вместе с изменениями материала и удаление ключа вместе со всем материалом и освобождением имени. Отклонённая операция не имеет побочных эффектов. `TryCreateAsync` требует initial Active v1 protected material и создаёт ревизию **1**, `TryReplaceAsync` требует expected revision и возвращает следующую положительную ревизию (+1); переполнение отклоняется. Ранее использованная пара `(ProviderId, KeyId)` остаётся зарезервированной в текущей authoritative history даже после удаления; имя после завершённого удаления можно использовать снова. `ReadMaterialAsync` проверяет ожидаемую ревизию одновременно с получением материала. Store не получает plaintext и не решает, разрешён ли lifecycle-переход.

`ProtectedStoreEnvelope` создаёт защитную копию opaque ciphertext (1–2 097 152 байта), содержит стабильный версионированный `ProtectorReference` и явный `ProtectionPurpose`, но сам **не шифрует и не подтверждает подлинность**. Реализация `IKeyStoreProtector` ОБЯЗАНА криптографически аутентифицировать переданный контекст, identity/generation protector и purpose. Неверный/изменённый контекст, назначение, повреждение или неподдерживаемое поколение — безусловный отказ, без plaintext fallback. `KeyStoreProtectionContext` даёт канонический AAD v1 для метаданных `(ProviderId, KeyId, записываемая ревизия)` и материала `(ProviderId, KeyId, KeyVersion)`. Защитный провайдер обязан исключить изменение AAD в течение асинхронной обработки и не сохранять borrowed sensitive spans. Корневой материал не экспортируется, возвращённый plaintext принадлежит вызывающему коду как `SensitiveMaterialLease` и должен освобождаться им. Исторические поколения требуют явной поддержки, не тихой смены ключа защиты.

Детерминированная стратегия 96-bit nonce требует отдельного `IRollbackProtectedNonceAllocator`, резервирующего непересекающиеся долговечные диапазоны `(Prefix32, Counter64)` для точной версии `KeyReference`. Диапазоны нельзя выдавать повторно после crash, restore или переинициализации счетчика; зафиксированные, но неиспользованные диапазоны сгорают. Контракт optional и не является частью `IKeyStore`; заявлять rollback protection без независимого authority нельзя. Для FileSystem-хранилища далее предусмотрена randomized AES-GCM policy. Откат authentic снимка невозможно надёжно обнаружить без независимой точки доверия.

Тестовый `MemoryStore` проверяет конкурирующие name claims, CAS гонки, замену material, несоответствие read revision, удаление/освобождение имени и отмену до commit. Это **не** production-хранилище и не доказательство межпроцессной надёжности. **Gate Phase 8:** сборка .NET 10, выполнение NUnit, независимая компиляция внешнего store/protector со ссылкой только на Abstractions, позднее — multiprocess crash/recovery тесты реальной реализации. Статическая проверка не закрывает gate.

## 6.7 Phase 9 — реализация software provider orchestration

`SoftwareKeyProviderBackend` — adapter для `IKeyStore` и `IKeyStoreProtector`, **не** готовый криптографический провайдер. Публичное API реализует Create, Get (FindLogical), Find (FindByName/FindExact), GetOrCreate, CreateVersion, Activate, Rotate, Retire, Discard, DeleteVersion, ForceDeleteVersion, Delete и ForceDelete. `SoftwareKeyRetention` определяет UTC retention и hold при создании/ротации версии. Профили новых симметричных ключей: AES-256-GCM, ChaCha20-Poly1305 при поддержке среды, HMAC-SHA-256/384/512, HKDF-SHA-256; материал создаётся CSPRNG (32 байта). Импорт, экспорт сырого материала, жизненный цикл ECDSA/RSA и сами AEAD/MAC/KDF операции пока отсутствуют.

Все lifecycle-переходы вычисляются чистым planner Phase 6 по аутентифицированному состоянию и фиксируются CAS-контрактом Phase 8. При create ревизия равна 1, replace использует строго `expected + 1`. Временный codec `LSM1` ограничивает объём метаданных (1 МБ), число версий (2048) и capabilities (64), проверяет identity, tombstones и high-water mark; временные byte arrays по возможности очищаются. До релиза нужны formal schemas и migration tests Phase 11. Protected material создаётся только для новых версий и удаляется при Discard/DeleteVersion/ForceDeleteVersion; удаление поколения — каскадное store delete. Неверные и cross-provider идентификаторы отклоняются. `FindExact` проверяет наличие protected material при той же ревизии для неудалённых версий.

Определённые CAS-конфликты и неопределённые commit **не вызывают автоматический retry**. Если mutating store call выбросил исключение после вызова, adapter возвращает `SoftwareKeyCommitUncertainException`: нужно сверить состояние в authoritative store и обеспечить idempotency на уровне вызывающего кода перед новой командой. `GetOrCreate` может прочитать победителя исключительно после однозначного `NameTaken` и обязан проверить полный профиль. Store и protector должны соблюдать контракты; fake-реализации доказывают лишь in-process поведение. `GetCapabilitiesAsync` объявляет пустой набор до появления исполняемых crypto operations. Gate остаётся открытым без настоящих .NET build/NUnit и интеграции durable cross-process storage.

## 6.8 Phase 10 — границы реализации AEAD nonce

Phase 10 добавляет внутреннюю, привязанную к точному `KeyReference` политику AES-256-GCM, не расширяя обязательные публичные контракты. Стратегия выбирается по доверенным данным provider dispatch: происхождение материала, статус restore, наличие реально проверенных provider guarantees и независимого rollback-resistant allocator.

1. При отсутствии allocator свежему ключу выдаются 96-битные randomized CSPRNG nonce; в рамках одного процесса лимит выдач для одного `KeyReference` составляет 2²⁰. Данный счётчик не долговечен и не ограничивает суммарные вызовы из независимых процессов; суммарный lifetime budget необходимо обеспечить на уровне будущего сервиса. Вероятностная коллизия не исключена математически.
2. Детерминированная стратегия требует `ProvidesRollbackProtection=true` и отдельного `IRollbackProtectedNonceAllocator`. Одна reservation выдаёт 64 уникальных counter values; незатраченные после остановки сессии считаются использованными. Повтор/смена домена внутри сессии отклоняются, неизвестный результат reservation блокирует дальнейшее использование данной сессии. За долговечное отсутствие пересечений после crash/restore отвечает реализация authority; обычный store и обычный FileSystem counter недопустимы.
3. Provider-managed режим не выдает nonce для локального AES и разрешён лишь если backend действительно владеет AEAD execution и nonce lifecycle; для импортированного материала нужна дополнительная подтверждённая защита от прежней истории nonce.
4. Старый восстановленный `KeyId` запрещено возвращать в forward Encrypt, пока не выполнена отдельная процедура сверки/re-key. Существующие sessions при обнаружении restore явно инвалидируются, но Phase 10 не реализует автоматическую систему уведомлений. Импортированный материал с неизвестной историей исключён из managed forward Encrypt.
5. Внутренняя проверка одного сообщения: 0–64 MiB. Лимиты проверяются до выдачи nonce. Никакой выпуск nonce сам по себе не подтверждает authorisation, current Active, identity key material или успешное шифрование.

**Gate:** реальные .NET 10 build/NUnit; параллельная выдача nonce, известные restore, тестовый независимый authoritative allocator, краевые диапазоны UInt64, несогласованные ответы allocator, неизвестный commit, imported-key restrictions. Никакой production allocator или AES-GCM whole-buffer service на данном этапе нет.

## 6.9 Phase 11 — стабильные схемы и граница миграций

Формат метаданных `LSMD` v2: ASCII magic `LSMD` (4 байта), `UInt16` little-endian schema version = 2, `UInt16` flags = 0, затем length-prefixed strict UTF-8 fields (длины `UInt16` little-endian), counts (`Byte` и `Int32`), целые значения little-endian (`Int64`), `Byte` retention hold. Порядок: ProviderId, KeyId, KeyName, key kind, algorithm, число capabilities и отсортированные capabilities, logical state, high-water mark, число версий, затем для каждой версии ordinal, state, hold, UTC ticks (0 = нет срока). Значения enum представлены **каноническими ASCII-именами** (`symmetric`, `asymmetric-private`, `asymmetric-public`; `active`, `retired`, `deleted`; `pending`, `active`, `retired`, `deleted`); никакие числовые значения CLR enum не участвуют в новом формате. Максимум 2048 версий, 64 capabilities, 1 MiB метаданных, 256 байт на текстовое поле; запрещены дубликаты, trailing bytes, неканоническая сортировка, неизвестные flags/версии, несоответствие protected identity и нелегальные lifecycle-состояния.

Унаследованный `LSM1` — байты `31 4D 53 4C` в исходном little-endian `Int32`. Допускается только чтение **после успешной аутентификации IKeyStoreProtector** и проверка строгих доменных инвариантов. Новые записи всегда v2. `SoftwareKeyMetadataCodec.MigrateToCurrent` реализует единственный существующий переход v1→v2 (и идемпотентный v2→v2) без сохранения; миграционный commit должен повторно защитить plaintext при **новой** ревизии, затем выполнить CAS replace вместе с material-effects. При конфликте обновить доверенный snapshot; после неопределённого commit — reconcile, не повторять mutation вслепую. Отдельный аутентифицированный счётчик или authority нужен для выявления отката **между** целыми корректными снимками.

`LSPB` v1: magic `LSPB`, `UInt16` version=1, `UInt16` flags=0, canonical store-instance UUID + `ProtectorReference` (два UTF-8 token поля с `UInt16` length). Bootstrap **не является доверенным источником protector/root secret**: identity сверяется с доверенной конфигурацией, а защищённые записи отдельно аутентифицируются с AAD. `LSNC` v1: magic `LSNC`, version/flags, exact `KeyReference` token, `UInt32` prefix, `UInt64` next counter, `UInt64` authority epoch. `ValidateSuccessor` выявляет локальный регресс для доверенных checkpoint-ов; storage rollback-resistance не доказывается. Схемы FileSystem/on-disk atomic update и cross-process recovery — Phase 12. Golden test data представлены байт-в-байт в `tests/Laveyana.Security.Tests/Fixtures`.

**Gate:** компиляция .NET 10 и выполнение NUnit с golden, corruption, future-version, mapping и migration tests остаются обязательными.

## Phase 12 — FileSystem prototype и gate безопасности

Экспериментальный `FileSystemKeyStore` реализует интерфейс `IKeyStore` без дополнительных extension contracts: одна версия снимка `LSFS` содержит `LSFB` body (имена, ревизии, защищённые envelopes, used-KeyId history) и отдельную аутентифицированную digest envelope. `IKeyStoreProtector` аутентифицирует SHA-256 body с domain-separated контекстом `Laveyana.Security/fs/v1/snapshot/{storeInstanceId}`. `LSPB` bootstrap хранит UUID и `ProtectorReference` без приватного материала; при открытии сверяются identity/generation (UUID можно закрепить опцией `ExpectedStoreInstanceId`). Имя и routing identities пока не шифруются; подлинность тела требует успешного unprotect digest. Формат ограничен по размеру, количеству записей, числу версий, проверяет trailing bytes, дублирующиеся значения и неизвестные версии.

Все операции захватывают общий эксклюзивный lock-file до чтения текущего состояния; последовательное переоткрытие снимка после lock обеспечивает уникальный claim и CAS на уровне кооперирующих экземпляров. Коммит: сериализация в отдельный temp, flush, rename/replace полного снимка; старые temp удаляются только после проверки committed snapshot. Повреждённое/недостающее authoritative состояние не воссоздаётся. Гарантии rename/flush ограничены свойствами используемой ОС/ФС; directory fsync и malicious concurrent path replacements остаются для Phase 13.

**Security release gate:** `EnableExperimentalWrites` по умолчанию выключен. На Phase 12 допустимы только явные тестовые записи, не production secrets. Полная проверка Unix owner/mode, Windows DACL/inheritance, всех parent path components, symlink/reparse и гонок открытия — обязательный Phase 13. Ни аутентифицированный manifest, ни `LSPB` не выявляют replay корректного старого снимка; external rollback detection отсутствует. `ProvidesRollbackProtection=false`, deterministic nonce allocation не подключается. Отдельные cross-process crash/recovery и платформенные ручные тесты обязательны перед выпуском.

## Phase 13 — контрольная точка платформенной защиты

На Linux каждый предок каталога проверяется через `statx(AT_SYMLINK_NOFOLLOW)`: доверенный владелец, отсутствие небезопасных прав на запись и отсутствие ссылок. Для каталога требуется `0700`, для файлов — отсутствие прав у группы и остальных, правильный владелец и тип обычного файла. Хранилище использует закреплённый дескриптор каталога, `openat(O_NOFOLLOW)`, `flock`, `renameat`/`renameat2(RENAME_NOREPLACE)` и `fsync` каталога после записи. Перечисление имён временных файлов не позволяет удалять файлы вне закреплённого каталога. Неожиданные права или владельцы приводят к отказу; автоматического исправления существующих ACL нет.

На Windows новый каталог создаётся с изолированным DACL (владелец, SYSTEM, Administrators), проверяются ACL файлов/каталогов, права предков и reparse points. **Чтение и переименование на Windows ещё используют строки путей; предотвращение всех гонок подмены требует handle-relative I/O и отдельных испытаний.** Другие платформы отклоняются. `ProvidesRollbackProtection=false`, опциональный экспериментальный режим записи сохраняется. Production-приёмка не завершена до сборки .NET 10, платформенных и конкурентных тестов и проверки долговечности записей.


### Реализация Phase 14 — Windows DPAPI CurrentUser (промежуточно)

`Laveyana.Security.Windows` реализует `IKeyStoreProtector` через Win32 `CryptProtectData`/`CryptUnprotectData` в CurrentUser-scope; `CRYPTPROTECT_LOCAL_MACHINE` не используется, UI запрещён. Внешний root-secret не создаётся. `LSWP` v1 содержит magic/version/length и opaque DPAPI ciphertext. Optional entropy вычисляется как SHA-256 с domain tag, точным `ProtectorReference`, purpose, длиной и содержимым AAD. Внутри DPAPI plaintext находится magic/length, SHA-256 от полезной нагрузки и контекста, затем payload; checksum дополнительно обнаруживает повреждённые ответы. Это не самостоятельная MAC, DPAPI — trust boundary. Неизвестные версии/context/purpose/generation отвергаются. Native plaintext очищается до `LocalFree`, managed plaintext передаётся как `SensitiveMaterialLease`. Размер AAD ограничен 64 KiB. На не-Windows ОС создание запрещено.

Тесты: новый экземпляр, неверный purpose/context, повреждение ciphertext, смена generation, отмена и unsupported OS. Исторические поколения, re-protection и rollback-защита отсутствуют. Windows .NET execution необходима для приёмки; FileSystem writes экспериментальные.


## Phase 14A — явная миграция protector и повторная защита

`Laveyana.Security.Protection.ProtectorGenerationRouter` использует один protector для
**новой записи** и явно зарегистрированные исторические поколения только для **чтения**.
Маршрутизация происходит по полному сохранённому `ProtectorReference`: без перебора
провайдеров, пробного расшифрования, plaintext fallback и скрытой миграции при чтении.
Неизвестные поколения запрещены. `Compromised` блокирует чтение и обычную re-protection:
при возможном раскрытии исходного материала нужна отдельная оценка инцидента и
**настоящая ротация рабочих ключей**, а не только перепаковка. Статус компрометации
задаётся явно приложением, но не хранится в отдельном доверенном реестре инцидентов.

`Laveyana.Security.Software.SoftwareKeyReprotectionService.ReprotectAsync(LogicalKeyHandle)`
обрабатывает **один логический ключ** по `ProviderId/KeyId`. Сначала проверяет
подлинность метаданных и всех не удалённых версий материала при ожидаемой ревизии.
Затем повторно защищает исторические версии текущим protector, сериализует метаданные
в `LSMD v2` с AAD для `revision + 1` и фиксирует метаданные и материал **одним CAS**.
Уже защищённые текущим поколением материалы повторно не шифруются. Сохраняются
`KeyReference`, исходный криптографический материал, история версий, active version,
алгоритм, capabilities и retention. При конфликте ревизий — отказ, без скрытых повторов.
При исключении во время commit результат **неопределён**: повторять вслепую нельзя,
необходимо сверить авторитетное состояние хранилища. `AlreadyCurrent` не гарантирует
глобально атомарное чтение.

Лимит — **128 живых версий материала** на атомарную транзакцию. Превышение приводит
к отказу без частичной миграции. Общей миграции «всех ключей» и автоматического
поиска в `IKeyStore` пока нет. Надёжность зависит от реальной атомарности
`TryReplaceAsync`; защита от возврата прежнего валидного снимка требует независимого
монотонного источника. Изменение поколения Windows DPAPI не обязательно заменяет
системный корневой DPAPI-ключ. Старые readers нельзя отключать до завершения миграции
и проверки резервных копий. Приёмка Phase 14A и production gate остаются открыты
до сборки .NET 10, NUnit и проверки файловой безопасности ОС.

```csharp
using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Protection;
using Laveyana.Security.Software;

// currentProtector, oldProtector, existingStore, providerId и keyId предоставляет приложение.
ProtectorGenerationRouter router = new(currentProtector,
    [new HistoricalProtectorRegistration(oldProtector, HistoricalProtectorStatus.LegacyReadOnly)]);
SoftwareKeyReprotectionService migration = new(providerId, existingStore, router);
KeyReprotectionResult result = await migration.ReprotectAsync(new LogicalKeyHandle(providerId, keyId));
// При SoftwareKeyCommitUncertainException сперва перечитать авторитетное состояние.
```


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

**Дополнительная проверка Phase 14A:** новые protected envelopes и внешний snapshot проходят проверку расшифровки и точного равенства plaintext **до** попытки фиксации. Это не заменяет независимую реализацию, audit protector и проверки Windows/Linux на реальной .NET сборке.


### Phase 16 — контракт исполняемого managed AES-GCM (предварительный)

`IAuthenticatedEncryptionBackend` поддерживает обычные/detached Encrypt/Decrypt/TryDecrypt с `EncryptedPayload`. Software backend исполняет только AES-256-GCM: для Encrypt аутентифицирует метаданные, выбирает exact Active version, читает материал с проверкой ревизии и только после этого получает nonce. Ciphertext привязан к exact KeyReference и каноническому AAD Phase 15. Decrypt использует точную Active/Retired версию и capability Decrypt, не переключается на новый материал после ротации. TryDecrypt возвращает null только для `AuthenticationTagMismatchException` с очисткой частичного plaintext. Лимит сообщений 16 МиБ, application AAD — 64 КиБ. Randomized budget локален процессу и НЕ доказывает глобальную уникальность после перезапуска/restore. Детерминированный режим требует независимый rollback-safe allocator и явную возможность store; при ошибках silent downgrade запрещён. Временная копия plaintext очищается. Приёмка остаётся открытой до выполнения .NET 10 тестов и платформенного hardening.

### Phase 17 — исполняемый контракт HMAC и цифровых подписей (предварительный)

`IManagedMacBackend.ComputeMacAsync` принимает логический ключ и сообщение не более 16 МиБ, аутентифицирует метаданные, проверяет Active + capability `Mac` и читает материал в той же ревизии. Поддерживаются полные теги HMAC-SHA-256/384/512. `MacResult` закрепляет точный ProviderId/KeyId/KeyVersion/алгоритм. `VerifyMacAsync` допускает только точную Active/Retired версию, проверяет отдельную capability `VerifyMac` и использует `CryptographicOperations.FixedTimeEquals`. `false` возвращается **только** при неверном теге; удаление версии, запрет политики, конфликт ревизии, ошибки protector и отмена — исключения. Переключать историческую проверку на новый ключ запрещено.

`IManagedSignatureBackend` задаёт Sign/Verify для `SignaturePayload`. `ManagedSignatureBackend` повторно проверяет metadata текущей логической и точной версии, policy и provider-wide capabilities. При этом **исполнитель** `IVersionedSignatureKeyOperations` обязан сам обеспечить фактические права, точную версию и отзыв ключа непосредственно в момент операции; интерфейс не выдаёт приватные байты. Новые подписи: ECDSA P-256 SHA-256 в IEEE P1363 (64 байта), RSA-PSS SHA-256 с новыми RSA-ключами >=3072 бит. Sign — только Active AsymmetricPrivate; Verify — точная Active/Retired public/private версия. Нет RSA PKCS#1 v1.5 для создания подписей и silent downgrade. Неверная подпись — `false`; ошибки исполнения и запрета доступа не маскируются.

`EphemeralSignatureKeyOperations` — действительно исполняющий .NET ECDSA/RSA класс с передачей владения ключом и `Dispose`, но только **process-local**: ни постоянного хранения, ни независимого межпроцессного отзыва. Существующий software lifecycle не создаёт и не сохраняет асимметричные пары. Production-подписание требует проверенного durable/system/HSM/remote `IVersionedSignatureKeyOperations`. Фактические .NET 10 build/NUnit/interoperability остаются открытыми.

### Phase 18 — agreement/derivation API (предварительный контракт)

`DerivationContext` (purpose 1–64 lower-ASCII, applicationContext 1–256 байт, outputLength 16–64) кодирует BigEndian length-prefixed транскрипт v1. Домены `Laveyana.Security/ECDH-P256/HKDF-SHA256/v1` и `Laveyana.Security/Symmetric/HKDF-SHA256/v1` независимы. ECDH контекст содержит две отсортированные канонические P-256 SPKI, а симметричный — exact `KeyReference`. Для HKDF используется IKM (ECDH raw secret или защищённый HKDF-ключ), `salt=SHA256(info)` и фиксированный info. Изменение purpose/параметров/сторон разделяет ключи. Формат до компиляции, векторов в .NET и security review не стабилен для production.

Реальная проверка Active/Derive/KeyAgreement и ревизии обязательна. Секрет возвращается исключительно как `DerivedKeyLease` с очищаемым owned buffer и синхронным `UseMaterial`; экспорт требует вызываемую разрешающую `IDerivedMaterialExportPolicy`. `EphemeralEcdhKeyOperations` — процессный executor; сторонние исполнители обязаны не отдавать raw ECDH и повторять проверку отзыва. ECDH не аутентифицирует peer; приложение должно аутентифицировать публичный ключ и контекст протокола.


### Phase 19 — предварительная проверка HPKE (не реализовано)

Условный API RFC 9180 `Seal/Open` **не поддерживается**. Exact suite reference: Base / DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM согласно Appendix A.3.1. Для возможной production AES-256-GCM suite нужны **собственные** официальные векторы и проверка интероперабельности. `tools/hpke_gate_verify.py` подтверждает корректность открытого эталона и негативных сценариев, но не проверяет C# реализацию. Запрещено заменять RFC KDF контекстом Phase 18, объявлять HPKE capabilities или публиковать половинчатый SealedPayload. См. `Laveyana.Security.HpkeGate.ru.md` — wire/info/AAD, exact identity, trust, revocation, replay, release критерии.

### Phase 20 — проверяемые границы streaming

Потоковый SHA-256/384/512 — локальный, независимый от key store. Полноразмерный HMAC-SHA-256/384/512 доступен через необязательный `IStreamingMacBackend` в Abstractions и программный backend; историческая проверка требует точной версии и VerifyMac capability. Вход читается до EOF через буфер до 64 КиБ; предел по умолчанию 1 ТиБ, предусмотрена необязательная точная доверенная длина. Поток принадлежит приложению. При отмене, I/O, нарушении размера/длины, прав или изменении ревизии — исключение; `false` означает только неправильный тег. Новый streaming AEAD-протокол и ciphertext encoding не вводились; gate отражён в `Laveyana.Security.StreamingGate.ru.md` и остаётся DEFERRED. Сборка .NET и запуск тестов не подтверждены.


### Phase 21 — контракты секретов и scoped material

Внешние провайдеры используют только Abstractions и реализуют read-oriented `ISecretProvider`. `FindAsync` возвращает `SecretDescriptor?`, `GetAsync` — `SecretReadResult?` с точной ссылкой и **переданным во владение** `SensitiveMaterialLease`. Null означает отсутствие, а не отказ в авторизации. `SecretHandle` и `SecretProviderRegistry` перепроверяют identity и ProviderId после await и очищают owned data при исключении callback, отмене или провале проверки. Нет геттера сырого byte[]/string, implicit conversion, JSON-сериализации и универсальной версии секрета. Visitor синхронный и не должен сохранять span либо запускать асинхронное его использование.

`CanOpenMaterial` и `CanExportMaterial` объявляются отдельно, по умолчанию обе false; это не разрешение на доступ, а callback технически не может запретить намеренную копию. Провайдер обеспечивает реальную авторизацию и отзыв. Необязательный `ISecretManagementProvider` предлагает `SetAsync`/`DeleteAsync` с правилами самого провайдера и маршрутизируется только явно. Дубликаты ID/alias и изменение identity отклоняются. Стандартного provider с постоянным хранением нет. Сборка и NUnit пока не запускались.



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

## Phase 25 — Observability: границы реализации

`SecurityObservability` выполняет опциональный учет managed operations без входных
секретов и без подмены результата. Публичные события ограничены перечислениями,
привязанными к API, а не к key names или исключениям. Метрики
`laveyana.security.operations` (counter), `laveyana.security.operation.duration`
(histogram, ms), `laveyana.security.audit.delivery_failures` (counter без identity
labels); трассировка использует ActivitySource `Laveyana.Security`. Логирование
структурировано, но ограничено только `Operation` и `Outcome`.

`ISecurityAuditSink` не является транзакционным/audit-of-record и не обеспечивает
доставку событий. Ссылка на текущий trace ID допускается в отдельном audit event,
но не в метриках. Application управляет listener, ILogger provider, метриками и
сохранением audit. Неподключенная телеметрия не влияет на работу библиотеки.

**Дополнение SA-05:** Необязательные audit-события передаются через задачи
ThreadPool, вне критического пути криптографических операций. В процессе
одновременно исполняются не более восьми обработчиков; собственная очередь,
повторная отправка, гарантированная доставка перед завершением программы и
ожидание успеха обработчика отсутствуют. При заполнении лимита новые события
теряются; потери и поздние исключения увеличивают счётчик ошибок доставки.
Порядок не гарантирован, обработчики могут выполняться параллельно,
`ExecutionContext` вызывающего кода не передаётся. Злонамеренно блокирующий
callback по-прежнему может навсегда занять один из ограниченного числа фоновых
потоков; это не изоляция процессов и не обязательный журнал аудита.

