# Laveyana.Security — Roadmap

[English](Laveyana.Security.Roadmap.md) | **Русский**

> План реализации Generation 1. Этап закрывается только после успешной проверки acceptance criteria и тестов; нельзя продолжать с известным нарушенным security invariant. HPKE и encrypted AEAD streaming могут оставаться deferred по итогам отдельных security gates.

Каждый этап отдельно фиксирует назначение, изменения, зависимости, критерии приёмки, проверки и ограничения. Детали реализации выбираются внутри утверждённого этапа; существенные архитектурные конфликты проходят через Decision Log.

---


> **Инфраструктурный этап H01: ЗАКРЫТ (16.10.2026).** Подтверждены Release/NUnit на обеих ОС, защита `master` и первый успешный ручной запуск месячной регрессии. [Подтверждения закрытия](../hardening/H01-Setup.ru.md). Это не закрывает проблемы безопасности Phase 27 и не разрешает production-использование экспериментального файлового хранилища.

> **Текущий статус верификации (2026-10-16):** H01 `Verify` успешно прошёл Release-сборку и NUnit на Windows/Ubuntu, а также source/docs checks. Функциональные фазы до Phase 27 по-прежнему нельзя считать production-accepted: Windows TOCTOU, rollback и nonce lifetime gates остаются открытыми. Исторические замечания о непроверенной сборке относятся к моменту соответствующего этапа. См. [README](../../README.ru.md) и [security review](../audit/Laveyana.Security.Phase27.SecurityAudit.ru.md).

## Phase 1 — Основа repository

- **Purpose:** Создать repository, проекты, build policy и documentation baseline.
- **Changes:** Создать Abstractions, Security, FileSystem, DependencyInjection, Tests, IntegrationTests; настроить net10.0, nullable, analyzers, XML docs, .editorconfig, Central Package Management, shared release version и актуальный EN/RU design baseline без README/CHANGELOG/LICENSE placeholders.
- **Dependencies:** Нет.
- **Acceptance criteria:** Clean build; нет cycles; все identities используют Laveyana.*; enforcement file-scoped namespace и English-only source documentation активен.
- **Tests / manual checks:** Собрать все projects; проверить analyzers/XML-doc; просканировать .cs на русские comments.
- **Remaining limitations:** Domain implementation ещё отсутствует.

---

## Phase 2 — Stable identifiers и domain model

- **Purpose:** Зафиксировать stable value semantics до появления workflows.
- **Changes:** Реализовать ProviderId/Alias, KeyName/Id/Version/Reference, SecretId/Reference, descriptors, states, capability IDs, algorithm IDs и validation.
- **Dependencies:** Phase 1.
- **Acceptance criteria:** Immutable value semantics; alias не сохраняется вместо ProviderId; stable IDs не зависят от CLR.
- **Tests / manual checks:** Equality/hash/validation и stable-identifier tests; malformed values rejected.
- **Remaining limitations:** Нет provider/store I/O и lifecycle orchestration.

---

## Phase 3 — Algorithm policy и local primitives

- **Purpose:** Предоставить local primitives и explicit algorithm policy catalog.
- **Changes:** Реализовать secure random, hash, fixed-time compare, HMAC, HKDF, PBKDF2, Advanced local primitive layer, Recommended/Supported/LegacyReadOnly policy.
- **Dependencies:** Phase 2 там, где нужны identifiers.
- **Acceptance criteria:** Known-answer vectors проходят; silent downgrade отсутствует; legacy/new-operation policy enforce.
- **Tests / manual checks:** Authoritative vectors и negative policy tests.
- **Remaining limitations:** Пока нет managed keys, AEAD orchestration и provider routing.

---

## Phase 4 — Sensitive memory model

- **Purpose:** Определить ownership и bounded raw-material access до provider APIs.
- **Changes:** Реализовать scoped material access, SensitiveMaterialLease, zeroization и import ownership semantics.
- **Dependencies:** Phases 1-3.
- **Acceptance criteria:** Deterministic disposal; нет meaningful ToString или implicit byte[] conversion; очищаются только owned buffers.
- **Tests / manual checks:** Dispose, exception-path и copy-minimization tests.
- **Remaining limitations:** Не гарантируется стирание external/runtime/OS copies.

---

## Phase 5 — Logical/exact handles и typed capabilities

- **Purpose:** Разделить forward-use identity и exact historical identity.
- **Changes:** Реализовать logical/exact handles и Encryption/Mac/Derivation/Asymmetric typed views без default raw exposure.
- **Dependencies:** Phases 2 и 4.
- **Acceptance criteria:** Logical handles не кэшируют stale Active; exact handles не переключаются; capability mismatch rejected.
- **Tests / manual checks:** Resolver/rotation simulations и exact-handle stability tests.
- **Remaining limitations:** Пока нет persistent lifecycle и concrete provider backend.

---

## Phase 6 — Pure key lifecycle state machine

- **Purpose:** Закодировать lifecycle invariants как deterministic domain logic до persistence.
- **Changes:** Реализовать transition matrix, Pending/Activate/Rotate planning/Retire/Discard/Delete/ForceDelete, version reservation, retention и idempotency classification.
- **Dependencies:** Phases 2 и 5.
- **Acceptance criteria:** Active invariant сохраняется; ForceDeleteVersion не удаляет current Active; discard заканчивается Deleted; version reuse невозможен внутри represented history.
- **Tests / manual checks:** Pure unit/property-style transition tests; без I/O.
- **Remaining limitations:** Нет durable effects и provider dispatch.

---

## Phase 7 — Provider backend contracts и registry

- **Purpose:** Определить external provider boundary до software-store adapter.
- **Changes:** Определить IKeyProviderBackend и minimal external supporting contracts в Abstractions; реализовать immutable registry, alias resolution, duplicate validation и exact routing.
- **Dependencies:** Phases 2 и 5.
- **Acceptance criteria:** External providers ссылаются только на Abstractions; duplicate IDs/aliases rejected; нет scan-all-providers routing и IKeyStore dependency.
- **Tests / manual checks:** Registry/routing/capability contract tests с fake providers.
- **Remaining limitations:** Software provider adapter намеренно отсутствует.

---

## Phase 8 — Storage и protection contracts

- **Purpose:** Зафиксировать software persistence и at-rest protection boundaries.
- **Changes:** Определить IKeyStore, revisions/results, atomic name claim/create, material primitives, rollback capability, optional nonce-state contract, IKeyStoreProtector, ProtectorReference и protection-purpose model.
- **Dependencies:** Phases 2, 6, 7.
- **Acceptance criteria:** Custom store/protector ссылается только на Abstractions; nonce allocator optional; root protection material не экспортируется contract API.
- **Tests / manual checks:** Compile fake external implementations; concurrency/result semantics tests.
- **Remaining limitations:** Concrete FileSystem persistence ещё нет.

---

## Phase 9 — Operational key orchestration и software provider adapter

**Состояние реализации (2026-10-09):** добавлены software lifecycle adapter, CAS-оркестрация, защищённые предварительные метаданные и fault-injection tests. Сборка .NET/NUnit и работа durable store пока не подтверждены; gate остаётся открытым.

- **Purpose:** Связать lifecycle rules с persistent provider/store operations.
- **Changes:** Реализовать software backend плюс Create/Get/Find/GetOrCreate/CreateVersion/Activate/Rotate/Retire/Discard/Delete/ForceDelete, optimistic concurrency, safe retries, loser cleanup и durable name release.
- **Dependencies:** Phases 6-8.
- **Acceptance criteria:** Operational workflows не обходят pure state machine; один provider/name даёт одного winner; cancellation/commit boundaries documented.
- **Tests / manual checks:** Fake-store concurrency/conflict/failure-injection tests, включая losing-creator cleanup.
- **Remaining limitations:** Concrete durable FileSystem guarantees пока отсутствуют.

---

## Phase 10 — AEAD nonce policy engine

- **Purpose:** Сделать managed AES-GCM nonce safety явной и capability-driven.
- **Changes:** Реализовать Randomized, RollbackProtectedDeterministic, ProviderManaged selection, bounds/exhaustion, imported-key restrictions и restore behavior.
- **Dependencies:** Phases 7-9.
- **Acceptance criteria:** Rollback-unprotected storage не выбирает deterministic; test rollback-protected backend резервирует unique ranges; unknown-history imported AES restricted.
- **Tests / manual checks:** Parallel/restart/crash range tests, CSPRNG nonce tests, overflow/exhaustion, external-restore simulation.
- **Remaining limitations:** Whole-buffer managed encryption payload/service ещё не завершён.

---

## Phase 11 — Persistent schemas и migrations

- **Статус реализации (2026-10-09):** LSMD v2, чтение legacy после аутентификации, migration в памяти, LSPB/LSNC и golden tests подготовлены; сборка .NET и NUnit не подтверждены.

- **Purpose:** Создать stable versioned persistence независимо от runtime classes.
- **Changes:** Реализовать persisted DTO, metadata format version, high-water mark, protector bootstrap/reference, optional rollback-protected nonce state mapping, migration chain и unknown-newer rejection.
- **Dependencies:** Phases 2, 8-10.
- **Acceptance criteria:** Golden formats stable; migrations deterministic; future format fail closed; crash recovery сохраняет current-history monotonic state.
- **Tests / manual checks:** Golden-file, migration, corruption, future-version и mapping round-trip tests.
- **Remaining limitations:** Concrete filesystem path/permission implementation ещё нет.

---

## Phase 12 — FileSystem store base

**Промежуточный результат (2026-10-09):** добавлены файловый снапшот с аутентификацией, общий lock, атомарная замена, строгий формат, тесты повреждений и запрет production-записи. Компиляция .NET, запуск NUnit, отдельные межпроцессные OS-проверки и Phase 13 platform hardening пока не подтверждены.

- **Purpose:** Предоставить protected default software store с первой реализации.
- **Changes:** Реализовать isolated root, path validation, protected envelopes, atomic name claim, conditional replace, temp/flush/validate/replace, revisions, recovery и cleanup поверх IKeyStoreProtector.
- **Dependencies:** Phases 8 и 11.
- **Acceptance criteria:** Нет raw secure-default material path; нет plaintext fallback; cross-process name claim; нет rollback-protected deterministic nonce claim.
- **Tests / manual checks:** Cross-process create/replace, crash/failure injection, envelope tamper/corruption tests.
- **Remaining limitations:** Не разрешать production запись чувствительных данных до завершения Phase 13 platform hardening: Phase 12+13 образуют единый security gate.

---

## Phase 13 — FileSystem platform hardening

**Промежуточная реализация (2026-10-09):** Linux: закреплённый каталог, no-follow I/O, владелец/права/предки, `flock`, `fsync`; Windows: проверки владельца/DACL/reparse. Тесты написаны, но не выполнены. Защита Windows от гонок и production-приёмка **открыты**.

- **Purpose:** Enforce host filesystem safety assumptions.
- **Changes:** Реализовать Windows ACL validation/hardening, Unix modes, owner/inheritance checks, symlink/reparse protections и fail-closed initialization.
- **Dependencies:** Phase 12.
- **Acceptance criteria:** Unsafe roots/redirection rejected; newly created safe root verified.
- **Tests / manual checks:** Platform integration tests permissions, ownership, inheritance, symlink/reparse attacks.
- **Remaining limitations:** Сам по себе не предоставляет platform root protector.

---

## Phase 14 — Concrete platform protector implementation(s)

**Промежуточная реализация (2026-10-09):** Windows DPAPI CurrentUser в отдельной сборке `Laveyana.Security.Windows`, формат `LSWP` v1, purpose/identity/AAD binding и очистка native plaintext. Windows-тесты подготовлены, но не выполнены. Другие платформы пока не получили concrete protector; .NET/Windows security gate открыты.

- **Purpose:** Предоставить реальную safe protection для выбранных platforms.
- **Changes:** Реализовать выбранный Windows/Android/etc. IKeyStoreProtector, stable ProtectorReference, purpose separation и opaque root protection secret.
- **Dependencies:** Phases 8, 12, 13.
- **Acceptance criteria:** Unavailable protector fail closed; Metadata и KeyMaterial contexts нельзя cross-use; root secret не раскрывается.
- **Tests / manual checks:** Platform availability/restart/tamper/context-separation tests.
- **Remaining limitations:** Concrete default protector получают только выбранные platforms.

---

## Phase 14A — Protector migration / re-protection

**Снимок реализации (2026-10-09):** Реализованы exact-reference legacy-read/current-write router, re-protection каждого ключа единым CAS и миграция FileSystem snapshot/bootstrap с восстановлением после прерывания, отказ для compromised status и тесты на сбои. Сборка .NET 10, NUnit, проверки Windows и production-gate FileSystem остаются открытыми.

- **Purpose:** Менять at-rest protection без ложной key rotation semantics.
- **Changes:** Реализовать legacy protector read, current protector write, explicit re-protect, recovery-safe replacement и legacy/compromised status handling.
- **Dependencies:** Phase 14 и persisted envelope format.
- **Acceptance criteria:** Same KeyReference/material до и после; old envelope survives failure; protector compromise остаётся отличим от key rotation.
- **Tests / manual checks:** Failure injection вокруг re-protection; legacy-read/current-write tests.
- **Remaining limitations:** Re-protection не устраняет возможную prior compromise cryptographic material.

---

## Phase 15 — Managed cryptographic result values

**Промежуточная реализация (2026-10-09):** `Laveyana.Security.Abstractions.Payloads` содержит immutable `EncryptedPayload`, `DetachedEncryptedPayload`, `SignaturePayload`, `MacResult`, `ManagedPayloadCodec` и `EncryptedPayloadAssociatedData`. Форматы `LEP1`, `LDP1`, `LSP1`, `LMR1` v1: строгие длины, версии, flags, exact `KeyReference`, недопустимые алгоритмы и лишние байты отвергаются. Для AEAD применяется канонический domain-separated AAD с точным ключом, алгоритмом, nonce, длиной ciphertext и *внешним* application AAD. Подлинность устанавливается только исполняемой криптографической операцией (Phases 16/17), **не** созданием объекта или `Decode`. Golden-файлы и NUnit написаны, но сборка и тесты .NET 10 не подтверждены. Exact-reference выбранной версии записывается в Phase 16; реальная сборка и интеграционные проверки остаются открытыми.

- **Purpose:** Дать managed crypto operations stable self-describing historical identity.
- **Changes:** Реализовать immutable EncryptedPayload, managed/detached variants, SignaturePayload, MacResult, exact-reference recording, internal authenticated metadata, external AAD и codecs/versioning.
- **Dependencies:** Phases 2, 5, 9-11.
- **Acceptance criteria:** Logical forward operations фиксируют exact version; historical operations resolve exact references; critical fields immutable/versioned.
- **Tests / manual checks:** Tamper, unknown-format, wrong-AAD/key и codec fuzz tests.
- **Remaining limitations:** High-level symmetric service — следующий phase.

---

## Phase 16 — Symmetric encryption high-level API

**Промежуточная реализация (2026-10-09):** `IAuthenticatedEncryptionBackend` и `SoftwareKeyProviderBackend` реализуют AES-256-GCM шифрование с Active версией, историческое exact-version расшифрование, detached и TryDecrypt (только неправильный tag становится null). Nonce policy Phase 10 действует с лимитом 16 МиБ; ChaCha20-Poly1305 исполнение deferred до поддержки nonce policy. Новые NUnit-тесты написаны, но не запущены. Независимые проверки rollback/production gate платформ ещё открыты.



- **Purpose:** Предоставить safe whole-buffer authenticated encryption/decryption.
- **Changes:** Реализовать AES-GCM default, supported alternatives, managed/detached paths, Decrypt и TryDecrypt поверх nonce engine и EncryptedPayload.
- **Dependencies:** Phases 9, 10, 15.
- **Acceptance criteria:** Ordinary consumer не управляет nonce/tag; strategy следует declared capabilities; failure categories сохраняются; exhaustion fail closed.
- **Tests / manual checks:** Known vectors, authentication negatives, unsupported capability, budget exhaustion, rotation/historical decrypt tests.
- **Remaining limitations:** Encrypted streaming остаётся gated/deferred.

---

## Phase 17 — MAC и signature APIs

- **Purpose:** Предоставить managed MAC/signing с exact historical identity.
- **Changes:** Реализовать MAC compute/verify, signature sign/verify, provider-backed async dispatch и public/private typed views.
- **Dependencies:** Phases 5, 7, 9, 15.
- **Acceptance criteria:** Invalid signature/MAC — expected negative result; provider failures остаются exceptions.
- **Tests / manual checks:** Known vectors, historical verify после rotation, capability mismatch и provider-failure tests.
- **Remaining limitations:** Asymmetric confidentiality остаётся отдельной gated capability.

---

## Phase 18 — Key agreement и derivation

- **Purpose:** Предоставить derived capabilities без default raw shared secret exposure.
- **Changes:** Реализовать ECDH default, mandatory KDF, canonical domain-separated derivation context, ephemeral derived capabilities и explicit materialization.
- **Dependencies:** Phases 3-5, 7, 9.
- **Acceptance criteria:** High-level key agreement не возвращает raw shared secret; разные purposes используют разные contexts.
- **Tests / manual checks:** Known vectors/interoperability, context separation и lifetime/zeroization tests.
- **Remaining limitations:** PQC KEM не является default Generation 1.

---

## Phase 19 — SealedPayload / standardized hybrid encryption

- **Purpose:** Добавить high-level asymmetric confidentiality только после dedicated security gate.
- **Changes:** Выбрать RFC 9180-compatible construction/implementation, exact suite/encoding/info/AAD/limits/vectors; выполнить focused security review; только затем реализовать Seal/Open/SealedPayload.
- **Dependencies:** Phases 5, 7, 15 плюс successful gate.
- **Acceptance criteria:** Conformance/interoperability vectors проходят; review complete; raw RSA arbitrary-payload encryption не является high-level default.
- **Tests / manual checks:** Suite vectors, tamper, recipient mismatch и policy tests.
- **Remaining limitations:** Если acceptable strategy отсутствует, phase остаётся unsupported/deferred и не блокирует остальной release.

- **Фактический статус (2026-10-09):** официальный RFC 9180 Appendix A.3.1 Base reference проверен автономно (6 ciphertext + 14 отрицательных сценариев), но нет проверенного .NET HPKE, интероперабельности, wire-format review и выполнения .NET/NUnit. **DEFERRED / UNSUPPORTED** согласно security gate. См. `Laveyana.Security.HpkeGate.ru.md`; API Seal/Open не добавлено.

---

## Phase 20 — Streaming

**Промежуточный результат (2026-10-09):** потоковые SHA-256/384/512, HMAC-SHA-256/384/512 с ограниченным буфером и точной версией, проверка ревизии после EOF и отрицательные NUnit-сценарии подготовлены. Зашифрованный сегментированный AEAD остаётся DEFERRED/UNSUPPORTED: отдельный security gate не пройден. .NET SDK/тесты не запускались. См. `Laveyana.Security.StreamingGate.ru.md`.


- **Purpose:** Предоставить bounded-memory streaming primitives без unsafe ad-hoc framing.
- **Changes:** После protocol gate реализовать streaming hash/MAC и approved segmented AEAD с completion/truncation/cancellation semantics и format versioning.
- **Dependencies:** Phases 3, 15-18 и successful AEAD streaming gate.
- **Acceptance criteria:** Reorder/duplicate/remove/truncate/splice detected; nonce/key limits enforce; bounded memory; no unauthenticated completion.
- **Tests / manual checks:** Negative stream corpus, large-stream tests, cancellation и fuzzing.
- **Remaining limitations:** Encrypted streaming может остаться deferred, если gate не пройден.

---

## Phase 21 — Secrets

**Промежуточный результат (2026-10-09):** подготовлены `ISecretProvider` (только Find/Get), `SecretReadResult`, callback-доступ через `SecretHandle`, точная маршрутизация `SecretProviderRegistry`, необязательный `ISecretManagementProvider` и metadata capabilities с fail-closed значениями по умолчанию. Добавлены отрицательные NUnit-тесты. Реальный встроенный provider/хранилище секретов не добавлялись. .NET-сборка и NUnit не подтверждены.

- **Purpose:** Реализовать read-oriented secret capabilities без лишнего копирования Keys lifecycle.
- **Changes:** Реализовать SecretId/Reference/Descriptor/Handle, multiple providers, deterministic routing, scoped access и optional management extension только при реальной потребности provider.
- **Dependencies:** Phases 4, 7 и shared registry/value infrastructure.
- **Acceptance criteria:** Нет default long-lived string/byte[]; deterministic routing; base provider требует только Get/Find.
- **Tests / manual checks:** Routing, absence semantics, lease cleanup и optional-management capability tests.
- **Remaining limitations:** Universal SecretVersion намеренно отсутствует.

---

## Phase 22 — Dependency injection

- **Purpose:** Предоставить validated composition без переноса business logic в DI.
- **Changes:** Реализовать AddSecurity, AddSecurityDefaults, provider/protector registration, alias resolution, capability/lifetime validation, immutable settings snapshot и platform-safe presets в platform packages.
- **Dependencies:** Operational core и хотя бы один selected safe protector для usable defaults.
- **Acceptance criteria:** Missing protector, duplicate identities, invalid capability/lifetime combinations fail at startup; unsafe fallback отсутствует.
- **Tests / manual checks:** Service-provider validation, lifetime/captive dependency и manual-vs-DI behavior tests.
- **Remaining limitations:** Automatic rotation worker остаётся выключенным по умолчанию.

---

## Phase 23 — Rotation policy и optional worker

- **Purpose:** Добавить policy-driven rotation без hidden runtime ownership.
- **Changes:** Реализовать TimeProvider-based policy evaluation, manual rotation engine и explicit opt-in hosted worker на том же engine.
- **Dependencies:** Phases 6, 9, 22.
- **Acceptance criteria:** Default не запускает worker; manual/automatic semantics совпадают; shutdown/cancellation documented.
- **Tests / manual checks:** Fake-time due/overdue, concurrent rotation и host-shutdown tests.
- **Remaining limitations:** Rotation policy не доказывает готовность external data к удалению old key.

---

## Phase 24 — Provider migration primitives

- **Purpose:** Поддержать controlled provider migration без изменения смысла old references.
- **Changes:** Создать destination provider/new KeyId, transfer/regenerate по exportability, validate/activate, expose checkpoints, retire/delete source после guards.
- **Dependencies:** Phases 7, 9, 15-18.
- **Acceptance criteria:** Old references immutable; hidden redirect отсутствует; non-exportable source не требует raw export; failures recoverable.
- **Tests / manual checks:** Exportability matrix, failure checkpoints, coexistence и application-reference migration tests.
- **Remaining limitations:** Application владеет transaction semantics migration dependent data/references.

---

## Phase 25 — Observability

- **Purpose:** Добавить diagnostics после стабилизации operations без sensitive leakage.
- **Changes:** Реализовать structured logging, metrics, ActivitySource и optional audit events с low-cardinality safe dimensions.
- **Dependencies:** Operational APIs и result taxonomy.
- **Acceptance criteria:** Нет sensitive payload/material и default high-cardinality identity labels; telemetry backend выбирает application.
- **Tests / manual checks:** Secret-scanning/manual review, cardinality и tracing-correlation tests.
- **Remaining limitations:** Core не хранит durable audit database/file.
- **Implementation status (2026-10-10):** Основной код и тесты Phase 25 подготовлены, статические проверки прошли; .NET 10/NUnit не выполнены, acceptance gate открыт. Audit остаётся best-effort без durability.

---

## Phase 26 — Final documentation synchronization

- **Purpose:** Синхронизировать repository documentation с реализованным Generation 1 behavior.
- **Changes:** Синхронизировать фактические API/Architecture/TechnicalSpecification/Roadmap/DecisionLog в EN/RU; сформировать README после реального кода и CHANGELOG перед первым public release, LICENSE только после явного выбора владельца.
- **Dependencies:** Все release-intended implementation phases.
- **Acceptance criteria:** EN/RU документы эквивалентны и соответствуют actual public API/lifecycle/provider/storage behavior.
- **Tests / manual checks:** Cross-language checklist, API/doc link validation и source-comment language scan.
- **Remaining limitations:** Deferred HPKE/streaming явно отмечены unsupported, если gates не пройдены.

- **Точка реализации (2026-10-10):** Подготовлены README и CHANGELOG на двух языках, общие статусы проектных документов, формулировки release gates, примечания о нумерации решений и автоматическая проверка документации на основе Phase 25. Криптографическое поведение исходников не изменено. Структурные проверки ссылок/API/этапов/решений доступны локально и в CI. Приёмка .NET/NUnit/безопасности остаётся открытой.

---

## Phase 27 — Полный security audit

> **Partial review snapshot (2026-10-10):** статические проверки и ручной source review выполнены; исправлены mutable AAD/message async races, тесты добавлены, но не запускались. Полная сборка, fuzz execution, cross-process/platform tests и внешняя приёмка отсутствуют. **NO-GO**. [Подробный отчёт](../audit/Laveyana.Security.Phase27.SecurityAudit.ru.md).


- **Purpose:** Выполнить release-gate review полной системы.
- **Changes:** Проверить dependency graph, public surface, secret exposure, concurrency, lifecycle, capability mismatches, persistence/recovery, permissions, formats; fuzz codecs; прогнать integration suite.
- **Dependencies:** Все release-intended implementation phases.
- **Acceptance criteria:** Нет known violated security invariant; documented threat-model limitations explicit; acceptance criteria Generation 1 выполнены.
- **Tests / manual checks:** Полная test matrix, fuzz corpus, failure injection, cross-process/platform integration и manual public-surface/security review. Проверить API compatibility gate для опубликованного baseline (если он существует), clean build/CI и consistency документации.
- **Remaining limitations:** Documented infrastructure limits вроде undetectable rollback без external authority остаются реальными limits.

---

## Граница релизной готовности

Phase 27 обязателен. Phase 19 (HPKE) и encrypted-AEAD часть Phase 20 могут остаться release-optional при непройденных gates: явно обозначить unsupported/deferred без небезопасных замен. Phases 12 и 13 совместно образуют security gate для writable FileSystem. Не создавать преждевременные README/CHANGELOG/LICENSE placeholders.

**Снимок реализации Phase 17 (2026-10-09):** `SoftwareKeyProviderBackend` вычисляет полный HMAC-SHA-256/384/512, проверяет точную Active/Retired версию и сравнивает теги за постоянное время. Добавлены независимые `IManagedMacBackend` / `IManagedSignatureBackend` и маршрутизация по точному `ProviderId`. `ManagedSignatureBackend` поддерживает ECDSA P-256 и RSA-PSS через переданные ему versioned crypto operations; `EphemeralSignatureKeyOperations` хранит приватные ключи только в памяти процесса и **не** является постоянным криптографическим провайдером. Постоянное асимметричное хранилище и отзыв ключей на уровне исполнителя остаются задачами следующей реализации. Компиляция .NET/NUnit и production gates не подтверждены.

**Снимок реализации Phase 18 (2026-10-09):** Опциональные `IManagedKeyAgreementBackend`/`IVersionedKeyAgreementOperations` + `ManagedKeyAgreementBackend` и временный `EphemeralEcdhKeyOperations` реализуют ECDH P-256 → обязательный HKDF-SHA-256. Реализованы `DerivationContext`, `DerivedKeyLease`, явная политика экспорта, `IManagedDerivationBackend` на защищённом software HKDF-ключе, typed extensions и exact routing. Добавлен независимый эталонный вектор и негативные тесты. **Не подтверждены** сборка/запуск NUnit и production security gate. Аутентификация peer, стойкое асимметричное хранилище и защита от межпроцессного отзыва не реализованы; PQC KEM не default.



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
