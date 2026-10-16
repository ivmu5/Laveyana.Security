# Laveyana.Security — самостоятельный мастер-промпт реализации

> **Статус:** архитектурный baseline Generation 1 принят; фактическая реализация должна подтверждаться кодом и тестами. Работа ведётся на .NET 10.
>
> **Самодостаточность:** весь обязательный контракт проектирования, инженерной реализации и предметные требования к `Laveyana.Security` содержатся прямо в этом файле. Для применения правил не требуются какие-либо отдельные исходные инструкции.
>
> **Разделение ответственности:** этот промпт задаёт обязательные правила и порядок работы. Четыре design-документа в `docs/design/` фиксируют утверждённое подробное ТЗ, архитектуру, историю решений и этапы реализации. Они не заменяют правила этого промпта.

## Текущая точка продолжения — H01 CI завершён, Phase 27 security gate открыт (2026-10-16)

- Исходники семи проектов и документация Generation 1 существуют; используется .NET 10.
- GitHub Actions `Verify` успешно выполнил source/docs проверку и Release build + NUnit на Windows и Ubuntu; существующие NuGet lock-файлы используются в locked mode.
- `master` защищён активным GitHub ruleset `Protect master`: Pull Request, три обязательные проверки, запрет force push и удаления ветки. Первый PR-цикл остаётся отдельным операционным подтверждением.
- Phase 19 HPKE `Seal/Open` и encrypted AEAD streaming из Phase 20 отложены и не поддерживаются.
- FileSystem остаётся экспериментальным: Windows TOCTOU, независимая rollback authority, durable nonce/cross-restart и crash/power-loss security gates не закрыты.
- Phase 27 остаётся **PARTIAL / NO-GO** до adversarial-проверок и независимого security sign-off. Успешный CI не означает production-приёмку.
- Текущие API/ограничения: `README.ru.md`; планы: `docs/design/Laveyana.Security.Roadmap.ru.md`; результаты аудита: `docs/audit/Laveyana.Security.Phase27.SecurityAudit.ru.md`.

---

## Быстрая навигация и приоритеты

- **Часть I:** общие архитектурные требования для библиотеки Laveyana: имена, границы, зависимости, DI, жизненный цикл, форматы, версии, тесты, README, документация и процесс проектирования.
- **Часть II:** все сквозные инженерные и API-правила: C#, async/cancellation, exceptions, buffers, security, telemetry, AOT, analyzers и XML-doc.
- **Часть III:** предметные исходные требования `Laveyana.Security`: scope, границы компонентов, ключи, защищённое хранение и контрольный список проектирования.
- **Часть IV:** рабочие security-инварианты и строгий протокол реализации Roadmap.

Четыре пары документов проекта: `TechnicalSpecification`, `Architecture`, `DecisionLog`, `Roadmap` в `docs/design/` (`.md` и `.ru.md`). Новые предметные ограничения уточняются в соответствующем из этих документов, а архитектурные решения не пересматриваются без новой технической причины. В случае несогласованности требуется явно назвать конфликт и согласованно исправить документы до кода, который зависит от решения.

---

## Часть I. Общая архитектура и жизненный цикл библиотеки

#### Назначение

Используй этот промпт как базовое ТЗ и архитектурный контракт при проектировании любой новой библиотеки или крупной подсистемы экосистемы `Laveyana`.

Цель — не просто написать рабочий код, а получить самостоятельную, переиспользуемую, предсказуемую и поддерживаемую .NET-библиотеку с чёткой зоной ответственности, минимальными зависимостями, понятным lifecycle и стабильным публичным API.

Существующий код, старые репозитории и прежние реализации считай прототипами и источниками идей. Не сохраняй их архитектуру только ради совместимости. Backward compatibility со старыми прототипами не требуется, если она отдельно не была запрошена.

---

### 1. Общая архитектура экосистемы

Экосистема `Laveyana` делится на независимые функциональные области. Общие нормы этого раздела применяются к каждой функциональной области; конкретные границы и legacy-источники `Laveyana.Security` определены в предметной части этого промпта.

Каждая самостоятельная функциональная область по умолчанию имеет отдельный Git-репозиторий и собственный lifecycle разработки и релизов. Не разделяй репозитории искусственно, если самостоятельной domain boundary нет.

Независимые области не должны зависеть друг от друга ради удобства: связывай их через целевые consumer-owned contracts и отдельные integration/adaptor assemblies, когда это требуется архитектурой.

**Правило именования интеграций:**

```text
Laveyana.{ConsumerDomain}.{IntegratedDomainOrProvider}
```

`{ConsumerDomain}` — область, чьему use case принадлежит интеграция; `{IntegratedDomainOrProvider}` — адаптируемая область или provider. Integration по умолчанию располагается в репозитории consumer-domain. Выделяй отдельный Git-репозиторий только при самостоятельной технической, ownership или release/support boundary.

Не создавай общий `Laveyana.Platform.Core`, `Laveyana.Common.Core` или `Laveyana.Platform.Contracts` без устойчивой реальной ответственности.


---

### 1.1. Naming contract Laveyana

`Laveyana` — обязательный корневой идентификатор всей новой экосистемы.

Любое новое имя, которое идентифицирует наш repository/project/assembly/package/root namespace, должно начинаться с:

```text
Laveyana.
```

Универсальные шаблоны (фигурные скобки обозначают placeholders, а не буквальные имена проектов):

```text
Repository / solution family
→ Laveyana.{Domain}

Projects / assemblies / NuGet PackageId
→ Laveyana.{Domain}.Abstractions
→ Laveyana.{Domain}
→ Laveyana.{Domain}.DependencyInjection
→ Laveyana.{Domain}.Tests

Namespaces
→ Laveyana.{Domain}
→ Laveyana.{Domain}.{Feature}

Integration package
→ Laveyana.{ConsumerDomain}.{IntegratedDomainOrProvider}
```

Правила:

- `AssemblyName`, `PackageId` и `RootNamespace` должны использовать один и тот же `Laveyana.*` family prefix, если нет отдельной технической причины для исключения;
- test/sample/tool projects, если они относятся к Laveyana, также начинаются с `Laveyana.`;
- integration/adaptor package именуется внутри `Laveyana.*`, а не как отдельный безымянный package;
- domain-identifying solution/repository/document names должны использовать `Laveyana` там, где это помогает однозначно понять принадлежность;
- в обычном описательном тексте допустимо сокращать имя конкретной области, но реальные repository/project/assembly/package/root namespace identities всегда используют `Laveyana.*`;
- имена старых репозиториев, прототипов и их внутренние типы не становятся частью нового API автоматически: их рассматривает только domain-specific prompt, если такой источник предоставлен;
- не вводить второй параллельный корневой namespace рядом с `Laveyana`.

Для generic примеров в этом документе обозначение `{Domain}` означает функциональную область внутри `Laveyana`:

```text
Laveyana.{Domain}
Laveyana.{Domain}.Abstractions
Laveyana.{Domain}.DependencyInjection
```

---

### 2. Стандартная структура библиотеки

Для крупной области базовая структура разделяется по стадии проекта.

До начала полноценной implementation обязательна design-часть:

```text
Laveyana.{Domain}/
├── src/                                      # допустим минимальный build skeleton
├── tests/                                    # допустим минимальный test skeleton
├── docs/
│   └── design/
│       ├── Laveyana.{Domain}.TechnicalSpecification.md
│       ├── Laveyana.{Domain}.TechnicalSpecification.ru.md
│       ├── Laveyana.{Domain}.Architecture.md
│       ├── Laveyana.{Domain}.Architecture.ru.md
│       ├── Laveyana.{Domain}.DecisionLog.md
│       ├── Laveyana.{Domain}.DecisionLog.ru.md
│       ├── Laveyana.{Domain}.Roadmap.md
│       └── Laveyana.{Domain}.Roadmap.ru.md
├── .editorconfig
├── Directory.Build.props
└── Directory.Packages.props
```

После появления реальной implementation/public API repository обычно развивается до:

```text
Laveyana.{Domain}/
├── src/
│   ├── Laveyana.{Domain}.Abstractions/
│   ├── Laveyana.{Domain}/
│   ├── Laveyana.{Domain}.DependencyInjection/
│   └── дополнительные проекты только при реальной границе
│
├── tests/
│   ├── Laveyana.{Domain}.Tests/
│   └── Laveyana.{Domain}.IntegrationTests/
│
├── docs/
├── samples/                                  # только если реально нужны
├── README.md                                 # после появления реального кода/API
├── README.ru.md                              # после появления реального кода/API
├── CHANGELOG.md                              # при подготовке первого public release
├── CHANGELOG.ru.md                           # при подготовке первого public release
├── LICENSE                                   # перед public distribution после explicit license decision
├── .editorconfig
├── Directory.Build.props
└── Directory.Packages.props
```

`README*`, `CHANGELOG*` и `LICENSE` не являются обязательными pre-implementation placeholders. Не создавай их заранее только ради шаблона.

Лицензия самой Laveyana-библиотеки никогда не выбирается автоматически этим промптом. До design/private development `LICENSE` может отсутствовать. Перед первым public distribution/release владелец проекта обязан явно выбрать лицензию, после чего repository/package metadata приводятся в соответствие этому решению.

#### Laveyana.{Domain}.Abstractions

Содержит только то, что consumer действительно должен видеть:

- публичные contracts;
- необходимые domain identifiers/value objects;
- result/status types;
- DTO/models, входящие в публичные contracts;
- exceptions, являющиеся частью контракта;
- реальные extension points.

Не выноси интерфейс для каждого внутреннего класса.

#### Laveyana.{Domain}

Содержит:

- стандартные реализации;
- orchestration;
- domain logic;
- внутренние workflows;
- validators;
- serializers;
- locking/concurrency mechanics;
- implementation details.

По умолчанию новый тип считается `internal`. Делай его `public`, только если consumer действительно должен им пользоваться.

Слово `core` в prose означает основную domain implementation/logic и **не** подразумевает отдельный `Laveyana.{Domain}.Core` project. `.Core` assembly создаётся только при отдельной реальной технической границе.

#### Laveyana.{Domain}.DependencyInjection

Содержит:

- `IServiceCollection` extensions;
- composition logic;
- DI-specific configuration API;
- регистрацию lifetimes;
- adapters к Generic Host lifecycle;
- DI validation.

Не помещай в него бизнес-логику.

#### Дополнительные assemblies

Создавай отдельный `.csproj`, только если существует реальная техническая граница:

- platform-specific код;
- отдельная внешняя dependency;
- самостоятельная реализация контракта;
- другой target framework;
- integration двух независимых domain-областей;
- необходимость не навязывать dependency всем consumers.

Примеры шаблонов именований:

```text
Laveyana.{Domain}.{Platform}
Laveyana.{Domain}.{Provider}
Laveyana.{ConsumerDomain}.{IntegratedDomain}
```

Не создавай assembly просто потому, что внутри библиотеки появился новый namespace или отдельное понятие.

---

### 3. Target framework

Текущая экосистема проектируется под .NET 10.

```text
cross-platform libraries → net10.0
platform-specific        → соответствующий .NET 10 TFM
MAUI                     → соответствующие .NET 10 MAUI TFMs
```

Не добавляй поддержку старых .NET или multi-targeting без реального требования.

При будущем переходе на новый релиз .NET миграция всей экосистемы выполняется отдельным контролируемым этапом.

---

### 4. Dependency rules

Основные domain-проекты должны иметь минимальный dependency graph.

Запрещено:

- циклические `ProjectReference`;
- зависимость независимой domain-библиотеки от другой независимой domain-библиотеки без integration layer;
- platform/framework dependency в основной domain assembly без реальной необходимости;
- тяжёлая dependency ради одного trivial helper;
- скрытая dependency через public API без понимания её compatibility cost.

Базовое направление:

```text
Laveyana.{Domain}.Abstractions
        ↑
        ├── Laveyana.{Domain}
        ├── Laveyana.{Domain}.DependencyInjection
        ├── replaceable implementation/provider packages
        └── integration packages, когда им нужен этот contract
```

Replaceable/external implementation по умолчанию должна зависеть от `Laveyana.{Domain}.Abstractions`, если для реализации контракта этого достаточно. Зависимость такой implementation от concrete `Laveyana.{Domain}` допустима только когда она намеренно использует concrete behaviour/implementation и это является реальной частью design, а не способом получить доступ к contract.

`Laveyana.{Domain}.DependencyInjection` может ссылаться на `Laveyana.{Domain}` и `Laveyana.{Domain}.Abstractions`, поскольку отвечает за composition стандартной реализации.

Integration package может ссылаться на обе интегрируемые области в соответствии со своей consumer-owned responsibility.

Если внешний тип появляется в public API, внешняя dependency становится частью публичного compatibility contract.

Централизуй версии `PackageReference` внутри repository через `Directory.Packages.props`.

Подробные cross-project правила third-party dependencies, reflection, trimming, AOT и dynamic code изложены ниже в инженерном разделе этого же промпта.

---

### 5. Взаимодействие между domain-библиотеками

Независимые области связываются через consumer-owned contracts и integration/adaptor projects.

Если библиотеке A нужна возможность от B, контракт формулируется с точки зрения потребности A, а integration package адаптирует B к этому контракту.

Не создавай общую транзакцию между независимыми domain-библиотеками, если реальной общей транзакции нет.

Каждая область гарантирует атомарность/целостность своих операций. Multi-domain workflow принадлежит application/integration/orchestration layer и при необходимости использует:

- retry;
- compensation;
- journal;
- checkpoint;
- recovery state.

---

### 6. DI и способы использования

Core-библиотека должна оставаться usable без DI.

Обычный application consumer по возможности зависит от:

```text
Laveyana.{Domain}.Abstractions
Laveyana.{Domain}.DependencyInjection
```

Полную `Laveyana.{Domain}` подключают напрямую, если нужны:

- manual construction;
- advanced API;
- стандартные concrete implementations;
- расширение библиотеки;
- direct use без DI.

Поддерживай два сценария DI-конфигурации:

#### Явная конфигурация

```csharp
services.AddX(settings =>
{
    settings
        .EnableSomething()
        .UseSomeImplementation()
        .WithTimeout(...);
});
```

#### Документированный default preset

```csharp
services.AddXDefaults();
```

`AddXDefaults()` должен быть обычным заранее определённым preset поверх той же configuration model, а не отдельной системой конфигурации.

Создавай `AddXDefaults()` только если существует один разумный, безопасный и хорошо документированный стандартный сценарий.

---

### 7. Configuration model

Публичная настройка выполняется через method-based configuration DSL.

Предпочтительно:

```csharp
settings
    .EnableFeature()
    .WithTimeout(...)
    .UseSomething();
```

а не:

```csharp
settings.FeatureEnabled = true;
settings.Timeout = ...;
```

Публичные setters по возможности отсутствуют.

Модель:

```text
XSettings
→ configure through methods
→ validate
→ normalize
→ immutable internal snapshot
→ runtime instance
```

После создания runtime instance последующее изменение исходного `Laveyana.{Domain}Settings` не должно влиять на уже работающий объект.

Runtime changes выполняются через явные runtime API, а не через мутацию options.

Configuration methods не должны выполнять I/O, создавать реальные ресурсы или запускать фоновые процессы.

---

### 8. Settings и secrets

Конфигурация и секреты разделены.

`Laveyana.{Domain}Settings` не должен хранить:

- passwords;
- API tokens;
- private keys;
- connection credentials;
- другие sensitive values.

Secrets передаются через отдельные contracts/providers и имеют собственный lifecycle.

Secrets не должны автоматически попадать в:

- logs;
- `ToString()`;
- diagnostics;
- exports;
- backups;
- persisted settings.

---

### 9. Lifecycle

Общая семантика:

```text
Construction ≠ Initialization ≠ Runtime ≠ Disposal
```

Конструктор:

- проверяет непосредственные аргументы;
- сохраняет dependencies;
- устанавливает in-memory invariants;
- не выполняет тяжёлый I/O;
- не запускает фоновые процессы.

`InitializeAsync()` используется только там, где реально требуется подготовка ресурсов.

`StartAsync()/StopAsync()` существуют только у компонентов с активным runtime.

Основная domain implementation определяет lifecycle; `Laveyana.{Domain}.DependencyInjection` лишь автоматизирует его через Generic Host при необходимости.

Partial initialization failure не должна оставлять объект в неопределённом состоянии.

`Dispose/DisposeAsync` освобождает принадлежащие объекту ресурсы и не выполняет скрытые бизнес-операции.

Ownership boundaries должны быть явными. Точные API-level conventions для `Stream`, buffers, `IDisposable`, leases и ownership transfer приведены в инженерном разделе ниже.

---

### 10. Background workers

Основная domain implementation не запускает скрытые бесконечные `Task.Run()`.

Background feature оформляется как явный worker с lifecycle:

```text
[Initialize] → Start → Running → Stop → Dispose
```

`Initialize` является optional phase и существует только если компоненту реально нужна отдельная подготовка ресурсов.

`Laveyana.{Domain}.DependencyInjection` может автоматически подключать worker к `IHostedService`/host lifecycle.

Worker должен поддерживать cancellation и корректный shutdown согласно инженерным нормам этого промпта.

---

### 11. Сквозные инженерные и API conventions

Сквозные нормы C# readability, именования API, async/cancellation, ресурсного владения, time/retry, исключений, потокобезопасности, сериализации, logging, зависимостей, AOT/trimming, комментариев и analyzers включены непосредственно в инженерную часть этого промпта. Они обязательны наряду с общими архитектурными нормами.

Предметная область Security может вводить обоснованные более строгие правила безопасности, но не скрытно отменять инженерные требования.

---

### 12. Persistent data ownership

Domain-библиотека владеет:

- моделью своих данных;
- семантикой;
- контрактами хранения.

Конкретный storage mechanism может быть заменяемой реализацией.

Если реализация использует другую нашу domain-библиотеку, она живёт в отдельном integration assembly.

Общая модель ownership:

```text
Laveyana.{Domain}.Abstractions
→ объявляет заменяемый domain contract

Laveyana.{Domain}
→ владеет domain semantics / стандартной orchestration

Laveyana.{Domain}.{Provider}
→ при необходимости реализует storage/backend contract

Laveyana.{ConsumerDomain}.{IntegratedDomain}
→ связывает независимые области через integration boundary
```

Не делай вывод о существовании какого-либо конкретного provider, storage engine или другой библиотеки из этих generic placeholders.

У одних live-данных по умолчанию должен быть один authoritative source.

Cache/export/snapshot не являются вторым независимым source of truth.

Исключение допустимо для сознательно спроектированной replication/multi-writer/multi-authority модели. В таком случае consistency/conflict/reconciliation model должна быть явно определена в domain architecture; нельзя случайно получить два независимых источника истины из-за удобства implementation.

---

### 13. Persistent format versioning

Версия библиотеки и версия persisted format — разные вещи.

Долгоживущий собственный формат имеет отдельный `FormatVersion`.

```text
Library: X.YYMM.R
Data format: integer/schema version
```

Не сериализуй internal runtime class и не считай автоматически получившийся JSON стабильным публичным форматом.

Используй persisted models/mapping там, где формат должен жить долго.

Неизвестная более новая версия формата не интерпретируется наугад.

#### Stable serialization boundary

Долгоживущий persistent/interchange format должен иметь намеренно определённую stable representation; serializer defaults не становятся durable contract автоматически.

Cross-project правила canonical encoding, culture independence, stable identifiers и запрета CLR/runtime names как случайной persistent identity закреплены в инженерном разделе ниже. Domain `TechnicalSpecification`/`Architecture` фиксируют специфичную семантику persistent formats.

---

### 14. Migrations и recovery

Миграции должны быть восстанавливаемыми.

Если операция может прерваться в несовместимом промежуточном состоянии, используй подходящую схему:

- DB transaction;
- temp + validate + replace;
- checkpoint;
- journal;
- resume;
- rollback/restore.

Не называй операцию атомарной, если реальная инфраструктура этого не гарантирует.

---

### 15. Extension points

Основной механизм расширения — composition через небольшие специализированные interfaces.

Интерфейс создаётся только если:

- consumer реально должен заменить реализацию;
- существует осознанная extension boundary;
- или контракт нужен для отделения consumer от implementation.

Не создавай интерфейс для каждого класса.

Наследование допустимо, но не является основным extension mechanism.

Plugin system и assembly scanning не вводятся без отдельного требования.

---

### 16. Public surface

Public API должен быть минимальным и понятным.

Public:

- consumer contracts;
- configuration API;
- result/status types;
- необходимые domain types;
- deliberate extension points;
- exceptions, являющиеся частью public semantics.

Internal:

- helpers;
- serializers;
- validators;
- locking;
- orchestration;
- workflow mechanics;
- implementation details.

#### Public API compatibility gate

Published public API является compatibility contract и не должен ломаться случайно.

Для released packages поддерживать automated API compatibility check относительно выбранного compatibility baseline, обычно последнего stable release той же поддерживаемой `X` generation.

Machine-checkable gate отвечает за surface, которую tooling действительно может сравнить надёжно, например:

- public types и members;
- signatures;
- visibility;
- generic constraints;
- public nullability annotations;
- public extension-contract shape.

Semantic compatibility не перекладывается на API-diff tooling. Изменения documented outcomes/exceptions, lifecycle, idempotency, externally meaningful enum/value semantics, defaults и других behavioural contracts проверяются architecture/API review, tests и документацией.

Detected breaking change не запрещён автоматически, но требует explicit decision. В зависимости от характера изменения необходимо:

- исправить случайный break;
- либо зафиксировать intentional breaking change;
- предоставить migration/deprecation path, когда это возможно;
- обновить tests и EN/RU documentation;
- изменить `X` compatibility generation, если изменение несовместимо с текущей line.

API compatibility tooling является guardrail, а не заменой архитектурного review.

---

### 17. Versioning и support policy

Версия repository/library/package:

```text
X.YYMM.R
```

Где:

- `X` — functional/compatibility generation публичного API и значимых lifecycle/behaviour contracts;
- `YYMM` — год и месяц stable release;
- `R` — порядковый номер опубликованного stable release **внутри пары `(X, YYMM)`**, начиная с `0`; при новом `X` или новом календарном месяце счётчик начинается снова с `0`.

Примеры:

```text
1.2610.0  → первый stable release октября 2026
1.2610.1  → второй stable release октября 2026
1.2611.0  → первый stable release ноября 2026
2.2703.0  → новое incompatible compatibility generation
```

`R` — **не CI build number**. Сколько бы промежуточных builds ни выполнил CI, stable package version меняется только для реального release.

Все NuGet packages, опубликованные из одного repository release, получают одну version.

Новые обратно совместимые функции, fixes и security updates не обязаны менять `X`.

Несовместимое изменение уже опубликованного public API/lifecycle/behaviour contract требует явного compatibility decision. По умолчанию оно переводит библиотеку в следующую `X` generation; исключение допустимо только по обоснованной и задокументированной необходимости (например, срочное устранение опасного API). Не допускай тихих несовместимых изменений внутри поддерживаемой generation.

#### Prerelease policy

Для prerelease использовать SemVer-compatible suffixes:

```text
1.2610.0-alpha.1
1.2610.0-alpha.2
1.2610.0-beta.1
1.2610.0-rc.1
1.2610.0
```

`alpha`, `beta`, `rc` обозначают maturity stage. Numeric suffix внутри stage увеличивается последовательно для конкретной planned stable version `X.YYMM.R`.

Если выпуск переносится в другой месяц или меняется целевая stable version, prerelease публикуется уже с **новой целевой версией**; прежние опубликованные package versions не переименовываются, не перезаписываются и не используются повторно. Публикация того же числа версии с другим содержимым запрещена.

Не использовать SemVer build metadata (`+...`) как единственный carrier информации, которую consumer должен видеть как часть package identity/release policy: NuGet normalization/resolution не должна быть источником неоднозначности.

#### Support policy

Полноценная support matrix обязательна после первого **stable public release**. До этого design/private/prerelease repository не обязан искусственно объявлять maintenance branches и EOL dates.

`main` представляет current development/current generation.

Release branches создаются только для реально поддерживаемых старых `X` generations, например:

```text
main        → current generation
release/2.x → поддерживаемая предыдущая generation
release/1.x → более старая generation, только если она действительно поддерживается
```

Не создавать пустые `release/X.x` branches заранее.

Для каждой реально поддерживаемой stable generation фиксировать:

- status: Current / Maintenance / Security-only / EOL;
- `Support Until`, если policy уже объявлена;
- допустимые типы обновлений/backports.

После EOL fixes и security backports больше не гарантируются.

#### Deprecation policy

Обычный breaking path:

```text
current API
→ [Obsolete] + documented migration path
→ removal in next X generation
```

Опасный/небезопасный API может удаляться быстрее при обоснованной необходимости.

#### CHANGELOG / release notes

`CHANGELOG.md` и `CHANGELOG.ru.md` создаются **при подготовке первого public release**, чтобы первый release уже имел release history/documentation, а не появляются постфактум.

После этого обе версии обновляются вместе на каждый release и описывают один и тот же набор user/developer-visible изменений.

Для каждого release фиксировать как минимум:

- version и release date;
- значимые additions/changes;
- deprecations/removals;
- bug fixes, влияющие на consumer behaviour;
- security-relevant changes, которые безопасно публиковать;
- breaking changes и migration notes;
- изменения persisted/interchange formats, если они есть.

CHANGELOG не является commit log. Не перечисляй внутренние refactor/rename/formatting изменения, которые не имеют значения для consumer или maintainer, если они не влияют на compatibility/architecture.

Release notes должны основываться на фактическом release content и не содержать историю общения с ИИ или процесс генерации документации.

---

### 18. Testing standard

Стандартно:

```text
Laveyana.{Domain}.Tests
Laveyana.{Domain}.IntegrationTests
```

Не создавай отдельный project под каждый вид тестов.

В зависимости от возможностей библиотеки покрывай:

- success path;
- expected failure;
- invalid configuration;
- dependency failure;
- cancellation;
- repeat/idempotency;
- concurrency;
- migration;
- recovery;
- corrupted data;
- security scenarios;
- compatibility.

Тестируй не только happy path.

#### 18.1. Build / CI / release contract

Repository должен собираться и проверяться из clean checkout без ручной подготовки локальных файлов, которые существуют только на машине разработчика.

Базовый reproducible path для library repository:

```text
restore
→ build
→ test
→ pack   # для publishable packages
```

Допустимые внешние prerequisites (например, .NET workload, platform SDK, signing infrastructure) должны быть явно документированы и не подменяться machine-specific hidden state.

Запрещено полагаться на:

- absolute user/machine paths;
- вручную скопированные DLL/files вне repository/package workflow;
- содержимое `bin/obj` от предыдущей сборки;
- локальные secrets/config files как обязательную часть обычного build;
- IDE-only state, без которого command-line/CI build ломается.

CI является authoritative verification path для поддерживаемых build/test/package scenarios.

Для publishable NuGet packages проверять как минимум:

- `PackageId`, version и description;
- repository metadata;
- README/package documentation linkage;
- явно выбранную license metadata/notice strategy, без автоматического выбора лицензии за владельца проекта;
- dependency metadata;
- отсутствие случайных tests/temp/secrets/build artifacts внутри package;
- возможность установить/использовать package как самостоятельный artifact.

Dependency `PackageReference` versions централизуются через `Directory.Packages.props`. Release version собственных packages repository задаётся отдельно через shared build property (`Directory.Build.props` или эквивалентный единый mechanism).

Symbols/SourceLink/source metadata добавлять для publishable packages, когда это поддерживается выбранным release workflow и не создаёт security/privacy проблем.

#### 18.2. Repository hygiene

Repository должен оставаться переносимым и чистым.

Обязательные правила:

- использовать `.gitignore` для build/IDE/temp artifacts;
- не коммитить `bin/`, `obj/`, `.vs/` и аналогичный generated local state;
- не коммитить secrets, tokens, passwords, private keys, production credentials или реальные sensitive test data;
- sample configuration содержит placeholders/examples, а не действующие secrets;
- не хранить machine-specific absolute paths;
- текстовые файлы использовать в согласованной UTF-8/line-ending policy через `.editorconfig` и при необходимости `.gitattributes`;
- generated artifacts коммитить только если они являются осознанной частью source/distribution contract;
- build/test не должен молча изменять tracked source files;
- repository должен оставаться пригодным для clone/build на другой поддерживаемой машине без ручного исправления путей.

---

### 19. Repository documentation

Исчерпывающие требования к source-code style, file-scoped namespaces, XML documentation/comments, nullable, warnings/analyzers, generated/vendor source содержатся в инженерном разделе ниже.

---

Вся пользовательская и репозиторная текстовая документация Laveyana должна поддерживаться **в двух языковых версиях**:

```text
*.md     → English
*.ru.md  → Russian
```

Это обязательное правило для README и содержательной документации в `docs/`, включая архитектурные документы, технические спецификации, Roadmap, Decision Log, migration guides, usage guides и другие документы, предназначенные для чтения человеком.

Минимальный комплект зависит от стадии проекта. До начала implementation обязательны design-документы:

```text
docs/design/Laveyana.{Domain}.TechnicalSpecification.md
docs/design/Laveyana.{Domain}.TechnicalSpecification.ru.md

docs/design/Laveyana.{Domain}.Architecture.md
docs/design/Laveyana.{Domain}.Architecture.ru.md

docs/design/Laveyana.{Domain}.DecisionLog.md
docs/design/Laveyana.{Domain}.DecisionLog.ru.md

docs/design/Laveyana.{Domain}.Roadmap.md
docs/design/Laveyana.{Domain}.Roadmap.ru.md
```

После появления реальной implementation/public API корень repository также содержит:

```text
README.md
README.ru.md
```

При подготовке первого public release добавляются:

```text
CHANGELOG.md
CHANGELOG.ru.md
```

Дополнительные guides/concepts/development/migrations/operations docs создаются только при реальной необходимости и располагаются в соответствующих `docs/` subdirectories согласно documentation lifecycle contract ниже.

Инженерные правила и нормы архитектуры в этом самостоятельном промпте являются единой нормативной основой библиотеки. Не требуй внешних первоначальных инструкций для их применения; если политика экосистемы меняется, обновляй интегрированный текст и проверяй соответствие design-документов.

English и Russian версии одного документа должны:

- иметь одинаковое назначение;
- содержать эквивалентный набор требований и решений;
- по возможности сохранять одинаковую структуру заголовков и порядок разделов;
- иметь взаимную навигацию между языковыми версиями;
- обновляться вместе при изменении архитектуры, public API, lifecycle, configuration, compatibility или Roadmap;
- не расходиться так, чтобы одна языковая версия становилась устаревшим или урезанным вариантом другой.

`README.md` является English-версией, `README.ru.md` — Russian-версией.
README описывает сам проект и его текущее состояние, а не историю разговора с ИИ.

Языковое парное правило не требует искусственно дублировать language-neutral artifacts, например:

- `LICENSE` самой библиотеки;
- original third-party licenses, `NOTICE`, copyright/legal texts, которые должны сохраняться в исходной форме;
- `.editorconfig`;
- `.csproj` / `.props` / `.targets`;
- JSON/XML schemas, если их содержимое является машинным контрактом;
- диаграммы и бинарные assets, если они не содержат отдельного prose-документа.

C# source documentation/comments не входят в EN/RU repository-document pairing; к ним применяются требования English-only из инженерного раздела этого промпта.

---

### 20. README generation contract

README является краткой технической точкой входа в **реально реализованный repository**, а не заменой полной API/architecture documentation.

Этот contract применяется после появления реальной implementation/public API. На pre-implementation architecture stage `README.md` и `README.ru.md` не создаются.

При создании или полном обновлении README необходимо подготовить **два самостоятельных файла**:

```text
README.md     → English
README.ru.md  → Russian
```

Обе версии описывают один и тот же проект и должны иметь эквивалентные:

- разделы;
- примеры;
- таблицы;
- архитектурные схемы;
- относительные ссылки на исходный код;
- `<details>` blocks;
- сведения о testing, lifecycle, limitations и dependencies.

Различаться должен естественный язык изложения, но не технический смысл или объём информации.

Имена `types`, `methods`, `interfaces`, `namespaces`, `packages`, `files`, `commands`, `parameters`, configuration keys и другие программные identifiers не переводятся.

#### 20.1. Language switcher

Сразу после названия проекта добавлять компактный переключатель языка.

В `README.md`:

```markdown
English | [Русский](README.ru.md)
```

В `README.ru.md`:

```markdown
[English](README.md) | Русский
```

`README.md` считается основной международной версией, но `README.ru.md` не является сокращённым переводом.

#### 20.2. Цель README и ограничение основной части

Разработчик, впервые открывший repository, должен примерно за **10 минут или меньше** понять:

- назначение библиотеки;
- основные возможности;
- крупные архитектурные подсистемы и их связи;
- основной public API;
- где находится ключевая логика;
- основные execution flows, если они неочевидны;
- где находятся tests;
- основные точки изменения и расширения.

Основная часть README должна оставаться компактной:

- короткие технические абзацы;
- небольшие таблицы только там, где они реально упрощают понимание;
- только основные classes/components/scenarios;
- без полного дерева repository;
- без перечисления каждой public overload/property;
- без повторения одной информации в нескольких разделах.

Подробности, которые полезны, но не нужны для первого знакомства, помещать в тематические `<details>` рядом с соответствующим разделом.

Содержимое `<details>` не ограничивается искусственным лимитом объёма, но не должно механически пересказывать код, XML-doc или каждый private helper.

#### 20.3. README описывает только фактический текущий repository

Перед созданием README необходимо изучить repository настолько, чтобы описание основывалось на реальной реализации.

Приоритет анализа:

1. solution и `.csproj`;
2. project/reference/dependency graph;
3. структура `src/`;
4. public API;
5. основные implementation classes;
6. DI registration/composition;
7. state/lifecycle/async/concurrency semantics;
8. tests;
9. существующие docs;
10. XML-doc и source comments.

README должен описывать **фактическую архитектуру и поведение текущего кода**, а не планируемую, предполагаемую или «более правильную» архитектуру.

Не придумывать classes, methods, packages, dependencies, supported scenarios, lifecycle guarantees, thread-safety guarantees, behavior или test coverage, которые нельзя подтвердить по repository.

Не превращай неподтверждённое или противоречивое поведение в утверждение README; при выявлении расхождения уточни факты до публикации документации. Это правило не устанавливает иерархию между кодом и утверждённым domain TechnicalSpecification.

Если критически важную информацию невозможно подтвердить, не заполнять пробел предположением. До финализации README необходимо отдельно уточнить этот факт у владельца проекта либо исключить неподтверждённое утверждение, если README остаётся корректным без него.

#### 20.4. README не содержит мета-контекст создания

README должен выглядеть так, будто он написан непосредственно для repository.

Запрещено упоминать:

- переписку;
- ИИ;
- prompt/instruction, по которому создавался документ;
- «переданные», «загруженные», «предоставленные» файлы;
- snapshot/archive/export как способ передачи проекта;
- ограничения среды анализа;
- отсутствие какого-либо файла именно «среди переданных материалов»;
- процесс анализа;
- промежуточные выводы;
- причины, по которым конкретный факт не удалось подтвердить.

Не писать формулировки вида:

```text
"В переданном архиве..."
"Среди предоставленных файлов..."
"На основании загруженного снимка..."
"В этой среде не удалось проверить..."
```

README описывает только сам проект.

#### 20.5. Относительные ссылки на исходный код

При первом значимом упоминании ключевого public type, extension point или implementation entry point по возможности добавлять относительную ссылку на реальный source file:

```markdown
[`SomeService`](src/Laveyana.SomeDomain/.../SomeService.cs)
```

Не создавать искусственный список всех типов только ради ссылок.

Ссылки должны вести только на реально существующие пути текущего repository.

#### 20.6. Рекомендуемое содержание README

Конкретный раздел создаётся только если он добавляет полезную информацию. Не создавать пустые или формальные sections только ради шаблона.

##### Заголовок и краткое введение

В начале:

- название проекта;
- language switcher;
- одно короткое предложение о назначении;
- компактный технический вводный абзац.

Не использовать рекламные формулировки.

##### Contents

После введения добавлять компактное содержание по фактически существующим крупным sections.

Не превращать contents в полное дерево всех headings и `<details>`.

##### Основные возможности

Кратко показывать, что consumer реально может сделать с библиотекой.

Не пересказывать internal architecture через список features.

##### Architecture

Показать крупные subsystems, responsibility и основные связи.

Если помогает пониманию — использовать компактную ASCII- или Mermaid-схему.

Для каждой крупной подсистемы указывать только responsibility, связи и 1–3 действительно ключевых type/interface.

Не перечислять все classes.

##### Repository navigation

Создавать только если физическая структура repository достаточно сложная.

Показывать сокращённое дерево, объясняющее **где находится код**, а не повторяющее architecture section.

##### Main execution flows

Создавать только для действительно важных неочевидных сценариев.

Формат:

```text
PublicApi.MethodAsync()
→ Coordinator
→ Storage/Provider
→ Result
```

Не превращать README в подробную sequence diagram.

##### Public API

Показывать основные entry points и минимальный реальный usage scenario.

Если библиотека использует DI/configuration/builder, показывать фактический рекомендуемый путь.

Кодовые примеры должны использовать только существующий public API.

Расширенные примеры помещать в `<details>`.

##### Testing

Создавать при наличии tests/test infrastructure.

Кратко описывать:

- test projects;
- назначение основных test categories;
- критические guarantees/invariants;
- как запустить tests;
- special environment requirements;
- куда добавлять tests при изменении соответствующей функциональности.

Не перечислять каждый test class/method.

##### Lifecycle and state

Создавать, если у библиотеки есть значимое состояние, resource ownership, subscriptions, long-lived services, caching, background work или другие lifecycle constraints.

Показывать:

- где создаётся state;
- кто им владеет;
- сколько он живёт;
- кто освобождает ресурсы;
- какие invariants нельзя нарушать.

##### Async and concurrency

Создавать только если это значимая часть поведения.

Фиксировать:

- какие operations async;
- `CancellationToken` semantics;
- thread-safety;
- concurrency constraints;
- UI-thread requirements, если они реально существуют.

Не объяснять основы `async/await` или `Task`.

##### Limitations and important behavior

Создавать только для существенных ограничений:

- unsupported scenarios;
- platform constraints;
- public API constraints;
- deliberate architectural compromises;
- behavior, которое consumer может ошибочно предположить;
- важные security/compatibility restrictions.

Не превращать section в TODO list.

##### Modification and extension points

Добавлять компактную практическую карту:

```markdown
| Задача | Основные точки изменения |
|---|---|
| Добавить новый provider | [`ISomeProvider`](...) / [`SomeRegistry`](...) |
| Изменить storage behavior | [`SomeStore`](...) / соответствующие tests |
```

Включать только практически значимые scenarios.

При наличии связанных tests указывать соответствующий test project/class.

#### 20.7. `<details>` как основной механизм углубления

Подробную техническую информацию размещать преимущественно рядом с соответствующим вопросом:

```html
<details>
<summary>Internal architecture details</summary>

...

</details>
```

Допустимое содержимое:

- internal subsystem structure;
- class/interface interaction;
- algorithms/workflows;
- lifecycle/state;
- DI/dependency details;
- error handling;
- extension points;
- important edge cases;
- test guarantees;
- причины неочевидных архитектурных решений;
- расширенные usage examples.

Не использовать `<details>` как место для механического dump всего кода или полного списка всех методов.

#### 20.8. Сторонние dependencies и licenses

При создании README необходимо определить **существенные** third-party dependencies.

Для значимых dependency проверить:

- package/library name;
- назначение в проекте;
- license;
- attribution/copyright requirements;
- необходимость `NOTICE`;
- необходимость распространения текста license;
- другие обязательные notices.

Не делать юридический вывод только по названию NuGet package.

При необходимости использовать package metadata, официальный repository или официальную documentation/license page.

Не помещать в README полный список packages ради полноты.

Упоминать dependency, если она важна для понимания архитектуры или использования, непосредственно влияет на integration либо требует attribution/notice.

Если требуется отдельный:

```text
LICENSE
NOTICE
THIRD-PARTY-NOTICES
```

или аналогичный файл, это должно быть отражено в repository requirements.

Не выбирать и не предлагать license самой Laveyana-библиотеки без отдельного решения владельца проекта.

Если license requirements существенной dependency остаются неоднозначными, не придумывать юридический вывод; этот вопрос должен быть разрешён до публикации финального README/release documentation.

#### 20.9. Стиль README

`README.md` писать на естественном техническом английском.

`README.ru.md` писать на естественном техническом русском.

Не делать буквальный машинный перевод, если он ухудшает читаемость. Сохранять технический смысл, структуру и факты.

Стиль:

- официальный;
- нейтральный;
- конкретный;
- технический;
- без маркетинговых оценок;
- без разговорных заголовков;
- без длинных вступлений;
- без повторений;
- без огромных таблиц;
- без объяснения общеизвестных основ C#/.NET, если это не требуется для конкретного проекта.

Не использовать без технической необходимости формулировки вроде:

```text
powerful
modern
flexible
enterprise-ready
```

Каждый section должен добавлять новую информацию.

#### 20.10. README final self-check

Перед завершением README проверить:

1. существуют `README.md` и `README.ru.md`;
2. language switcher корректен;
3. структура, примеры, tables, diagrams и `<details>` эквивалентны;
4. нет смысловых расхождений между EN/RU;
5. после первых абзацев понятно назначение библиотеки;
6. основная часть формирует mental model примерно за 10 минут или меньше;
7. Contents соответствует фактическим sections;
8. architecture/public API/key flows понятны;
9. modification/extension points понятны;
10. test section соответствует реальным tests;
11. все упомянутые types/methods/files/packages реально существуют;
12. нет неподтверждённого поведения;
13. нет повторения одной информации в нескольких sections;
14. подробности вынесены в тематические `<details>`;
15. substantial dependencies/license obligations проверены;
16. README не содержит meta-context анализа/переписки/передачи исходников;
17. обе версии используют единый технический стиль.

Если основная часть README становится слишком большой, сокращать её или переносить детали в `<details>`, а не увеличивать целевое время первого знакомства.

Итоговый README workflow всегда выдаёт два отдельных файла:

```text
README.md
README.ru.md
```

Не объединять оба языка в один README.

---



### 21. Documentation lifecycle and `docs/` organization

Документация Laveyana рассматривается как часть lifecycle проекта. Нельзя одинаково документировать планируемую архитектуру до реализации и фактическое поведение после появления кода.

Основной принцип:

```text
Before implementation
→ документация определяет требования, границы и план

During implementation
→ design docs поддерживаются синхронно с принятыми решениями

After implementation
→ user/developer docs описывают фактический код и public API
```

#### 21.1. Документация до начала implementation

До начала полноценной реализации должны существовать четыре согласованных design-документа:

```text
docs/design/Laveyana.{Domain}.TechnicalSpecification.md
docs/design/Laveyana.{Domain}.TechnicalSpecification.ru.md

docs/design/Laveyana.{Domain}.Architecture.md
docs/design/Laveyana.{Domain}.Architecture.ru.md

docs/design/Laveyana.{Domain}.DecisionLog.md
docs/design/Laveyana.{Domain}.DecisionLog.ru.md

docs/design/Laveyana.{Domain}.Roadmap.md
docs/design/Laveyana.{Domain}.Roadmap.ru.md
```

Их роли:

- `TechnicalSpecification` — что библиотека обязана делать: scope, requirements, semantics, ограничения, acceptance criteria;
- `Architecture` — как библиотека устроена: assemblies/projects, dependency directions, components, boundaries, ownership и lifecycle;
- `DecisionLog` — почему выбраны конкретные архитектурные решения; фиксируются только реальные архитектурные развилки, а не каждая implementation detail;
- `Roadmap` — в каком порядке выполнять реализацию: phases, dependencies, acceptance criteria, tests/manual checks и remaining limitations.

До завершения этого design baseline полноценную implementation library не генерировать, кроме минимального repository/build skeleton, если он нужен для проверки структуры.

На pre-implementation architecture stage `README.md` и `README.ru.md` **не создаются**. До появления реального кода точкой входа являются design documents в `docs/design/`. Это исключает documentation drift и не позволяет описывать как существующий API то, что пока является только планом.

#### 21.2. Документация во время implementation

Design-документы не становятся архивом сразу после появления кода. Они поддерживаются как living architectural baseline.

Если реализация обнаруживает реальное противоречие или требует нового архитектурного решения:

```text
new technical fact
→ evaluate impact
→ update DecisionLog when a real architectural choice exists
→ update Architecture when boundaries/design changed
→ update TechnicalSpecification when requirements/contracts changed
→ update Roadmap when implementation order/dependencies changed
→ implement code
```

При этом не создавать новый DXX для безопасных implementation details, которые можно выбрать внутри уже утверждённого roadmap step.

#### 21.3. Документация после появления реального кода

После появления фактического public API и implementation user/developer documentation строится по реальному repository.

Обязательная root documentation:

```text
README.md
README.ru.md
```

При подготовке первого public release:

```text
CHANGELOG.md
CHANGELOG.ru.md
```

Дополнительные документы создаются только когда они действительно нужны для использования, сопровождения или изменения библиотеки.

Не создавать пустые documents/directories только ради стандартной структуры.

#### 21.4. Стандартная структура `docs/`

Рекомендуемая структура:

```text
docs/
├── design/
│   ├── Laveyana.{Domain}.TechnicalSpecification.md
│   ├── Laveyana.{Domain}.TechnicalSpecification.ru.md
│   ├── Laveyana.{Domain}.Architecture.md
│   ├── Laveyana.{Domain}.Architecture.ru.md
│   ├── Laveyana.{Domain}.DecisionLog.md
│   ├── Laveyana.{Domain}.DecisionLog.ru.md
│   ├── Laveyana.{Domain}.Roadmap.md
│   └── Laveyana.{Domain}.Roadmap.ru.md
│
├── guides/
│   └── consumer-oriented usage/configuration/integration guides
│
├── concepts/
│   └── detailed domain/conceptual models that are too large for README
│
├── development/
│   └── contributor/developer docs such as testing, build and release
│
├── migrations/
│   └── version/API/data migration guides when migrations actually exist
│
└── operations/
    └── deployment/runtime/recovery/diagnostics docs when the domain needs them
```

Only `design/` is expected as part of the pre-implementation architecture baseline. Other subdirectories are optional and appear only when the project has corresponding documentation.

#### 21.5. Назначение documentation categories

##### `docs/design/`

Для разработчиков самой библиотеки и архитектурного сопровождения. Отвечает на вопросы:

- что является обязательным requirement;
- где проходят architecture boundaries;
- почему приняты решения;
- что и в каком порядке реализовывать.

##### `docs/guides/`

Для consumer-facing задач:

- getting started;
- configuration;
- DI/integration;
- extension points;
- common usage scenarios.

Guide должен описывать реальный supported workflow, а не будущий план.

##### `docs/concepts/`

Для сложной предметной/архитектурной модели, которую нельзя кратко объяснить в README без перегрузки.

Примеры:

```text
Lifecycle model
Provider model
Identity model
Transaction model
State model
```

Не создавать отдельный concept document, если README/Architecture уже объясняют вопрос достаточно.

##### `docs/development/`

Для разработчиков, которые меняют сам repository:

```text
Testing.md / Testing.ru.md
BuildAndRelease.md / BuildAndRelease.ru.md
Contributing.md / Contributing.ru.md
```

Создавать только те документы, для которых реально существует полезный workflow.

##### `docs/migrations/`

Создаётся только при реальной migration между API/data/configuration generations.

Migration guide должен объяснять:

- от какой версии/generation выполняется переход;
- что изменилось;
- какие breaking changes есть;
- чем заменить старый API;
- нужно ли мигрировать persistent data/configuration;
- before/after examples, когда они полезны.

Не создавать пустые future migration guides заранее.

##### `docs/operations/`

Используется только когда библиотека имеет operational concerns, например:

- deployment;
- service lifecycle;
- backup/restore;
- recovery;
- diagnostics;
- production configuration;
- platform/service management.

Utility/library domain без operational surface не обязан иметь этот каталог.

#### 21.6. Root repository documentation

Root repository остаётся компактным:

```text
Laveyana.{Domain}/
├── src/
├── tests/
├── docs/
├── README.md             # после появления реальной implementation/public API
├── README.ru.md          # после появления реальной implementation/public API
├── CHANGELOG.md          # при подготовке первого public release
├── CHANGELOG.ru.md       # при подготовке первого public release
├── LICENSE               # перед public distribution после explicit license decision
├── Directory.Build.props
├── Directory.Packages.props
└── .editorconfig
```

Design documents не размещаются в root без специальной причины; стандартное место — `docs/design/`.

#### 21.7. Один authoritative source для каждого вида информации

Не копировать одинаковое подробное содержание между README, Architecture, TechnicalSpecification, concept guides и XML-doc. Иначе документы со временем расходятся.

Authoritative ownership:

| Информация | Основной источник |
|---|---|
| Externally observable requirements, semantics и invariants | `TechnicalSpecification` |
| Internal structure, dependency/ownership boundaries и architecture mechanisms | `Architecture` |
| Почему принято архитектурное решение | `DecisionLog` |
| Что реализовывать / что ещё осталось | `Roadmap` |
| Как быстро начать использовать библиотеку | `README` / `GettingStarted` |
| Точная семантика конкретного public type/member | C# XML documentation |
| Что фактически проверяется | Tests |
| Что изменилось между public releases | `CHANGELOG` |
| Как перейти между несовместимыми версиями | `docs/migrations/` |

Другие документы дают краткое объяснение и ссылку на authoritative source вместо копирования больших разделов.


#### 21.8. Правило полезности документации

Новый document/section создаётся только если он:

- помогает использовать библиотеку;
- объясняет существенную архитектурную/предметную модель;
- помогает безопасно изменить/расширить implementation;
- фиксирует реальную migration/operational procedure;
- является authoritative design/release record.

Не создавать:

- пустые placeholder docs;
- каталоги без документов;
- дубли README под другим именем;
- формальные guides без реального workflow;
- документы, механически пересказывающие XML-doc или source code.

#### 21.9. Language parity

Все человекочитаемые документы в `docs/` следуют общему language contract:

```text
*.md     → English
*.ru.md  → Russian
```

EN/RU pair создаётся и обновляется как единый documentation change. Исключения остаются только для language-neutral artifacts и legal/vendor texts, перечисленных в repository documentation contract. Original third-party license/NOTICE/copyright text не переводится и не переписывается автоматически.

---

### 22. Порядок архитектурной работы

Не начинай писать реализацию сразу.

Сначала:

1. изучи существующий repository/code/docs, если они приложены;
2. восстанови фактические обязанности текущего проекта;
3. сравни их с архитектурными, инженерными и предметными требованиями этого промпта;
4. найди смешение ответственности, дублирование и неправильные dependencies;
5. сформируй текущий архитектурный snapshot;
6. обсуждай только реальные оставшиеся архитектурные вопросы по одному;
7. фиксируй решения;
8. не возвращайся к уже закрытому вопросу без новой причины;
9. когда реальные противоречия закончились — останови архитектурный аудит;
10. подготовь итоговые `TechnicalSpecification`, `Architecture`, `DecisionLog` и `Roadmap` как согласованные English `.md` + Russian `.ru.md` пары внутри `docs/design/`;
11. только после этого переходи к реализации.

Не создавай новые DXX из каждой мелкой детали. Implementation details, которые можно безопасно решить во время соответствующего roadmap-step, не требуют отдельного архитектурного решения.

---

### 23. Формат спорного решения

Используй компактный формат:

```text
#### DXX. Название

Проблема

1. Вариант 1
2. Вариант 2
3. Вариант 3

Рекомендация

1 / 2 / 3?
```

Разбирай один существенный вопрос за раз.

---

### 24. Итог работы по каждой библиотеке

В конце архитектурного этапа должен существовать однозначный ответ на вопросы:

- зачем библиотека существует;
- что входит в её scope;
- что явно не входит в scope;
- какие assemblies существуют и зачем;
- какие public contracts являются стабильными;
- какие реализации поставляются стандартно;
- как работает DI;
- какой lifecycle у компонентов;
- кто владеет ресурсами и persistent data;
- как обеспечивается thread safety;
- как выполняются migrations/recovery;
- какие integration points существуют;
- какие dependencies разрешены/запрещены;
- как выполняется versioning/support;
- какие acceptance criteria подтверждают готовность.

После этого сформируй реалистичный Roadmap маленькими проверяемыми шагами.


---

## Часть II. Обязательные инженерные и API-правила

### 1. Общие принципы

- Предпочитай стандартные возможности .NET/ASP.NET Core/MAUI собственным abstractions, если платформа уже адекватно решает задачу.
- Делай поведение явным и предсказуемым; не скрывай важные lifecycle, ownership, retry, fallback или compatibility semantics.
- Public API минимален; новый type/member по умолчанию `internal`, если consumer не обязан его видеть.
- Не оптимизируй код по минимальному числу строк; оптимизируй по ясности, предсказуемости и сопровождаемости.

### 2. C# readability и formatting

- Один основной top-level type на файл по умолчанию; filename соответствует type.
- Используй понятные полные имена вместо неочевидных сокращений.
- Сложные signatures, invocations, initializers, boolean expressions, LINQ/fluent chains разбивай по смысловым строкам.
- Не используй clever one-liners, nested ternary и чрезмерно плотный LINQ, если многошаговый код понятнее.
- Независимые фазы метода визуально разделяй; guard clauses используй там, где они упрощают control flow.
- Не скрывай неправильную responsibility boundary через `region`, `partial` или искусственное file splitting.
- Жёсткого line-length limit нет; читаемость важнее количества символов.

#### File-scoped namespaces

Для first-party maintained `.cs` по умолчанию используй:

```csharp
namespace Laveyana.Example;
```

а не block-scoped namespace. Один source file по умолчанию принадлежит одному namespace. Block-scoped namespace допустим только при реальной технической причине. `.editorconfig` должен закреплять file-scoped namespace как стандартный стиль.

### 3. Naming semantics публичного API

```text
GetXxx         → объект ожидается существующим; absence не возвращается как обычный null
FindXxx        → absence является normal outcome и может быть выражена null/result
TryXxx         → ожидаемый отрицательный outcome выражен без exception для нормального failure path
CreateXxx      → создаёт новый объект/resource
GetOrCreateXxx → получает существующий или создаёт новый согласно documented atomicity/concurrency semantics
DeleteXxx      → уничтожает entity/resource согласно contract
RemoveXxx      → убирает связь/регистрацию/элемент и не обязано уничтожать underlying resource
```

Idempotency не выводится из имени и документируется отдельно.

### 4. Async и cancellation

- Реальный I/O, IPC, network/database work и отменяемое async ожидание используют `Async` API.
- Не создавай fake async для чистого CPU/in-memory кода без причины.
- `CancellationToken` — последний parameter там, где операция реально отменяема.
- `OperationCanceledException` не заворачивается в domain exception.
- Fire-and-forget допустим только при явном owner/lifecycle/error observation.
- Cancellation не обещает rollback уже committed durable effect; commit boundary должен быть документирован для важных операций.

### 5. Time, timeout и retry

- Domain logic, зависящая от текущего времени, использует `TimeProvider` вместо разрозненных static clock calls.
- Durable timestamps с UTC semantics нормализуются к UTC (`+00:00`) или эквивалентному явно определённому UTC representation.
- Caller cancellation и timeout — разные причины завершения; не маскируй их друг под друга без осознанного public contract.
- Retry разрешён только при определённой retry semantics; он bounded, cancellable/testable where applicable и не скрывает partial effects.
- Non-idempotent operation не retry'ится автоматически без idempotency/recovery/transaction mechanism, делающего повтор безопасным.
- Infinite retry loops запрещены.

### 6. Outcomes и exceptions

Expected negative outcomes (`not found`, `conflict`, `already exists`, expected transition rejection) выражаются `null`, status/enum или специализированным result type только когда semantics однозначна.

Operational/unexpected failures идут через exceptions. Programming errors используют стандартные .NET exceptions. Не использовать `catch (Exception) => false` или аналогичное поглощение неизвестной ошибки.

### 7. Nullable, warnings и suppressions

- Nullable reference types включены repository-wide.
- Public nullability является частью API contract/compatibility surface.
- Compiler/analyzer warning сначала исправляется по причине, а не механически скрывается.
- `!`, `#pragma warning disable`, `NoWarn`, `SuppressMessage` и analyzer suppression не используются routine-образом для clean build.
- Необходимая suppression максимально узкая и имеет понятную technical justification.
- Broad/global suppression, скрывающая реальные defects, запрещена.
- Clean build означает отсутствие известных first-party compiler/analyzer defects, а не их массовое подавление.

### 8. Resource и buffer ownership

Default:

```text
resource передан caller-ом в method
→ ownership остаётся у caller-а,
  если API явно не объявляет ownership transfer
```

Для `Stream`, `Memory<T>`, `IMemoryOwner<T>`, `IDisposable`, `IAsyncDisposable`, handles, connections, leases и аналогичных values документируй, когда применимо:

- кто владеет ресурсом;
- кто вызывает Dispose/DisposeAsync;
- удерживает ли callee reference после вызова;
- может ли buffer быть изменён;
- изменяется ли `Stream.Position`;
- можно ли переиспользовать resource;
- что происходит при exception/cancellation;
- является ли операция explicit ownership transfer.

Не dispose'ить caller-owned resource скрыто.

### 9. Thread safety и synchronization

- Shared/DI services проектируются thread-safe, если их lifetime предполагает конкурентное использование.
- Thread-safety важных public types документируется.
- Предпочитай narrow/per-resource synchronization глобальному lock.
- Не выполняй arbitrary callbacks/user code под internal lock без явно доказанной необходимости.

### 10. Collections, events и callbacks

- Не возвращай mutable internal collection напрямую.
- Public collection semantics (snapshot/live view/order/mutability) документируются.
- Events/callbacks используются только для реального observation/extension scenario; не создавай глобальный EventBus по умолчанию.
- Subscription ownership и unsubscribe/disposal semantics должны быть определены.

### 11. Validation

- Configuration/input validation выполняется до необратимых side effects, насколько это возможно.
- Не дублируй одинаковую validation logic в нескольких слоях без причины.
- Invalid configuration должна fail-fast до runtime work, если состояние можно проверить заранее.

### 12. Serialization и culture independence

Persistent/interchange formats имеют explicit canonical representation и не зависят от `CurrentCulture`/`CurrentUICulture`.

Не использовать как durable contract без отдельного решения:

- произвольный `ToString()`;
- culture-dependent parse/formatting;
- CLR/namespace/assembly-qualified names;
- случайные numeric enum values;
- declaration order.

Stable identifiers и format versions задаются явно. Runtime/domain type становится persistent schema только если это сознательный stable contract.

### 13. Logging, metrics и tracing

Используй стандартные .NET abstractions:

```text
ILogger<T>
System.Diagnostics.Metrics
ActivitySource
```

Concrete backend выбирает application. Secrets/sensitive payload не попадают в telemetry. Избегай high-cardinality identifiers в metric labels по умолчанию.

Фактическая Phase 25 добавляет `SecurityObservability` с фиксированными `SecurityOperation` и
`SecurityOperationOutcome`, `ILogger`, `ActivitySource`, `Meter` и необязательным
`ISecurityAuditSink`. Используй только ограниченные коды событий в логах и метриках;
identity и текст исключения не проходят через observability. Audit — best-effort,
не durable; обязательную доставку обеспечивает приложение. Реальная сборка и NUnit
пока не подтверждены.

### 14. Third-party dependency policy

Перед новой dependency сначала проверь стандартные возможности .NET/platform.

Существенную dependency оцени по:

- license/NOTICE/attribution requirements;
- maintenance status;
- security posture;
- target framework/platform support;
- trimming/AOT impact;
- reflection/dynamic code;
- transitive dependencies.

Не подключай тяжёлый package ради trivial helper. Не выпускай third-party implementation types в public API случайно; если внешний type есть в public signature, это намеренная часть integration/compatibility contract.

### 15. Reflection, trimming и AOT

Reflection, assembly scanning и runtime dynamic-code generation не являются default mechanism, если задачу можно выразить typed/static API. Assembly scanning не используется как скрытый standard discovery mechanism.

Для каждой runtime library на design/implementation уровне фиксируется:

```text
Trimming: Supported / Not guaranteed
AOT:      Supported / Not guaranteed
```

`Not applicable` допустим только для artifact, который не является runtime library/code и к которому соответствующая характеристика действительно неприменима.

Planned/required status фиксируется в `TechnicalSpecification`; после реализации фактически подтверждённый status отражается в README и, когда существует стандартная package/build metadata, в ней.

`Supported` подтверждается подходящим publish/build/test scenario. Dependencies с reflection/dynamic code оцениваются на влияние на trimming/AOT/target platforms.

### 16. Source-code documentation и comments

Вся first-party maintained C# documentation/comments — English-only, включая XML-doc, `//`, block comments, TODO/FIXME и explanations of lifecycle/security/concurrency/recovery.

Документируй все named types, constructors и methods, включая internal/private implementation code. Для каждого named method/constructor нужен понятный English XML-doc summary; private docs могут быть короче public contract docs.

Для public/security-sensitive API документируй по необходимости purpose, ownership, lifecycle, thread safety, idempotency, cancellation, negative outcomes, exceptions, nullability, concurrency, persisted effects, security behaviour, defaults и DI lifetime.

Inline comments объясняют **why/invariant/ordering/recovery boundary**, а не повторяют очевидный код.

### 17. Generated/vendor source

Эти style/XML-doc requirements обязательны для first-party maintained source.

Generated или vendored source может следовать собственному формату, если:

- он явно изолирован/помечен как generated/vendor code;
- не редактируется вручную как first-party source;
- его build/analyzer treatment не скрывает defects first-party кода;
- выполняются license/NOTICE requirements;
- при необходимости generation pipeline воспроизводим.

Не переписывай сторонний legal/header text ради соответствия Laveyana style.

### 18. Build/analyzer conventions

- Repository содержит `.editorconfig`.
- XML documentation generation включена для library projects.
- Missing public documentation warnings не подавляются без причины.
- Analyzers поддерживают nullability/API quality/readability; их не выключают глобально для удобства.
- Tests/samples следуют тому же basic readability style; source comments остаются English-only.

### 19. Obsolete и dangerous API

- Обычный устаревающий API получает `[Obsolete]`, понятную replacement/migration guidance и удаляется согласно compatibility-generation policy.
- Dangerous/destructive operation должна быть явно названа/документирована и не использоваться safe defaults.
- Небезопасный API может быть ограничен/удалён быстрее обычного deprecation lifecycle, если это оправдано риском.


---

## Часть III. Предметные требования Laveyana.Security

#### Контекст

Мы проектируем новую библиотеку/область `Laveyana.Security` для модульной .NET 10 экосистемы.

##### Фактический исходный репозиторий

- **Название исходного репозитория:** `CryptoKit`.
- **Указанный владельцем GitHub URL:** https://github.com/ivmu5/CryptoKit
- **Имя проектируемой библиотеки:** `Laveyana.Security`.
- **Статус:** `CryptoKit` — существующий исходный проект по сведениям владельца; доступность содержимого GitHub на момент подготовки комплекта независимо не подтверждена.

Это ссылка на **исходный репозиторий**, а не на опубликованный репозиторий новой библиотеки Laveyana. Не переименовывай удалённый репозиторий, не придумывай новый GitHub URL и не объявляй миграцию выполненной по одному лишь промпту. При реальной работе с кодом используй фактически полученный snapshot/доступное содержимое репозитория; если содержимое недоступно, не делай вид, что изучил его. Новое имя репозитория и стратегия переноса могут быть выбраны при выполнении миграции, но пока не являются существующим URL.

`CryptoKit` считай прототипом и источником кода/идей, а не обязательной архитектурой. Backward compatibility с текущим public API не требуется, если отдельно не будет принято обратное решение.

Архитектура экосистемы и инженерные правила уже включены выше; требования области `Laveyana.Security` усиливают их там, где этого требует безопасность.

---

### Уже принятые решения для Laveyana.Security

#### Scope

`Laveyana.Security` отвечает за:

```text
Cryptography
Keys
Secrets
```

В scope входят:

- безопасные high-level cryptographic operations;
- advanced low-level crypto API для специальных сценариев;
- key generation;
- key identity/metadata;
- key providers;
- key storage contracts;
- key lifecycle;
- rotation/retirement/delete semantics;
- secret-provider contracts;
- безопасное обращение с secret/key material;
- hashing/HMAC/signing/verification/encryption/decryption там, где это универсальные crypto primitives.

Не входят:

- authentication;
- authorization;
- JWT/business identity workflows;
- user management;
- database-specific encryption workflow;
- transport/network protocol security;
- domain-specific decisions о том, что именно нужно шифровать.

Domain-specific security workflow реализуется integration layer соответствующей области.

Пример:

```text
Laveyana.Security
→ предоставляет crypto/key capabilities

Laveyana.Persistence.Security
→ решает, какие данные Laveyana.Persistence шифровать
  и как использовать Laveyana.Security
```

---

### Структура

Базово рассматривай:

```text
Laveyana.Security/
├── src/
│   ├── Laveyana.Security.Abstractions/
│   ├── Laveyana.Security/
│   ├── Laveyana.Security.FileSystem/          # стандартный key storage candidate
│   └── Laveyana.Security.DependencyInjection/
│
├── tests/
│   ├── Laveyana.Security.Tests/
│   └── Laveyana.Security.IntegrationTests/
│
└── docs/
```

`Cryptography`, `Keys`, `Secrets` пока являются logical modules/namespaces одной основной `Laveyana.Security` assembly, а не отдельными `.csproj`.

Platform/integration implementations добавляются отдельно только при реальной границе:

```text
Laveyana.Security.Windows
Laveyana.Security.Android
Laveyana.Persistence.Security
...
```

---

### Laveyana.Security.Abstractions

Должен содержать только стабильные consumer contracts и реальные extension points.

Кандидаты:

- high-level key management contracts;
- `IKeyProviderBackend` как внешний provider/backend extension contract;
- `IKeyStore` как внешний contract software-managed storage (не provider API);
- key identifiers/descriptors;
- crypto contracts, если consumer должен работать через DI abstraction;
- secret-provider contracts;
- public result/status types;
- необходимые public exceptions.

Не выноси интерфейсы для внутренних serializer/locking/workflow classes без реального extension use case.

---

### Cryptography API

Уже решено:

> Safe high-level API по умолчанию + отдельный advanced API.

High-level consumer не должен вручную управлять nonce/tag/mode и другими параметрами там, где библиотека может выбрать и проверить безопасный стандартный вариант.

Advanced API может дать более низкоуровневый контроль сознательно.

Не изобретай собственные cryptographic algorithms. Используй современные стандартные primitives и реализации .NET, если нет обоснованной причины использовать проверенную внешнюю библиотеку.

---

### Key material

Уже решено:

> Secret key material по умолчанию opaque.

Обычный consumer работает с key handle/object/descriptor и не получает `byte[]` автоматически.

Сырой secret material доступен только через явный advanced/export API.

При проектировании учти:

- минимизацию copies;
- очистку временных mutable buffers, где это возможно;
- раздельную семантику public/private material;
- запрет утечки в logs/diagnostics/ToString;
- ownership/disposal чувствительного материала.

---

### Key storage

Должен существовать заменяемый storage contract, например `IKeyStore`.

Стандартная реализация хранения поставляется отдельной assembly, предположительно:

```text
Laveyana.Security.FileSystem
```

`Laveyana.Security.FileSystem` является **реализацией `IKeyStore`**, а не самостоятельным `IKeyProviderBackend`. Software provider backend находится в domain orchestration и использует заменяемый `IKeyStore`. OS/HSM/remote provider backends реализуют отдельный `IKeyProviderBackend` contract.

Оба external contracts (`IKeyStore`, `IKeyProviderBackend`) вместе с необходимыми типами расширения принадлежат `Laveyana.Security.Abstractions`. Реализации не должны ссылаться на concrete `Laveyana.Security` только ради этих contracts.

```text
Laveyana.Security (software provider backend)
    → IKeyStore
        → Laveyana.Security.FileSystem / consumer implementation

Laveyana.Security (provider orchestration)
    → IKeyProviderBackend
        → OS / HSM / remote implementation
```

`AddSecurityDefaults()` может включить standard software backend и FileSystem store **только при наличии явно выбранного/зарегистрированного безопасного `IKeyStoreProtector`**. Если protector отсутствует или не поддерживается, настройка/инициализация должна fail-fast; **plaintext/unsafe fallback запрещён**. Общая cross-platform DI assembly не должна скрыто выбирать platform protector.

Обычный `IKeyStore` не обязан резервировать AEAD nonce ranges. Детерминированная стратегия допустима только через отдельную optional rollback-protected monotonic-state capability. Для rollback-unprotected FileSystem AES-GCM default — randomized CSPRNG nonce; не выдавать FileSystem несуществующую rollback-protection guarantee.

Явная configuration/DI composition позволяет заменить storage/provider/protector по реальным declared capabilities.

---

### Контроль полноты предметной архитектуры

Для нового или изменённого design baseline аудируй `Laveyana.Security` как отдельную область. До архитектурных изменений изучи приложенный snapshot текущего `CryptoKit`, если он будет предоставлен.

Первоначальный архитектурный этап Generation 1 уже закрыт в design-документах. Используй следующий перечень как checklist при обоснованном пересмотре архитектуры или существенных изменениях реализации. Не открывай повторно закрытые вопросы без новых технических оснований.

Проверь как минимум следующие вопросы:

1. Полный список cryptographic capabilities первой версии.
2. Граница high-level vs advanced API.
3. Типы key handles/key descriptors и rules их lifetime.
4. Семантика `Create / Get / Find / GetOrCreate / Rotate / Retire / Delete`.
5. Concurrent `GetOrCreate` одного `(ProviderId, KeyName)` с atomic name claim и одной logical key generation.
6. Rotation model.
7. Retirement vs physical delete.
8. Key versioning/identity.
9. Key store contract.
10. Стандартная FileSystem implementation и её security model.
11. File permissions/ACL/Unix permissions.
12. Защита key material at rest и граница ответственности storage/provider.
13. Secret provider model.
14. Export/import secret material.
15. RSA public/private key representation.
16. Symmetric key representations.
17. Algorithms and safe defaults.
18. Serialization/persistent metadata formats.
19. Persistent format migrations/recovery.
20. Cancellation/thread safety/idempotency.
21. DI registrations and lifetimes.
22. Background key rotation — нужна ли вообще и кому принадлежит.
23. Logging/metrics/tracing без утечки секретов.
24. Tests: crypto vectors, concurrency, corruption, permissions, recovery, compatibility.
25. Что из текущего CryptoKit оставить, переделать, переместить или удалить.

Не создавай DXX для каждого пункта автоматически. Поднимай отдельное решение только там, где есть реальный архитектурный выбор.

---

### Проверяемые результаты архитектурного этапа

Архитектурный baseline уже оформлен следующими документами; при его корректировке поддерживай их согласованность:

```text
docs/design/Laveyana.Security.TechnicalSpecification.md
docs/design/Laveyana.Security.TechnicalSpecification.ru.md
docs/design/Laveyana.Security.Architecture.md
docs/design/Laveyana.Security.Architecture.ru.md
docs/design/Laveyana.Security.DecisionLog.md
docs/design/Laveyana.Security.DecisionLog.ru.md
docs/design/Laveyana.Security.Roadmap.md
docs/design/Laveyana.Security.Roadmap.ru.md
```

В Roadmap раздели работу на маленькие проверяемые шаги и для каждого укажи:

```text
Purpose
Changes
Dependencies
Acceptance criteria
Tests / manual checks
Remaining limitations
```

Полноценную реализацию разрешено вести после подтверждения завершённости архитектурного baseline; существование документов само по себе не является подтверждением качества реализации.


Итоговые EN/RU-документы должны описывать эквивалентные требования и находиться в `docs/design/`. На архитектурном этапе не создавать `README.md` / `README.ru.md`, `CHANGELOG` или placeholder `LICENSE`; их жизненный цикл определён выше в разделе документации. В `Roadmap` каждого этапа указывать `Purpose`, `Changes`, `Dependencies`, `Acceptance criteria`, `Tests / manual checks`, `Remaining limitations`.


---

## Часть IV. Протокол безопасной реализации

### 1. Сводка критических security invariants

1. `KeyName` — alias; `KeyId` — immutable logical generation; `KeyVersion` — never-reused identity **в пределах authoritative history**. Persisted `KeyReference = ProviderId + KeyId + KeyVersion`; `ProviderAlias` не сохраняется вместо `ProviderId`.
2. Forward-use logical capability разрешает актуальную `Active` версию **на каждую операцию**; exact-version capability не переключается после rotation. Managed payload/подпись/MAC фиксируют использованную exact historical reference.
3. `GetOrCreate` имеет store-level atomic name claim/create на `(ProviderId, KeyName)` для межпроцессной корректности. Локальный lock — оптимизация, не доказательство атомарности.
4. `Active`, `Retired`, `Deleted` и version `Pending` имеют явные transition rules. Обычный delete текущей Active-version невозможен. Staged activation атомарно/восстанавливаемо заменяет Active; discard удаляет Pending material, но не освобождает KeyVersion identity.
5. Secret/key bytes opaque по умолчанию. Export/import/temporary access — явные Advanced capabilities; minimum copies, owned-buffer zeroization, никакого сохранения sensitive material в telemetry/ToString.
6. Нет plaintext fallback. FileSystem с первого безопасного writable deployment требует выбранного `IKeyStoreProtector`, authenticated envelopes, проверенных permissions/owner/path/symlink guards; generic DI не угадывает platform protector.
7. Authenticated metadata **не доказывают rollback protection**. Default FileSystem rollback-unprotected. Crash recovery и old-snapshot restore различаются; known external rollback требует explicit reconciliation перед unsafe forward use.
8. AES-GCM: randomized CSPRNG nonces по умолчанию для rollback-unprotected store; deterministic допустим только при независимой rollback-protected monotonic reservation capability; provider-managed — при проверенной backend guarantee. Imported material с unknown nonce history не пускается в обычный managed forward Encrypt без безопасной стратегии.
9. Persistent schema/payload/envelope versions независимы от NuGet version; неизвестные будущие форматы reject/fail-closed. No silent algorithm downgrade, no custom HPKE/segmented AEAD protocol ради закрытия чек-листа.
10. `Seal/Open` через HPKE и encrypted streaming — отдельные security gates и могут остаться deferred; соответствующие API не объявлять supported до проверки.

Этот список — сводка критических требований для проверки регрессий. Детальные security-specific semantics определены предметными разделами этого промпта и design-документами.

### 2. Правило исполнения этапов

1. **До правок** проверь фактический snapshot/repository, завершённые этапы и возможный diff с design baseline. Если исходников нет — не изображай выполненную сборку/тесты.
2. Выбери первый незакрытый пункт `Roadmap`. Назови его цель, concrete файлы/подсистемы, ограничения и проверки. Не перескакивай через security-dependent step.
3. Реализуй только необходимый scope этапа: интерфейсы по реальным extension boundaries; default `internal`; readable .NET 10 C#, file-scoped namespaces, source XML-doc/comments на английском; никаких необоснованных dependencies или suppressions.
4. Выполни относящиеся unit/integration/negative/concurrency/security tests и build. Сообщи **фактически выполненные** команды, результат, непроверенные платформы и реальные blockers. Нельзя объявлять `passed`, не выполнив проверку.
5. Обнови живые design-документы при новых фактах. Новый DXX создавай только при существенной развилке. Если тест выявил нарушение security invariant — не продолжай следующую фазу, пока оно не устранено/не эскалировано как блокер.
6. Передай законченный артефакт: diff/список изменённых файлов либо полный архив по запросу; отдельно укажи завершённые проверки, ограничения и **следующий** Roadmap step. Не обещай фоновой или будущей работы.

### 3. Документирование и release

- Для `Laveyana.Security` действуют **обязательные четыре дизайн-документа в EN/RU парах** в `docs/design/`: их нельзя слить в один только ради уменьшения числа файлов. Не создавать два authoritative текста об одном и том же.
- README на EN/RU формируется после появления реального implementation/public API. CHANGELOG — при подготовке первого public release; LICENSE — после явного решения владельца перед public distribution. Никаких пустых placeholders.
- Версионирование **`X.YYMM.R`**, а не старое `X.YY.MM.DD`; `R` — stable release number внутри `(X, YYMM)`. Отдельные версии для persistence, payload и envelopes.
- Compatibility/API-diff, prerelease, migrations, documentation languages, build/CI, C# style и source XML docs регулируются разделами общих и инженерных норм **внутри этого промпта**.
- Конечный release gate: все обязательные acceptance criteria из TechnicalSpecification + полная audit Phase 27 из Roadmap; неподтверждённые HPKE/streaming features явно помечены unsupported/deferred.

### 4. Ограничения дальнейшего диалога

Не задавай повторно вопросы по закрытым DXX, не расширяй функциональность за пределы scope по инерции, не выдавай дизайн за написанный код. Если в ходе реализации выявлено новое доказуемое противоречие, сформулируй 2–3 варианта и последствия для safety/public API/recovery, предложи выбор, зафиксируй решение в соответствующих authoritative документах. Для безопасных implementation details внутри Roadmap выбирай решение самостоятельно, проверяй его тестами и двигайся дальше.

---

## Текущий статус реализации — Phase 14 (2026-10-09)

Добавлена отдельная сборка `Laveyana.Security.Windows` с `WindowsDpapiUserProtector` (DPAPI CurrentUser, без LocalMachine и plaintext fallback), форматом `LSWP` v1, binding reference/purpose/AAD и очисткой native plaintext. Это выбранная platform-specific реализация, а не универсальная политика для других ОС. D45 зафиксирован в DecisionLog. Приёмка открыта до реальной сборки .NET 10 и выполнения Windows NUnit; FileSystem Windows TOCTOU/production gate остаётся открытым, `EnableExperimentalWrites` — только для тестов. Следующий этап — Phase 14A, явная re-protection.


---

## Текущий статус реализации — Phase 14A (2026-10-09)

Добавлены явная миграция FileSystem snapshot/bootstrap (с закреплённым UUID и восстановлением после прерывания), `ProtectorGenerationRouter` (точная маршрутизация legacy-read и current-write,
явная блокировка compromised/unknown) и `SoftwareKeyReprotectionService` (CAS-атомарная
повторная защита всех неудалённых версий одного ключа с сохранением material, KeyId,
версий и политики). D46 зафиксирован в DecisionLog. Добавлены fault-injection и
concurrency NUnit-тесты; фактическая сборка .NET 10, запуск NUnit, Windows DPAPI и
production-проверка FileSystem не подтверждены. Следующий этап — Phase 15.

## Текущий статус реализации — Phase 15 (2026-10-09)

Добавлены immutable payload/result модели в `Laveyana.Security.Abstractions.Payloads`: `EncryptedPayload`, `DetachedEncryptedPayload`, `SignaturePayload`, `MacResult`, `ManagedPayloadCodec` и `EncryptedPayloadAssociatedData`. Канонические бинарные форматы v1 `LEP1`/`LDP1`/`LSP1`/`LMR1` используют exact `KeyReference`, лимиты и fail-closed parsing; для AEAD задан единый domain-separated AAD, привязывающий публичные метаданные и внешний application AAD без его сохранения в payload. Кодек и конструкторы сами ничего не аутентифицируют. Написаны golden-файлы и NUnit-тесты; сборка .NET 10 и запуск NUnit остаются непроверенными. D47 добавлено в DecisionLog. Phase 16 должен реализовать криптографическое шифрование, реальную проверку tag и exact-version selection; security/production gates предыдущих этапов не закрыты.


## Текущий статус реализации — Phase 16 (2026-10-09)

Добавлен исполняемый AES-256-GCM API в `SoftwareKeyProviderBackend` с optional provider-контрактом `IAuthenticatedEncryptionBackend`, маршрутизацией `ProviderRegistry.RouteAead`, `EncryptAsync`/`DecryptAsync`/`TryDecryptAsync` и detached-вариантами. Логический Encrypt проверяет действующую Active версию и материал в одной ревизии store; Decrypt использует exact KeyReference из payload (Active/Retired), без implicit rotation fallback. AAD аутентифицирует critical metadata; TryDecrypt возвращает null исключительно при неверном AEAD tag. Используется Phase 10 nonce policy, лимит сообщения 16 МиБ, внешний AAD — 64 КиБ. ChaCha20-Poly1305 execution deferred. Подготовлены NUnit-отрицательные, concurrency и ротационные тесты; .NET 10 build/NUnit фактически не подтверждены. D48 зафиксирован в DecisionLog. Security/production gates ранних этапов остаются открытыми, Phase 17 — MAC/signature API.

## Текущий статус реализации — Phase 17 (2026-10-09)

`SoftwareKeyProviderBackend` дополнен `IManagedMacBackend`, `ComputeMacAsync` и `VerifyMacAsync` с использованием HMAC-SHA-256/384/512, защищённого материала точной версии, проверки ревизии и фиксированного по содержимому времени сравнения полного тега. Создание MAC использует только Active; проверка допускает Active/Retired и независимо проверяет `VerifyMac`. Неверный MAC — false, отказ доступа или сбой инфраструктуры — исключение. `ProviderRegistry` маршрутизирует MAC и подписи по постоянному ProviderId.

Для асимметричных подписей добавлены `IManagedSignatureBackend`, `IVersionedSignatureKeyOperations` и `ManagedSignatureBackend`, который проверяет свежие metadata, возможности, kind и состояние перед ECDSA P-256 SHA-256 либо RSA-PSS SHA-256. Конкретный `EphemeralSignatureKeyOperations` исполняет обе схемы на .NET, но хранит ключи только в памяти процесса и не обеспечивает persistent storage/revocation; настоящая авторизация должна повторяться в доверенном executor на момент операции. Не внедрять приватные асимметричные ключи в существующий симметричный формат без отдельного проекта и аудита.

Подготовлены NUnit-тесты HMAC, ротации, отказов, ECDSA/RSA-PSS и маршрутизации. Сборка и NUnit в .NET 10 фактически **не подтверждены**. Production security gate Phase 13/14 и rollback protection также остаются открытыми. Следующий этап Roadmap — Phase 18 (key agreement / derivation). Решение D49 сохранено в DecisionLog.

## Текущий статус реализации — Phase 18 (2026-10-09)

Добавлены P-256 ECDH c обязательным HKDF-SHA-256 (`ManagedKeyAgreementBackend`, `EphemeralEcdhKeyOperations`, `IVersionedKeyAgreementOperations`), симметричная derivation через защищённый `HkdfSha256` ключ (`IManagedDerivationBackend`), канонический контекст v1 с domain separation, `DerivedKeyLease` (zeroization, callback access), явная политика экспорта, typed extensions и маршрутизация `ProviderRegistry`. ECDH peer authentication и durable/private key provider отсутствуют, raw shared secret не возвращается. Добавлен независимо рассчитанный контрольный вектор и NUnit-тесты; **.NET SDK не установлен, сборка и NUnit не подтверждены**. Открыты производственные security gates (FileSystem rollback, Windows TOCTOU, защита ключей). Следующий этап — Phase 19 (SealedPayload, только после отдельного security review).


## Текущий статус — Phase 19 HPKE Gate (2026-10-09)

Phase 19 является необязательным для Generation 1 release, но требует dedicated security gate **до** появления публичного `Seal/Open/SealedPayload`. Для него создан подробный отчёт `docs/design/Laveyana.Security.HpkeGate.ru.md` с exact RFC 9180 suite, доверительными границами, версиями, правилами AAD/info, угрозами MITM/replay, лимитами и criteria to unblock. Официальный эталон RFC 9180 Appendix A.3.1 Base P-256/HKDF-SHA256/AES-128-GCM находится в `tests/hpke-gate/rfc9180-a3-base.json`. Независимый `tools/hpke_gate_verify.py` на Python `cryptography` сверил все промежуточные значения, 6 ciphertext и 14 негативных проверок. Это **НЕ** доказывает .NET реализацию.

Публичные HPKE API не созданы; флаг поддержки отсутствует. Gate **OPEN**, Phase 19 помечена `deferred/unsupported`, на Phase 20 допускается переход без этой опции. Для включения HPKE нужны одобренная поддерживаемая .NET-реализация, authoritative vectors exact production suite, .NET/NUnit и межпровайдерное interoperability, полноценная проверка ключевой политики и исполнения, wire/info/AAD/identity, focused security review, закрытие других production blockers. **Не использовать Phase 18 ECDH HKDF как реализацию HPKE RFC 9180.** Решение D51.

## Отметка реализации Phase 20 (2026-10-09)

Потоковые SHA/HMAC добавлены с ограниченным буфером и проверкой ожидаемой длины/ревизии ключа. `IStreamingMacBackend` необязателен для внешних провайдеров; маршрутизация только по ProviderId. Сегментированное AEAD не реализовано и остаётся DEFERRED до отдельного security gate; не подменять его произвольным шифрованием независимых чанков. .NET 10 сборка/NUnit ещё не подтверждены. Источник деталей — `docs/design/Laveyana.Security.StreamingGate.ru.md` и D52.


## Отметка реализации Phase 21 (2026-10-09)

Подготовлен минимальный read-oriented `ISecretProvider` с `FindAsync`/`GetAsync` в Abstractions; scoped `SecretHandle`, owned `SecretReadResult` с zeroization при Dispose, отдельный `SecretProviderRegistry` (exact ProviderId, no fallback) и необязательный `ISecretManagementProvider`. Нет универсальной SecretVersion, автоматических сохранений или встроенного persistent provider. `CanOpenMaterial` и `CanExportMaterial` — независимые metadata-флаги, по умолчанию false, не заменяют авторизацию backend. Безопасность подтверждалась только статическими проверками; сборка и NUnit не выполнялись. Решение D53.


## Отметка реализации Phase 22 (2026-10-09)

Создан явно конфигурируемый DI composition-layer: `AddSecurity`,
`AddSecurityDefaults`, `SecurityCompositionBuilder`, `SecurityCompositionSnapshot`,
регистрация key/secret provider, store, protector и nonce allocator, проверка
дубликатов и singleton lifetime, отдельная host-startup validation динамических
capabilities. Не создаются hidden service workers, platform guessing и plaintext
fallback. `FileSystemKeyStore.OpenAsync` выполняется вызывающим приложением до
регистрации. Добавлены интеграционные NUnit-тесты и решение D54. Сборка .NET 10,
запуск NUnit и production security gate пока не подтверждены.


## Отметка реализации Phase 23 (2026-10-09)

Реализованы явная `RotationPolicy`/`RotationAssignment` с trusted UTC activation
anchor, `RotationEngine` с общим ручным и плановым путём, conditional backend
`IConditionalKeyRotationBackend` с expected Active version CAS, и opt-in
`AddSecurityRotationWorker` с требованием application-owned durable one-shot claim
`IRotationWorkSource`. Worker не запускается по умолчанию; нет blind retry при
uncertain commit. Приложение отвечает за расписание, авторизацию и reconciliation.
Добавлены тесты fake time, CAS-конкуренции и host shutdown. D55. Сборка .NET 10,
выполнение NUnit, межпроцессный и platform security gates пока не подтверждены.

## Отметка реализации Phase 24 (2026-10-09)

Подготовлены пошаговые migration primitives: новые ProviderId/KeyId, отдельные опциональные интерфейсы native transfer, regeneration-only software adapter, проверка точных версий/capabilities, неизменяемые checkpoint и явное подтверждение переключения ссылок приложением. Исходные ссылки не перенаправляются; удаление/retirement требует отдельной provider-side защиты. D56. Журнал и actual data/reference migration принадлежат приложению. Реальные сборка .NET 10/NUnit, native transfer и production platform security gate остаются неподтверждёнными.
