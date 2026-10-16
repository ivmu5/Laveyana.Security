# Phase 19 — HPKE security gate (RU)

**Статус: DEFERRED / UNSUPPORTED.** Отчёт фиксирует подготовительные решения, а не разрешение выпускать криптографическое API. `Seal`, `Open`, `SealedPayload`, реестр HPKE-capabilities и новый бинарный формат **не добавляются** до прохождения всех критериев приёмки.

## 1. Нормативная основа и кандидат

- RFC 9180 (включая опубликованные verified errata), прежде всего §§ 4–7, 8–9 и Appendix A.
- Исходный **эталон проверки совместимости**: `mode_base=0x00`, `DHKEM(P-256, HKDF-SHA256)=0x0010`, `HKDF-SHA256=0x0001`, `AES-128-GCM=0x0001`. Это точный набор RFC 9180 Appendix A.3.1, а **не переключение существующего AES-256-GCM API на AES-128**.
- Для будущего API остаётся кандидатом `DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM (0x0002)`, однако требуется отдельный официальный набор векторов для этой exact suite. Перенос результата A.3.1 на другой AEAD не является доказательством совместимости.
- До приёмки реализации API не объявляет поддерживаемую suite и не добавляет скрытый fallback.

## 2. Принципиальные границы протокола

1. Только **RFC 9180 single-shot Base mode** как первый кандидат. Не подменять стандартный `LabeledExtract` / `LabeledExpand` собственным контекстом `DerivationContext` Phase 18 и не составлять самодельный `ECDH + HKDF + AES-GCM`.
2. Каждый вызов Seal должен использовать новую непредсказуемую ephemeral-пару; `enc` — канонический 65-байтовый uncompressed P-256 public key. В single-shot Base mode nonce рассчитывается библиотекой по RFC; внешний nonce и повтор контекста запрещены.
3. Контракт ключа должен фиксировать **точный** `ProviderId + KeyId + KeyVersion`; Open запрещено перенаправлять на новую версию при ротации. Исполнитель операции обязан повторно проверить статус и права доступа приватного ключа, включая отзыв.
4. `info` — отдельное версионированное domain separation приложения/протокола. AAD должен аутентифицировать существенные поля будущего wire-header, точную версию ключа, suite/mode и **внешний** application AAD. Изменение получателя, suite, info или AAD должно завершаться отказом, без plaintext и fallback.
5. Парсер будущего envelope должен быть ограниченным и строгим: неизвестный формат, mode, KEM/KDF/AEAD, encoding, extra bytes, неверная точка EC, неправильная длина `enc`/ciphertext, несоответствие размера и состояния — отказ.
6. Кандидат ограничений: plaintext **не более 16 МиБ**, external AAD **не более 64 КиБ**, `info` **не более 4 КиБ**; верхние пределы входного конверта и конкретное wire-layout нужно отдельно зафиксировать до реализации. Приватный ключ и промежуточные секреты не сериализуются и не возвращаются наружу.
7. `mode_base` **не аутентифицирует отправителя** и не даёт защиты от replay. Доверие к public key получателя и проверка идентичности лежат на внешнем протоколе; нельзя считать Base mode подписанным сообщением.
8. Любой отказ проверки тега должен уничтожать частичный plaintext; ошибки доступа, провайдера, формата и ключевой политики не маскируются под «неверный tag». Межпроцессное хранение приватных асимметричных ключей и отзыв пока не реализованы.

## 3. Подготовленные доказательства

- `tests/hpke-gate/rfc9180-a3-base.json` содержит опубликованный **тестовый** вектор RFC 9180 Appendix A.3.1 с тестовыми приватными ключами (только fixtures, никогда production).
- `tools/hpke_gate_verify.py` выполняет автономную проверку с `cryptography`: P-256 ECDH обеими сторонами, RFC-labeled HKDF, shared secret, key schedule, key/base nonce/exporter secret, AEAD ciphertext на sequence 0/1/2/4/255/256, 14 проверок отказа при подмене.
- На доступной Python `cryptography 46.0.4` скрипт прошёл. Это проверка **эталона**, не код C# и не функциональная реализация библиотеки.
- Репозиторий не получил новых публичных `Seal` / `Open` контрактов: нельзя случайно начать использовать незавершённую функцию.

### Запуск reference-only проверки

```bash
python tools/hpke_gate_verify.py
```

Требуется внешняя Python-библиотека `cryptography`, которая **не добавляется** как production dependency NuGet. Проверка не выполняется автоматически внутри .NET/NUnit и не должна считаться частью успешной .NET-приёмки.

## 4. Незакрытые обязательные критерии

| Gate | Состояние |
|---|---|
| Exact candidate для независимой проверки и официальный базовый вектор | Готово (A.3.1) |
| Сверка эталона на криптографическом движке, negative cases | PASS — только Python reference |
| Выбор доверенной, поддерживаемой .NET HPKE implementation strategy | **OPEN** |
| .NET 10 build + NUnit suite vectors, Seal/Open, tamper, policy, key-version and revocation tests | **OPEN** |
| Проверка пересечения wire format / `info` / AAD / trust и replay model | **OPEN** |
| Interop с независимым RFC 9180 провайдером, exact production suite vectors | **OPEN** |
| Focused security review (включая key custody/zeroization/error semantics) | **OPEN** |
| Устранение существующих production blockers FileSystem / platform protection | **OPEN** |

**Решение:** Phase 19 остаётся `deferred`. Phase 20 может продолжаться без `Seal`/`Open`, так как Roadmap объявляет HPKE release-optional. При возвращении к этапу сначала закрыть перечисленные gate, затем создавать новые публичные типы и wire-форматы. Не выдавать проверку Python за .NET interop или внешний security audit.

**Источники:** https://www.rfc-editor.org/rfc/rfc9180.html ; https://www.rfc-editor.org/errata/rfc9180 (проверка изменений в errata перед выпуском обязательна).
