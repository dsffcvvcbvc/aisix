# CP-патч: combos-экран работает через gateway Admin API (spec для AISIX-Cloud)

> Статус: PROPOSAL, не применён. Репозитория AISIX-Cloud рядом нет
> (проверено 2026-09-27: `/home/ernur/AISIX-Cloud` отсутствует,
> `openapi/cp-admin.yaml` в дереве `aisix/` не найден) — ниже точный
> spec-патч, который нужно внести на стороне control plane.
> Основа — реализованная поверхность `aisix-admin::combos_handler`
> (`crates/aisix-admin/src/combos_handler.rs`), маршруты
> `crates/aisix-admin/src/lib.rs`, OpenAPI
> `crates/aisix-admin/src/openapi.rs` (`Combo`, `ComboModel`, `ComboEntry`).

## 1. Что уже умеет DP (и почему это не новый ресурс)

**Combo — это virtual routing model, а не отдельный ресурс.** Запись
комбо пишется в коллекцию `models`; её `routing`-блок несёт
`strategy` + `targets`. Поэтому:

- новый ресурс в `cp-admin.yaml` **не нужен** и не должен появляться:
  добавление `Combo` как шестого `kind` в `Model` продублировало бы
  уже существующий `routing` и заставило бы пересматривать все
  model-keyed механизмы ради второй записи одного и того же;
- **все поля, которые эта поверхность принимает, уже есть в спеке**:
  `display_name` (управляемое нами `name`), `routing.strategy`,
  `routing.targets[].model` / `.weight` / `.priority` / `.tags`. То есть
  четверка слоёв CP из правила «config knob не зашит, пока его не
  отдаёт control plane» сводится здесь к чеклисту, который уже выполнен
  для `Model`: спека, Go-модель, etcd-проекция и форма уже есть.

Что реально нужно от CP — перестать быть источником истины для combos
и начать быть клиентом gateway Admin API.

## 2. Точный spec-патч для `openapi/cp-admin.yaml`

**Изменений схемы не требуется.** Ни одно поле, принимаемое
`POST /admin/v1/combos`, не является для спеки новым, и ни одно не
переименовывается. Существующие ограничения спеки, которые поверхность
унаследовала, закрывают две дыры, о которых стоит знать явно:

1. `Model.routing` и прямые upstream-поля — взаимоисключающие
   (`oneOf`). Комбо пишет `display_name` + `routing` и **не** пишет
   `provider` / `model_name` / `provider_key_id`. Форма CP обязана
   скрывать прямые поля у модели с `kind: routing`, иначе CP сохранит
   документ, который DP-loader отвергнет как невалидный.
2. `routing.targets[].model` — **имя**, не id. В режиме standalone
   (resources-файл) id резолвить нечем: DP отвергает `model_id` в
   файле ресурсов явным сообщением. Это ровно зарегистрированная ось
   расхождения «reference style: names here vs UUIDs in the CP» — она
   уже есть в `openapi/cross-plane-allowlist.yaml`, новой записи не
   требует.

## 3. Go-модель / валидация / проекция — чеклист

1. **Схема + биндинги:** без изменений (см. §2). Регенерация Go-биндингов
   из `cp-admin.yaml` не требуется.
2. **Go-модель** (`internal/cpapi/resources/`): без изменений. Комбо —
   это `Model` с `Kind == "routing"`. Новый тип `Combo` на Go-стороне
   вводить не надо: он стал бы вторым представлением `Model` и
   рассинхронизировался бы с ним на первом же переименовании.
3. **Валидация запроса:** добавить в существующий путь сохранения
   `Model` правило «у `kind: routing` непринимаемы `provider`,
   `model_name`, `provider_key_id`» — то, что `oneOf` спеки уже
   выражает, но которое суррогатная модель CP могла обходить.
4. **etcd-проекция:** без изменений. Проекция `Model` уже пишет
   `routing`/`targets`; пере-проекция коллекции не нужна (нет reshape,
   нет нового optional-ключа — ср. `ReprojectMcpAclOnce`, который здесь
   не применим).
5. **Тесты:** CP↔DP Go-интеграция в `e2e/cases/`:
   - комбо, сохранённое **через gateway Admin API** (`POST
     /admin/v1/combos`), читается DP и обслуживается: запрос с
     `model: <combo name>` уходит на один из `models` в `targets`;
   - комбо, сохранённое **через CP** с запрещённым полем, отвергается
     CP до записи в etcd (а не падает на DP-loader);
   - документ с `targets[].model_id` отвергается DP в standalone-режиме
     с внятным сообщением (регрессия подтверждает §2.2).

## 4. Dashboard — чеклист

Главное изменение: combos-экран перестаёт читать/писать собственную
коллекцию и ходит в gateway Admin API.

- **Слой доступа:** заменить вызовы собственного combos-хранилища на
  `GET/POST /admin/v1/combos` и `GET/PATCH/DELETE
  /admin/v1/combos/{id}`. Ответ `ComboEntry` уже содержит `id`, нужный
  для адресного PATCH/DELETE; `PATCH` принимает тело, отличное от
  `id`, так что ответ `GET` можно редактировать и отправлять обратно
  без преобразования.
- **Форма:** поля только `name`, `strategy`, `models[]` (внутри —
  `model`, `weight`, `priority`, `tags`).
  - `strategy` — выпадающий список ровно из шести значений
    (`round_robin`, `consistent_hash`, `failover`, `least_cost`,
    `least_latency`, `least_busy`). Список получать из
    `schemas/resources/routing.schema.json` (definitions
    `RoutingStrategy`), а не дублировать в коде.
  - `models[]` — выбор из существующих **прямых** моделей. Combo-ref
    (вложенные группы) и provider-wildcard в UI не предлагать: DP их
    отвергает, а вложенная группа без guard на циклы — не то, что
    стоит показывать как рабочую опцию.
- **Чего форма НЕ должна отправлять** (DP отвергнет каждое из этих
  полей с 400, называя его): `description`, `displayName`, `config`,
  `allowedProviders`, `allowedModelFamilies`, `system_message`,
  `tool_filter_regex`, `context_cache_protection`, `context_length`,
  `dimensions`, `isActive`, `isHidden`; на уровне шага — `label`,
  `connectionId`, `allowedConnectionIds`, `prompt`,
  `fallbackOnlyOnQuotaExhaustion`, `kind`, `model_id`. Любой из них,
  который сегодня форма умеет рисовать, должен быть убран из combo-режима
  (в режиме редактирования прямой модели он остаётся).
- **i18n:** `messages/en.json` + `messages/zh.json` (обе — правило CP) —
  подписи целевого списка, подсказки стратегий и текст ошибки о поле вне
  контракта.
- **Playwright-тест:** создать комбо → combo-экран показывает его →
  перетащить/переставить цель → сохранить → перезагрузить → порядок и
  веса на месте; ввести поле вне контракта в combo-режиме → форма не
  даёт отправить (или показывает ошибку 400 с именем поля), а не
  «успешно сохраняет и молча теряет».

## 5. Что осталось за CP-стороной (осознанный долг)

Каждое отвергнутое поле — это не баг DP, а отсутствующая функциональность
в routing-модели. Список на будущее, с владельцем на CP-стороне:

| Поле | Что для этого нужно в DP | Заметка |
| --- | --- | --- |
| `config.*` (44+ ключа) | поштучно сопоставить с полями `routing`/`model` либо описать в `cp-admin.yaml` | `maxRetries` и `retries` семантически **не** одно и то же; мапить «похожее» нельзя |
| 13 стратегий из 19 etalon | реализовать алгоритм либо сузить UI | `priority` ≈ `failover` + tier, `weighted` ≈ `round_robin`; остальные (auto, lkgp, fusion, pipeline, headroom, reset-aware, …) — отдельная работа |
| combo-ref / provider-wildcard | guard на циклы + резолв wildcard-шаблонов | вложенность сегодня отвергается осознанно |
| `system_message`, `tool_filter_regex` | поля на `Model` | в `cp-admin.yaml` их нет, значит нет и в etcd |
| `isActive` / `isHidden` | `enabled` на строке `Model` | сегодня у `Model` нет собственного `enabled` |
| `context_length`, `dimensions`, `context_cache_protection` | поля на `Model` | то же |

Каждая строка — отдельная задача DP + парная задача CP. Добавлять поле
«просто чтобы форма могла его нарисовать» нельзя: принятое и
непрочитанное поле читается на консоли как «настроено» и не делает
ничего.

## 6. Contract-check

- Расхождений не добавляет: ни одно поле не переименовано, не удалено и
  не перетипизировано; `Combo` не появляется в спеке как ресурс.
- Если `contract-check.yml` покажет расхождение по путям Admin API —
  это будет расхождение пятой оси («поверхность управления»), её надо
  внести в `openapi/cross-plane-allowlist.yaml` с этой же ссылкой на
  документ; четыре зарегистрированные оси (reference style, tenancy
  scoping, credential custody, CP-derived fields) не затрагиваются.
