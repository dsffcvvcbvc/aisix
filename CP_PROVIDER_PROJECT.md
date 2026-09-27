# CP-патч: поле `project` в `provider_key` (spec для AISIX-Cloud)

> Статус: PROPOSAL, не применён. Репозитория AISIX-Cloud рядом нет
> (проверено 2026-09-26: `/home/ernur/AISIX-Cloud` отсутствует,
> `openapi/cp-admin.yaml` в дереве `aisix/` не найден) — ниже точный
> spec-патч, который нужно внести на стороне control plane.
> Основа — уже реализованное поле `ProviderKey.project` в Rust:
> `crates/aisix-core/src/models/provider_key.rs:53-61`,
> `resolve_project` в `crates/aisix-provider-vertex/src/antigravity.rs:839-847`,
> сгенерированная схема `schemas/resources/provider_key.schema.json`
> (секция `project`, `required: ["display_name"]`).

## 1. Контракт поля (что уже умеет DP)

- Тип: `Option<String>`, serde `default`, `skip_serializing_if = "None"`.
- Документ без ключа грузится как `None` (тест
  `project_defaults_to_none_for_legacy_documents`,
  `provider_key.rs:649-656`); round-trip при установленном значении —
  `project_round_trips_when_set` (`provider_key.rs:659-667`).
- Резолюция: `ProviderKey.project` (trimmed; пустая/пробельная строка =
  absent) побеждает; иначе best-effort `loadCodeAssist`-discovery,
  мемоизированный по access token (`discover_project`,
  `antigravity.rs:1052`; `resolve_project_owned`, `antigravity.rs:1113-1126`);
  иначе fail-open fallback `ANTIGRAVITY_DEFAULT_PROJECT =
  "aicode-consumers"` (`antigravity.rs:52-57`). Синхронный срез —
  `resolve_project` (`antigravity.rs:983-989`). Тест:
  `project_prefers_provider_key_over_default` (`antigravity.rs:1905`).
- Строгая схема: поле прямо выводится из структуры через schemars
  (`provider_key_root_schema`, `models/schema.rs:1206-1245`); в `required`
  только `display_name`. Ленient-схема (etcd-загрузчик) принимает его же.
- Поле потребляет ТОЛЬКО Antigravity-мост (Google Cloud Code `project`
  в envelope). Остальные мосты его игнорируют.

## 2. Точный spec-патч для `openapi/cp-admin.yaml`

В схеме `ProviderKey` (рядом с `api_base`) добавить:

```yaml
project:
  type: string
  nullable: true
  minLength: 1
  maxLength: 256
  example: "my-cloud-project"
  description: >-
    Optional upstream project id dispatched with the request
    (Google Cloud Code `project` envelope field for the Antigravity
    bridge). Omit the key to use the data plane's shared default.
    An empty or whitespace-only value is treated as absent.
```

Правила:

- `required` НЕ расширять (поле optional; DP держит `required`
  только на `display_name` — сверено со сгенерированной схемой).
- `pattern` НЕ вводить: DP делает только `trim`, GCP-формат проекта
  на этом слое не валидируется (валидация пути есть лишь у Vertex
  `validate_url_token`, Antigravity envelope её не требует).
- `additionalProperties: false` закрытого валидатора CP — именно то,
  что сегодня отрезает поле: без этого патча CP отвергнет документ
  до записи в etcd (DP-половина уже готова, CP-половина — этот файл).

Если spec в репозитории OpenAPI 3.1: `nullable: true` заменить на
`type: ["string", "null"]` — семантика та же (ключ может отсутствовать
или быть `null`; сериализация DP ключ опускает).

## 3. Go-модель / валидация / проекция — чеклист

Четыре слоя CP (по правилу «конфиг-кноб не зашит, пока его не отдаёт
control plane», `AGENTS.md` в `aisix/`):

1. **Схема + биндинги:** патч §2 выше + регенерация Go-биндингов
   из `cp-admin.yaml`.
2. **Go-модель** (`internal/cpapi/resources/`):
   ```go
   // Ø — omitempty: неписаное поле не едет в etcd вообще.
   Project *string `json:"project,omitempty"`
   ```
   Указатель, не plain string: различие «не задано» vs «пусто»
   обязано дожить до проекции (пустое DP всё равно trim'ит в absent,
   но CP не должен подменять отсутствие пустой строкой в чужой
   логике). Валидация запроса: absent OK; present — после trim
   непусто, длина ≤ 256.
3. **etcd-проекция:** писать ключ `project` только когда set
   (omitempty-конвенция: «projects only operator-set fields»);
   документ без ключа обязан грузиться на всех DP от support floor
   (`dpfloor.Version`) — он и грузится: поле аддитивно-опциональное,
   serde `default`, lenient-схема открыта. Отдельной репроекции
   коллекции НЕ требуется (ср. `ReprojectMcpAclOnce` — тот паттерн
   для reshape; здесь reshape нет, только новый optional ключ).
4. **Тесты:** CP↔DP Go-интеграция в `e2e/cases/` — документ с
   `project` сохраняется через CP, читается DP, envelope уносит
   значение; документ без `project` — старый DP floor его грузит
   (lenient), новый DP подставляет `aicode-consumers`.

## 4. Dashboard — чеклист

- Поле ввода на форме provider-key (рядом с `api_base`):
  label `Project (Antigravity)`, placeholder `aicode-consumers`,
  hint «Leave empty to use the gateway default».
- Только для ключей Antigravity-провайдеров показывать/подсвечивать
  (поле игнорируется остальными мостами — см. §1); скрытие —
  UX-решение, не валидация (CP принимает поле для любого ключа,
  как и DP).
- i18n: `messages/en.json` + `messages/zh.json` (обе — правило CP).
- Playwright-тест: set → save → reload → значение на месте;
  clear → save → ключ в etcd отсутствует (omitempty).

## 5. Contract-check

- После мержа CP-спека расхождение `project` должно исчезнуть из
  отчёта `contract-check.yml`; если оно было внесено в
  `openapi/cross-plane-allowlist.yaml` как известное — удалить запись
  оттуда (allowlist — для намеренных расхождений из четырёх
  зарегистрированных осей; `project` к ним не относится).
