# Qoder `pt-*` PAT на шлюзе: почему громкая ошибка вместо сайлента

> Статус: ограничение реализации, не баг. Проверено по коду 2026-09-26.
> Связанный мост: `crates/aisix-provider-openai/src/qoder.rs`.

## Что происходит

Если `provider_key.api_key` начинается с `pt-`, любой вызов через мост
`qoder` (и `chat`, и `chat_stream`) немедленно завершается ошибкой,
до какого-либо сетевого вызова:

```text
BridgeError::InvalidUpstreamConfig(
  "qoder PAT (pt-…) credentials require the local qodercli binary, "
  "which the gateway does not ship; use an OAuth or DashScope key instead"
)
```

Код: `crates/aisix-provider-openai/src/qoder.rs:166-184`
(`api_key()` — проверка `k.starts_with("pt-")` на строке 173).

## Почему `pt-*` требует локальный `qodercli`

В OmniRoute TS-стороне PAT идут отдельным путём —
`executeViaQoderCli` (`omniroute/open-sse/executors/qoder.ts:231-249,
335-357`): токен определяется как PAT (`token.startsWith("pt-")`,
строка 237), и запрос исполняется через локальный бинарник `qodercli`,
который внутри себя выполняет WASM-подписанную Cosy-авторизацию.
Чистая HTTP-реализация Cosy мертва (комментарий в коде: «the only path
that works for PATs now that the pure-HTTP Cosy reimplementation
is dead», `qoder.ts:335-337`), HTTP-эквивалента у этого пути нет.

У Rust-шлюза sidecar-бинарника нет и быть не должно (один нативный
бинарь без внешних рантаймов — архитектурный закон §1.2 в `AGENT.md`),
поэтому повторить этот путь нечем. Сознательное расхождение
зафиксировано в шапке моста (`qoder.rs:24-28`).

## Почему не сайлент

Молчаливая альтернатива — отправить `pt-*` как `Bearer` на
DashScope (`https://dashscope.aliyuncs.com/compatible-mode/v1`,
`QODER_DEFAULT_BASE`, `qoder.rs:58`) — дала бы чужой opaque 401
или, хуже, запрос, выставленный не тому биллингу, без единой
подсказки оператору. Громкий `InvalidUpstreamConfig` вместо этого:

- указывает точную причину и готовое действие (OAuth или DashScope-ключ);
- срабатывает до сети, в обоих путях (`chat` — `qoder.rs:500`,
  `chat_stream` — `qoder.rs:550`);
- не маскируется под ретраибельный upstream-статус и не роняет
  соседние ключи в cooldown по чужой вине.

## Что делать оператору (на шлюзе `pt-*` не заводится никак)

1. **OAuth-путь:** положите в `provider_key.api_key` OAuth
   `refresh_token`; задайте все три env —
   `QODER_OAUTH_CLIENT_ID`, `QODER_OAUTH_CLIENT_SECRET`,
   `QODER_OAUTH_TOKEN_URL` (все три обязательны, встроенного
   дефолта нет; `qoder.rs:280-291`). Рефреш — реактивный, один раз
   на 401 (`refresh_on_401`, `qoder.rs:298-326`).
2. **DashScope-путь:** положите в `provider_key.api_key` обычный
   DashScope API-ключ (не `pt-*`). Уйдёт как `Bearer` с
   `x-dashscope-authtype: qwen-oauth` (`qoder.rs:111-141`).
3. **Нужен именно PAT:** ведите этот трафик через TS-сторону
   OmniRoute (там `qodercli` есть), а не через шлюз.

## Справка: `qodercli` на TS-стороне (для полноты, шлюза не касается)

- Установка: при отсутствии бинарника TS возвращает 502 с текстом
  «Install it from https://qoder.com or set CLI_QODER_BIN to its
  path» (`executors/qoder.ts:370-383`; резолвер
  `services/qoderCliResolve.ts:27-30` — явный путь через
  `CLI_QODER_BIN`, иначе `qodercli` из `PATH`, на Windows через
  cliRuntime-резолвер `.cmd`-обёрток).
- PAT: взять на `https://qoder.com/account/integrations` или через
  env `QODER_PERSONAL_ACCESS_TOKEN` (`services/qoderCli.ts:76-77,
  905-921`); интерактивный вход — `qodercli /login` (браузерный
  логин упоминается в `services/qoderCli.ts:76-77, 694`).
- Изоляция: OmniRoute гоняет CLI в отдельном `--config-dir`
  (`QODER_CLI_CONFIG_DIR`, `services/qoderCli.ts:72-90`), чтобы PAT
  через `QODER_PERSONAL_ACCESS_TOKEN` не затирал браузерный логин
  оператора.

## Сверка с TS-источником OAuth

- `services/tokenRefresh/providers/qoder.ts:11-37` — тот же Basic
  `base64(id:secret)` + form
  `{grant_type, refresh_token, client_id, client_secret}`; без
  конфигурации — warn «browser OAuth is not configured» и `null`
  (Rust-аналог: `Ok(None)` в `refresh_on_401`).
- Реестр: `config/providers/registry/qoder/index.ts:14-17`
  (`clientIdEnv`, `clientSecretEnv`, `process.env.QODER_OAUTH_TOKEN_URL`).
