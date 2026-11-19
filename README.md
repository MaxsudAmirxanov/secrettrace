# SecretTrace

Отслеживание жизненного цикла секретов в собственной инфраструктуре: где лежит каждый зарегистрированный
секрет, кто им пользуется и не утёк ли он туда, где его быть не должно. Хранятся только HMAC-отпечатки,
не значения.

> Статус: этапы 0–5 из [docs/architecture.md](docs/architecture.md): ядро отпечатков, схема БД, журнал аудита,
> авторизация (пароль + обязательный TOTP, сессии, CSRF, API-токены, роли), API реестра секретов с allow-rules
> и OpenAPI. Сканеры, алерты и UI — следующие этапы.

## Требования

- Rust 1.89+ (`rustup`), Docker с Compose v2, `openssl`, `make`.

## Быстрый старт (Docker Compose)

```sh
make secrets      # создаёт deploy/secrets/* (пароли БД, pepper); в git не попадают
make up           # postgres → migrate → server
curl -s localhost:8080/healthz   # {"status":"ok"}
curl -s localhost:8080/readyz    # {"status":"ready"}
```

**Сделайте резервную копию `deploy/secrets/pepper_keys` и `deploy/secrets/data_key`.** Без pepper отпечатки
нельзя ни проверить, ни пересчитать: все секреты придётся регистрировать заново. Без data key пропадут
TOTP-привязки: всем пользователям придётся сбрасывать MFA.

## Пользователи и вход

```sh
make admin NAME=alice     # создать администратора (пароль вводится скрыто, минимум 12 символов)
```

Вход проходит в два шага, TOTP обязателен для всех ролей:

1. `POST /api/v1/auth/login` `{username, password}`: выдаётся сессия на 5 минут, годная только для MFA.
2. При первом входе `POST /api/v1/auth/mfa/enroll` возвращает `otpauth://`-ссылку для приложения-аутентификатора.
3. `POST /api/v1/auth/mfa/verify` `{code}`: выдаётся новая полноценная сессия (12 ч, тайм-аут бездействия 30 мин).

Изменяющие запросы требуют заголовок `X-CSRF-Token`. Токен возвращают `login`, `verify` и `GET /auth/me`.
Каждый код TOTP принимается один раз. После 5 неудачных попыток (пароль или код) учётная запись
блокируется на 15 минут. Ответы на неудачный вход одинаковы, чтобы по ним нельзя было узнать,
существует ли пользователь. Причина неудачи пишется в журнал аудита.

| Роль | Права |
|---|---|
| `viewer` | только чтение |
| `operator` | секреты, источники, сканы, алерты |
| `admin` | всё, включая API-токены, каналы уведомлений и журнал аудита |

Администрирование из командной строки (действия пишутся в аудит):

```sh
docker compose run --rm --no-deps server reset-mfa   --username alice   # сбросить TOTP и все сессии
docker compose run --rm --no-deps server unlock-user --username alice   # снять блокировку
```

**API-токены** для агентов и CI создаёт администратор: `POST /api/v1/api-tokens`
`{name, kind: agent|ci|automation, scopes: [ingest:profile|ingest:match|ingest:findings], expires_in_days}`.
Значение токена (`stk_…`) показывается один раз, хранится только его SHA-256. Токен передаётся как
`Authorization: Bearer stk_…`. Отзыв: `DELETE /api/v1/api-tokens/{id}`, действует сразу.

## Локальная разработка

```sh
make db-up                         # временный Postgres 17 на 127.0.0.1:54329 (роли st_owner/st_app)
cp .env.example .env               # вставьте ключи из: cargo run -p st-server -- gen-pepper / gen-data-key
set -a; . ./.env; set +a
cargo run -p st-server -- migrate
cargo run -p st-server -- create-user --username alice --role admin
cargo run -p st-server -- serve
cargo run -p st-server -- verify-audit
```

## Тесты и проверки

```sh
make test         # unit + интеграционные (поднимает Postgres в Docker)
make test-unit    # без БД
make lint         # rustfmt --check + clippy pedantic с -D warnings
make audit        # cargo audit
```

Интеграционные тесты получают отдельную БД на каждый тест.

- `crates/st-server/tests/db.rs`: целостность hash-chain аудита, обнаружение подмены и удаления строк, откат
  вместе с транзакцией, линейность цепочки при конкурентной записи, запрет `UPDATE/DELETE/TRUNCATE`
  для рантайм-роли, CHECK-ограничения политики hints.
- `crates/st-server/tests/secrets.rs`: регистрация без утечки digest (ни в ответ, ни в аудит), дубликаты
  в том числе после ротации pepper, роли и CSRF, валидация с ответами problem+json, частичное обновление
  с различием «поле не передано / null», конечные статусы, пагинация без дублей, буквальные `%` и `_`
  в поиске, места нахождения и счётчик нарушений.
- `crates/st-server/tests/openapi.rs`: закоммиченный `docs/openapi.json` совпадает с кодом; у всех закрытых
  операций объявлена авторизация, у изменяющих — CSRF; схемы ответов не содержат digest и отпечатков.
  Перегенерировать спецификацию: `UPDATE_OPENAPI=1 cargo test -p st-server --test openapi`.
- `crates/st-server/tests/auth.rs`: полный вход с привязкой TOTP, ротация сессии после MFA, хранение seed
  только в зашифрованном виде, повторное использование кода, CSRF, одинаковые ответы и блокировка,
  rate-limit, роли, выпуск, проверка и отзыв API-токенов, отсутствие токенов и имён в аудите, сброс MFA.

## Реестр секретов

Спецификация API: [docs/openapi.json](docs/openapi.json); на сервере отдаётся по `GET /api/v1/openapi.json`.

```sh
# 1. digest считается локально; значение не покидает машину
secrettrace digest --type api-key > digest.json
# 2. регистрация (сессия оператора + X-CSRF-Token)
POST /api/v1/secrets
{ "name": "prod-aws-deploy", "type": "api_key", "owner": "platform",
  "digest": "<из digest.json>", "hints": { "prefix": "AKIA", "length": 20 },
  "allow_rules": [ { "source_type": "git_repo", "uri_pattern": "git@github.com:acme/infra-secrets.git",
                     "path_pattern": "sealed/**" } ],
  "expires_at": "2027-06-01T00:00:00Z" }
```

| Метод | Путь | Роль | Назначение |
|---|---|---|---|
| GET | `/api/v1/secrets?status=&type=&owner=&q=&limit=&cursor=` | viewer | список с фильтрами, курсорная пагинация |
| POST | `/api/v1/secrets` | operator | регистрация по digest |
| GET | `/api/v1/secrets/{id}` | viewer | карточка: маска, allow-rules, число мест и нарушений |
| PATCH | `/api/v1/secrets/{id}` | operator | владелец, назначение, срок, статус, allow-rules (заменяются целиком) |
| GET | `/api/v1/secrets/{id}/locations?is_allowed=` | viewer | где найден секрет |

- **Дубликаты.** Повторная регистрация того же значения отклоняется с 409, в том числе если значение
  зарегистрировано под старой версией pepper. Повторное имя тоже даёт 409.
- **Статусы.** `revoked` и `rotated` конечные: вернуть секрет в `active` нельзя, новое значение регистрируется
  как новый секрет.
- **Allow-rules.** Glob-шаблоны: `*` не пересекает `/`, `**` пересекает, `a/**/b` совпадает и с `a/b`.
  Все заданные поля правила (тип источника, URI, путь, окружение) должны совпасть.
- **Ответы** не содержат digest, отпечаток и версию pepper. Ошибки приходят в формате RFC 7807
  (`application/problem+json`).

## CLI: digest секрета без отправки значения

```sh
cargo run -p st-cli -- digest --type api-key           # скрытый ввод
secrettrace digest --type private-key --stdin < key.pem
```

Значение нормализуется и хешируется локально, затем затирается в памяти. На выходе — digest, допустимые
по политике подсказки и маска, например `AKIA…`. Значение нельзя передать аргументом: argv виден в `ps`
и истории shell.

## Конфигурация

Все переменные описаны в [.env.example](.env.example). Любую чувствительную переменную `ST_X` можно
передать как `ST_X_FILE` (путь к файлу, например Docker secret). Задать обе одновременно — ошибка.

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `ST_DATABASE_URL` | — | рантайм-подключение (роль `st_app`) |
| `ST_MIGRATION_DATABASE_URL` | = `ST_DATABASE_URL` | подключение для `migrate` (роль `st_owner`) |
| `ST_PEPPER_KEYS` | — | `1:<base64>,2:<base64>`, ключи ≥ 32 байт |
| `ST_PEPPER_CURRENT` | максимальная версия | версия для новых отпечатков |
| `ST_DATA_KEY` | — | base64 32 байт, AES-256-GCM для TOTP-seed'ов |
| `ST_COOKIE_SECURE` | `true` | `Secure` и префикс `__Host-` у cookie; `false` только для разработки по HTTP |
| `ST_SESSION_TTL_SECS` / `ST_SESSION_IDLE_SECS` | `43200` / `1800` | срок жизни сессии и тайм-аут бездействия |
| `ST_TOTP_ISSUER` | `SecretTrace` | имя в приложении-аутентификаторе |
| `ST_TRUSTED_PROXIES` | — | IP прокси, чьему `X-Forwarded-For` доверять |
| `ST_LISTEN_ADDR` | `0.0.0.0:8080` | адрес API |
| `ST_LOG_FORMAT` / `ST_LOG` | `json` / `info` | формат и фильтр логов |
| `ST_DB_MAX_CONNECTIONS` | `10` | размер пула |
| `ST_REQUEST_TIMEOUT_SECS` | `30` | таймаут запроса |
| `ST_MAX_BODY_BYTES` | `1048576` | лимит тела запроса |

## Структура

```
crates/st-core     нормализация, digest, hints, маскирование (общее для сервера и клиентов)
crates/st-server   API (axum), авторизация, админ-команды, аудит, pepper
crates/st-cli      CLI `secrettrace`
migrations/        SQL-миграции (встраиваются в бинарник)
testdata/          общие тест-векторы digest (эталон посчитан независимой реализацией на Python)
deploy/            init-скрипт Postgres, секреты (gitignored)
docs/              архитектура и ADR
```
