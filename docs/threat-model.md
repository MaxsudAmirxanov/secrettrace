# SecretTrace — модель угроз

Состояние на этап 13 (коммит `89eaabb`). Каждая защита ниже сверена с кодом; пути указаны относительно корня
репозитория. Устройство системы — в [architecture.md](architecture.md), здесь — от кого и как она защищена
и чего пока не умеет.

## 1. Активы

| Актив | Где | Ценность для атакующего | Чем защищён |
|---|---|---|---|
| Отпечатки секретов `fp = HMAC(pepper_v, d)` | `secrets.fingerprint` | с pepper — офлайн-перебор слабых паролей | без pepper бесполезны (`crates/st-server/src/crypto/pepper.rs`) |
| Client digest `d = SHA-256(domain ‖ canonical)` | только в полёте: CLI/браузер → `/secrets`, `/ingest/*/match` | перебор слабых паролей без pepper | TLS, тела ingest не логируются, CLI печатает digest только по `--show-digests` |
| Pepper (`ST_PEPPER_KEYS`) | Docker secret у `server`, `worker`, `migrate` | вместе с дампом — офлайн-перебор | только в файлах `deploy/secrets` (0700 каталог), не в БД и не у агентов |
| Data key (`ST_DATA_KEY`) | Docker secret у `server`, `migrate` | расшифровка TOTP seed → обход MFA | AES-256-GCM, id пользователя — AD (`crypto/aead.rs`); у воркера ключа нет |
| Hints (префикс, суффикс 4, длина) | `secrets.hint_*` | сужение перебора | политика `st-core/src/hints.rs` + CHECK в `migrations/0001_core.sql`; у паролей и строк подключения подсказок нет |
| API-токены `stk_…` | у CI/агентов; в БД — SHA-256 | запись находок, оракул `/match` | срок ≤ 365 дн., scopes, привязки CN/источника/окружения (`auth/extract.rs`, `ingest.rs`) |
| Сессии | cookie `__Host-st_session`; в БД — SHA-256 | действия от имени пользователя | HttpOnly, SameSite=Strict, Secure, 12 ч / 30 мин, ротация после MFA (`auth/session.rs`) |
| Журнал аудита | `audit_log` | сокрытие действий | hash-chain + `REVOKE UPDATE/DELETE/TRUNCATE` у `st_app` (`audit.rs`, `0001_core.sql:215`) |
| Места (`locations`) | БД | **карта утечек**: какой репозиторий, путь и коммит содержат зарегистрированный секрет | RBAC (viewer+), значений и digest нет; см. § 5 |
| Git credentials (`credential_ref`) | файлы `deploy/worker/git-credentials` | доступ к репозиториям | только у воркера, привязка к хостам `<ref>.hosts`, askpass (`worker/credentials.rs`) |
| Ключ CA | `deploy/pki/out/ca/ca.key` (0600) | выпуск любых клиентских сертификатов | в контейнеры не монтируется (`docker-compose.yml`, сервис `edge`) |
| Ключ edge | `deploy/pki/out/server/server.key` (0644 в каталоге 0700) | MITM для UI и API | монтируется только в `edge` |

## 2. Участники и границы доверия

```
                 Интернет / корпоративная сеть
  браузер (viewer/operator/admin)        CI / агенты (токен + клиентский сертификат)
          │ TLS :443                                  │ mTLS :8443
══════════╪═══════════════════ граница 1: edge ═══════╪═════════════════════════════
          ▼                                           ▼
     ┌──────────────── nginx (uid 101, read-only) ───────────────┐
     │ :8443 UI+API, ingest → 403     :9443 только ingest, CA+CRL │
     │ чистит X-SecretTrace-Client-CN  ставит CN проверенного серт.│
     └───────────────────────┬───────────────────────────────────┘
══════════════ граница 2: доверенный прокси (ST_TRUSTED_PROXIES = 10.213.0.10) ═════
                             ▼ сеть edge (фикс. подсеть)
                  secrettrace-server serve  ── data key, pepper
                             │ сеть db (internal)
══════════════ граница 3: роли БД (st_app / st_owner) ══════════════════════════════
                         Postgres 17
                             ▲ сеть db
                  secrettrace-server worker ── pepper, git credentials
                             │ сеть egress
══════════════ граница 4: недоверенные git-серверы и содержимое репозиториев ═══════
                  git-хосты из ST_WORKER_ALLOWED_HOSTS

  Хост и его оператор (deploy/secrets, deploy/pki/out, docker) — доверенная база.
```

Профили атакующих:

| Профиль | Что у него есть | Чего не должен получить |
|---|---|---|
| A1 внешний без учётных данных | сеть до :443/:8443 | вход, API, факт регистрации значения |
| A2 украденный токен CI | `stk_…` | работу без сертификата; запись чужих источников/окружений; данные реестра |
| A3 украденный клиентский сертификат | `client.crt/key` | что-либо без токена с тем же `cert_cn` |
| A4 враждебное содержимое репозитория | файлы и история, которые читают CLI/воркер | выполнение кода, чтение вне репозитория, подмену результатов |
| A5 скомпрометированный viewer | сессия viewer | изменения, токены, аудит |
| A6 похититель дампа БД | копия Postgres | значения секретов, сессии, токены, TOTP |
| A7 скомпрометированный воркер | процесс воркера | data key, сессии пользователей |
| A8 враждебный git-сервер | ответы на fetch | credentials для других хостов, SSRF, текст в UI |

## 3. STRIDE по компонентам

### 3.1 Edge (nginx, `deploy/nginx/nginx.conf`)

| | Угроза | Защита |
|---|---|---|
| S | клиент выдаёт себя за CI | `ssl_verify_client on`, `ssl_client_certificate` = CA SecretTrace, `ssl_crl`, `ssl_verify_depth 1` |
| S | подделка `X-SecretTrace-Client-CN` / `X-Forwarded-For` | на :8443 CN очищается (`proxy_set_header … ""`), на :9443 перезаписывается `$ssl_client_cn`; XFF = `$remote_addr`; общий `proxy_headers.conf` в каждой location (иначе nginx теряет унаследованные заголовки); заголовки с `_` nginx отбрасывает по умолчанию |
| T | MITM | TLS 1.2/1.3, только ECDHE+AEAD, без session tickets, HSTS на :443 |
| R | нет следа запросов | JSON access log: путь без query, статус, CN, `request_id` сервера |
| I | утечка через логи | query и заголовки не пишутся; клиентский `X-Request-Id` отбрасывается |
| D | исчерпание | `client_max_body_size` 2m/16m, таймауты прокси; `limit_req` нет (§ 5) |
| E | выход из контейнера | uid 101, `read_only`, `cap_drop: ALL`, `no-new-privileges`, без entrypoint-скриптов образа; ключ CA не смонтирован |

### 3.2 Сервер (API, `crates/st-server`)

| | Угроза | Защита |
|---|---|---|
| S | подбор пароля / TOTP | argon2id, одинаковый 401, блокировка 5/15 мин без продления, лимиты 20/мин IP, 10/мин имя, 5 TOTP (`auth/ratelimit.rs`, `routes/auth.rs`) |
| S | фиксация сессии | новый токен после MFA, старый удаляется (`routes/auth.rs`, `mfa_verify`) |
| S | CSRF | SameSite=Strict + `X-CSRF-Token = H(domain ‖ session)` на всех не-GET (`auth/extract.rs`, `SessionAuth`) |
| S | токен без сертификата / чужой CN | один `UPDATE … WHERE (cert_cn IS NULL OR cert_cn = $cn) AND (cert_cn IS NOT NULL OR NOT $require)`; CN берётся только от пира из `ST_TRUSTED_PROXIES`, повтор заголовка = нет CN (`auth/extract.rs`, `client_cn`) |
| T | подмена окружения/источника, чтобы попасть под allow-правило | привязки токена `environment`, `source_type`, `source_uri_pattern` → 403 (`ingest.rs`, `bound_environment`, `check_source_binding`) |
| T | «закрыть» чужие находки | `no_longer_present` только для мест того же токена и старше начала скана (`ingest.rs`, `complete`) |
| T | гонки при приёме | `FOR UPDATE` на скан, `FOR SHARE` на секреты, порядок блокировок (`ingest.rs`) |
| R | действия без следа | аудит в той же транзакции, что и действие; hash-chain, `verify-audit` (`audit.rs`) |
| I | утечка значения через ответы | ответы без digest/отпечатков; 422 без присланных значений (`extract.rs`, `redact_input`); RFC 7807 без внутренних деталей (`error.rs`) |
| I | оракул «зарегистрирован ли X» через `/match` | бюджет уникальных digest'ов в час на токен, общий с `/findings`; аудит счётчиков (`ingest.rs`, `IngestLimiter`) |
| I | XSS/clickjacking в UI | CSP `default-src 'none'; script-src 'self'…; frame-ancestors 'none'` (`web.rs`), React без `dangerouslySetInnerHTML` |
| D | большие тела | `DefaultBodyLimit`, 8 МиБ только у `/findings` (`app.rs`); лимиты 10 000 digest'ов / 5 000 находок на запрос |
| E | повышение роли | `CurrentUser::require(role)` в каждом обработчике; себя менять нельзя, последний админ защищён (`routes/users.rs`) |

### 3.3 Postgres (`migrations/`)

| | Угроза | Защита |
|---|---|---|
| T | правка/удаление аудита рантаймом | у `st_app` отозваны `UPDATE/DELETE/TRUNCATE` на `audit_log` и доступ к `_sqlx_migrations` (`0001_core.sql:209-217`) |
| T | обход проверок кода | CHECK'и: hints, форматы `cert_cn`/`environment`/`credential_ref`, длины (`0001`, `0004`, `0005`) |
| I | дамп | отпечатки (HMAC), хеши сессий и токенов, зашифрованные TOTP seed; значений и digest нет |
| E | доступ из сети | сеть `db` с `internal: true`; суперпользователь только в init-скрипте (`deploy/postgres/init`) |

### 3.4 Воркер (`crates/st-server/src/worker`) и CLI (`crates/st-cli`) — чтение недоверенных репозиториев

| | Угроза | Защита |
|---|---|---|
| S | git-сервер просит credential для другого хоста | askpass отвечает только на `https://[user@]<хост источника>[:port]`, 407 прокси без ответа (`credentials.rs`, `prompt_is_for_host`); credential только для хостов из `<ref>.hosts` (`check_host_binding`) |
| T | `refs/replace`, grafts, alternates подменяют содержимое | `GIT_NO_REPLACE_OBJECTS=1`, удаление `GIT_*` переменных расположения (`st-source/src/git.rs`, `SCRUBBED_ENV`, `GIT_BASE_ENV`) |
| I | SSRF во внутреннюю сеть | `ST_WORKER_ALLOWED_HOSTS` обязателен; IP-литералы (включая `0x7f.1`, `2130706433`) только явно (`remote.rs`, `is_ip_literal`); `http.followRedirects=false`; только https/ssh (`fetch.rs`) |
| I | credential в argv/env/логах/БД | файл в `Zeroizing`, копия во временный 0600-каталог задачи, `GIT_ASKPASS` = сам бинарник; ошибки git сведены к категориям, `remote:`-текст не сохраняется (`fetch.rs`, `classify`) |
| E | выполнение кода из репозитория | `core.fsmonitor=false`, `core.hooksPath=/dev/null`, без сабмодулей, `GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_GLOBAL=/dev/null`, `protocol.allow=never` кроме https/ssh, `transfer.fsckObjects` (`fetch.rs`, `git.rs`) |
| E | симлинки/FIFO в рабочем дереве (CLI `scan fs`) | `walkdir` без следования, `O_NOFOLLOW | O_NONBLOCK` + `fstat` (`st-source/src/fs.rs`) |
| D | огромные репозитории/blob'ы | `ST_WORKER_MAX_REPO_BYTES` во время fetch, `max_blob_bytes`, лимиты экстрактора (16 МиБ, 10 000 кандидатов, бюджет декодирования), линейные регулярки (`st-extract`) |
| D | зависание | тайм-аут задачи, `lowSpeedLimit`, kill группы процессов (`kill_process_group`), аренда и жнец (`queue.rs`) |

## 4. Сценарии атак

**4.1 Дамп БД (A6).** Атакующий получил `pg_dump`. Отпечатки — HMAC с pepper, которого в БД нет: перебор
невозможен. Сессии и токены хранятся как SHA-256 от 256-битных случайных значений — обратить нельзя. TOTP seed
зашифрованы data key. **Утекает карта утечек** (`locations`: URI, пути, коммиты зарегистрированных секретов),
имена и владельцы секретов, hints. Если вместе с дампом украден `deploy/secrets/pepper_keys` (например, бэкап
хоста), слабые пароли перебираются офлайн: `d` считается без секретов, `fp = HMAC(pepper, d)` проверяется по
таблице. Поэтому у паролей нет hints, а pepper не раздаётся агентам.

**4.2 `/match` как оракул (A2).** Токен с `ingest:match` может спросить, зарегистрирован ли digest. Защиты:
бюджет `ST_INGEST_DIGESTS_PER_HOUR` (по умолчанию 200 000, `ingest.rs:67`), общий с `/findings`, аудит
`ingest.match` со счётчиками, в compose — обязательный клиентский сертификат (`ST_INGEST_REQUIRE_CLIENT_CERT`).
**Остаточный риск:** 200 000 проверок в час на токен (4,8 млн в сутки) — это онлайн-перебор словаря против
зарегистрированных паролей. Лимиты живут в процессе и умножаются на число реплик. Алертов на всплеск нет
(этап 10). См. § 5, O-3.

**4.3 Сокрытие нарушения (A2).** Скомпрометированный CI хочет, чтобы утечка выглядела разрешённой: заявить
`environment` или URI, под который есть allow-правило, или «закрыть» место. Привязки токена
(`environment`, `source_type`, `source_uri_pattern`) дают 403. Без привязок атака возможна — их надо задавать
каждому токену CI. Закрыть чужие места нельзя: `no_longer_present` трогает только места того же токена.
Записать **ложные** находки в рамках своей привязки токен может — это шум, а не сокрытие.

**4.4 Подделка CN мимо edge (A1/A2).** На :443 заголовок очищается, на :9443 перезаписывается. Прямой доступ
к серверу есть только из сети `edge` и с хоста, но сервер верит CN лишь от `10.213.0.10`: пир с другим адресом
получает «нет сертификата», и токен с `cert_cn` не проходит. Занять адрес edge в docker-сети без привилегий
на хосте нельзя. **Разбор DN** (O-1, закрыт): если CA подписывает сертификаты с атрибутами, которые
контролирует заявитель, `O=evil\,CN=ci-infra` в RFC 2253 выглядит как ещё один CN. `map` в edge отбрасывает
DN с экранированием и с несколькими `CN=`, такой сертификат не даёт CN. Собственный `pki.sh` таких
сертификатов и не выпускает: subject задаёт оператор, CN проверяется по `[A-Za-z0-9._-]`.

**4.5 Украденный сертификат (A3) или токен (A2) по отдельности.** Сертификат без токена даёт только TLS до
ingest и 401. Токен без сертификата при `require_client_cert` даёт 401 (причина — только в логе сервера,
`API token refused`), отказ не обновляет `last_used_at`. Отзыв: токен — `DELETE /api-tokens/{id}` сразу;
сертификат — `make revoke-cert` (CRL + reload edge).

**4.6 SSRF и кража credentials через воркер (A8, оператор-злоумышленник).** Оператор задаёт источник
`https://169.254.169.254/…` — IP-литерал не в списке, отказ. `https://internal.example/…` — отказ, если хоста нет
в `ST_WORKER_ALLOWED_HOSTS`. С `ST_WORKER_ALLOW_ANY_HOST=true` (O-6, закрыт) внутренние имена отвергаются
сразу (`localhost`, однословные имена вроде сервисов compose, `.local`, `.internal`, `.lan`, `.home.arpa`…),
а остальные резолвятся до fetch: все адреса должны быть публичными, и git подключается к проверенному
(`http.curloptResolve`, ssh `HostName` + `HostKeyAlias`), поэтому DNS rebinding не сработает
(`worker/remote.rs`, `resolve_pinned`). Через HTTP-прокси имя резолвит прокси. Чужой хост с `credential_ref` → отказ без запуска git (`<ref>.hosts`). Редирект
на другой хост — `followRedirects=false`; запрос пароля для другого URL — askpass молчит. Текст ответа сервера
(`remote:`, порты, баннеры) в БД не попадает: зритель не прочитает подставленные сообщения и не просканирует
порты по ошибкам.

**4.7 Враждебный репозиторий (A4).** `.git/config` с `core.fsmonitor=…` или хуками — отключены явными `-c`.
`refs/replace/*` — `GIT_NO_REPLACE_OBJECTS`. Ветка `--output=/etc/x` — ревизии проверяются и идут после
`--end-of-options`. Симлинк `config -> /run/secrets/pepper_keys` в `scan fs` — `O_NOFOLLOW`, не прочитается.
Blob на 10 ГиБ — `max_blob_bytes`, репозиторий-бомба — `MAX_REPO_BYTES` во время fetch. Путь с управляющими
символами — экранируется и обрезается до 1024 байт (`worker/scan.rs`, `sanitize_path`). Кандидаты-«бомбы»
(base64 в base64) — глубина 3 и бюджет декодирования.

**4.8 Сессии.** Фиксация — токен меняется после MFA. Кража cookie через XSS — HttpOnly, строгий CSP. CSRF —
SameSite=Strict и токен из сессии. Повтор TOTP — `totp_last_step`. Подбор — блокировка без продления
(атакующий не держит учётную запись заблокированной вечно).

**4.9 Аудит.** `st_app` не может менять и удалять строки; вставка в середину или правка через `st_owner`
ломает цепочку, `verify-audit` это находит. **Не обнаруживается удаление хвоста** цепочки владельцем БД
(O-4): нужен внешний якорь head-хеша.

**4.10 Компрометация воркера (A7).** RCE в git или в разборе содержимого даёт атакующему pepper, git credentials
и роль `st_app` — ту же, что у сервера: чтение всей БД (включая `locations`), запись находок, вставки в аудит.
Не даёт data key, cookie пользователей и ключ CA. Вместе с pepper это офлайн-перебор слабых паролей (4.1).
Это главный риск изоляции (O-2).

**4.11 Оператор как оракул.** `POST /secrets` с уже зарегистрированным digest возвращает 409 с id секрета.
Каждая такая попытка пишется в аудит (`secret.create.duplicate`: id найденного секрета, введённое имя и тип,
без digest), а попыток регистрации — не больше 100 в час на пользователя (`SECRET_CREATES_PER_HOUR`,
429), считая и успешные, и дубликаты (O-5, закрыт). Промах тоже не бесшумен: он создаёт секрет
и запись `secret.create`.

## 5. Остаточные риски и открытые вопросы

| # | Приоритет | Риск | Где | Что сделать |
|---|---|---|---|---|
| O-1 | закрыт | разбор CN из `$ssl_client_s_dn` поддавался экранированной запятой в другом атрибуте (`O=evil\,CN=ci-infra` → `ci-infra`) и выбирал первый из нескольких CN (только при CA, подписывающем чужие subject'ы) | `deploy/nginx/nginx.conf` (`map $ssl_client_s_dn`) | исправлено: DN с `\` или с двумя `CN=` даёт пустой CN, то есть «нет сертификата» |
| O-2 | высокий | воркер с той же ролью БД, что и сервер, и с pepper | `docker-compose.yml` (сервис `worker`), `0001_core.sql:209` | отдельная роль `st_worker` (чтение `sources`/`secrets`, запись `scan_jobs`/`locations`, вставка в аудит); matching на сервере по внутреннему API, чтобы убрать pepper из воркера |
| O-3 | средний | оракул `/match`: 200 000 digest'ов в час на токен, лимитер в памяти процесса (×реплики), алертов нет | `ingest.rs:67`, `auth/ratelimit.rs` | алерт на расход бюджета (этап 10), меньший лимит по умолчанию для `kind=ci`, общий лимитер в Postgres при нескольких репликах |
| O-4 | средний | удаление хвоста аудита не обнаруживается | `audit.rs` | периодический экспорт head-хеша во внешнее хранилище / в сообщения алертов |
| O-5 | закрыт | 409 на дубликат при регистрации был неаудируемым и неограниченным оракулом для operator | `registry.rs` (`Registered::Duplicate`), `routes/secrets.rs` | исправлено: аудит `secret.create.duplicate` (без digest) в закоммиченной транзакции; 100 попыток в час на пользователя |
| O-6 | закрыт | `ST_WORKER_ALLOW_ANY_HOST=true` пропускал `localhost` и внутренние имена, DNS-ответ не проверялся (rebinding) | `worker/remote.rs`, `worker/fetch.rs` | исправлено: внутренние имена отвергаются; имя резолвится, все адреса должны быть публичными, git привязывается к проверенному адресу. Остаток: через HTTP-прокси резолвит прокси |
| O-7 | средний | алерты не реализованы: нарушение видно только в UI и коде выхода CI | этап 10 | реализовать outbox, Telegram/webhook |
| O-8 | средний | истёкший CRL (90 дней) блокирует **всех** клиентов mTLS | `deploy/pki/pki.sh`, `ssl_crl` | cron `pki.sh crl` + reload; мониторинг `nextUpdate` |
| O-9 | средний | ключ CA на том же хосте, что и edge | `deploy/pki/out/ca/ca.key` | внешний/офлайн CA для продакшена; на хосте только `ca.crt` и `crl.pem` |
| O-10 | низкий | OCSP нет; отзыв действует после reload edge | `nginx.conf` | reload в `revoke-cert` уже есть; при необходимости — короткоживущие сертификаты |
| O-11 | низкий | базовые образы не зафиксированы по digest (`rust`, `debian`, `distroless`, `postgres`, `nginx`) | `Dockerfile`, `docker-compose.yml` | `image@sha256:…` и обновления через Renovate/Dependabot |
| O-12 | низкий | строки JS нельзя затереть: значение секрета в браузере живёт до GC | `web/src/crypto` | поле очищается сразу после digest; для ключевого материала — CLI |
| O-13 | низкий | `safe.directory=*` в образе CLI | `Dockerfile:31` | приемлемо для одноразового CI-контейнера, который только читает; альтернатива — `--user` владельца checkout |
| O-14 | низкий | ключ edge 0644 (иначе uid 101 не прочитает через bind mount); защищён каталогом 0700 | `pki.sh`, `cmd_server` | Docker secrets с `uid/gid/mode` в swarm, либо группа 101 на хосте |
| O-15 | низкий | нет `limit_req` на edge: перебор логинов ограничен только лимитами сервера в процессе | `nginx.conf` | `limit_req_zone` по `$binary_remote_addr` на `/api/v1/auth/` |
| O-16 | закрыт | гранты `st_app` выдавались только в `0001` на `ALL TABLES`: таблица из будущей миграции осталась бы без прав | `crates/st-server/tests/db.rs` (`runtime_role_grants_cover_every_table`) | правило: каждая миграция с `CREATE TABLE` выдаёт `GRANT` явно (без `ALTER DEFAULT PRIVILEGES`, чтобы новые таблицы не доставались `st_app` молча); тест проверяет права на все таблицы и последовательности |
| O-17 | низкий | токен сам создаёт источник с любым URI в рамках привязки и может занять сгенерированное имя `type:uri` | `ingest.rs`, `source_name` | привязки `source_uri_pattern` у всех токенов; имя источника оператора не зависит от генерации |
| O-18 | информация | `GET /api/v1/openapi.json`, `/healthz`, `/readyz` без аутентификации | `app.rs` | спецификация и так публична в репозитории; при желании — закрыть на edge |

## 6. Чек-лист эксплуатации

- [ ] **Резервные копии** `deploy/secrets/pepper_keys` и `data_key` — отдельно от бэкапов БД (вместе они
      дают офлайн-перебор, § 4.1). Потеря pepper = перерегистрация всех секретов, data key = сброс всех MFA.
- [ ] `ST_EDGE_BIND` — конкретный интерфейс, а не `0.0.0.0`, если хватает внутренней сети; порт сервера наружу не публиковать.
- [ ] `ST_INGEST_REQUIRE_CLIENT_CERT=true` (по умолчанию в compose) и `ST_TRUSTED_PROXIES` = только адрес edge.
- [ ] Каждому токену CI/агента — `cert_cn`, `source_uri_pattern`, `environment`; срок — минимально нужный
      (90 дней вместо 365); неиспользуемые (`last_used_at`) — отзывать.
- [ ] Cron: `deploy/pki/pki.sh crl && docker compose exec edge nginx -s reload` раз в месяц (CRL живёт 90 дней).
- [ ] Ключ CA — вне сервера (или свой CA); после выпуска клиентских сертификатов `ca.key` убрать с хоста.
- [ ] Сертификат edge обновлять до истечения 397 дней; для браузеров — сертификат доверенного CA.
- [ ] `ST_WORKER_ALLOWED_HOSTS` — явный список; `ST_WORKER_ALLOW_ANY_HOST` и `ST_WORKER_ALLOW_LOCAL_REPOS` — `false`.
- [ ] Файлы `deploy/worker/git-credentials/<ref>` — токены только на чтение, у каждого `<ref>.hosts`.
- [ ] `secrettrace-server verify-audit` по расписанию; head-хеш сохранять вне БД (O-4).
- [ ] Минимум администраторов; роль operator — только тем, кто регистрирует секреты (O-5).
- [ ] Следить за `ingest.match` в аудите: резкий рост уникальных digest'ов у токена — признак перебора (O-3).
- [ ] Обновлять базовые образы и зависимости (`cargo audit`, `npm audit` в CI).
