# Protean — руководство разработчика / архитектура

> Это самый подробный документ по внутреннему устройству. Для быстрого старта и
> модели «сверху» см. [GETTING-STARTED.md](GETTING-STARTED.md). Проектные заметки
> по cert-провайдерам — [ARCHITECTURE-openvpn-ikev2.md](ARCHITECTURE-openvpn-ikev2.md),
> по сетевым топологиям — [TOPOLOGIES.md](TOPOLOGIES.md). Здесь мы на них ссылаемся
> и достраиваем их до уровня кода, а не дублируем.
>
> Аудитория — разработчик, который будет **менять и расширять** код: добавлять
> провайдеры/стратегии, править модель данных, воркеры, слой SSH и API.
> Указатели вида `файл:строка` даны там, где важна точная точка входа.

---

## Оглавление

1. [Стек и принципы](#1-стек-и-принципы)
2. [Карта репозитория и пакетов](#2-карта-репозитория-и-пакетов)
3. [Обзор архитектуры + диаграмма](#3-обзор-архитектуры)
4. [Composition root: `cmd/panel/main.go`](#4-composition-root)
5. [Жизненный цикл HTTP-запроса](#5-жизненный-цикл-http-запроса)
6. [Абстракция провайдера](#6-абстракция-провайдера)
7. [Как добавить новый провайдер (пошагово)](#7-как-добавить-новый-провайдер)
8. [Multi-server: ключ `server:instance`, Manager, реестр](#8-multi-server)
9. [SSH-слой (`internal/sshexec`)](#9-ssh-слой)
10. [statusCache и модель конкурентности](#10-statuscache-и-конкурентность)
11. [Фоновые воркеры](#11-фоновые-воркеры)
12. [Auth: crypto, сессии, CSRF, 2FA, rate-limit, pending](#12-auth)
13. [Модель данных: таблица за таблицей](#13-модель-данных)
14. [Слой `store`](#14-слой-store)
15. [wg-family внутренности](#15-wg-family)
16. [PKI и cert-провайдеры (OpenVPN, IKEv2)](#16-pki-и-cert-провайдеры)
17. [Модуль Xray и как написать новую стратегию](#17-модуль-xray)
18. [Mesh и маршрутизация](#18-mesh-и-маршрутизация)
19. [Подсистема уведомлений](#19-подсистема-уведомлений)
20. [Контракт installer-скрипта (verbs)](#20-контракт-installer-скрипта)
21. [Клиентские конфиги, IPAM, overlap](#21-клиентские-конфиги-ipam-overlap)
22. [UI: шаблоны, статика, embed](#22-ui-шаблоны-статика-embed)
23. [Метрики и health](#23-метрики-и-health)
24. [Сборка, запуск, тесты](#24-сборка-запуск-тесты)
25. [Соглашения по коду](#25-соглашения-по-коду)
26. [Известные ограничения и backlog](#26-известные-ограничения-и-backlog)

---

## 1. Стек и принципы

- **Язык / модуль**: Go, модуль `protean` (`go.mod`), `go 1.25.0`.
- **Без CGO**: собирается `CGO_ENABLED=0` (`Dockerfile:6`), итог — статический бинарь.
- **Образ**: multi-stage → `gcr.io/distroless/static-debian12` (`Dockerfile:8`). В образе нет
  shell/curl, поэтому health-check делает сам бинарь через флаг `-healthcheck`
  (`cmd/panel/main.go:195`, `docker-compose.yml:10`).
- **`embed` для всего фронта и миграций**: HTML-шаблоны и статика (`internal/web/web.go:14-18`),
  SQL-миграции (`internal/store/migrate.go:10-11`). Node/сборочного шага нет.
- **Зависимости** (`go.mod`): `pgx/v5` (Postgres, без ORM), `pquerna/otp` (TOTP),
  `skip2/go-qrcode` (QR), `xmppo/go-xmpp` (XMPP), `x/crypto` (SSH, bcrypt, curve25519),
  `x/sync` (singleflight), `software.sslmate.com/src/go-pkcs12` (.p12 для IKEv2).
- **UI**: server-rendered `html/template` + вендоренные htmx и Pico.css. Никакого SPA.

Ключевые архитектурные идеи:

- **Панель ничего не проксирует.** Она правит конфиги и дёргает службы на удалённых
  хостах по SSH; VPN-трафик идёт мимо панели.
- **Единый интерфейс провайдера** (`vpn.Provider`) + набор **опциональных
  capability-интерфейсов**, которые обнаруживаются через type-assertion. Так ядро
  остаётся тонким, а различия бэкендов (wg vs cert vs xray) живут в реализациях.
- **Одна привилегированная точка на хосте** — root-owned скрипт
  `protean-installer.sh` с жёстким enum действий и NOPASSWD-sudo только на него
  (см. [§20](#20-контракт-installer-скрипта)).
- **Секреты шифруются в БД** приложением (AES-256-GCM), а не хранятся в открытом
  виде; единственный ключ — `SECRET_KEY`.
- **Один процесс** — гарантируется advisory-lock в Postgres (`store.AcquireSingletonLock`,
  `internal/store/store.go:53`), потому что in-process блокировки конфигов и
  rate-limiter рассчитаны на единственный инстанс.

---

## 2. Карта репозитория и пакетов

```
cmd/panel/main.go            composition root: config → store → migrate → auth →
                             registry → servers.Manager → api.Server → воркеры → HTTP

internal/
  config/      Config + Load() из ENV (валидация на старте)
  store/       Postgres (pgx, рукописный SQL), миграции (embed), 1 файл на домен
    migrations/*.sql           19 миграций, hand-rolled runner
  auth/        Encryptor(AES-GCM), Manager(сессии), CSRF, TOTP, bcrypt, LoginLimiter, PendingAuth
  sshexec/     переиспользуемый SSH-клиент (ctx, timeout, host-key pinning, метрики)
  servers/     Manager: пул SSH + сборка провайдеров из таблицы servers, dynamic rebuild
  web/         embed шаблонов/статики, html/template, funcMap
  api/         HTTP: роутинг, middleware, statusCache, mesh, metrics, notify, воркеры,
               handlers_*.go по доменам, view-models (types.go)
  vpn/         абстракция Provider + Registry + IPAM + overlap + Installer
    wgfamily/    общий движок WireGuard/AmneziaWG (парс/рендер conf, wg dump, firewall)
    wireguard/   тонкая фабрика над wgfamily (binary "wg")
    amneziawg/   тонкая фабрика над wgfamily (binary "awg" + obfuscation-поля)
    pki/         внутренний x509 CA, выпуск/подпись/CRL
    openvpn/     cert-провайдер (ccd/iroute, tls-crypt, .ovpn, CRL)
    ikev2/       cert-провайдер (swanctl, .p12/.mobileconfig/.sswan, CRL)
    xray/        VLESS/VMess/Trojan/SS — стратегии, config.json, relay-цепочки
    clientconfig/ сборка wg-конфига клиента + QR

scripts/       setup-host.sh (готовит хост), protean-installer.sh (root-owned контракт)
Dockerfile, docker-compose.yml, docker-compose.test.yml, TESTING.md, .env.example
```

Внутри `store/` и `api/` действует правило «один файл — один домен»: `store/servers.go`,
`store/xray.go`, `store/certs.go`, `api/handlers_peers.go`, `api/handlers_xray.go` и т. д.

---

## 3. Обзор архитектуры

```
                         HTTPS (за вашим TLS-прокси)
  оператор ── браузер ─────────────────────────────► api.Server (net/http, ServeMux)
                                                          │
        ┌───────────────────────────┬─────────────────────┼───────────────────────────┐
        ▼                           ▼                     ▼                             ▼
   auth.Manager               vpn.Registry         statusCache (5s TTL,          фоновые воркеры
   (сессии/2FA/CSRF)     (map instanceName→Provider) singleflight)          (expiry, reconcile, notify,
        │                           │                                        report, reapply-mesh)
        ▼                           ▼
   store.Store               servers.Manager ── строит по одному ── sshexec.Client (пул) ── SSH ─► хост
   (Postgres, pgx)           Provider на инстанс из                                    (wg/awg/openvpn/
   секреты AES-GCM           таблицы servers                                            ikev2/xray + installer.sh)
```

Слои и их зона ответственности:

| Слой | Пакет | Отвечает за |
|------|-------|-------------|
| HTTP / UI | `internal/api`, `internal/web` | роутинг, auth-middleware, CSRF, рендер шаблонов, кэш статуса, метрики, воркеры, оркестрация мутаций |
| Абстракция VPN | `internal/vpn` (+ subpkgs) | интерфейс провайдера, реестр, конкретные бэкенды, IPAM, overlap, installer |
| Хостовый доступ | `internal/servers`, `internal/sshexec` | пул SSH-клиентов, сборка провайдеров, привилегированные операции |
| Состояние | `internal/store` | Postgres, секреты (шифр), миграции, singleton-lock |
| Безопасность | `internal/auth` | пароли, сессии, CSRF, 2FA, rate-limit, шифрование секретов |
| Оповещения | `internal/notify` | каналы Telegram/Mattermost/RocketChat/VoceChat/XMPP/email |
| Конфиг | `internal/config` | загрузка/валидация ENV |

Данные передаются в терминах доменных типов `vpn.Peer`, `vpn.ServerStatus`,
`vpn.PeerSpec`, `vpn.NewPeerResult` (`internal/vpn/provider.go:17-77`) — API-слой не
знает деталей конкретного бэкенда, кроме тех, что доступны через capability-интерфейсы.

---

## 4. Composition root

Весь порядок инициализации — в `cmd/panel/main.go:77-190`. Это единственное место,
где всё связывается; менять зависимости следует здесь.

Порядок запуска (`main()`):

1. **Флаг `-healthcheck`** (`main.go:78-83`): если задан — просто дёргает
   `http://127.0.0.1:<port>/healthz` и выходит 0/1 (`runHealthcheck`, `main.go:195`).
   Так распознаётся здоровье контейнера без shell.
2. **Логирование** (`setupLogging`, `main.go:53`): slog, уровень из `LOG_LEVEL`
   (debug|info|warn|error), формат из `LOG_FORMAT` (text|json).
3. **Сигналы**: `signal.NotifyContext(SIGINT, SIGTERM)` → корневой `ctx` (`main.go:87`).
4. **`config.Load()`** (`main.go:90`) — валидирует ENV, падает при ошибке (`fatal`).
5. **`store.Open`** (`main.go:95`) — pgxpool + ping.
6. **`AcquireSingletonLock`** (`main.go:103`) — отказ запускать второй инстанс
   на той же БД (`ErrAlreadyRunning`).
7. **`store.Migrate`** (`main.go:107`) — применяет неприменённые миграции.
8. **`auth.NewManager` + `SeedAdmin`** (`main.go:111-116`) — создаёт админа из
   `ADMIN_USERNAME/ADMIN_PASSWORD`, если таблица `users` пуста.
9. **`auth.NewEncryptor(SECRET_KEY)`**, **`NewCSRF`**, **`NewPendingAuth`** (`main.go:118-124`).
10. **`vpn.NewRegistry()`** и **`servers.NewManager(...)`** с `Template` из ENV
    (интерфейсы wg/awg, параметры OpenVPN/IKEv2, тайм-ауты SSH) (`main.go:126-139`).
11. **`seedDefaultServer`** (`main.go:28`, `142`): если заданы legacy `SSH_HOST/SSH_USER/
    SSH_KEY_PATH` и в таблице `servers` пусто — создаёт сервер `default` (плавная
    миграция со старой одно-серверной установки). Иначе no-op.
12. **`mgr.LoadAll(ctx)`** (`main.go:145`): строит SSH-клиенты и провайдеры для всех
    серверов из БД. Ошибки отдельных серверов логируются, но не валят старт.
13. **`api.NewServer(...)`** (`main.go:150`) и wiring через сеттеры:
    - `SetHostsFunc` — живой снимок `serverID → HostProbe` для `/healthz` и `/metrics`.
    - `SetInstallerFunc(mgr.Installer)` — резолвинг installer'а по серверу.
    - `SetServerManager(mgr)` — runtime rebuild/remove серверов.
    - `SetTrustProxy(cfg.TrustProxy)`.
14. **Запуск воркеров** (`main.go:161-165`): `StartExpiryWorker(5m)`,
    `ReconcileState`, `ReapplyMeshForwarding`, `StartNotifyWatcher(1m)`,
    `StartReportWorker(10m)`. См. [§11](#11-фоновые-воркеры).
15. **HTTP-сервер** (`main.go:167`): `Handler = srv.Routes()`, `ReadHeaderTimeout=10s`.

Shutdown (graceful):

- Горутина ждёт `ctx.Done()` и вызывает `httpServer.Shutdown` с тайм-аутом 10с (`main.go:173-180`).
- После остановки HTTP — `srv.WaitWorkers(15s)` (`main.go:188`) даёт воркерам
  завершить текущую итерацию (например, in-flight запись конфига).
- `defer mgr.CloseAll()` закрывает SSH-соединения, `defer st.Close()` освобождает
  advisory-lock и пул.

---

## 5. Жизненный цикл HTTP-запроса

Роутинг — стандартный `http.ServeMux` (Go 1.22+ с методами и `{param}` в пути),
собирается в `Server.Routes()` (`internal/api/server.go:211-288`). Обёртка
`withMetrics` (`server.go:292`) считает запросы/ошибки/латентность.

Типичный путь мутации (`POST /providers/{provider}/peers`):

```
withMetrics
  └─ requireAuth (middleware.go:35)
       ├─ читает cookie protean_session → auth.Authenticate (HMAC-хэш → строка sessions)
       ├─ ensureCSRFCookie → на небезопасных методах validCSRF (double-submit + подпись)
       ├─ кладёт username и csrfToken в context
       └─ handler (handlers_peers.go:handleCreatePeer)
            ├─ reg.Get(provider) → vpn.Provider
            ├─ парс формы, сбор PeerSpec (AllowedIPs = адрес + выбранные subnet CIDR)
            ├─ выбор ветки: own_public_key → ConfiguredPeerAdder;
            │                client_csr → CSRSigner; иначе → prov.AddPeer
            ├─ для wg-family: Seal(privateKey) + store.SavePeerSecret (иначе rollback RemovePeer)
            ├─ expiry / category (опц.)
            ├─ s.audit(...) — запись в audit_log
            ├─ s.invalidateStatus(provider) — сбросить кэш
            └─ 303 redirect на /providers/{provider}
```

Важные инварианты:

- **CSRF** (`middleware.go:52-56`, `91-97`): stateless double-submit. Токен —
  `<nonce>.<hmac(nonce)>`, подписан `SESSION_SECRET`. Значение лежит и в cookie
  `protean_csrf`, и в форме/заголовке `X-CSRF-Token`; на unsafe-методах должны
  совпасть и быть валидно подписаны. `pageHeader` (`providers.go:108`) кладёт токен
  во view, чтобы формы не забывали его.
- **clientIP** (`middleware.go:128`): `X-Forwarded-For` доверяется **только** при
  `TRUST_PROXY=1`; иначе берётся `RemoteAddr`, чтобы не подделать IP для
  rate-limit/аудита.
- **Peer ID в URL**: публичный ключ wg — стандартный base64 (`+`, `/`, `=`), в пути
  неудобен, поэтому `encodePeerID/decodePeerID` (`peerid.go`) перекодируют в
  RawURL-base64.
- Все чтения статуса/пиров в обработчиках идут через кэш: `providerStatus` /
  `providerPeers` (`server.go:188-202`), а после мутации — `invalidateStatus`.
- **Рендер**: `render(w, "имя_шаблона", view)` (`render.go:10`); ошибка шаблона →
  500 + лог.

Файлы обработчиков по доменам: `handlers_auth.go` (login/2FA/logout),
`handlers_dashboard.go`, `handlers_peers.go`, `handlers_server.go` (серверный конфиг
интерфейса), `handlers_network.go` (mesh/egress/сервис), `handlers_setup.go`
(provision cert-серверов), `handlers_ca.go` (импорт BYOC CA), `handlers_backups.go`,
`handlers_providers.go` (Install/Detect), `handlers_xray.go`, `handlers_servers.go`
(CRUD серверов), `handlers_mesh.go`, `handlers_notify.go`, `handlers_subnets.go`,
`handlers_audit.go`, `handlers_account.go`, `handlers_metrics.go`.

---

## 6. Абстракция провайдера

Определена в `internal/vpn/provider.go`. Это сердце расширяемости.

### 6.1 Обязательный интерфейс `Provider` (`provider.go:80-97`)

```go
type Provider interface {
    Name() string   // стабильный ID ИНСТАНСА, ключ в реестре/БД/URL: "hq:wg0"
    Type() string   // ТИП бэкенда: "wireguard"|"amneziawg"|"openvpn"|"ikev2"|"xray"
    Status(ctx) (ServerStatus, error)
    ListPeers(ctx) ([]Peer, error)
    AddPeer(ctx, PeerSpec) (NewPeerResult, error)
    UpdatePeer(ctx, id string, PeerSpec) error
    RemovePeer(ctx, id string) error
    UpdateServerConfig(ctx, ServerConfig) error
}
```

- `Name()` возвращает **инстанс-ключ** `server:instance` (см. [§8](#8-multi-server));
  `Type()` — тип, по которому определяется поведение (mesh-способность, поля
  обфускации AmneziaWG, установка).
- `NewPeerResult` (`provider.go:66`) содержит `PrivateKey`, который существует
  только в момент создания и **никогда** не возвращается из `ListPeers`. Собрать из
  него клиентский конфиг — задача вызывающего (API-слой + `clientconfig`), потому что
  это зависит от политики маршрутизации, о которой сам провайдер не знает.

### 6.2 Опциональные capability-интерфейсы

Обнаруживаются через `p.(Interface)` в API-слое. Реализуй те, что нужны бэкенду.

| Интерфейс | Метод(ы) | Кто реализует | Смысл |
|-----------|----------|---------------|-------|
| `ForwardingManager` (`:102`) | `ForwardingEnabled`, `EnableForwarding` | wg-family | управление host-FORWARD правилами для mesh |
| `KeyRotator` (`:109`) | `RotatePeerKey(oldPub)` | wg-family | перегенерация ключей на месте |
| `ConfiguredPeerAdder` (`:116`) | `AddConfiguredPeer(pub, spec)` | wg-family | добавить пира с готовым pubkey (re-enable, client-keygen) |
| `ConfRestorer` (`:122`) | `RestoreConf(content)` | wg-family | заменить весь конфиг сырым снимком |
| `NetworkController` (`:128`) | `EgressEnabled`, `ApplyNetworking(egress)` | wg-family | host-networking: forwarding + NAT egress |
| `ServiceNamed` (`:135`) | `ServiceName()` | wg-family, openvpn, ikev2, xray | имя systemd-юнита для start/stop/enable |
| `ClientConfigProvider` (`:145`) | `ClientConfigFile(id)` | openvpn, ikev2 | провайдер сам хранит креды и отдаёт готовый файл; API **не** пломбирует приватный ключ в `peer_secrets` |
| `ClientProfileProvider` (`:153`) | `ProfileFormats`, `ClientProfile(id, format)` | ikev2 | доп. форматы (`.mobileconfig`, `.sswan`) |
| `CAImporter` (`:165`) | `ImportCA(cert, key)` | openvpn, ikev2 | BYOC — принять внешний CA |
| `CSRSigner` (`:173`) | `AddPeerFromCSR(csr, spec)` | openvpn, ikev2 | подписать клиентский CSR (ключ не покидает клиента) |
| `ServerProvisioner` (`:181`) | `EnsureServer(pushRoutes, egress)` | openvpn, ikev2 | явная развёртка сервера (CA/сертификаты/конфиг/служба) |

Флаг `ClientConfigProvider` в API-слое используется как признак **cert-провайдера**:
он влияет на выдачу конфига (`handlers_peers.go:633`), пломбирование секретов
(`handlers_peers.go:225`), disable→remove вместо soft-disable (`handlers_peers.go:410`),
пропуск reconcile (`reconcile.go:28`) и mesh-FORWARD через installer (`mesh.go:79`).

**Матрица реализаций** (кто что поддерживает):

| capability | wireguard/amneziawg | openvpn | ikev2 | xray |
|---|:-:|:-:|:-:|:-:|
| ForwardingManager | ✓ | | | |
| KeyRotator | ✓ | | | |
| ConfiguredPeerAdder | ✓ | | | |
| ConfRestorer | ✓ | | | |
| NetworkController | ✓ | | | |
| ServiceNamed | ✓ | ✓ | ✓ | ✓ |
| ClientConfigProvider | | ✓ | ✓ | |
| ClientProfileProvider | | | ✓ | |
| CAImporter | | ✓ | ✓ | |
| CSRSigner | | ✓ | ✓ | |
| ServerProvisioner | | ✓ | ✓ | |

Xray — особый случай: его `AddPeer/UpdatePeer/RemovePeer/UpdateServerConfig`
возвращают `ErrNotImplemented`/ошибку (`xray/provider.go:88-99`); клиентами он
управляет своим отдельным API (`AddClient/RemoveClient`) через страницу Xray.

### 6.3 Реестр (`Registry`, `provider.go:187-245`)

- `map[string]Provider` + слайс `order` для стабильного порядка в UI.
- Потокобезопасен (`sync.RWMutex`).
- `Register` (идемпотентно по имени), `Unregister`, `Get`, `List` (в порядке
  регистрации), `Names`.
- Ключ — `Name()` инстанса = `server:instance`.

---

## 7. Как добавить новый провайдер

Пошагово на примере нового бэкенда (тип `foo`):

1. **Создай пакет** `internal/vpn/foo/`. Определи `type Provider struct{...}` и
   конструктор `New(Options) *Provider`. Держи внешние зависимости за узкими
   интерфейсами внутри пакета: `SSH` (Run/ReadFile/WriteFile), `Sealer` (Seal/Open),
   `Store` — так же, как это сделано в `openvpn/provider.go:18-42` и
   `ikev2/provider.go:17-40`. Это упрощает тесты и разрывает циклы импорта.

2. **Реализуй `vpn.Provider`**: `Name()` возвращает `opts.Instance`
   (scoped-ключ), `Type()` — `"foo"`. `Status/ListPeers/AddPeer/...` — по семантике
   бэкенда. Для in-process атомарности правок держи `sync.Mutex` в структуре и бери
   его в каждом мутирующем методе (как `wgfamily.Provider.mu`, `wgfamily/provider.go:73-78`).

3. **Реши, какие capability-интерфейсы нужны**, и реализуй их методы. Например,
   если бэкенд сертификатный — `ClientConfigProvider`, `ServerProvisioner`,
   `CSRSigner`, `CAImporter` (используй `internal/vpn/pki` для CA/выпуска/CRL —
   [§16](#16-pki-и-cert-провайдеры)). Если сетевой (wg-подобный) — `ForwardingManager`,
   `NetworkController`, `ConfiguredPeerAdder`, `KeyRotator`, `ConfRestorer`.
   API-слой сам подхватит их через type-assertion; регистрировать нигде не нужно.

4. **StoreAdapter**: если провайдеру нужно своё хранилище, добавь методы в
   `internal/store/` (новый файл `store/foo.go` + миграция) и адаптер
   `foo/storeadapter.go`, реализующий узкий интерфейс `foo.Store` через
   `*store.Store` (образцы — `openvpn/storeadapter.go`, `xray/storeadapter.go`).

5. **Миграция**: добавь `internal/store/migrations/00NN_foo.sql`. Раннер
   (`migrate.go`) применяет файлы в лексикографическом порядке; каждый — в своей
   транзакции. **Провайдер-ключевые таблицы держи со scoped-ключом** `provider`
   (`server:instance`), см. образец 0018/0019 для xray. Секреты храни как
   `BYTEA` с AES-пломбой.

6. **Wiring в Manager**: в `servers.Manager.buildProviders` (`internal/servers/manager.go:169`)
   добавь создание инстанса `foo.New(...)` со `scope(local)` в качестве `Instance`.
   Manager вызывается для каждого сервера, поэтому провайдер автоматически появится
   на всех хостах.

7. **Template/ENV** (опц.): если у бэкенда есть настраиваемые параметры — добавь
   поля в `servers.Template` (`manager.go:26`) и в `config.Config` + `config.Load`
   (`internal/config/config.go`), и прокинь их в `main.go:127-139`.

8. **Тип для UI**: внеси тип в `knownProviderTypes` (`internal/api/providers.go:11`),
   если он устанавливаемый со страницы Install, и (если mesh-способен) в
   `meshCapableTypes` (`api/providers.go:84`). Добавь верб установки в
   `protean-installer.sh` и `VALID_PROVIDER` (см. [§20](#20-контракт-installer-скрипта)).

9. **UI-страницы/обработчики**: при необходимости — новый `handlers_foo.go`,
   маршруты в `Routes()` и шаблоны в `internal/web/templates/`.

10. **Тесты**: юнит-тесты пакета (`foo/*_test.go`); интеграционные с реальным хостом —
    под build-тегом (как `wgfamily` под `integration`).

Минимальный жизнеспособный провайдер = п.1–2 + п.6. Всё остальное — по мере
необходимости фич.

---

## 8. Multi-server

### 8.1 Схема ключей `server:instance`

Каждый инстанс провайдера идентифицируется ключом вида `server:instance`
(например `hq:wg0`, `default:openvpn`). Разделитель — двоеточие, выбран потому, что
позволяет уложить весь ключ в **один** сегмент URL (`/providers/{provider}`).

Хелперы разбора (в `internal/api`):

- `serverOf(key)` (`server.go:170`) и `serverPart(key)` (`providers.go:51`) → часть до `:`.
- `localName(key)` (`providers.go:45`) → часть после `:`.
- `providerLabel(key)` (`providers.go:61`) → человекочитаемое `"<Type> <instance> @ <server>"`
  (сервер добавляется только если серверов больше одного — `multiServer()`).

Все провайдер-ключевые таблицы БД используют этот scoped-ключ в колонке `provider`
(миграция `0017_server_scope.sql` переносит legacy-строки под префикс `default:`).

### 8.2 `servers.Manager` (`internal/servers/manager.go`)

Владеет пулом SSH-клиентов и держит `vpn.Registry` синхронизированным с таблицей
`servers`.

- Состояние под `sync.Mutex`: `clients` (serverID → `*sshexec.Client`), `installers`
  (serverID → `*vpn.Installer`), `names` (serverID → зарегистрированные имена инстансов).
- **`LoadAll`** (`manager.go:67`) — построить всё при старте; ошибки серверов
  собираются, но не валят остальные.
- **`Rebuild(serverID)`** (`manager.go:86`): дешифрует SSH-ключ (`enc.Open`),
  создаёт `sshexec.Client`, строит провайдеры (`buildProviders`), затем под
  мьютексом снимает старые инстансы этого сервера из реестра (`Unregister`),
  закрывает старый SSH-клиент, регистрирует новые и обновляет installer. Вызывается
  из обработчиков `handleCreateServer`/`handleUpdateServer` для live-применения.
- **`Remove(serverID)`** (`manager.go:125`): дерегистрация + закрытие SSH.
- **`buildProviders`** (`manager.go:169`) — «шаблон» набора провайдеров на сервер:
  по одному WireGuard/AmneziaWG на каждый интерфейс из `Template`, плюс по одному
  OpenVPN, IKEv2 и Xray. Каждому `Instance` присваивается `scope(local) = srv.ID+":"+local`.
  `PublicHost` берётся из строки сервера (или `Host`, если пуст).
- **`Hosts()`** (`manager.go:157`) — снимок `serverID → *sshexec.Client` для
  health/metrics. **`Installer(serverID)`** (`manager.go:140`) — резолвинг installer'а.

### 8.3 Wiring в API

`api.Server` получает функции-«поставщики» (не сам Manager напрямую для hosts):
`SetHostsFunc` (адаптирует `*sshexec.Client` под интерфейс `HostProbe`),
`SetInstallerFunc(mgr.Installer)`, `SetServerManager(mgr)` (интерфейс `ServerManager`
с `Rebuild/Remove`, `server.go:160`). Так API-слой не зависит от `servers` жёстко
и легко мокается в тестах.

**Хранилище серверов**: таблица `servers` (`0016_servers.sql`), тип `store.Server`
(`store/servers.go:13`). SSH-приватный ключ хранится AES-пломбированным
(`EncKeyPEM`), `HostKey` пиннит host-key (пусто ⇒ TOFU).

---

## 9. SSH-слой

`internal/sshexec/client.go` — маленький переподключающийся SSH-клиент. Один
`*Client` на сервер; потокобезопасен (каждый вызов открывает свою session поверх
общего соединения).

- **`Config`** (`client.go:21`): Host/Port/User, `KeyPath` **или** `KeyPEM`
  (последний имеет приоритет — для UI-серверов ключ приходит расшифрованным из БД),
  `Timeout` (dial), `CmdTimeout` (backstop одной команды, дефолт 30с), `HostKey`
  (пиннинг) / `KnownHostsPath`.
- **Проверка host-key** (`buildHostKeyCallback`, `client.go:122`) в порядке
  предпочтения: (1) `HostKey` из конфига → `ssh.FixedHostKey` (строго,
  production-режим, заполняется `setup-host.sh`); (2) `KnownHostsPath` → OpenSSH
  known_hosts; (3) **TOFU** (`tofuCallback`, `client.go:142`) — пиннит первый
  увиденный ключ на время жизни процесса, логирует fingerprint с подсказкой запиннить.
- **`connection`** (`client.go:172`): под мьютексом; при наличии живого соединения
  делает дешёвую проверку (открыть/закрыть session), иначе `net.Dialer.DialContext`
  (ctx ограничивает dial/handshake) + `ssh.NewClientConn`.
- **`Run`** (`client.go:203`): считает метрики (atomic: `cmds`, `cmdErrs`,
  `lastLatency`), запускает `LC_ALL=C LANG=C <cmd>` (стабильный локаль-независимый
  вывод для парсинга), watchdog: `select` между `sess.Wait()` и `cmdCtx.Done()`;
  при тайм-ауте/отмене закрывает session и дренит горутину. Ненулевой exit или
  stderr → ошибка с текстом stderr.
- **`ReadFile`** — через `cat`; **`WriteFile`** (`client.go:282`) — через heredoc
  `cat > path <<'PROTEAN_EOF'`. Сознательно **не** write-temp-then-rename: перезапись
  на месте требует прав только на сам файл, а не на каталог — под это заточена
  модель прав на хосте (group-write ровно на управляемые конфиги).
- **`ShellQuote`** (`client.go:302`) — обёртка аргументов в одинарные кавычки.
- **`Ping`** (`client.go:77`) — `Run("true")` для health-check. **`Stats`**
  (`client.go:68`) — снимок счётчиков для `/metrics`. **`InterfaceExists`** —
  `ip link show <iface>`, чтобы отличать «интерфейс отсутствует» от «команда упала».

Тест `internal/sshexec/client_test.go` поднимает **in-process SSH-сервер** и
проверяет dial/handshake/exec, отмену по ctx, per-command timeout и host-key pinning.

---

## 10. statusCache и конкурентность

`internal/api/statuscache.go` — короткоживущий кэш для `Status` **и** `ListPeers`.

- TTL: `statusTTL = peersTTL = 5s` (`statuscache.go:17-20`). Дашборд опрашивается
  ~каждые 7с, несколько представлений спрашивают статус одновременно — кэш
  схлопывает это в один SSH round-trip.
- **`golang.org/x/sync/singleflight`**: `sfStatus`/`sfPeers` схлопывают
  одновременные промахи, чтобы медленный хост дёргался один раз, а не N.
- Ошибки тоже кэшируются кратко — чтобы не долбить упавший хост.
- **`invalidate(name)`** (`statuscache.go:117`) — сбрасывает и статус, и пиров;
  вызывается сразу после мутаций (`s.invalidateStatus(...)`), чтобы оператор видел
  изменения немедленно.
- Обёртки на уровне `Server` nil-safe: `providerStatus`/`providerPeers`
  (`server.go:188-202`) при `s.status == nil` (в тестах) идут напрямую к провайдеру.

Модель конкурентности в целом:

- **Одна запись на интерфейс за раз**: у wg-family — `p.mu` в провайдере
  (`wgfamily/provider.go`), гарантирует атомарность read-modify-write конфига и
  откат при неудаче live-apply.
- **Один процесс на БД**: advisory-lock (`store.go:53`).
- **atomic-счётчики** для метрик (SSH и HTTP), без блокировок на горячем пути.
- **Фоновые воркеры** учитываются `WaitGroup` (`goWorker`, `server.go:118`) и
  джойнятся на shutdown.

---

## 11. Фоновые воркеры

Все запускаются в `main.go:161-165` и оборачиваются в `goWorker`
(`server.go:118`), чтобы `WaitWorkers` (`server.go:128`) дождался их на shutdown.
Каждый уважает отмену `ctx`.

| Воркер | Файл | Период | Что делает |
|--------|------|--------|-----------|
| `StartExpiryWorker` | `expiry.go:11` | 5 мин (+раз на старте) | `ListDuePeers` → `disablePeer` (wg-family: soft-disable; cert: remove) → удалить строку expiry |
| `ReconcileState` | `reconcile.go:17` | один раз на старте | сравнивает БД с живым хостом для wg-family (не cert), **логирует** дивергенции (orphan secrets, пиры без ключа), НЕ авторемонтирует |
| `ReapplyMeshForwarding` | `mesh.go:103` | один раз на старте | переустанавливает host-FORWARD правила для mesh-enabled cert-провайдеров (эти правила, в отличие от wg-quick PostUp, не переживают reboot) |
| `StartNotifyWatcher` | `notify.go:92` | 1 мин | поллит статус провайдеров, эмитит события на переходах (up/down, connect/disconnect) |
| `StartReportWorker` | `notify.go:228` | 10 мин (проверка) | по расписанию шлёт накопительный email-отчёт |

`ReconcileState` намеренно **не чинит** расхождения: краш между записью на хост и в
БД мог оставить, например, сохранённый приватный ключ для несуществующего пира;
молчаливое удаление могло бы уничтожить не ту сторону, поэтому проблема выносится в
лог для оператора.

---

## 12. Auth

Пакет `internal/auth` — транспортно-независимый (cookie живут в `internal/api`).
Два независимых секрета:

- **`SECRET_KEY`** (64 hex = 32 байта) → `auth.Encryptor` (AES-256-GCM) для
  шифрования секретов в БД.
- **`SESSION_SECRET`** (≥16 симв.) → HMAC-SHA256 для сессионных токенов, CSRF и
  pending-2FA-токенов.

### 12.1 `Encryptor` (`crypto.go`)

- `NewEncryptor(keyHex)` (`crypto.go:17`): `hex.Decode` → `aes.NewCipher` →
  `cipher.NewGCM`. 64 hex-символа декодируются в 32 байта ⇒ AES-256.
- `Seal(plaintext) []byte` (`crypto.go:33`): случайный nonce (`gcm.NonceSize()`,
  обычно 12 байт) через `crypto/rand`, layout результата — **`nonce || ciphertext+tag`**.
  Без AAD.
- `Open(blob) string` (`crypto.go:43`): проверка длины, `nonce = blob[:n]`,
  расшифровка.
- Что шифруется: приватные ключи пиров wg (`peer_secrets`), SSH-ключи серверов
  (`servers.enc_key_pem`), конфиги каналов уведомлений, CA-ключи (`ca_material`),
  Xray-параметры и клиентские креды.

### 12.2 Сессии (`token.go`, `manager.go`)

- Токен = **32 случайных байта**, base64url (`token.go:26`). Это **непрозрачное**
  значение, внутри нет username/expiry.
- В БД хранится `HMAC-SHA256(raw)` в hex (`token.go:35`) — утечка строки `sessions`
  без знания `SESSION_SECRET` не даёт валидную cookie.
- `createSession` (`manager.go:97`): TTL `SessionTTL = 30 дней` (`manager.go:17`),
  `store.CreateSession(userID, hash, expiresAt)`.
- `Authenticate(raw)` (`manager.go:111`): перехэшировать cookie → `GetSession`.
- `Login` (`manager.go:64`): при несуществующем юзере всё равно считает bcrypt по
  `dummyHash` (`manager.go:19`) — защита от timing-энумерации. Если `TOTPEnabled` —
  возвращает `needTOTP=true` без сессии.
- `CompleteTOTPLogin` (`manager.go:86`), `ChangePassword` (`manager.go:127`,
  минимум 8 символов), `SeedAdmin` (`manager.go:44`, no-op если юзеры есть).

### 12.3 CSRF (`csrf.go`)

Stateless double-submit. Токен `<nonce>.<hmac(nonce)>` (nonce — 16 байт).
`Issue`/`Valid`/`Match` (`csrf.go:26-51`), сравнения константного времени
(`hmac.Equal`, `subtle.ConstantTimeCompare`). Без срока годности — валидность
только по подписи + совпадению cookie/формы.

### 12.4 TOTP (`totp.go`)

`github.com/pquerna/otp/totp`, issuer `"Protean"`. `GenerateTOTPSecret(account)`
даёт secret + `otpauth://` URL (secret не сохраняется до подтверждения).
`EnableTOTP` (`totp.go:33`) проверяет код и сохраняет secret с `enabled=true`;
`DisableTOTP` требует текущий пароль. Дефолты библиотеки: SHA1, 6 цифр, 30с.

### 12.5 Прочее

- **`password.go`**: bcrypt, `bcrypt.DefaultCost` (=10).
- **`ratelimit.go`**: `LoginLimiter` — in-memory **sliding-window** по IP;
  `NewLoginLimiter(5, 5*time.Minute)` в `server.go:147` (5 попыток за 5 мин).
  Считает **каждую** попытку логина (успех/неудача).
- **`pending.go`**: `PendingAuth` — короткоживущий (TTL 5 мин, `pending.go:22`)
  подписанный токен `base64url(username).expUnix.hmacSig`, несущий username между
  шагом пароля и шагом TOTP; клиент не может перескочить на 2FA или подменить
  username без прохождения пароля.

Поток логина в API: `handleLoginSubmit` (`handlers_auth.go:30`) → `auth.Login` →
если `needTOTP`, показать форму 2FA с `pending.Issue(username)` →
`handleLogin2FA` (`handlers_auth.go:62`) → `pending.Verify` + `CompleteTOTPLogin`.

---

## 13. Модель данных

Postgres, схема `wgpanel`. Раннер миграций — рукописный (`migrate.go`): таблица
`wgpanel.schema_migrations`, файлы из `embed` применяются в лексикографическом
порядке, каждый в своей транзакции с записью факта применения. Библиотеки миграций
нет намеренно (нужды малы и статичны).

Таблица по таблице (в скобках — миграция, где введена):

| Таблица | Миграция | Ключ | Назначение / заметки |
|---------|----------|------|----------------------|
| `users` | 0001 (+0006) | `id` | админы; `password_hash` (bcrypt); 0006 добавил `totp_secret`, `totp_enabled` |
| `sessions` | 0001 | `id`, uniq `token_hash` | серверные сессии; хранится HMAC токена, не сам токен; индекс по `expires_at` |
| `subnets` | 0001 (+0003) | `id` | каталог маршрутизируемых сайт-сетей; 0003 сделал его **mesh-wide** (снял per-provider scope, uniq по `cidr`) |
| `peer_secrets` | 0001 | `(provider, public_key)` | AES-зашифрованные приватные ключи пиров, сгенерированных панелью — единственное место с секретным ключевым материалом пиров |
| `audit_log` | 0002 | `id` | действия админов; индекс `ts DESC` |
| `conf_backups` | 0004 | `id` | pre-write снимки конфигов (панель не может писать в `/etc/wireguard`, только в сам файл) |
| `disabled_peers` | 0005 | `(provider, public_key)` | soft-disable для wg-family (у wg-quick нет состояния «выключен»): определение пира сташится здесь |
| `provider_settings` | 0007 | `provider` | per-provider тумблеры `mesh_enabled`, `internet_egress` (оба по умолчанию off) |
| `ca_material` | 0008 | `provider` | CA cert (открытый) + AES-ключ; `source` = `internal`\|`external` |
| `openvpn_clients` | 0008 (+0017) | `(provider, cn)` | выпущенный сертификат + AES-ключ + `address`/`subnets` (ccd/iroute) |
| `ikev2_clients` | 0009 (+0017) | `(provider, cn)` | как выше + `p12_password` (для повторного экспорта .p12) |
| `peer_expiry` | 0010 | `(provider, peer_id)` | опциональное истечение доступа; индекс по `expires_at` |
| `notify_channels` | 0011 | `kind` | per-канал `enabled` + AES-зашифрованный JSON конфига |
| `notify_settings` | 0011 (+0012,+0013) | singleton (`id=true`) | тумблеры событий и параметры email-отчёта; 0012 — гранулярный контент; 0013 — per-category события |
| `notify_pending` | 0011 | `id` | события, накопленные с последнего отчёта |
| `notify_peer_mute` | 0012 | `(provider, peer_id)` | заглушить конкретных пиров |
| `peer_category` | 0013 | `(provider, peer_id)` | `site`\|`client` (по умолчанию `client`) — для выбора событий |
| `revoked_certs` | 0014 | `(provider, serial)` | серийники отозванных сертификатов (десятичная строка big.Int) |
| `crl_number` | 0014 | `provider` | монотонный номер CRL на провайдера |
| `cert_server_routes` | 0015 | `provider` | последние применённые push-routes + egress cert-сервера (чтобы провайдер регенерировал конфиг без пересчёта API) |
| `servers` | 0016 | `id` (слаг) | удалённые хосты; AES-ключ SSH; `host_key` (пиннинг); `public_host` |
| `xray_instances` | 0018 | `provider` | одна активная стратегия на инстанс; `enc_params` (AES JSON), `enc_relay` (AES JSON RelaySpec, NULL=прямой egress) |
| `xray_clients` | 0019 | `(provider, name)` | клиенты (креды) на инстанс; `enc_cred` (AES JSON) |

### Scoping `server:instance` (миграция 0017)

`0017_server_scope.sql` — ключевая для multi-server:

- Добавляет колонку `provider` в `openvpn_clients`/`ikev2_clients` (были на голом
  `cn`) и перекраивает первичный ключ на `(provider, cn)`.
- Префиксует все provider-ключевые строки во **всех** таблицах на `default:`
  (`UPDATE ... SET provider = 'default:' || provider WHERE provider NOT LIKE '%:%'`).
  Guard `NOT LIKE '%:%'` делает миграцию идемпотентной.

Так одно-серверная установка бесшовно переезжает под сервер `default`, а строки
разных серверов больше не коллизируют.

---

## 14. Слой store

`internal/store` — pgx напрямую, рукописный SQL, без ORM (`store.go:1-4`). Один файл
на домен: `users.go`, `sessions.go`, `servers.go`, `subnets.go`, `secrets.go`
(`peer_secrets`), `disabled.go`, `expiry.go`, `certs.go` (`ca_material` + cert-клиенты),
`crl.go`, `provider_settings.go`, `notify.go`, `audit.go`, `backups.go`, `xray.go`,
`ikev2.go`.

Общие соглашения:

- `Open` (`store.go:21`) — pgxpool + ping. `Close` освобождает singleton-соединение
  и пул.
- `ErrNotFound` (`users.go:11`) — единая «строка не найдена»; методы мапят
  `pgx.ErrNoRows` в неё (образец `GetServer`, `servers.go:57`).
- Upsert через `INSERT ... ON CONFLICT ... DO UPDATE` (образцы `SaveXrayInstance`,
  `xray.go:19`; `SetProviderSettings`, `provider_settings.go:35`).
- «Отсутствует строка ⇒ дефолты» — важный паттерн: `GetProviderSettings`
  (`provider_settings.go:20`) при `ErrNoRows` возвращает `{false,false}` (standalone),
  а не ошибку.
- Все секретные поля (`enc_*`) — `BYTEA`, наполняются `Encryptor.Seal` в вызывающем
  коде; store сам не шифрует.

---

## 15. wg-family

`internal/vpn/wgfamily` — общий движок для WireGuard и AmneziaWG. Пакеты
`wireguard` и `amneziawg` — тонкие фабрики над ним.

### 15.1 Провайдер (`wgfamily/provider.go`)

- Структура — всего два поля: `opts Options` и `mu sync.Mutex` (`provider.go:72-80`).
  Мьютекс сериализует **каждое** чтение/RMW конфига, чтобы конкурентные админ-действия
  или пересекающийся поллинг статуса не потеряли пира и не увидели полузаписанный файл.
- `Options` (`provider.go:35-64`): `ProviderName` (=`Type()`), `InstanceID` (=`Name()`),
  `Interface`, `ConfPath`, `Binary` (`"wg"`/`"awg"`), `ServiceName`, `PublicHost`,
  `HandshakeOnlineWindow` (дефолт **180с**), `SSH` (SSHRunner), `Backup` (BackupSink).
- Все живые команды строятся как `sudo <Binary> ...`, например
  `sudo <Binary> show <iface> dump`, `sudo <Binary> set <iface> peer <pub> ...`,
  `sudo systemctl restart <ServiceName>`. Аргументы экранируются `sshexec.ShellQuote`.

Реализуемые интерфейсы: `vpn.Provider` целиком + `ForwardingManager`, `KeyRotator`,
`ConfiguredPeerAdder`, `ConfRestorer`, `NetworkController`, `ServiceNamed`. Cert- и
xray-специфичные интерфейсы **не** реализуются.

### 15.2 Парсинг `wg show dump` (`dump.go`)

`ParseDump` (`dump.go:32`): TSV. Строка 0 — интерфейс (PrivateKey, PublicKey,
ListenPort, FwMark). Далее пиры (≥8 полей): PublicKey, PresharedKey, Endpoint,
AllowedIPs (split по `,`), LatestHandshake (unix, 0 ⇒ zero-time), RxBytes, TxBytes,
PersistentKeepalive (`off` ⇒ 0). Литерал `(none)` → пустая строка (`noneEmpty`).

**Online** определяется в провайдере, не в dump: пир онлайн, если
`!LatestHandshake.IsZero() && LatestHandshake.After(now - HandshakeOnlineWindow)`
(`provider.go:189-196`, `222`).

### 15.3 Парсинг/рендер конфига и firewall (`conf.go`)

- Модель: `KV{Key,Value}` (упорядоченная пара), `ConfPeer{Name, Opts}`,
  `ConfFile{InterfaceOpts, Peers}`. Имя пира хранится как комментарий `# Name: <name>`
  прямо над блоком `[Peer]` (конвенция панели — у wg нет понятия имени). Прочие
  комментарии теряются на round-trip.
- `ParseConf` (`conf.go:32`) / `Render` (`conf.go:84`) — построчно.
- **Управляемые правила firewall** помечаются тегом-подстрокой `protean`:
  - iptables (`iptablesRules`, `conf.go:166`): PostUp/PostDown с
    `iptables -I FORWARD -i/-o %i -j ACCEPT -m comment --comment protean-fwd`; при
    egress добавляется NAT `-t nat -A POSTROUTING -s <tunnelCIDR> -o <wanIface> -j
    MASQUERADE -m comment --comment protean-nat`.
  - nft (`nftRules`, `conf.go:186`): per-interface таблица `inet protean_%i` (в имени
    есть подстрока `protean`, поэтому `isManagedRule` её узнаёт); PostDown сносит всю
    таблицу.
  - `isManagedRule` (`conf.go:141`): ключ `PostUp`/`PostDown` **и** значение содержит
    `protean`. Правила оператора не трогаются.
- Выбор бэкенда: `firewallBackend` (`provider.go:509`) — `iptables`, если
  `command -v iptables` успешен, иначе `nft`.
- `SetManagedNetworking` (`conf.go:148`): сначала `dropManaged` (снять старые
  Post*-строки с тегом), затем добавить нужные (идемпотентно).

### 15.4 Запись с откатом

- `writeConf` (`provider.go:124`): читает текущий конфиг с хоста как `prev`, при
  наличии `Backup` — best-effort `SaveConfBackup` (сбой бэкапа только предупреждает),
  затем `WriteFile(ConfPath, Render())`.
- `writeConfAndApply`: `writeConf` → `applyPeerLive`. Если live-apply упал и `prev`
  известен — пишет `prev` обратно (откат), гарантируя, что on-disk не разойдётся с
  живым состоянием; при сбое самого отката — `slog.Error` о возможной дивергенции.

### 15.5 Ключи (`keys.go`)

`GenerateKeyPair` (`keys.go:13`): 32 случайных байта, кламп по RFC 7748
(`priv[0] &= 248; priv[31] &= 127; priv[31] |= 64`), публичный =
`curve25519.X25519(priv, Basepoint)`, оба в base64 (как `wg genkey`/`pubkey`).
Генерации preshared-ключей здесь нет.

### 15.6 Различия wireguard vs amneziawg

Обе фабрики (`wireguard.New`, `amneziawg.New`) имеют одинаковую сигнатуру и делегируют
`wgfamily.New`. Разница только в `Options`:

| Опция | wireguard | amneziawg |
|-------|-----------|-----------|
| ProviderName / `Type()` | `wireguard` | `amneziawg` |
| Binary | `wg` | `awg` |
| ServiceName | `wg-quick@<iface>` | `awg-quick@<iface>` |

Поля обфускации AmneziaWG (`Jc,Jmin,Jmax,S1,S2,H1..H4`, `amneziawg.go:19`) проходят
generic-путём через `ServerConfig.Extra` → `InterfaceSet(k,v)` в
`UpdateServerConfig` (`provider.go:447`); спец-кода под них нет. Пути конфигов задаёт
Manager: `/etc/wireguard/<iface>.conf` и `/etc/amnezia/amneziawg/<iface>.conf`
(`servers/manager.go:178-183`).

---

## 16. PKI и cert-провайдеры

### 16.1 `internal/vpn/pki`

Крошечный x509-CA на Go (без easy-rsa). Ключ CA хранит вызывающий (зашифрованным, в
БД). Один и тот же код выпуска обслуживает и внутренний, и внешний (BYOC) CA.

- **Интерфейс `CertAuthority`** (`pki.go:34-40`): `CACertPEM()`,
  `IssueServer(cn, dnsNames, ips, validFor)`, `IssueClient(cn, validFor)`.
  `SignCSRWithCN`, `CAKeyPEM`, `CreateCRL` — методы конкретного `*CA`, не входят в
  интерфейс.
- Константы: `rsaBits = 2048`, CN CA = `"Protean CA"`.
- `NewInternalCA(validFor)` (`pki.go:58`): RSA-2048, 128-битный серийник, self-signed,
  `KeyUsage = CertSign|CRLSign`, `IsCA=true`, `MaxPathLenZero=true` (не может выпускать
  под-CA), без EKU.
- `LoadCA(caCertPEM, caKeyPEM)` (`pki.go:95`, BYOC): парсит cert+RSA-ключ, отвергает
  если `!IsCA`.
- `IssueServer` (`pki.go:115`) — EKU `ServerAuth` + SAN (dnsNames/ips);
  `IssueClient` (`pki.go:123`) — EKU `ClientAuth`. Оба через `issue` (`pki.go:209`):
  свежий RSA-2048-лист, серийник 128 бит, `NotBefore = now-1h`, `NotAfter = now+validFor`,
  `KeyUsage = DigitalSignature|KeyEncipherment`.
- `SignCSRWithCN(csrPEM, cn, validFor)` (`pki.go:132`): парсит CSR, проверяет
  `CheckSignature()` (клиент владеет ключом), CN форсится на переданный (subject CSR
  игнорируется), EKU `ClientAuth`. Возвращает только cert (ключ остаётся у клиента).
- `CreateCRL(revoked, number, thisUpdate, nextUpdate)` (`pki.go:175`) — подписанный
  `X509 CRL`, монотонный `Number`.
- `SerialFromCertPEM(certPEM)` (`pki.go:201`) — серийник сохранённого сертификата для
  записи отзыва.

Валидности в провайдерах: `caValidity = 10 лет`, `leafValidity = 2 года`
(`openvpn/provider.go:94`, `ikev2/provider.go:83`).

### 16.2 OpenVPN (`internal/vpn/openvpn`)

Дизайн — см. [ARCHITECTURE-openvpn-ikev2.md](ARCHITECTURE-openvpn-ikev2.md); здесь код.

- `Options` (`provider.go:50`): Instance, Interface, ConfPath, ServerDir, CCDDir,
  StatusPath, ServiceName, PublicHost, ListenPort, Proto, ServerNet, ServerMask, SSH,
  Store, Enc. `Provider{opts, mu, ca}`. Реализует `ServiceNamed`,
  `ClientConfigProvider`, `CAImporter`, `CSRSigner`, `ServerProvisioner`.
  **Не** реализует ForwardingManager/NetworkController (mesh-FORWARD для cert идёт
  через installer, [§18](#18-mesh-и-маршрутизация)).
- `EnsureServer` (`provider.go:441`): грузит/создаёт CA, выпускает серверный
  сертификат, генерит tls-crypt (если нет валидного), `rebuildCRL` (всегда пишет
  хотя бы пустой валидный CRL), пишет `ca.crt/server.crt/server.key/tls-crypt.key/
  crl.pem`, `mkdir -p ccd`, рендерит и пишет server.conf (`crl-verify`,
  `client-config-dir`, `client-to-client`, `topology subnet`, push-routes,
  `redirect-gateway` при egress), `systemctl enable --now` + `restart`.
- `AddPeer` (`provider.go:248`): `IssueClient(cn)`, `Seal` ключа,
  `splitClientAllowedIPs` → адрес (host-route) + subnets, `writeCCD`
  (`ifconfig-push` + `iroute`), `SaveOpenVPNClient`. Рестарт не нужен (OpenVPN читает
  ccd на подключении).
- `AddPeerFromCSR` (`provider.go:288`): `SignCSRWithCN`, сохраняет клиента с **nil**
  ключом ⇒ в `.ovpn` нет `<key>`.
- `ClientConfigFile` (`provider.go:397`): `.ovpn` с инлайновыми
  `<ca>/<cert>/<key>/<tls-crypt>` (`bundle.go`).
- `ParseStatus` (`status.go:27`): строки `CLIENT_LIST`, авто-детект разделителя
  (tab v3 / запятая v2).
- Отзыв: `RemovePeer` → `revoke` → `AddRevokedCert` + `rebuildCRL` (OpenVPN
  перечитывает CRL на новом подключении, без рестарта).

### 16.3 IKEv2 / strongSwan (`internal/vpn/ikev2`)

- `Options` (`provider.go:48`): Instance, ConnName (дефолт `protean`), SwanctlDir,
  ServiceName (`strongswan`), ServerID (public host / SAN), Pool, DNS, SSH, Store, Enc.
  Реализует `ServiceNamed`, `ClientConfigProvider`, `ClientProfileProvider`,
  `ServerProvisioner`, `CAImporter`, `CSRSigner`.
- `EnsureServer` (`provider.go:426`): CA, серверный сертификат, каталоги
  `x509ca/x509/private/conf.d/x509crl`, файлы CA/сервера, CRL, `SaveServerRoutes`,
  `systemctl enable --now`, `writeConnAndLoad`.
- `swanctl.go` `RenderConnections`: общая road-warrior connection (без `remote.id`)
  + по одной connection на сайт `<conn>-<cn>`, матченной по `remote.id = CN` и
  анонсирующей `remote_ts = subnets` (strongSwan предпочитает более специфичную).
  Файл `/etc/swanctl/conf.d/<ConnName>.conf` **полностью** регенерируется и
  `swanctl --load-all` на каждом add/update/remove пира.
- Профили (`profiles.go`): `.mobileconfig` (Apple: payload PKCS#12 + IKEv2 VPN) и
  `.sswan` (strongSwan Android JSON). UUID детерминированно из CN (`uuidFrom`), оба
  встраивают p12 ⇒ недоступны для CSR-клиентов.
- `p12.go` `BuildP12` — `pkcs12.Modern.Encode`, пароль на клиента случайный
  (`randPassword`, 24 hex), хранится в `ikev2_clients.p12_password` для повторной
  выгрузки.
- `listsas.go` `ParseListSAs` — best-effort парс `swanctl --list-sas` (ключ на
  `ESTABLISHED` + идентичность в кавычках); формулировки зависят от версии strongSwan.
- Отзыв: `rebuildCRL` → `x509crl/crl.pem` + `swanctl --load-all` (плагин revocation).

`cert_server_routes`: и OpenVPN, и IKEv2 персистят push-routes/egress через
`SaveServerRoutes`/`GetServerRoutes` (`storeadapter.go`), чтобы регенерировать
конфиг автономно (без пересчёта mesh-маршрутов API-слоем).

---

## 17. Модуль Xray

`internal/vpn/xray` — DPI-устойчивые протоколы (VLESS+Reality, VMess, Trojan,
Shadowsocks). Провайдер управляет клиентами через **свою** страницу, а не через
generic peer-flow (`provider.go:88-99` возвращает `ErrNotImplemented`).

### 17.1 Интерфейс `Strategy` (`xray.go:59-77`)

```go
type Strategy interface {
    Name() string                                                    // слаг, ключ реестра
    Label() string                                                   // строка UI
    Params() []ParamSpec                                             // транспортные параметры оператора
    Cred() CredKind                                                  // CredUUID | CredPassword
    MultiClient() bool                                               // >1 клиент?
    BuildInbound(p Params, clients []Client) (map[string]any, error) // inbound для config.json
    ClientLink(p Params, c Client, host string) (string, error)      // share-ссылка клиента
}
```

Типы: `ParamSpec{Key,Label,Placeholder,Default,Required,Secret}` (`xray.go:18`);
`Params map[string]string` с `Value(key)` (`xray.go:40`); `Client{Name,UUID,Password}`
(`xray.go:42`); `CredKind` (`CredUUID=0`, `CredPassword=1`, `xray.go:51`). Хелперы
`requireParams` (`xray.go:150`), `needClients` (`strategies.go:89`).

### 17.2 Реестр (compile-time) и 6 стратегий

`registry map[string]Strategy` + `Register(s)` / `Get(name)` / `All()`
(`xray.go:79-95`). Регистрация — в **едином `init()`** (`strategies.go:386`):

| Name() | Label() | Протокол | Cred | Multi |
|--------|---------|----------|------|:-:|
| `reality-vless-tcp` | VLESS + Reality (TCP) — max stealth | VLESS+Reality/TCP, flow xtls-rprx-vision | UUID | ✓ |
| `vless-vision-tls` | VLESS + Vision (TLS) | VLESS+XTLS-Vision/TLS | UUID | ✓ |
| `vmess-ws-tls` | VMess + WebSocket + TLS (CDN) | VMess+WS+TLS | UUID | ✓ |
| `trojan-tcp-tls` | Trojan (TLS) | Trojan+TCP+TLS | Password | ✓ |
| `shadowsocks-2022` | Shadowsocks 2022 (single client) | SS 2022 | Password | ✗ |
| `vless-grpc-tls` | VLESS + gRPC + TLS | VLESS+gRPC+TLS | UUID | ✓ |

### 17.3 Крипто-хелперы (`xray.go`)

- `NewUUID()` (`xray.go:101`) — RFC-4122 v4.
- `GenRealityKeypair()` (`xray.go:120`) — `ecdh.X25519`, ключи в base64 RawURL;
  приватный → server config, публичный → client link.
- `NewShortID()` (`xray.go:133`) — 8 байт hex (Reality shortId).
- `NewPassword(n)` (`xray.go:142`) — n байт hex.

### 17.4 Сборка config.json и relay-цепочки (`config.go`)

- `BuildServerConfig(inbounds, relay)` (`config.go:25`): `log`+`inbounds`+`outbounds`.
  Если `relay != nil` — outbounds `[relay, freedom, blackhole]` и routing-правило,
  гонящее **весь** tcp/udp egress через `relay` (без прямого fallback — egress должен
  уйти за рубеж). Иначе `[freedom, blackhole]` без routing.
- `RelaySpec{Strategy, Host, Params}` (`config.go:64`).
- `BuildRelayOutbound(spec)` (`config.go:74`): собирает **исходящий** (dial) outbound
  для foreign-egress relay. Поддержаны reality-vless / vless-vision / vless-grpc /
  trojan / shadowsocks; **VMess как relay не поддержан** (default → ошибка). Это —
  реализация «цепочек туннелей через зарубежный relay».

### 17.5 Парсинг ссылок (`parse.go`)

`ParseClientLink(link)` (`parse.go:15`): `vless://` / `trojan://` / `ss://`
(SIP002). Выбирает стратегию по признакам (`security=reality`, `type=grpc`, …) и
достаёт креды/SNI/pbk/sid. Используется для импорта relay-ссылки.

### 17.6 Провайдер (`provider.go`)

- `Options{Instance("xray"), ConfigPath("/usr/local/etc/xray/config.json"),
  ServiceName("xray"), PublicHost, SSH, Store, Enc}`.
- Xray-специфичный API: `Apply(strategy, params, relay)` (`provider.go:104`),
  `AddClient(name)` (`:139`), `RemoveClient(name)` (`:172`), `ClientLinks` (`:186`),
  `Subscription` (`:212`, base64 всех ссылок для Happ/v2rayN/nekoray),
  `Current` (`:226`).
- `rebuild` (`provider.go:232`): instance → strategy → clients → `BuildInbound` →
  (relay) `BuildRelayOutbound` → `BuildServerConfig` → `WriteFile(ConfigPath)` →
  `systemctl enable --now` + `restart`.
- Хранение под пломбой: `enc_params`, `enc_relay`, и **каждый** клиент как отдельный
  AES-JSON-блоб (`saveClient`, `provider.go:315`). `ensureInstanceCrypto`
  (`provider.go:347`) генерит/сохраняет Reality-ключи и shortId (только для
  `reality-vless-tcp`); `instanceCryptoKeys` (`provider.go:368`) сохраняются между
  re-apply одной стратегии.

### 17.7 Рецепт: новая стратегия

1. В `strategies.go` — пустой struct `type myProtoTLS struct{}`.
2. Реализуй все 7 методов (value-receiver, stateless):
   - `Cred()` решает, какой кредо генерит `AddClient` (`NewUUID` vs `NewPassword(16)`)
     и какое поле `Client` заполняется.
   - `MultiClient()==false` ⇒ `AddClient` отвергнет второго клиента; тогда
     `BuildInbound` использует `clients[0]` (образец `shadowsocks2022`).
   - `Params()` — **только** транспортные параметры (не креды и не генерируемые
     Reality-ключи). Переиспользуй константы ключей `pXxx` (`strategies.go:14-31`),
     помечай пароли `Secret: true`.
   - `BuildInbound` — сначала `requireParams(...)` и `needClients(...)`, затем верни
     inbound-map (listen/port/protocol/settings/streamSettings).
   - `ClientLink` — собери share-ссылку (переиспользуй `vlessLink`/`trojanLink`).
3. Зарегистрируй: `Register(myProtoTLS{})` в существующем `init()` (`strategies.go:386`).
   Это **единственный** шаг регистрации; `All()`/`Get()` подхватят.
4. Если нужны инстанс-секреты (как Reality-ключи) — расширь `ensureInstanceCrypto`
   и `instanceCryptoKeys` (`provider.go:347`, `:368`).
5. Если стратегия должна работать egress-relay'ем — добавь `case` в
   `BuildRelayOutbound` (`config.go:77`) и (для импорта ссылки) ветку в `parse.go`.
6. `Apply/AddClient/rebuild/ClientLinks/Subscription` менять не нужно — они
   strategy-agnostic и работают через интерфейс + реестр.

Ключевое ограничение: per-client креды живут в `Client`, никогда в `Params`
(relay-ключи `pUUID`/`pPassword` — только для одиночного relay-dial).

---

## 18. Mesh и маршрутизация

Концепция и топологии — [TOPOLOGIES.md](TOPOLOGIES.md) и
[ARCHITECTURE-openvpn-ikev2.md](ARCHITECTURE-openvpn-ikev2.md). Код — `internal/api/mesh.go`.

- **Mesh — per-provider тумблер** (`provider_settings.mesh_enabled`, по умолчанию
  off = standalone параллельный туннель). Mesh-способные типы:
  `meshCapableTypes = {wireguard, amneziawg, openvpn, ikev2}` (`api/providers.go:84`).
- **Плоскость маршрутизации** — `routesForPeer` / `computeRoutes` (`mesh.go:143-205`):
  клиент получает AllowedIPs = свой туннель + все каталожные сайт-сети + (если
  mesh-enabled) туннели **других** mesh-enabled провайдеров **того же сервера** +
  (если egress) `0.0.0.0/0`, минус то, что клиент сам приносит. Это и делает клиента
  WireGuard и клиента AmneziaWG взаимно достижимыми без NAT.
- **Плоскость данных**:
  - wg-family управляет FORWARD/NAT своими PostUp/PostDown (см. [§15.3](#153-парсингрендер-конфига-и-firewall)).
  - cert-провайдеры **не** реализуют `ForwardingManager`; их mesh-FORWARD ставится
    внешне через installer: `applyCertMeshForwarding` (`mesh.go:74`) →
    `inst.Forward(ctx, add|del, cidr)`. Правило key'ится на subnet (имя tun/pool не
    фиксировано), без NAT.
  - `ReapplyMeshForwarding` (`mesh.go:103`) переустанавливает эти правила на старте
    (не переживают reboot).
- **Hot-apply**: смена mesh/egress на странице Network cert-провайдера
  автоматически ре-провизит сервер (`provisionCert`, `handlers_setup.go:14`) со
  свежими push-routes/egress + mesh-FORWARD. Для wg-family egress — host-изменение
  (NAT + рестарт интерфейса) через `NetworkController.ApplyNetworking`
  (`handlers_network.go:96-107`).
- **Overlap-контроль** (`internal/vpn/overlap.go`): `CIDROverlap` /
  `CheckNoOverlap` — пересекающиеся подсети ломают no-NAT маршрутизацию
  (неоднозначный destination), поэтому отвергаются/выделяются в UI (`handlers_mesh.go:68`).
- **Ограничение**: mesh сейчас **per-server** (`meshCapableInstances(serverID)`,
  `api/providers.go:92`). Cross-host mesh — отдельная будущая фича ([§26](#26-известные-ограничения-и-backlog)).

---

## 19. Подсистема уведомлений

Пакет `internal/notify` + оркестрация в `internal/api/notify.go`.

- **Интерфейс `Channel`** (`notify/notify.go:20`): `Kind()`, `Send(ctx, Message)`.
  `Message{Subject, Body}`. Отдельных Dispatcher/Multi нет.
- **Виды** (`notify.go:27`): `telegram`, `mattermost`, `rocketchat`, `vocechat`,
  `xmpp`, `email`. Фабрика `New(kind, cfg map[string]string)` (`notify.go:44`).
- Каналы:
  - `webhookChannel` (`webhook.go:51`) — Mattermost и Rocket.Chat (оба принимают
    `{"text":...}`);
  - `telegram` — Bot API `sendMessage`;
  - `voceChat` — POST `text/plain` с заголовком `x-api-key`;
  - `xmppChannel` (`xmpp.go`) — свежее соединение на сообщение, StartTLS;
  - `email` (`email.go`) — `net/smtp`, RFC822, PlainAuth если задан user.
- **Модель конфига**: `notify_channels` (per-kind `enabled` + AES-JSON конфиг),
  `notify_settings` (singleton: тумблеры событий + email-отчёт), `notify_pending`
  (буфер отчёта), `notify_peer_mute`, `peer_category`.
- **События** (не CRUD, а **производные** от поллинга статуса): interface up/down;
  connect/disconnect, разбитые по категории пира (`site`/`client`); «неизвестный/
  чужой пир подключился». Логика — `watchTick` (`api/notify.go:111`).
- **Диспетчеризация**: `emit(text)` (`api/notify.go:59`) — цикл по `AllKinds()`,
  **email пропускается** (он только для отчёта), каждый канал строится заново и
  `Send`; при `ReportEnabled` текст добавляется в `notify_pending`.
- **Отчёт**: `maybeSendReport` (`api/notify.go:246`) — по расписанию
  (`ReportIntervalHours`) собирает статус + события с прошлого отчёта и шлёт email.
- **Секреты**: конфиги каналов пломбируются `enc.Seal`/`enc.Open`
  (`encodeChannelConfig`/`decodeChannelConfig`, `api/notify.go:17-35`).

> Замечание для разработчика (факт из кода): `notify.AllKinds()` (`notify.go:36`)
> сортирует **копию** и возвращает несортированный оригинал — сортировка на
> возвращаемое значение не влияет. Порядок фактически = порядок объявления
> `ks`. Если нужна детерминированность — чинить здесь.

---

## 20. Контракт installer-скрипта

`scripts/protean-installer.sh` — единственная привилегированная поверхность на хосте.
Кладётся `setup-host.sh` root-owned по фиксированному пути
`InstallerPath = /usr/local/lib/protean/protean-installer.sh`
(`internal/vpn/installer.go:14`), NOPASSWD-sudo даётся только на него.

Go-обёртка — `vpn.Installer` (`installer.go`), `NewInstaller(ssh)`; каждый метод
выполняет `sudo <InstallerPath> <verb> <args...>` по SSH. Ровно **5 вербов**:

| Верб | Go-метод | Команда | Аргументы / валидация |
|------|----------|---------|-----------------------|
| `detect` | `Detect(ctx)` | `sudo … detect` | нет; вывод = JSON `HostInfo` (os_family, pretty_name, pkg_manager, systemd, supported, providers{installed,installable}) |
| `install` | `Install(ctx, provider)` | `sudo … install <provider>` | provider ∈ `^(wireguard\|amneziawg\|openvpn\|ikev2\|xray)$` |
| `status` | `ServiceStatus(ctx, unit)` | `sudo … status <unit>` | unit по regex; возвращает active/inactive/unknown |
| `service` | `Service(ctx, action, unit)` | `sudo … service <action> <unit>` | action ∈ start\|stop\|restart\|enable\|disable; enable/disable = `--now` |
| `forward` | `Forward(ctx, action, cidr)` | `sudo … forward <add\|del> <cidr>` | action ∈ {add,del}; cidr = IPv4-CIDR; ставит FORWARD-accept на subnet, **без NAT** |

Скрипт валидирует ещё раз на своей стороне (defense-in-depth, `protean-installer.sh:310-347`):
`VALID_PROVIDER`, `VALID_UNIT`, `VALID_ACTION`, `VALID_CIDR`, `VALID_FWD`. Установка
пакетов — через определённый пакетный менеджер (apt/dnf/yum/pacman/zypper); Xray —
через официальный get-скрипт; часть провайдеров недоступна на некоторых ОС
(например AmneziaWG требует AUR-хелпера на Arch, нет пакета на SUSE).

**Важно**: отдельного верба `nat` нет; egress-NAT для wg-family делается через
PostUp/PostDown внутри самого wg-конфига (не через installer). `forward` умеет только
add/del FORWARD-accept и сознательно не трогает NAT.

Установку/детект оркестрирует `handlers_providers.go` (`Install` работает над
**типом**, не инстансом; `Detect` наполняет страницу Install).

---

## 21. Клиентские конфиги, IPAM, overlap

- **`internal/vpn/clientconfig`**: `Build(Params)` (`clientconfig.go:27`) собирает
  текст wg-конфига (`[Interface]` PrivateKey/Address/DNS/Extra + `[Peer]`
  PublicKey/Endpoint/AllowedIPs/PersistentKeepalive). `Extra` — точка вставки
  obfuscation-полей AmneziaWG. `QRPNG(text)` (`clientconfig.go:51`) — QR-PNG
  (go-qrcode, Medium, 320px). Отделён от провайдеров, потому что политику маршрутов
  (`AllowedIPs`) решает API-слой (`buildClientConfigText`, `handlers_peers.go:553`),
  а не провайдер.
- **`internal/vpn/ipam.go`**: `FirstCIDR(addr)` — первый (IPv4) элемент dual-stack
  строки; `NextFreeIP(cidr, used)` (`ipam.go:23`) — первый свободный /32 (или /128)
  в подсети, пропуская сетевой адрес (broadcast/gateway **не** пропускаются).
- **`internal/vpn/overlap.go`**: `CIDROverlap(a,b)` (одна сеть содержит базовый адрес
  другой), `CheckNoOverlap(candidate, existing)`.

---

## 22. UI: SPA, статика, embed

- `internal/web/web.go`: `//go:embed dist` — весь собранный React+AntD SPA
  (`frontend/`, см. `frontend/vite.config.ts`, выход прямо в
  `internal/web/dist`). `SPAAssetsHandler()`/`SPAFontsHandler()` отдают
  `dist/assets/*`/`dist/fonts/*` под `/assets/`/`/fonts/`;
  `ServeIndexHTML`/`ServeLoginHTML`/`ServePortalHTML` отдают
  `index.html`/`login.html`/`portal.html` (три отдельных Vite-входа — админка,
  standalone логин, standalone портал).
- Раньше здесь были server-side `html/template` шаблоны — их больше нет,
  вся отрисовка на клиенте, панель отдаёт только собранный SPA.
- Смоук-тесты SPA-шелла/маршрутов: `internal/api/routes_smoke_test.go`
  (`TestSPAFallbackServesShellWithoutSession`, `TestLoginPageIsPublic`) —
  требуют реальный `dist/index.html`/`dist/login.html` (или хотя бы
  заглушку, см. §24) иначе не скомпилируются вообще, не просто упадут.

---

## 23. Метрики и health

- **`/healthz`** (`handlers_auth.go:12`) — неаутентифицированный. БД обязательна
  (503, если недоступна). Недоступность хоста по SSH **не** валит проб (иначе
  контейнер перезапускался бы из-за удалённой проблемы): 200 + `ok (host degraded: …)`.
  Агрегатное здоровье хостов кэшируется (`hostHealthy`, `server.go:86`, дефолт 10с).
- **`/metrics`** (`handlers_metrics.go`, формат Prometheus) — под Bearer-токеном
  `METRICS_TOKEN` (пусто ⇒ endpoint выключен). Сбор — `gatherMetrics`
  (`metrics.go:21`): `protean_up`, per-interface up/port/peers/rx/tx, per-peer
  online/handshake/rx/tx, per-server host_up + SSH-счётчики, HTTP-счётчики, Go
  runtime. Рендер — `renderMetrics` (`metrics.go:134`) с HELP/TYPE и стабильной
  сортировкой (юнит-тестируемо).
- HTTP-метрики собирает middleware `withMetrics` (`server.go:292`).

---

## 24. Сборка, запуск, тесты

Полностью описано в [TESTING.md](../TESTING.md); краткая выжимка:

Самый короткий путь с чистого клона: `make test`, `make build`, `make dev`
(см. `Makefile`) — дальше расписано, что каждая цель делает под капотом, на
случай если нужен более тонкий контроль.

Локальная сборка/запуск:

```sh
cd frontend && npm ci && npm run build && cd ..  # заполняет internal/web/dist (go:embed)
go build ./cmd/panel                 # статический бинарь (CGO off в Docker)
go vet ./...
```

`internal/web/dist` не хранится в git (`.gitignore`) — это выходные файлы
`vite build`, встраиваемые через `go:embed` в `internal/web/web.go`; без
предварительной сборки фронтенда `go build ./cmd/panel` упадёт с "pattern
dist: no matching files found" — причём это ошибка КОМПИЛЯЦИИ, не теста, и
затрагивает весь `internal/api` (импортирует `internal/web`), не только
`cmd/panel`. Сборка через Docker (`docker compose ... up --build`) делает
это автоматически (см. `Dockerfile`'s multi-stage build).

Тесты:

```sh
./scripts/ensure-frontend-dist.sh    # no-op если реальная сборка уже есть
go test -race ./...                  # юнит + in-process интеграция (без внешних служб)
```

`ensure-frontend-dist.sh` кладёт минимальную заглушку (`index.html`/
`login.html`/`portal.html` + пустые `assets/`/`fonts/`) — этого достаточно
чтобы пакет скомпилировался и два SPA-shell смоук-теста прошли, реальную
сборку никогда не перезаписывает.

Покрывает чистую логику, парсеры/билдеры, PKI, notify (httptest), API-слой и
**SSH-клиент end-to-end** против in-process SSH-сервера.

- **Store-интеграция** (тег `dbtest`) — против настоящего Postgres на порту 5433:

```sh
docker compose -f docker-compose.test.yml up -d
PROTEAN_TEST_DB='postgres://wgpanel:wgpanel@localhost:5433/wgpanel?sslmode=disable' \
  go test -tags dbtest ./internal/store/
docker compose -f docker-compose.test.yml down -v
```

Схема дропается и ре-мигрируется в начале прогона; без `PROTEAN_TEST_DB` тесты
скипаются (а не падают).

- **WireGuard-интеграция** (тег `integration`, нужен root + `wg`/`ip`):

```sh
sudo PROTEAN_INTEGRATION=1 go test -tags integration ./internal/vpn/wgfamily/ -run Integration -v
```

Гоняет в одноразовом network namespace.

- **Xray** — юнит-тесты пакета `internal/vpn/xray` (`*_test.go`).

Docker (весь app):

```sh
docker compose up --build -d
curl -fsS localhost:8080/healthz
docker compose down -v
```

Полный список ENV — в `internal/config/config.go` и `.env.example`:

`DATABASE_URL`, `SSH_HOST`, `SSH_PORT`, `SSH_USER`, `SSH_KEY_PATH`, `SSH_HOST_KEY`,
`SSH_KNOWN_HOSTS`, `SSH_CMD_TIMEOUT`, `SESSION_SECRET`, `SECRET_KEY`, `PUBLIC_HOST`,
`LISTEN_ADDR`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `WG_INTERFACES`/`WG_INTERFACE`,
`AWG_INTERFACES`/`AWG_INTERFACE`, `OVPN_INSTANCE`/`OVPN_PORT`/`OVPN_PROTO`/
`OVPN_SERVER_NET`/`OVPN_SERVER_MASK`, `IKEV2_POOL`/`IKEV2_DNS`, `METRICS_TOKEN`,
`TRUST_PROXY`, `LOG_LEVEL`, `LOG_FORMAT`.

Обязательны всегда: `DATABASE_URL`, `SESSION_SECRET`, `SECRET_KEY`. `SSH_*` опциональны
(серверы добавляются в UI); если задан `SSH_HOST`, то обязательны его спутники
`SSH_USER`/`SSH_KEY_PATH`/`PUBLIC_HOST` (seed сервера `default`). Валидация на старте:
`SECRET_KEY` ровно 64 hex, `SESSION_SECRET` ≥16, корректность CIDR/proto.

---

## 25. Соглашения по коду

Наблюдаемые в репозитории паттерны — держись их при расширении:

- **Узкие интерфейсы у потребителя**, а не у поставщика: каждый провайдер объявляет
  собственные `SSH`/`Sealer`/`Store` внутри своего пакета (образцы
  `openvpn/provider.go:18-42`, `ikev2`, `xray`) и получает конкретные типы через
  адаптеры. Разрывает циклы импорта и упрощает моки.
- **Опциональные фичи — через capability-интерфейсы и type-assertion**, не через
  «толстый» базовый интерфейс.
- **Инвариант «пир существует ⟺ его ключ сохранён»**: при сбое сохранения секрета
  создание пира откатывается `RemovePeer` (`handlers_peers.go:230-241`, аналогично
  rotate). Записи на хост с откатом — `writeConfAndApply` (wg-family).
- **Секреты никогда в открытом виде в БД**: всё через `Encryptor.Seal`; поля `enc_*`
  = `BYTEA`.
- **Best-effort побочки** (аудит, бэкап конфига, mesh-FORWARD, буфер отчёта) логируют
  ошибку, но не валят основное действие (`audit.go:11`, `writeConf`).
- **Кэш сбрасывается сразу после мутации** (`s.invalidateStatus`).
- **Локаль-независимый парсинг**: удалённые команды идут с `LC_ALL=C LANG=C`; наличие
  интерфейса проверяется по exit-коду `ip link`, а не по тексту ошибки.
- **Идемпотентные миграции**, каждая в транзакции; guard-условия (`NOT LIKE '%:%'`,
  `IF NOT EXISTS`) для безопасного повтора.
- **Один файл — один домен** в `store/` и `api/`.
- **Структурное логирование** `slog` с key-value; `fatal` только на старте.
- **Стабильная сортировка вывода** там, где его читают тесты (метрики, рендер).

---

## 26. Известные ограничения и backlog

- **Cross-host mesh не реализован.** Mesh считается per-server
  (`meshCapableInstances(serverID)`, `api/providers.go:92`); туннели провайдеров
  **разных** хостов в один L3 без NAT сейчас не сливаются панелью. Роутер-сайд-мердж
  (topology B, [TOPOLOGIES.md](TOPOLOGIES.md)) — рабочая альтернатива. См. также
  auto-memory `relay-chaining-and-happ.md` (foreign-egress relay + возможные
  DPI-устойчивые протоколы) — Xray-relay уже частично закрывает эту потребность.
- **Один набор провайдеров на сервер** (`servers.Template`): несколько инстансов
  одного типа настраиваются только для wg-family (список интерфейсов); для
  OpenVPN/IKEv2/Xray — по одному инстансу на хост. Мульти-инстанс cert/xray —
  большее изменение (см. заметку в [ARCHITECTURE-openvpn-ikev2.md](ARCHITECTURE-openvpn-ikev2.md)).
- **`ReconcileState` только логирует**, не чинит расхождения БД↔хост (осознанно).
- **Парсер `swanctl --list-sas` best-effort** — формулировки зависят от версии
  strongSwan; online-статус IKEv2-пиров может быть неточным.
- **VMess нельзя использовать как egress-relay** (`config.go` default → ошибка).
- **step-ca ACME CertAuthority** — запланированная, но не реализованная реализация
  интерфейса (панель тогда не держала бы приватный ключ CA вовсе); интерфейс
  `pki.CertAuthority` уже под это сформирован.
- **`internal/webtls` ACME-режим не проверен вживую.** Панель умеет выпускать
  сертификат через generic ACME (Let's Encrypt prod/staging или свой ACME-сервер,
  например step-ca) — `internal/webtls/manager.go`, `buildACMEManager` — код
  собран и покрыт юнит-тестами (в т.ч. поведение при недоступности/ошибке ACME:
  откат на постоянный self-signed фолбэк), но реальный round-trip выпуска
  сертификата **ни разу не гонялся против настоящего CA**: для этого нужен
  реальный публичный домен с DNS, указывающим на хост, и открытый наружу порт
  80 (HTTP-01) или 443 (TLS-ALPN-01) — ничего из этого недоступно в текущей
  dev-песочнице. Перед тем как полагаться на ACME-режим в проде — проверьте
  его один раз вручную (проще всего через `acme_directory_url` = LE **staging**,
  чтобы не упереться в rate-limit) и только затем переключайтесь на прод-URL.
- **`notify.AllKinds()` возвращает несортированный список** (сортировка на копии —
  no-op); детерминированность порядка каналов не гарантирована.
- **TOFU host-key** — не для production: пиннить `SSH_HOST_KEY` / host_key сервера.
```
