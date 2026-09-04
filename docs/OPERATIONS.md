# Protean — руководство по эксплуатации (OPERATIONS / SRE runbook)

> Для инженера, который **разворачивает, мониторит, бэкапит, обновляет и чинит**
> Protean в проде. Быстрый старт не дублируется — см.
> [GETTING-STARTED.md](GETTING-STARTED.md). Ручной чеклист деплоя и обоснование
> компромиссов прав — в [../DEPLOYMENT.md](../DEPLOYMENT.md). Тесты —
> [../TESTING.md](../TESTING.md). Пользовательские сценарии в UI —
> [USER-GUIDE.md](USER-GUIDE.md).

Оглавление:

1. [Обзор сервиса и зависимости](#1-обзор-сервиса-и-зависимости)
2. [Развёртывание (compose) и справочник переменных](#2-развёртывание-compose-и-справочник-переменных)
3. [TLS / reverse proxy](#3-tls--reverse-proxy)
4. [Подготовка VPN-хоста через setup-host.sh](#4-подготовка-vpn-хоста-через-setup-hostsh)
5. [Первый запуск и засев администратора](#5-первый-запуск-и-засев-администратора)
6. [Бэкапы и восстановление](#6-бэкапы-и-восстановление)
7. [Аварийное восстановление (DR)](#7-аварийное-восстановление-dr)
8. [Обновления и миграции](#8-обновления-и-миграции)
9. [Мониторинг и алертинг](#9-мониторинг-и-алертинг)
10. [Логирование](#10-логирование)
11. [Рутинные операции](#11-рутинные-операции)
12. [Чеклист безопасности (hardening)](#12-чеклист-безопасности-hardening)
13. [Плейбуки инцидентов](#13-плейбуки-инцидентов)
14. [Ёмкость и ограничения](#14-ёмкость-и-ограничения)

---

## 1. Обзор сервиса и зависимости

**Что это.** Protean — один статический Go-бинарь (`/panel`), собранный
`CGO_ENABLED=0` и упакованный в **distroless-образ** (`gcr.io/distroless/static-debian12`).
В образе **нет шелла, нет `curl`, нет `wg`/`psql`** — это влияет на отладку
(см. ниже) и на healthcheck (флаг `-healthcheck`, а не `curl`).

Панель сама VPN-трафик не терминирует: она по SSH правит конфиги и дёргает
службы на управляемых хостах, а трафик идёт напрямую между клиентами и хостами.

**Компоненты и зависимости в рантайме:**

| Компонент | Роль | Обязателен | Отказ = |
|---|---|---|---|
| Контейнер `panel` | Веб-UI, API, воркеры, SSH-клиенты | да | сервис недоступен |
| Postgres (схема `protean`) | всё состояние: пользователи, сессии, зашифрованные секреты, серверы, подсети, аудит, CRL, xray-клиенты, снапшоты конфигов | да | панель **не стартует** и `/healthz` → 503 |
| Управляемый VPN-хост(ы) | где реально живут wg/awg/ovpn/ikev2/xray | для работы VPN | «host degraded», но панель **жива** |
| Reverse proxy (nginx/caddy) | TLS-терминация | де-факто да (Secure-cookie) | логин не работает по HTTP |

**Фоновые воркеры** (стартуют в `main`, останавливаются по контексту):

| Воркер | Период | Что делает |
|---|---|---|
| Expiry worker | 5 мин | авто-disable (wg) / удаление (cert) пиров с истёкшим сроком |
| Notify watcher | 1 мин | мгновенные события (up/down, connect/disconnect) в каналы |
| Report worker | 10 мин | накопительный email-отчёт по расписанию |
| Reconcile (one-shot) | старт | логирует расхождения БД↔живой хост, **не чинит сам** |
| ReapplyMeshForwarding (one-shot) | старт | восстанавливает FORWARD-правила cert-провайдеров (не переживают reboot хоста) |

**Жизненный цикл процесса.** `main` ловит `SIGINT`/`SIGTERM` → отменяет
контекст → `httpServer.Shutdown` с таймаутом **10 c** → `WaitWorkers(15s)` ждёт
завершения текущей итерации воркеров (например, дописывающего конфиг) → лог
`shutdown complete`. Если воркеры не успели за 15 c — WARN
`shutdown: background workers did not stop within timeout`.

**Единственность экземпляра.** На старте панель берёт **session-level advisory
lock** в Postgres (ключ `0x77677066e` = «wgpn») на выделенном соединении,
держит до `Close`. Второй экземпляр на ту же БД падает с
`another Protean instance is already using this database`. Это **намеренно**:
внутренние мьютексы конфига и rate-limiter рассчитаны на один процесс. Не
запускать 2+ реплик на одну БД.

---

## 2. Развёртывание (compose) и справочник переменных

### 2.1 Топология compose

`docker-compose.yml` в репозитории поднимает **только** контейнер `panel`.
Postgres предполагается **уже работающим** в отдельном контейнере на этом хосте
(или внешним). Ключевые моменты файла:

- `ports: "127.0.0.1:8080:8080"` — панель слушает только loopback; наружу её
  выставляет reverse proxy. **Не** менять на `0.0.0.0`, если перед ней нет TLS.
- `healthcheck: ["CMD", "/panel", "-healthcheck"]` — бинарь сам стучит в
  `http://127.0.0.1:<port>/healthz` (таймаут внутри 4 c) и выходит 0/1.
  Параметры: `interval 30s`, `timeout 5s`, `retries 3`, `start_period 10s`.
- `secrets: ssh_key` → файл `./secrets/id_ed25519`, монтируется в
  `/run/secrets/ssh_key`, на него указывает `SSH_KEY_PATH` в compose.
- `extra_hosts: host.docker.internal:host-gateway` — позволяет контейнеру
  дойти до sshd **того же** VPS без host-network. Требует Docker ≥ 20.10.
- `networks: postgres-net: external: true` — **обязательно** привести к реальной
  docker-сети Postgres-контейнера:
  ```sh
  docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' <pg-container>
  ```
  и вписать это имя в секцию `postgres-net`.

> Важно: `docker-compose.yml` пробрасывает в контейнер только подмножество
> переменных (`SSH_HOST/PORT/USER`, `WG_INTERFACE`, `AWG_INTERFACE` и legacy-набор).
> Если нужны `WG_INTERFACES`, `METRICS_TOKEN`, `TRUST_PROXY`, `SSH_HOST_KEY`,
> `LOG_*`, `OVPN_*`, `IKEV2_*`, `SSH_CMD_TIMEOUT` — **добавьте их в секцию
> `environment:`** compose-файла (значения берутся из `.env`). Наличие строки в
> `.env` само по себе не пробросит переменную, если её нет в `environment:`.

`docker-compose.test.yml` — отдельный, только для интеграционных тестов store
(Postgres на порту 5433, tmpfs, эфемерный). К проду отношения не имеет.

### 2.2 Справочник переменных окружения

Читается в `internal/config/config.go`. Валидация — на старте (fail-fast).

| Переменная | Значение / назначение | Обяз. | Дефолт | Секрет |
|---|---|---|---|---|
| `DATABASE_URL` | DSN Postgres (`postgres://user:pass@host:5432/db?sslmode=…`) | **да** | — | да (пароль) |
| `LISTEN_ADDR` | адрес прослушки HTTP | нет | `:8080` | нет |
| `SESSION_SECRET` | подпись сессий/CSRF; **≥ 16 символов** | **да** | — | да |
| `SECRET_KEY` | **64 hex** (32 байта) AES-256-GCM; шифрует все секреты в БД | **да** | — | **критично** |
| `ADMIN_USERNAME` | сид первого админа (пока таблица `users` пуста) | нет¹ | — | нет |
| `ADMIN_PASSWORD` | пароль сида админа | нет¹ | — | да |
| `PUBLIC_HOST` | публичный IP/hostname VPS → Endpoint в клиентских конфигах | нет² | — | нет |
| `SSH_HOST` | хост для сид-сервера `default` (legacy одно-серверный режим) | нет | — | нет |
| `SSH_PORT` | порт SSH | нет | `22` | нет |
| `SSH_USER` | пользователь SSH | нет² | — | нет |
| `SSH_KEY_PATH` | путь к приватному ключу в контейнере | нет² | — | путь к секрету |
| `SSH_HOST_KEY` | пиннинг host key (строка `ssh-ed25519 AAAA…`) | нет | пусто (TOFU) | нет |
| `SSH_KNOWN_HOSTS` | альтернатива: путь к OpenSSH known_hosts | нет | — | нет |
| `SSH_CMD_TIMEOUT` | таймаут одной удалённой команды, сек (> 0) | нет | `30` | нет |
| `TRUST_PROXY` | `1` → доверять `X-Forwarded-For` (только за прокси) | нет | `0` | нет |
| `WG_INTERFACES` | список wg-интерфейсов через запятую (`wg0,wg1`) | нет | `wg0`³ | нет |
| `AWG_INTERFACES` | список awg-интерфейсов | нет | `awg0`³ | нет |
| `OVPN_INSTANCE` | имя инстанса `openvpn-server@<instance>` | нет | `server` | нет |
| `OVPN_PORT` | порт OpenVPN (int) | нет | `1194` | нет |
| `OVPN_PROTO` | `udp`\|`tcp` | нет | `udp` | нет |
| `OVPN_SERVER_NET` | IPv4-сеть сервера OpenVPN | нет | `10.8.0.0` | нет |
| `OVPN_SERVER_MASK` | маска (dotted) | нет | `255.255.255.0` | нет |
| `IKEV2_POOL` | CIDR пула IKEv2 | нет | `10.9.0.0/24` | нет |
| `IKEV2_DNS` | DNS для IKEv2-клиентов | нет | `1.1.1.1` | нет |
| `METRICS_TOKEN` | Bearer для `/metrics`; **пусто = эндпоинт выключен (404)** | нет | пусто | да |
| `LOG_LEVEL` | `debug`\|`info`\|`warn`\|`error` | нет | `info` | нет |
| `LOG_FORMAT` | `text`\|`json` | нет | `text` | нет |
| `WG_CONF_PATH` / `AWG_CONF_PATH` | переопределение путей conf-файлов | нет | производные от имени интерфейса | нет |

¹ Если оба заданы — сид срабатывает, только пока `users` пуста.
² Обязательны **только если задан `SSH_HOST`** (сид сервера `default`): тогда
`config.Load` требует `SSH_USER`, `SSH_KEY_PATH`, `PUBLIC_HOST`, иначе стартовая
ошибка `missing required environment variables`.
³ `WG_INTERFACES` перекрывает legacy `WG_INTERFACE`; аналогично для awg.

**Валидации на старте (иначе процесс падает с ненулевым кодом):**
`SECRET_KEY` ровно 64 hex; `SESSION_SECRET` ≥ 16; `SSH_CMD_TIMEOUT` > 0;
`SSH_KEY_PATH` (если задан) — файл читается; `IKEV2_POOL` — валидный CIDR;
`OVPN_SERVER_NET`/`OVPN_SERVER_MASK` — валидные IPv4; `OVPN_PROTO` ∈ {udp,tcp};
`OVPN_PORT`/`SSH_PORT` — целые. Если `SSH_HOST_KEY` и `SSH_KNOWN_HOSTS` оба
пусты — WARN про TOFU (не фатально).

### 2.3 Мультисервер vs. legacy seed

Серверы добавляются **в UI** (страница Servers), SSH-реквизиты шифруются в БД
(`SECRET_KEY`). Переменные `SSH_*`/`PUBLIC_HOST` в окружении используются
**только** для авто-сида сервера `default` при первом запуске (когда серверов в
БД ещё нет) — плавная миграция со старой одно-серверной установки. На чистой
мультисерверной установке `SSH_HOST` можно оставить пустым и добавить серверы
через UI.

---

## 3. TLS / reverse proxy

Панель **сама терминирует HTTPS** на `LISTEN_ADDR` (по умолчанию `:8080`) — с
самого первого запуска, даже до входа админа: при отсутствии сохранённого
режима автоматически генерируется свой self-signed CA + лист-сертификат
(`internal/webtls`, таблицы `tls_state`/`tls_self_signed`), и панель поднимает
`ServeTLS`, а не голый `ListenAndServe`. Голый HTTP отдаётся только в режиме
`proxy` (см. ниже) — попытка обратиться по `http://` в остальных режимах
получает `301` на `https://` того же адреса (детектится на лету по первым
байтам соединения, `internal/webtls/sniff.go`), а не голую ошибку TLS-стека.

Режим настраивается в самой панели (админка → **Сертификаты**, `/tls`),
без правки compose/ENV:

- **`self_signed`** (по умолчанию) — свой CA, конфигурируемый алгоритм ключа
  (RSA-2048/4096, ECDSA P-256/P-384), срок действия и автопродление. Всегда
  остаётся как **постоянный фолбэк**: если активный режим — `acme`/`manual` —
  и его сертификат сломался/протух, панель прозрачно продолжает работать по
  HTTPS на self-signed вместо падения на HTTP (важно: сессионная cookie
  ставится с флагом `Secure`, поэтому реальный даунгрейд на HTTP разлогинил
  бы всех разом — фолбэк на self-signed это и предотвращает).
- **`acme`** — универсальный ACME-клиент: `acme_directory_url` — Let's
  Encrypt (prod/staging) или свой ACME-сервер (например step-ca). ⚠️
  **Живьём не проверялся** — нужен реальный публичный домен с DNS на этот
  хост и открытый порт 80 (HTTP-01) либо 443 (TLS-ALPN-01, по умолчанию, без
  доп. порта). Перед продом проверьте один раз через LE **staging**
  (`https://acme-staging-v02.api.letsencrypt.org/directory`), чтобы не
  упереться в rate-limit прод-CA при отладке.
- **`manual`** — вставить готовый сертификат+ключ (PEM) вручную.
- **`proxy`** — TLS терминирует внешний реверс-прокси (nginx/Traefik), панель
  на `LISTEN_ADDR` отдаёт **обычный HTTP** только самому прокси (нормально —
  это приватный сетевой хоп, не публичный трафик). Переключение в этот режим
  и обратно требует **перезапуска контейнера** — сам листенер пересоздаётся
  только при старте процесса, налету TLS↔HTTP не переключить.

Пример nginx перед панелью в режиме `proxy`:

```nginx
server {
    listen 443 ssl;
    server_name vpn.example.com;
    # ssl_certificate / ssl_certificate_key — свои

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

`X-Forwarded-For`/`X-Forwarded-Proto` панель использует для rate-limit логина
по IP, аудита и баннера "небезопасное соединение". Ставить `TRUST_PROXY=1`
можно **только** когда перед панелью реально стоит доверенный прокси: иначе
заголовки подконтрольны клиенту и можно подделать IP/схему. Без прокси
оставить `TRUST_PROXY=0` (берётся реальный socket-адрес, схема — из реального
TLS-состояния соединения).

`/metrics` защищён только Bearer-токеном (не сессией) — по возможности
скрапить по loopback/внутренней сети, не наружу.

---

## 4. Подготовка VPN-хоста через setup-host.sh

`scripts/setup-host.sh` запускается **на самом VPS от root, интерактивно** (не
`curl | bash` — задаёт вопросы; проверяет TTY и root). Рядом должен лежать
`scripts/protean-installer.sh` (скрипт кладёт его на хост).

```sh
scp scripts/setup-host.sh scripts/protean-installer.sh root@HOST:/tmp/
ssh -t root@HOST 'bash /tmp/setup-host.sh'
```

### 4.1 Что скрипт делает по шагам

1. **Детект дистрибутива** по `/etc/os-release` → семейство arch/debian/rpm/suse.
   На **не-systemd** (нет `/run/systemd/system`) — выход с ошибкой. Если SELinux
   в `Enforcing` — предупреждение (WireGuard булевы не нужны; нестандартные порты
   OVPN/IKEv2 могут потребовать `semanage port -a`).
2. Спрашивает, какие провайдеры ставить сейчас (всё опционально — можно позже из
   UI со страницы Install):
   - **WireGuard**: пакет; если конфига нет — спрашивает адрес/порт, генерит
     ключи, пишет `/etc/wireguard/wg0.conf` (0600), `enable --now wg-quick@wg0`.
     Если конфиг есть — **не трогает**, только читает `ListenPort`.
   - **AmneziaWG**: Arch — через AUR (`yay`/`paru`); debian/rpm — предупреждение
     ставить руками. Конфиг `/etc/amnezia/amneziawg/awg0.conf` с плейсхолдерами
     обфускации `Jc/Jmin/Jmax/S1/S2/H1-4` (должны совпадать на всех клиентах).
   - **OpenVPN / strongSwan**: **только пакет** (панель их пока не настраивает
     из setup-host — провижн из UI кнопкой «Set up»).
3. **Всегда** (даже без VPN сейчас — панель должна уметь поставить позже):
   - создаёт системного пользователя **`protean`** с шеллом **`/bin/bash`**
     (не `nologin`: sshd выполняет команды через шелл; с `nologin` панель ничего
     бы не запустила);
   - генерит ему **ed25519 SSH-ключ**, публичный кладёт в
     `~protean/.ssh/authorized_keys` (700/600, `chown` на пользователя);
   - кладёт **root-owned installer** `/usr/local/lib/protean/protean-installer.sh`
     (`install -m 0755 -o root -g root`) — панель **не может его модифицировать**;
   - ставит **узкие NOPASSWD sudoers** в `/etc/sudoers.d/protean` (см. 4.2),
     валидирует `visudo -cf` **перед** установкой (если не прошло — оставляет
     `.new` и печатает ошибку, боевой файл не трогает);
   - выдаёт **группе `protean-conf`** (в неё входит `protean`) права rw на
     conf-файл(ы) интерфейса(ов) и `g+x` на директорию (см. 4.3).
4. Спрашивает про `net.ipv4.ip_forward=1` → пишет `/etc/sysctl.d/99-protean.conf`.
5. **Подсказки по фаерволу** — только печатает готовые команды (ufw/firewalld/nft),
   **сам фаервол не трогает** (риск отрезать себе SSH). UDP-порты открывать вручную.
6. Спрашивает про создание БД в **уже работающем Postgres-контейнере**: имя
   контейнера, admin-юзер, имя роли/БД (`protean`), пароль (можно принять
   сгенерированный). Идемпотентно: если роль/БД есть — не пересоздаёт. Выводит
   имя docker-сети контейнера для `postgres-net`.
7. Генерит `/root/protean-deploy/panel.env` (`SECRET_KEY`, `SESSION_SECRET`,
   `ADMIN_*`, `DATABASE_URL`, `PUBLIC_HOST`, `SSH_HOST_KEY` через `ssh-keyscan`)
   и кладёт туда `id_ed25519`. Скрипт **идемпотентен**: перезапуск не
   перезатирает существующие conf-файлы, ключи, роли/БД.

### 4.2 Модель sudoers (единственная привилегированная поверхность)

Файл `/etc/sudoers.d/protean` (0440), `Cmnd_Alias PROTEAN_CMDS` содержит только:

- **путь installer-скрипта** `/usr/local/lib/protean/protean-installer.sh`
  (аргументы whitelist-ятся **внутри** скрипта строгим enum — см. 4.4);
- `wg`/`wg-quick` и `awg`/`awg-quick` (если соответствующий VPN установлен);
- `systemctl restart wg-quick@*` / `awg-quick@*` (даже до подъёма интерфейса —
  чтобы mesh-форвардинг можно было включить позже);
- `systemctl enable --now`/`restart` для `openvpn-server@*`, `strongswan*`, `xray`;
- `swanctl` (если установлен).

Произвольные команды панель выполнить **не может**. Проверить фактические права:

```sh
sudo -l -U protean
```

> Комментарий в файле просит **не расширять его руками** — при повторном запуске
> setup-host он перезаписывается. Свои правила — отдельным файлом в `sudoers.d`.

### 4.3 Права на conf-файлы (осознанный компромисс)

Панель правит `wg0.conf`/`awg0.conf` **напрямую без sudo** (добавляет/убирает
`[Peer]`, правит `[Interface]`), поэтому conf делается `chmod 660`,
`chgrp protean-conf`, а директория — `g+x`. **В этом же файле лежит приватный
ключ сервера** (`PrivateKey =`). Панель его никогда не показывает и не хранит в
БД (ей нужен только публичный, через `wg show … dump`), но технически
компрометация панели/её SSH-ключа = компрометация серверного приватного ключа.
Обоснование и альтернатива (sudo-обёрнутый `cat`/`tee` + `0600 root:root`) — в
[DEPLOYMENT.md §6](../DEPLOYMENT.md).

Для cert-провайдеров и xray скрипт готовит group-writable каталоги (те же права
той же группе):
`/etc/openvpn/server` (+ `ccd`), `/etc/swanctl/{x509,x509ca,private,conf.d,x509crl}`,
`/usr/local/etc/xray` — режим `2770` (setgid), группа `protean-conf`.

### 4.4 Installer-скрипт: строгий enum действий

`protean-installer.sh` — единственная root-поверхность. Верб + whitelisted-аргументы:

| Верб | Аргументы | Действие |
|---|---|---|
| `detect` | — | JSON: os_family, pkg_manager, systemd, selinux, providers{installed,installable} |
| `install <provider>` | `wireguard\|amneziawg\|openvpn\|ikev2\|xray` | ставит бэкенд (репозитории PPA/DEB822/COPR/AUR по дистрибутиву; xray — official install-release.sh) |
| `status <unit>` | systemd-unit (regex-валидация) | `active`/`inactive`/`unknown` |
| `service <action> <unit>` | action ∈ {start,stop,restart,enable,disable} | управление VPN-юнитом |
| `forward <add\|del> <cidr>` | CIDR (regex) | идемпотентное FORWARD ACCEPT-правило mesh (без NAT) |

Валидация вербов/аргументов — и в bash (`VALID_*` regex), и в Go-обёртке.

### 4.5 Ручные шаги после скрипта

- [ ] `/root/protean-deploy/id_ed25519` → `./secrets/id_ed25519` (`chmod 600`) рядом с compose.
- [ ] `/root/protean-deploy/panel.env` → `./.env` там же.
- [ ] Привести `postgres-net` в compose к реальной docker-сети Postgres.
- [ ] Прочитать `/etc/sudoers.d/protean` глазами.
- [ ] Если `sshd_config` содержит `AllowUsers` — добавить туда `protean` (скрипт
      только предупреждает).
- [ ] Открыть UDP-порты wg/awg в фаерволе (команды скрипт подсказал).
- [ ] Настроить reverse proxy с HTTPS (см. §3).
- [ ] `docker compose build && docker compose up -d`; проверить чистый старт
      (`docker compose logs panel`) — миграции применяются сами.
- [ ] После проверки — **удалить `/root/protean-deploy`** с хоста (там копия
      приватного ключа и секретов, нужны только транзитно).

### 4.6 Пер-дистрибутивные заметки

| Семейство | WireGuard | AmneziaWG | Примечание |
|---|---|---|---|
| Debian/Ubuntu (apt) | `wireguard` | PPA `ppa:amnezia/ppa` (Ubuntu) / DEB822 (Debian, руками) | — |
| RHEL/Fedora (dnf) | `wireguard-tools` | COPR `amneziavpn/amneziawg` | учёт SELinux |
| Arch (pacman) | `wireguard-tools` | AUR (`yay`/`paru` обязателен) | без helper — понятный отказ |
| openSUSE (zypper) | `wireguard-tools` | **нет пакета** | AmneziaWG вручную |
| не-systemd | — | — | `detect` → `supported:false`, установка недоступна |

---

## 5. Первый запуск и засев администратора

На старте по порядку: `config.Load` → `store.Open`+Ping → **AcquireSingletonLock**
→ **Migrate** (авто) → `SeedAdmin` (если заданы `ADMIN_USERNAME`+`ADMIN_PASSWORD`
и таблица `users` пуста) → `NewEncryptor` → загрузка серверов
(`seedDefaultServer` при первом запуске из legacy `SSH_*`, затем `LoadAll`) →
запуск воркеров → HTTP listen.

Сид админа срабатывает **только пока `users` пуста**. Штатная смена пароля — в
UI на `/account` (нужен текущий пароль). Аварийный сброс:

```sql
DELETE FROM protean.users WHERE username = 'admin';
-- перезапустить контейнер с нужным ADMIN_PASSWORD в .env → сид сработает снова
```

Потеря 2FA-устройства:

```sql
UPDATE protean.users SET totp_enabled=false, totp_secret='' WHERE username='admin';
```

Проверка чистого старта — в логе `listening addr=:8080` без предшествующих
`fatal`. Если старт падает — смотри сообщение `fatal` (`config`, `database`,
`startup`, `migrate`, `seed admin`, `encryptor`, `seed default server`).

---

## 6. Бэкапы и восстановление

### 6.1 Где что лежит

| Данные | Место | Зачем |
|---|---|---|
| Пользователи, сессии, подсети, аудит, CRL, xray-клиенты, настройки, **зашифрованные** приватные ключи клиентов/CA/SSH/notify | Postgres, схема `protean` | без этого нельзя повторно выдать конфиг созданного клиента |
| Полная конфигурация интерфейса + всех пиров | conf-файл на хосте (`/etc/wireguard/wg0.conf`, `/etc/amnezia/amneziawg/awg0.conf`) | это и есть источник истины по состоянию wg/awg |
| Cert-провайдеры: CA/cert/key/conf | на хосте (`/etc/openvpn/server`, `/etc/swanctl`) + CA-ключ в БД (зашифрован) | PKI |
| `SECRET_KEY` | `.env` (вне БД) | **без него все зашифрованные секреты в БД нерасшифровываемы** |

> **Источник истины по wg/awg — conf-файл на хосте**, не БД панели. БД хранит
> лишь то, чего нет в conf: пользователей, сессии, справочник подсетей и
> сгенерированные приватные ключи клиентов.

### 6.2 Бэкап Postgres

```sh
# Логический дамп только схемы панели (роль/контейнер — свои):
docker exec -i <pg-container> pg_dump -U <admin> -n protean -Fc protean > protean-$(date +%F).dump
```

Восстановление:

```sh
docker exec -i <pg-container> pg_restore -U <admin> -d protean --clean --if-exists < protean-YYYY-MM-DD.dump
```

### 6.3 Бэкап конфигов хоста и SECRET_KEY

- Conf-файлы хоста бэкапить обычным бэкапом хоста или отдельным cron (это те же
  файлы, что правят и скрипт, и панель).
- **`SECRET_KEY` хранить отдельно от БД** — в секретах CI/CD или
  password-менеджере, не только в `.env` на диске. Потеря = см. §7.2.

### 6.4 Встроенные снапшоты конфига (conf_backups)

Перед **каждой** перезаписью conf панель кладёт снапшот прежнего содержимого в
`protean.conf_backups` — **последние 20 на провайдер** (лишние удаляются). Это
страховка от неудачной правки, доступная в UI: **страница
`/providers/{provider}/backups`** (кнопка Restore у нужного снапшота). Если апплай
падает и бэкап тоже не удался — WARN `wgfamily: config backup failed (continuing)`.

Восстановление вручную из БД:

```sql
SELECT id, saved_at, left(content, 60) FROM protean.conf_backups
  WHERE provider='wireguard' ORDER BY saved_at DESC;
-- скопировать нужный content в /etc/wireguard/wg0.conf на хосте, затем:
--   systemctl restart wg-quick@wg0
```

---

## 7. Аварийное восстановление (DR)

### 7.1 Потеря БД

Восстановить из `pg_dump` (§6.2). Если дампа нет, но **conf-файлы на хостах
живы**: подними панель на пустой БД → миграции создадут схему → пиры будут видны
на дашборде (читаются из conf), но **клиентские конфиги уже созданных пиров не
выгрузить** (приватных ключей в БД нет). По каждому такому пиру — кнопка
**rotate** (новая пара ключей, конфиг снова выгружается; старый ключ сразу
перестаёт работать — переустановить на клиенте). Пользователей/сессий не будет —
сработает сид админа (если `users` пуста).

### 7.2 Потеря `SECRET_KEY` — критично

`SECRET_KEY` шифрует **все** секреты в БД: приватные ключи клиентов, SSH-ключи
серверов, CA-ключи, конфиги уведомлений, xray-креды. **Без ключа они
безвозвратно нерасшифровываемы.** Последствия и действия:

- **Клиентские ключи** (wg): повторно конфиг не выдать → **rotate** каждого пира.
- **SSH-ключи серверов**: панель не сможет подключиться к хостам → пересоздать
  серверы в UI (заново вставить приватные ключи) или пересеять `default` из
  `SSH_*`.
- **CA-ключи** (OpenVPN/IKEv2): PKI утеряна → перепровижнить сервер («Set up»),
  перевыдать всем клиентам (старые сертификаты станут невалидны).
- **notify/xray**: перенастроить каналы и применить xray-модули заново.

**Ротация `SECRET_KEY`**: `panel -rotate-key-old <старый> -rotate-key-new <новый>`
перешифровывает все 15 секрет-колонок в БД одной транзакцией (либо всё,
либо ничего — verify-проход перед коммитом подтверждает, что каждая
строка реально читается новым ключом и даёт тот же plaintext). Панель на
время команды должна быть **остановлена** (утилита берёт тот же
singleton advisory lock, что и работающий процесс, — если панель жива,
команда сразу откажет). Порядок:

```sh
docker compose stop panel   # или systemctl stop, смотря как развёрнуто
panel -rotate-key-old $OLD_SECRET_KEY -rotate-key-new $NEW_SECRET_KEY -rotate-key-dry-run   # проверка без записи
panel -rotate-key-old $OLD_SECRET_KEY -rotate-key-new $NEW_SECRET_KEY                        # реальная ротация
# обновить SECRET_KEY в .env/секретах на $NEW_SECRET_KEY
docker compose start panel
```

`-rotate-key-detect <ключ>` — read-only проверка, каким ключом сейчас
реально читается БД (пригодится, если команда прервалась и непонятно,
успел ли коммит пройти). Полностью реализовано и покрыто тестами
(`internal/keyrotate`, `-tags dbtest`); что явно вне зоны ответственности
утилиты — обновление `SECRET_KEY` в самом деплойменте (`.env`/секреты
CI-CD) после ротации в БД, это отдельный шаг оператора. Отсюда правило
по-прежнему: **бэкапить и хранить `SECRET_KEY` максимально надёжно и
отдельно от БД** — перед ротацией на важной инсталляции стоит сделать
`pg_dump` (ротация не трогает старый ключ, но лишняя подстраховка не
помешает).

`SESSION_SECRET` подписывает сессии/CSRF — его ротация просто **разлогинивает
всех** пользователей (не критично, но заметно).

### 7.3 Потеря VPN-хоста

Панель жива (`/healthz` → `ok (host degraded: …)`). Восстановить хост, прогнать
`setup-host.sh` заново (идемпотентен), восстановить conf-файлы из бэкапа/снапшотов
(§6.4). Если менялся SSH host key — обновить пиннинг (`SSH_HOST_KEY` для сида или
поле сервера в UI), иначе будет `host key mismatch` (защита от MITM).

---

## 8. Обновления и миграции

### 8.1 Раскатка нового образа

```sh
cd <deploy-dir>
git pull                                   # или получить новый тег/исходники
docker compose build panel
docker compose up -d panel                 # пересоздаст контейнер
docker compose logs -f panel               # дождаться "listening" без fatal
curl -fsS http://127.0.0.1:8080/healthz    # "ok"
```

`restart: unless-stopped` вернёт контейнер после падения/reboot. Даунтайм на
время рестарта — секунды. Из-за **advisory-lock** нельзя сделать классический
blue-green с двумя живыми экземплярами на одну БД: старый должен отпустить lock
(остановиться) прежде, чем новый его возьмёт. Практически: `up -d` останавливает
старый контейнер, освобождается lock, поднимается новый.

### 8.2 Миграции

- Применяются **автоматически на старте** (`store.Migrate`), в порядке имён
  файлов, каждая **в своей транзакции**; при ошибке — rollback этой миграции и
  падение старта (`fatal migrate`). Уже применённые пропускаются (учёт в
  `protean.schema_migrations`).
- Сейчас **19 миграций** (`0001_init.sql` … `0019_xray_clients.sql`), встроены в
  бинарь через `embed`.
- Проверить состояние:
  ```sql
  SELECT filename, applied_at FROM protean.schema_migrations ORDER BY filename;
  ```

### 8.3 Безопасность обновления и откат

- **Перед апгрейдом сделать `pg_dump`** (§6.2) — единственный надёжный способ
  отката схемы: **down-миграций нет**, откат = восстановление дампа.
- Откат образа: `docker compose` со старым тегом/коммитом. Если новая версия уже
  применила новую миграцию, а старый бинарь её не знает — старый обычно
  стартует (лишние таблицы/колонки ему не мешают), но **гарантий нет**: если
  сомневаешься — восстановить БД из дампа, снятого до апгрейда.
- Не запускать миграции параллельно из двух экземпляров — advisory-lock это и
  так предотвращает (второй экземпляр не стартует).

---

## 9. Мониторинг и алертинг

### 9.1 /healthz — семантика

`GET /healthz` (без авторизации):

| Условие | Код | Тело |
|---|---|---|
| БД недоступна (Ping fail) | **503** | `db unreachable` |
| БД ok, все хосты по SSH ok | 200 | `ok` |
| БД ok, часть хостов по SSH недоступна | **200** | `ok (host degraded: <server>: <err>; …)` |

Ключевое: **отказ хоста НЕ роняет контейнер** (это удалённая проблема, не смерть
панели) — только помечается в теле. Доступность хостов кэшируется **~10 c**,
чтобы не делать SSH-раунд-трип на каждый пробинг. Docker-healthcheck (`-healthcheck`)
считает контейнер здоровым при 200 → «host degraded» контейнер **не** перезапустит.

**Рекомендация алертинга:** алертить на **503** (панель нерабочая) немедленно;
на подстроку `host degraded` — как warning (VPN-хост, а не панель).

### 9.2 /metrics — эндпоинт и все серии

`GET /metrics`, Prometheus text. Доступ: `METRICS_TOKEN` пуст → **404** (выключен);
неверный/отсутствующий Bearer → **401** (`WWW-Authenticate: Bearer`, сравнение
токена — constant-time). Не под сессией — держать токен секретным, скрапить
внутренним трафиком.

| Метрика | Тип | Метки | Смысл / алерт |
|---|---|---|---|
| `protean_up` | gauge | — | 1 = панель жива |
| `protean_interface_up` | gauge | `provider` | 1 = интерфейс поднят. **Алерт: `== 0`** |
| `protean_listen_port` | gauge | `provider` | UDP-порт интерфейса |
| `protean_peers_total` | gauge | `provider` | всего пиров |
| `protean_peers_online` | gauge | `provider` | пиров с недавним handshake |
| `protean_rx_bytes_total` | counter | `provider` | принято на интерфейсе |
| `protean_tx_bytes_total` | counter | `provider` | отправлено на интерфейсе |
| `protean_peer_online` | gauge | `provider`,`peer` | 1 = недавний handshake. Алерт для site-пиров |
| `protean_peer_last_handshake_seconds` | gauge | `provider`,`peer` | сек с последнего handshake (0 = никогда). **Алерт: `> 3600`** для site |
| `protean_peer_rx_bytes` | counter | `provider`,`peer` | принято от пира |
| `protean_peer_tx_bytes` | counter | `provider`,`peer` | отправлено пиру |
| `protean_host_up` | gauge | `server` | 1 = хост доступен по SSH. **Алерт: `== 0`** |
| `protean_ssh_commands_total` | counter | `server` | выполнено SSH-команд |
| `protean_ssh_command_errors_total` | counter | `server` | SSH-команд с ошибкой. **Алерт: рост rate** |
| `protean_ssh_last_command_seconds` | gauge | `server` | длительность последней SSH-команды. Алерт: близко к `SSH_CMD_TIMEOUT` |
| `protean_http_requests_total` | counter | — | обслужено HTTP-запросов |
| `protean_http_request_errors_total` | counter | — | ответов ≥ 500. **Алерт: рост rate** |
| `protean_http_last_request_seconds` | gauge | — | длительность последнего HTTP-запроса |
| `protean_go_goroutines` | gauge | — | число горутин. Алерт: монотонный рост = утечка |
| `protean_go_heap_bytes` | gauge | — | heap в использовании. Алерт: аномальный рост |

> Если `interface_up == 0`, per-peer/rx/tx/port по этому провайдеру не
> публикуются (в `gatherMetrics` идёт `continue`). Отсутствие метрик пиров —
> само по себе сигнал, что интерфейс down.

### 9.3 Zabbix (без Prometheus)

Готовые шаблоны в `zabbix/`: `protean-zabbix-7.4.yaml`, `protean-zabbix-8.0.yaml`
(идентичны, кроме поля `version`). Импорт:

1. Zabbix UI → **Data collection → Templates → Import** → выбрать YAML под свою
   версию сервера.
2. Создать/выбрать хост, слинковать шаблон **«Protean by HTTP»**.
3. Задать макросы:
   - `{$PROTEAN_URL}` — базовый URL без слэша (`http://127.0.0.1:8080` или
     `https://vpn.example.com`);
   - `{$PROTEAN_TOKEN}` — `METRICS_TOKEN`;
   - `{$PROTEAN_INTERVAL}` — интервал скрейпа (дефолт `1m`);
   - `{$PROTEAN_PEER_HS_MAX}` — порог устаревшего handshake, сек (дефолт `3600`).

Внутри: master HTTP-item `protean.metrics` (один скрейп/интервал), зависимые
item'ы c preprocessing «Prometheus pattern», **LLD-дискавери пиров** (online /
handshake-age / rx / tx + триггер «peer offline») и триггеры: WireGuard down
(High), AmneziaWG down (Average), нет метрик 10 мин (Warning). Если на хосте
только один из двух VPN — item'ы отсутствующего просто «not supported»/no-data,
безвредно. Детали — `zabbix/README.md`.

Prometheus/Grafana (если поднимешь позже) — scrape с `authorization: Bearer` на
`/metrics`; либо Grafana поверх Zabbix-datasource. Prometheus-сервер не
обязателен.

---

## 10. Логирование

`slog` в stderr; уровень `LOG_LEVEL` (debug|info|warn|error), формат `LOG_FORMAT`
(text|json — json удобен для Loki/ELK/Zabbix-log). Смотреть:
`docker compose logs -f panel`.

**За чем следить (что означает и что делать):**

| Сообщение | Уровень | Смысл / действие |
|---|---|---|
| `listening addr=…` | INFO | нормальный старт |
| `sshexec: trusting host key on first use; pin it via SSH_HOST_KEY` | WARN | **TOFU**: host key не запиннен — запиннить (`SSH_HOST_KEY`/поле сервера), иначе окно для MITM |
| `host key mismatch for … (possible MITM)` | (ошибка соединения) | ключ хоста сменился vs. запомненного/запиннена — расследовать: легитимная переустановка хоста vs. атака |
| `reconcile: stored key for a peer not present on the interface (orphan secret)` | WARN | в БД есть ключ пира, которого нет на интерфейсе (крэш между delete на хосте и в БД) — почистить вручную при необходимости |
| `reconcile: state summary` | INFO | сводка расхождений БД↔хост (orphan_secrets, peers_without_stored_key). `peers_without_stored_key` нормально для client-keygen |
| `reconcile: list peers/secrets failed; skipping` | WARN | хост/БД недоступны на момент старта — сверка пропущена |
| `wgfamily: config backup failed (continuing)` | WARN | не удался снапшот перед правкой — правка продолжилась без страховки |
| `wgfamily: apply-live failed AND config rollback failed; on-disk config may diverge from live state` | ERROR | **серьёзно**: живое состояние и conf разошлись — сверить `wg show` с conf, при необходимости `systemctl restart wg-quick@…` |
| `wgfamily: rotate live-apply failed AND config rollback failed; on-disk config may diverge` | ERROR | то же при ротации ключа |
| `create/rotate peer: stored-secret failure AND rollback failed; manual cleanup needed` | ERROR | пир создан/ротирован на хосте, но секрет в БД не сохранён и откат не удался — ручная чистка |
| `expiry: disable/clear … failed` | ERROR | воркер истечения не смог отключить/очистить пир — проверить доступность хоста |
| `notify: send/report send failed` | ERROR | канал уведомлений недоступен — проверить его настройки/сеть |
| `cert mesh forwarding: no installer for server` / `cert mesh forwarding … err` | ERROR | не удалось применить FORWARD-правило mesh |
| `shutdown: background workers did not stop within timeout` | WARN | воркеры не завершились за 15 c при остановке — возможна незавершённая правка конфига |
| `fatal …` (config/database/migrate/…) | ERROR + выход | старт провалился — по ключу понять причину (§5) |

---

## 11. Рутинные операции

### 11.1 Добавить сервер

UI **Servers → Add server**: id-слаг (`hq`), host/port/user, публичный адрес,
пиннинг host key (`ssh-keyscan -t ed25519 <host>`), вставить SSH-приватный ключ
(шифруется в БД). SSH-клиент и провайдеры сервера собираются и регистрируются
**на лету, без рестарта** панели. Появятся инстансы `hq:wg0`, `hq:openvpn` и т.д.
Не забыть прогнать `setup-host.sh` на самом хосте заранее.

### 11.2 Удалить сервер

UI **Servers → delete**. SSH-клиент и провайдеры снимаются с реестра на лету
(`Remove`). Данные хоста (conf, ключи) на нём не трогаются — чистить вручную,
если нужно.

### 11.3 Ротация SSH-ключа сервисного пользователя

1. Сгенерить новую пару: `ssh-keygen -t ed25519 -f newkey -N ''`.
2. На хосте добавить `newkey.pub` в `~protean/.ssh/authorized_keys` (старый пока
   не убирать).
3. В UI (Servers → edit нужного сервера) вставить новый приватный ключ, сохранить
   (шифруется в БД, SSH-клиент пересобирается). Для legacy `default` —
   заменить `./secrets/id_ed25519` и перезапустить контейнер.
4. Убедиться, что панель ходит (`protean_host_up == 1`, действие в UI проходит).
5. Убрать старый ключ из `authorized_keys` на хосте.

### 11.4 Остановить/запустить VPN-службу (экономия ресурсов)

UI страница **Network (per-provider)** → управление системным сервисом
(start/stop/enable/disable). Под капотом — installer-верб `service <action> <unit>`
через sudo (whitelisted). Так отключают неиспользуемый VPN, не удаляя его.

### 11.5 Пиры: rotate / disable / enable

- **rotate** — новая пара ключей (имя/AllowedIPs/keepalive сохраняются); старый
  ключ сразу перестаёт работать (переустановить на клиенте). Способ усыновления
  внешних пиров и ротации при утечке.
- **disable** — убирает пир с живого интерфейса и из conf, но сохраняет его
  определение и приватный ключ (`peer_secrets`); **enable** возвращает как был.
  Временное отключение площадки без потери настроек.

### 11.6 Отладка внутри контейнера — нельзя

Образ distroless: нет шелла/`wg`/`psql`, `docker compose exec panel sh` **не
сработает**. Отладка — только логи (`docker compose logs -f panel`) и SSH до
хоста напрямую (§13).

---

## 12. Чеклист безопасности (hardening)

- [ ] **Пиннинг host key** каждого сервера (`SSH_HOST_KEY`/поле в UI или
      `SSH_KNOWN_HOSTS`). Иначе — TOFU (WARN в логе), окно для MITM на первом
      коннекте.
- [ ] **TLS перед панелью** (§3); панель наружу не выставлять голым HTTP.
- [ ] `TRUST_PROXY=1` **только** за доверенным прокси; иначе `0`.
- [ ] `ports` панели — `127.0.0.1:8080` (не `0.0.0.0`), доступ только через прокси.
- [ ] Прочитать `/etc/sudoers.d/protean`; **не расширять** его руками; проверять
      `sudo -l -U protean`.
- [ ] Installer-скрипт root-owned `0755` — панель не может его менять (проверить
      `stat /usr/local/lib/protean/protean-installer.sh`).
- [ ] `SECRET_KEY` хранить отдельно от БД (менеджер секретов/CI), бэкапить; помнить
      о невозвратности при потере (§7.2).
- [ ] `METRICS_TOKEN` секретный; `/metrics` скрапить внутренним трафиком.
- [ ] `./secrets/id_ed25519` — `chmod 600`; после деплоя удалить
      `/root/protean-deploy` с хоста.
- [ ] Помнить о компромиссе: SSH-пользователь панели читает conf с приватным
      ключом сервера (§4.3) — компрометация панели = компрометация серверного ключа.
- [ ] Фаервол: открыты только нужные UDP-порты VPN и порт(ы) прокси; SSH-доступ
      ограничен.
- [ ] 2FA (TOTP) для админа — включить на `/account`.
- [ ] Аудит (`/audit`) фиксирует скачивание конфигов/QR (утечка ключевого
      материала) — периодически просматривать.

---

## 13. Плейбуки инцидентов

### 13.1 «host degraded» в /healthz / `protean_host_up == 0`

Панель жива, хост по SSH недоступен. Проверить SSH руками **с той же машины, где
крутится Docker**:

```sh
ssh -i ./secrets/id_ed25519 protean@<SSH_HOST> 'sudo wg show'
```

- `host.docker.internal` не резолвится → Docker ≥ 20.10 и наличие
  `extra_hosts: host.docker.internal:host-gateway` в compose.
- `sudo: a password is required` → `/etc/sudoers.d/protean` не установился
  (setup-host печатает явную ошибку, если `visudo -cf` не прошёл) или путь к
  бинарю в правиле не совпадает с реальным (`command -v wg`). Проверить
  `sudo -l -U protean`.
- `host key mismatch` → сравнить с запинненым ключом; легитимная переустановка
  хоста → обновить пиннинг; иначе расследовать MITM.
- `Permission denied (publickey)` → ключ не в `authorized_keys` или `AllowUsers`
  в sshd не включает `protean`.

### 13.2 БД недоступна / `/healthz` 503 / панель не стартует

`docker compose logs panel`. Проверить `DATABASE_URL` и что `postgres-net` в
compose совпадает с реальной docker-сетью Postgres-контейнера
(`docker inspect … .NetworkSettings.Networks`). Проверить, что Postgres поднят и
принимает соединения. Если старт падает на `startup … another Protean instance
is already using this database` — где-то жив второй экземпляр (или залипло
lock-соединение): найти и остановить лишний контейнер; после его остановки
advisory-lock освобождается.

### 13.3 Интерфейс «flapping» / 500-е на дашборде

- Дашборд «DOWN» сразу после установки → `systemctl status wg-quick@wg0` (или
  `awg-quick@awg0`) и `journalctl -u wg-quick@wg0` на хосте.
- Рост `protean_http_request_errors_total` → искать в логе ERROR-и вокруг правок
  (`wgfamily: apply-live failed …`). Если on-disk conf разошёлся с живым
  состоянием — сверить `wg show <iface>` с conf-файлом, при необходимости
  `systemctl restart wg-quick@<iface>` (перечитает conf) и/или восстановить
  снапшот (§6.4).
- `protean_ssh_last_command_seconds` близко к `SSH_CMD_TIMEOUT` и растут ошибки —
  хост тормозит/перегружен (см. 13.8).

### 13.4 Проблемы cert/CRL (OpenVPN/IKEv2)

- Клиент не подключается после удаления другого клиента → проверить, что CRL
  раздаётся: OpenVPN `crl-verify`, strongSwan `x509crl` + был ли `swanctl
  --load-all`. Провижнинг делает панель кнопкой «Set up».
- CA-ключ живёт зашифрованным в БД; при потере `SECRET_KEY` PKI восстановлению не
  подлежит — перепровижнить и перевыдать (§7.2).
- Отозванный клиент всё ещё коннектится → убедиться, что сервис перечитал CRL
  (рестарт соответствующего юнита).

### 13.5 Xray не подключается

Модуль Xray — сквозной стек (transport+security+protocol). Секреты стабильны
между применениями; панель выдаёт client-link. Если не проходит DPI/сеть — в UI
сменить **модуль** (`reality-vless-tcp` → `vless-vision-tls` → `vmess-ws-tls` и
т.д.) и Apply. Проверить, что `xray` установлен (Install) и юнит активен
(`status xray`). Egress-relay (цепочки) — проверить корректность вставленного
client-link зарубежного сервера.

### 13.6 Пересечение подсетей mesh (overlap)

Панель **запрещает** пересечение туннельных CIDR и подсетей площадок (иначе
маршрутизация без NAT неоднозначна). Страница **Mesh** и страница **Subnets**
предупреждают о пересечениях. Развести подсети так, чтобы они не перекрывались;
после правок — включить форвардинг на Mesh (пишет PostUp/PostDown и рестартит
интерфейс). Обратный маршрут в LAN площадки — вне зоны панели (см.
[DEPLOYMENT.md §0](../DEPLOYMENT.md)).

### 13.7 Зависшая SSH-команда

Каждая удалённая команда ограничена `SSH_CMD_TIMEOUT` (дефолт 30 c) — это
backstop от залипшего хоста. SSH-клиент **reconnecting**: при обрыве
переподключается на следующей команде. Если команды стабильно упираются в
таймаут — хост перегружен/сеть деградировала; проверить хост, при необходимости
поднять `SSH_CMD_TIMEOUT`. Метрика `protean_ssh_last_command_seconds` показывает
длительность последней команды по серверу.

### 13.8 Общая деградация / рост ресурсов

`protean_go_goroutines` монотонно растёт или `protean_go_heap_bytes` аномально —
собрать логи, рассмотреть контролируемый рестарт контейнера (даунтайм — секунды,
advisory-lock освобождается при остановке).

---

## 14. Ёмкость и ограничения

- **Один экземпляр панели на БД** (advisory-lock). Горизонтально панель не
  масштабируется — внутренние мьютексы и rate-limiter рассчитаны на один процесс.
  HA — только «одна активная реплика + быстрый рестарт», не active-active.
- **Сериализация правок по интерфейсу.** У wg-family провайдера per-provider
  мьютекс (`mu`) сериализует **каждую** операцию чтения и read-modify-write конфига.
  То есть одновременные правки одного интерфейса выполняются строго по очереди —
  это защищает от гонки конфига, но при большом потоке операций даёт латентность.
- **Одно SSH-соединение на хост.** На каждый сервер — один reconnecting
  SSH-клиент (безопасен для конкурентного использования, но соединение одно).
  Команды к одному хосту делят это соединение; при обрыве — переподключение на
  следующей команде.
- **Состояние читается через короткий кэш** (single-flight, TTL ~секунды) —
  дашборд/метрики не делают SSH-раунд-трип на каждый запрос. Health хостов
  кэшируется ~10 c.
- **Только systemd-дистрибутивы** (apt/dnf/pacman/zypper) для установки из
  панели; на не-systemd `detect` → `supported:false`.
- **Форвардинг через `iptables`** (nft-совместимый шим на современных
  дистрибутивах); на чисто-nftables без `iptables-nft` правила адаптировать
  вручную.
- **Mesh — по-серверно** (в пределах провайдеров одного хоста); межсерверный mesh
  пока не реализован.
- **OpenVPN/IKEv2** панель умеет ставить и (для этих cert-провайдеров)
  провижнить/выдавать клиентов из UI; часть возможностей — задел на будущее (см.
  README «Известные ограничения»).
```
