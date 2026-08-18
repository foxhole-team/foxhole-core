<p align="center">
    <img
      src="../media/fhg.gif"
      alt="FoxHole Core"
      width="180"
      height="180"
    >
</p>

<p align="center">
  <a href="../README.md">
    <img src="https://img.shields.io/badge/🇬🇧-English-ff7a00?style=flat-square">
  </a>
  <a href="README.ru.md">
    <img src="https://img.shields.io/badge/🇷🇺-Русский-ff7a00?style=flat-square">
  </a>
</p>

<p align="center">
  <a href="https://github.com/foxhole-team/foxhole-core/releases">
    <img src="https://img.shields.io/github/v/release/foxhole-team/foxhole-core?label=version&style=flat-square" alt="Version">
  </a>
</p>

# 🦀 FoxHole Core

![Rust](https://img.shields.io/badge/core-Rust-000000?logo=rust&logoColor=white&style=flat-square)
![Android](https://img.shields.io/badge/platform-Android-3DDC84?logo=android&logoColor=white&style=flat-square)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-007ec6?style=flat-square)](https://www.gnu.org/licenses/gpl-3.0.html)
![❤️ We support I2P](https://img.shields.io/badge/❤️_We_support-I2P-7B1FA2?style=flat-square)

**FoxHole Core** - нативное сетевое ядро FoxHole Guard на Rust. Оно исполняет
сетевой data plane системного Android VPN-туннеля: принимает TUN от приложения,
разбирает TCP/UDP-потоки, применяет маршрутизацию и DNS-политику, выбирает
outbound и создаёт защищённые сетевые соединения.

```text
FoxHole Guard / Android
        ↓
VpnService + TUN + policy
        ↓
      C/JNI ABI
        ↓
    FoxHole Core
        ↓
TUN → flow engine → routing policy → outbound
                              ├─ VPN / Named Outbound
                              ├─ Tor / Arti
                              ├─ I2P → loopback SOCKS5 → i2pd
                              ├─ Direct → protected socket
                              └─ Block
```

> [!WARNING]
> **Статус:** ранняя бета. Production hardening и часть device-гейтов ещё не
> завершены. Зрелость отдельных протоколов указана в таблице ниже; фактически
> проверенную совместимость см. в [`interop.md`](interop.md).
>
> **TLS-отпечаток:** соединение Reality отправляет браузерный ClientHello - семь
> профилей, транскрибированных из uTLS, совпадающих с реальным Chromium в
> читаемой части JA4.
> rustls не реализует RSA- и CBC-наборы, которые несёт Chrome, и не даёт API ни
> для GREASE, ни для порядка расширений. Направление в активной разработке и
> экспериментах; кандидат на закрытие - другой TLS-стек (BoringSSL).

### Документация

| Документ | Назначение |
| --- | --- |
| [Бета-архитектура](architecture/README.md) | архитектура трёх репозиториев, границы доверия и доставка данных публичной беты |
| [SECURITY.md](../SECURITY.md) | сообщение об уязвимости и security scope |
| [threat-model.md](threat-model.md) | модель угроз и границы безопасности |
| [abi.md](abi.md) | FFI-контракт: handles, потоки, паники, коды ошибок и лимиты |
| [interop.md](interop.md) | фактически проверенная совместимость с независимыми пирами |
| [fingerprints/](../fingerprints/) | происхождение REALITY ClientHello fingerprints |

---

## ⚙️ Основные возможности

| Слой | Реализация |
| --- | --- |
| **TUN** | `ipstack`, TCP/UDP flow engine, ICMPv4 echo, ограниченные таблицы потоков |
| **Маршрутизация** | скомпилированные индексы, O(1) package policy, Direct/VPN/Tor/Block, I2P gate |
| **DNS** | UDP/TCP, DoT, DoH, cache, stale cache, fake-IP |
| **Android protected dialer** | Android-callback `protect(fd)` → привязка к выбранному Android `Network` → connect/send |
| **TLS** | rustls/WebPKI, SNI, ALPN, SPKI SHA-256 pin, ECH и ECH GREASE |
| **Фаервол** | приоритет Block, kill switch, карантин, TTL-правила |
| **Карта трафика** | живые потоки, учёт per-app/per-lane, состояние route/outbound |
| **События ядра** | ограниченный нативный поток событий с явным счётчиком `dropped` |
| **Web Apps / leases (только ABI)** | identity, leases и уведомления сохранены в JNI ради совместимости с v0.0.1; в FoxHole Guard нет рабочего вызова |
| **Обмен файлами (только ABI)** | XChaCha20-Poly1305-хранилище и onion-публикация сохранены в JNI; в FoxHole Guard нет пользовательского сценария |
| **Прокси-сервер в локальной сети** | SOCKS5 / HTTP CONNECT, обязательная авторизация, привязка к сети, JNI-точки входа |
| **Android / Native ABI** | версионированный C/JNI ABI, capabilities JSON, безопасные handles |

Таблицы потоков ограничены количеством по умолчанию 1024 TCP и
512 UDP. Поток сверх лимита отклоняется и учитывается.

---

## 🧭 Архитектура и модель работы

### Связь с моделью FoxHole Guard

На уровне приложения пользователь работает с цепочкой **режим → сценарий →
правила маршрутизации**. Эти понятия принадлежат FoxHole Guard. Перед применением
приложение преобразует их в runtime-конфигурацию и route/DNS/application policy,
которую исполняет FoxHole Core.

FoxHole Core не выбирает пользовательский режим самостоятельно. Его задача -
детерминированно применить уже собранную политику к каждому новому потоку и
отказать fail-closed, если требуемый защищённый маршрут недоступен.

### Принципы ядра

- фиксированный `enum Outbound`;
- один Android protected dialer;
- собственный TCP/UDP flow engine;
- скомпилированная routing policy;
- атомарный reload политики;
- fail-closed маршрутизация;
- на Android каждый внешний сокет проходит `protect(fd)` и привязывается к выбранному физическому `Network` до connect/send;
- отсутствие silent downgrade при отказе защищённого маршрута.

Per-app/application policy компилируется внутри `foxcore-route` и обновляется через
нативный API без пересоздания TUN.

I2P - отдельная runtime-граница: FoxHole Core подключается к уже
запущенному `i2pd` через локальный SOCKS5-адаптер и не управляет самим
I2P-процессом.

---

## 🔌 Поддерживаемые протоколы

| Протокол        | Поддержка                                                                      | Зрелость       |
| --------------- | ------------------------------------------------------------------------------ | -------------- |
| **VLESS**       | raw, WebSocket, HTTP Upgrade, gRPC/H2, TLS, ECH; Reality и Vision на raw TCP   | `beta`         |
| **VMess**       | AEAD (`alterId=0`), TCP/UDP, raw, WebSocket, HTTP Upgrade, gRPC/H2, TLS, ECH   | `beta`         |
| **Hysteria2**   | QUIC/H3, Brutal, Salamander obfs, TCP/UDP, hopping порта назначения            | `beta`         |
| **WireGuard**   | реализация рукопожатия Noise_IKpsk2, L3-туннель, `reserved`, `wg://`, `.conf` | `beta`         |
| **AmneziaWG**   | параметры AWG и шаблоны init-пакетов 2.0                                       | `experimental` |
| **Trojan**      | TLS TCP/UDP, WebSocket, HTTP Upgrade, gRPC/H2, ECH                             | `beta`         |
| **Shadowsocks** | AEAD + AEAD-2022, TCP/UDP                                                      | `beta`         |
| **Outline**     | вариант Shadowsocks, статический prefix (AEAD по TCP)                          | `beta`         |
| **Naive**       | нативный HTTP/2 CONNECT с padding по протоколу, только TCP                     | `beta`         |
| **TUIC**        | нативный v5, QUIC, TCP/UDP, фрагментация                                       | `experimental` |
| **AnyTLS**      | нативный v2, мультиплексирование, padding, TCP/UoT                             | `experimental` |
| **ShadowTLS**   | строгий v3 / TLS 1.3, внутри только Shadowsocks                                | `experimental` |
| **SOCKS5**      | CONNECT, UDP ASSOCIATE, авторизация                                            | `beta`         |
| **HTTP**        | CONNECT-прокси                                                                 | `beta`         |
| **Tor**         | Arti, TCP, `.onion`, мосты, pluggable transports, onion service                | `beta`         |
| **I2P**         | TCP-only SOCKS5-адаптер к внешнему `i2pd`                                      | `experimental` |
| **Selector**    | именованная группа outbound'ов, connect failover, urltest                      | `beta`         |

`Selector` - это служебный outbound, стоящий перед максимум 64 другими.
Приложение оборачивает в него каждый импортированный профиль, поэтому он есть
на каждом подключении.

### Ограничения композиции транспортов

Списки выше - по протоколам, а не свободно сочетающееся меню:

- **Reality** работает только по raw TCP и взаимоисключим с обычным TLS; его
  нельзя положить под WebSocket, HTTP Upgrade, gRPC или H2.
- **Vision** в этой реализации требует TLS 1.3 на внешнем слое и
  `packet_encoding = xudp` и отклоняет UDP на порт 443.
- **Outline** `prefix=` применяется к AEAD-шифрам по TCP; для AEAD-2022 и UDP
  не переносится.
- **Hysteria2 port hopping** меняет порт назначения в пределах настроенного
  набора, сохраняя один защищённый локальный UDP-сокет. Референсный клиент
  меняет также исходный порт, поэтому эта реализация намеренно уже.
- **ShadowTLS v3** несёт Shadowsocks и ничего больше; share-link-формы для
  него нет.

### Shadowsocks / Outline

Поддерживаются:

- AEAD;
- AEAD-2022;
- Outline `prefix=`, для AEAD по TCP;
- нативный SIP003-транспорт `v2ray-plugin` (WebSocket);
- нативный `simple-obfs` `http` / `tls`.

Оба плагина реализованы нативно; плагин-подпроцесс не запускается никогда, а
любой другой SIP003-плагин отклоняется. Outline рассматривается как вариант конфигурации Shadowsocks.

### WireGuard / AmneziaWG

WireGuard - L3-туннель с реализацией рукопожатия Noise_IKpsk2. Время
жизни ключей следует протоколу:

- сессионный ключ ротируется задолго до истечения;
- после `REJECT_AFTER_TIME` (180 с) ключ больше ничего не шифрует, а
  предыдущий перестаёт расшифровывать, поэтому опоздавшая датаграмма под
  отставным ключом отбрасывается;
- байты `reserved` переносятся, поэтому провайдеры, использующие их, работают.

Endpoint roaming не реализован; серверной роли нет.

AmneziaWG добавляет junk/header-параметры (`Jc`, `Jmin`, `Jmax`, `S1`–`S4`,
`H1`–`H4`) и шаблоны тегов init-пакетов 2.0 `I1`–`I5`. Диапазоны `H1`–`H4` не
поддерживаются; одиночные значения - да.

### Отклонено

- **ShadowsocksR (SSR)** - устарел и не поддерживается.
- **ShadowTLS v1** - FoxHole Core реализует только строгий ShadowTLS v3.

---

## 🛣️ Маршрутизация трафика

Поддерживаемые route actions:

```text
Direct
VPN
Named Outbound
Tor
I2P
Block
```

Политика, которую передаёт приложение, может учитывать:

- package/application identity;
- домен и суффикс домена;
- CIDR;
- DNS policy;
- TTL-правила;
- глобальный kill switch.

Route/DNS/application policy обновляется атомарно без рестарта TUN: каждый
новый поток видит либо целиком новую политику, либо целиком старую, никогда -
смесь, а отклонённый reload не меняет ничего. Обычный reload не пересчитывает
маршрут открытого активного потока немедленно: поведение уже открытых потоков
зависит от data plane и опубликованных runtime capabilities.

До 16 именованных outbound'ов и до 64 членов внутри selector'а. Изменение
конфигурации протокола или добавление/удаление outbound'ов требует нового
runtime generation.

### Fail-closed

FoxHole Core не перенаправляет защищённый трафик в `Direct`, когда требуемый
маршрут недоступен:

```text
App → VPN
       ↓
   VPN failure
       ↓
     Block
```

Приложения с явно заданным `Direct` продолжают работать через отдельный
protected dialer.

---

## 🌐 DNS

Встроенный DNS обработчик поддерживает:

```text
UDP
TCP
DoT
DoH
cache
stale cache
fake-IP
route-aware DNS
```

`.onion` и `.i2p` обрабатываются fail-closed и никогда не утекают в clearnet
DNS.

DNS bootstrap на Android идёт через выбранный физический Android `Network`.

Пакетные туннели, включая WireGuard, не могут использовать fake-IP для
обычного clearnet L3-трафика; несовместимые конфигурации отклоняются, а не
тихо деградируют.

---

## 🧅 Доступ к сети Tor

Tor реализован через **Arti** и входит в стандартную Android-сборку.

Поддерживаются:

- TCP;
- `.onion`;
- мосты, напрямую и через managed pluggable transports;
- пользовательская изоляция;
- таймауты;
- сетевые соединения через Android protected dialer;
- onion services.

---

## 🕸️ Доступ к сети I2P

FoxHole Core не встраивает I2P-роутер и не управляет им:

```text
FoxHole Core
   ↓
127.0.0.1 SOCKS5
   ↓
 i2pd
   ↓
 I2P
```

Требования:

- loopback endpoint;
- только TCP;
- `.i2p` через fake-IP;
- route action I2P;
- авторизация RFC 1929 при настроенных учётных данных.

---

## 🧱 Фаервол

Политика фаервола - часть routing engine.

Поддерживаются:

- per-app блокировка;
- приоритет Block;
- карантин;
- kill switch;
- TTL-правила;
- зависящее от data plane завершение живых потоков глобальным kill switch,
  сменой сети или явным адресным вызовом revocation;
- типизированные отказы reload.

---

## 📡 События ядра и аудит

Ядро публикует ограниченный поток событий, который приложение вычитывает; ядро
никогда не вызывает Java само. Буфер держит 512 событий; не поместившиеся
события сообщаются явным счётчиком `dropped` для затронутого окна.

Виды событий:

```text
blocked
dns_blocked
config_applied
confirmation_required
confirmation_expired
outbound_unavailable
outbound_restored
```

В поставляемом ABI также есть события открытия и закрытия потоков карты трафика со
своим счётчиком `dropped`. JNI-точки событий компонентов и обмена файлами сохранены
ради совместимости с v0.0.1, но текущее приложение на них не подписывается.

FoxHole Core не ведёт постоянный журнал безопасности и не содержит FoxHole
Sentinel. FoxHole Sentinel и долговременный журнал FoxHole Guard находятся на
уровне Android-приложения; ядро только отдаёт ограниченные event streams, которые
приложение может использовать для журнала, карты трафика и локальной корреляции.

---

## 🧩 Расширения и системные компоненты

Описанная ниже модель компонентов, leases и хранилища реализована в ядре. Её 19
Android JNI-точек остаются в релизной библиотеке, потому что их уже выпустили в
v0.0.1, но продукт их не вызывает. LAN-прокси и loopback-входы входят в отдельную
поверхность Engine.

На уровне ядра FoxHole Core у каждого компонента есть ограниченный
ASCII-идентификатор. Web App также имеет отдельно проверяемый канонический
HTTPS-origin - это его origin identity для авторизации и уведомлений. Userinfo,
путь кроме `/`, query и фрагмент отклоняются при регистрации, поэтому разные
варианты записи одного origin не создают разные identity.

Работа авторизуется через lease. Lease - не постоянный грант: он может пережить
выдавший его runtime, поэтому каждая операция заново проверяет доступность.

| Назначение lease | Маршрут, в который он резолвится |
| --- | --- |
| Web-навигация | собственный маршрут Web App |
| Web-уведомление | собственный маршрут Web App |
| Обмен файлами (в разработке) | всегда Tor; clearnet-fallback отсутствует |
| Прокси-сервер в локальной сети | component lease route отсутствует; пресет выбирает VPN/Tor-upstream |

Поставляемое ядро содержит реализацию хранилища, поддержку onion service и
совместимые JNI-точки, поэтому `share.compiled` сообщает о наличии кода. При этом
FoxHole Guard не вызывает эту **находящуюся в разработке** поверхность.

---

### Прокси-сервер в локальной сети

Прокси-сервер принадлежит одной runtime generation. Ему не назначается
component lease route: выбранный пресет независимо направляет SOCKS5- и HTTP
CONNECT-входы в VPN- или Tor-upstream.

- **SOCKS5** и **HTTP CONNECT**.
- **Авторизация обязательна и не отключается.** SOCKS5-клиент, предлагающий
  только «без авторизации», отклоняется; HTTP без `Proxy-Authorization` получает
  `407`. Учётные данные действуют только в пределах одной runtime generation.
- **Привязка ограничена.** Только Wi-Fi и Ethernet; сотовые интерфейсы,
  wildcard, unspecified и multicast-адреса отклоняются. Привязывается ровно
  один адрес.
- **Пользователь подтверждает сеть отдельно для каждой runtime generation.**
  Подтверждение хранится только в памяти. Смена сети закрывает listeners и
  аннулирует учётные данные вместо автоматической перепривязки.

Пресеты:

```text
vpn     SOCKS5 → VPN,  HTTP → VPN
tor     SOCKS5 → Tor,  HTTP → Tor
mixed   SOCKS5 → VPN,  HTTP → Tor
```

Пресета `direct` нет.

Loopback-входы именованы, несут собственные учётные данные и попадают в снимок
runtime; форма зафиксирована в
`crates/foxcore-android/capabilities.schema.json` и описана в
[abi.md](abi.md).

Компонент доступен из Android через `nativeConfirmLanNetwork`,
`nativeStartLanProxy`, `nativeStopLanProxy` и `nativeLanProxyStatus`.

---

## 🤖 Android / Native ABI

FoxHole Core предоставляет версионированный C/JNI ABI.

Android-приложение запрашивает capabilities в runtime.

В релизной библиотеке 33 JNI-метода `FoxholeNativeEngine`, а Guard объявляет 32:
намеренно отсутствует только устаревший старт без Android `Network`. Атомарный
старт с подписанным DNS-набором и `nativeTrafficMap` используются в рабочем пути.
Декларации импорта ссылок и continuity сохранены только как совместимый ABI;
Kotlin-обёрток продукта для них нет. Подписанное DNS-обновление сначала сохраняется,
затем ставится live в стабильный движок; включение фильтра или смена trust выполняют
атомарную замену, а неактивный движок читает bundle при следующем старте.

В релизных ELF-файлах также сохранены 19 JNI-методов компонентов и обмена файлами
из v0.0.1. Это совместимость ABI, а не выпущенная функция Guard.

Capabilities включают:

- скомпилированные протоколы;
- поддержку TCP/UDP;
- транспорты;
- опциональные функции;
- неподдерживаемые расширения.

Релизный ABI:

```text
arm64-v8a
```

Только arm64: живой трафик, матрица протоколов и Tor не проверялись на 32-битном
ARM. `armeabi-v7a` и `x86_64` собираются и проходят ELF-гейт, но не публикуются.

Гейты нативной сборки:

- закреплённый Rust toolchain;
- закреплённый Android NDK;
- RELRO/NOW;
- неисполняемый стек;
- выравнивание страниц 16 KiB;
- `libandroid.so`;
- замороженные ABI-v1 C/JNI exports и совместимость capabilities/config;
  export-набор ELF проверяется для каждой собранной ABI.

---

## 🔏 Целостность релиза

Релиз из `main` допускается только тогда, когда его дерево исходников совпадает с успешно прошедшим полный гейт `dev`. Релизный workflow публикует те же Android-библиотеки, которые сохранил этот гейт, и не пересобирает их в `main`.

Архив каждого релиза содержит прошедшие гейт JNI-библиотеки,
их rollback-манифест, зафиксированные CycloneDX SBOM и `Cargo.lock`. Релиз
также содержит `SHA256SUMS` и keyless Sigstore provenance, привязанный к этому
репозиторию, workflow и релизному коммиту:

```bash
sha256sum -c SHA256SUMS
gh attestation verify foxcore-android-v<версия>.tar.gz \
  --repo foxhole-team/foxhole-core
```

---

## 🗂️ Структура workspace

```text
crates/
├── foxcore-api
├── foxcore-runtime
├── foxcore-android
├── foxcore-tun
├── foxcore-route
├── foxcore-dns
├── foxcore-dialer
├── foxcore-transport
├── foxcore-relay
├── foxcore-outbound
├── foxcore-trafficmap
├── foxcore-link
├── foxcore-component
├── foxcore-share
│
├── proto-vless
├── proto-reality
├── proto-vmess
├── proto-hysteria2
├── proto-tuic
├── proto-trojan
├── proto-shadowsocks
├── proto-anytls
├── proto-shadowtls
├── proto-tor
├── proto-i2p
├── proto-socks
├── proto-http
├── proto-naive
├── proto-wireguard
│
└── foxcore-testkit
```

---

## 🧪 Сборка и проверки

Toolchain закреплён в `rust-toolchain.toml`.

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

Полная проверка Android-части:

```bash
cargo check -p foxcore-android --all-features
```

---

## ❤️ Поддержать

**XMR (Monero):**

```text
48yBVPTdcyJ1WoJtnKmVpEZziEsDy4HvbCW7eQDS9mfdiWPFXwZ8F5h9YZ2UTTBLxPcJgQgvth7iqLZM2yMCaQ432qaouqr
```

**BTC (Bitcoin):**

```text
bc1qatnyy7jcpqrp0d3dk9rta9vqfejgh4mysd6m2f
```

**ETH (Ethereum):**

```text
0xDEBA357Cc8f5E865ea7FFa98E138C8241A16A465
```

---

## ⚠️ Дисклеймер

- Tor является товарным знаком The Tor Project. FoxHole Core не является
  продуктом The Tor Project, не одобрен, не спонсируется и не аффилирован с
  The Tor Project.
- FoxHole Core не является официальным продуктом I2P или PurpleI2P.

---

## 📄 Лицензия

FoxHole Core распространяется по лицензии:

**GNU General Public License v3.0 or later (`GPL-3.0-or-later`)**

Copyright (C) 2026 FOXHOLE TEAM.

Лицензии сторонних зависимостей документированы в
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) и в SBOM:

```text
sbom/*.cdx.json
```

## 🔗 Связанные проекты

[![FoxHole Guard](https://img.shields.io/badge/GitHub-FoxHole_Guard-181717?logo=github)](https://github.com/foxhole-team/foxhole-guard)
[![Version](https://img.shields.io/github/v/release/foxhole-team/foxhole-guard?label=version)](https://github.com/foxhole-team/foxhole-guard/releases)

[![FoxHole DB](https://img.shields.io/badge/GitHub-FoxHole_DB-181717?logo=github)](https://github.com/foxhole-team/foxhole-db)
[![Version](https://img.shields.io/github/v/release/foxhole-team/foxhole-db?label=version)](https://github.com/foxhole-team/foxhole-db/releases)
