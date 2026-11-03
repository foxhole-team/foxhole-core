<h1 align="center">🦀 FoxHole Core</h1>

<div align="center">

**FoxHole Core** - сетевое ядро экосистемы FoxHole на Rust.
Оно обрабатывает TCP/UDP-потоки, применяет правила маршрутизации и DNS
и подключает выбранный протокол. Android-приложения FoxHole Guard и FoxHole VPN
работают с ядром через C/JNI, а роутерный клиент OpenWrt использует Linux CLI.
Состав возможностей зависит от сборки и интеграции.

</div>

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
  <a href="./README.ru.md">
    <img src="https://img.shields.io/badge/🇷🇺-Русский-ff7a00?style=flat-square">
  </a>
</p>

<p align="center">
  <a href="https://github.com/foxhole-team/foxhole-core/releases">
    <img src="https://img.shields.io/github/v/release/foxhole-team/foxhole-core?label=version&style=flat-square" alt="Version">
  </a>
  <img src="https://img.shields.io/badge/status-beta-yellow?style=flat-square" alt="Status: beta">
</p>

![Rust](https://img.shields.io/badge/core-Rust-000000?logo=rust&logoColor=white&style=flat-square)
![Android](https://img.shields.io/badge/platform-Android-3DDC84?logo=android&logoColor=white&style=flat-square)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-007ec6?style=flat-square)](https://www.gnu.org/licenses/gpl-3.0.html)
![❤️ We support I2P](https://img.shields.io/badge/❤️_We_support-I2P-7B1FA2?style=flat-square)

| Вариант сборки | Состав |
| --- | --- |
| Android JNI | По умолчанию профиль `shipped`, включая Tor, I2P-адаптер и экспериментальную публикацию onion services |
| Linux CLI | По умолчанию Hysteria2; другие VPN-протоколы выбираются при сборке. Tor и I2P в CLI не включены |
| Конкретный клиент | Показывает только доступные ему функции; наличие возможности в Core не означает её наличие в интерфейсе приложения |

<p align="center"><a href="#quickstart">Начать</a> · <a href="#features">Возможности</a> · <a href="#details">Подробности</a> · <a href="#whats-new">Что нового</a> · <a href="../ROADMAP.md">Roadmap</a> · <a href="verification/1.0.2/README.md">Verification</a></p>

<a id="whats-new"></a>

## 🆕 Что нового — 1.0.3

- Исправлена DNS-маршрутизация в сценариях работы приложения.

<a id="features"></a>

## ⚙️ Основные возможности

| Слой | Реализация |
| --- | --- |
| **TUN** | TCP-актор на точно закреплённом smoltcp, собственные UDP-demux и ICMPv4 echo, ограниченная память потоков и пакетов |
| **Маршрутизация** | скомпилированные индексы, O(1) package policy, Direct/VPN/Tor/Block, I2P gate |
| **DNS** | UDP/TCP, DoT, DoH по HTTP/2, DoQ, DoH по HTTP/3, cache, stale cache, fake-IP |
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
512 UDP. Поток сверх лимита отклоняется и учитывается; TCP admission также
делит общий бюджет буферов 64 МиБ, а handshake, который не установил соединение,
освобождает резерв через 30 секунд. Каждый UDP-поток удерживает не больше
32 пакетов, пока занят его outbound; UDP- и raw-ответы используют ограниченные
очереди по 256 пакетов обратно к TUN, а переполнение UDP отбрасывается и
учитывается счётчиком.

---

## Импорт подписок и профилей

| Входной формат | Что поддерживается |
| --- | --- |
| URI-подписка | Ссылки по одной на строке или тело подписки в Base64 |
| Clash / Mihomo YAML | Совместимые узлы в `proxies`; неподдерживаемые узлы и настройки клиента обозначаются явно |
| SIP008 JSON | Списки серверов Shadowsocks версии 1 |
| Outline JSON | Объект одного ключа Shadowsocks; также поддерживаются ссылки `ss://` |

Поддерживаемые URI-схемы: `vless`, `vmess`, `hysteria2` / `hy2`,
`trojan`, `ss`, `wg` / `wireguard`, `socks` / `socks5`,
`http` / `https`, `naive+https`, `anytls`.
Доступность подключения зависит от протокольных модулей сборки.
Ссылки `socks4://` и `naive://` отклоняются.
CLI также импортирует канонический JSON Core и конфигурацию WireGuard `[Interface]`;
команде `import` нужен ровно один профиль. Произвольные JSON-конфигурации Xray и
sing-box не являются поддерживаемым форматом подписки.

Core разбирает тело подписки без сетевой загрузки. Загрузка, перенаправления и
проверка TLS относятся к клиенту, включая динамические источники Outline `ssconf://`.
Android-приложения FoxHole дополнительно раскрывают ссылки импорта v2rayTun перед
вызовом Core. Частичный импорт явно возвращает отклонённые записи; строгий импорт
отклоняет неподдерживаемую запись. См. [разбор подписок](../crates/foxcore-link/src/lib.rs),
[структурированные форматы](../crates/foxcore-link/src/structured.rs) и
[CLI-импорт](../crates/foxcore-cli/src/import.rs).

## 🔌 Поддерживаемые протоколы

| Протокол        | Поддержка                                                                      | Зрелость       |
| --------------- | ------------------------------------------------------------------------------ | -------------- |
| **VLESS**       | raw, WebSocket, HTTP Upgrade, gRPC/H2, XHTTP stream-one по H2, TLS, ECH; Reality под потоковыми транспортами, Vision только на raw TCP | `beta` |
| **VMess**       | AEAD (`alterId=0`), TCP/UDP, raw, WebSocket, HTTP Upgrade, gRPC/H2, XHTTP stream-one по H2, TLS, ECH | `beta` |
| **Hysteria2**   | QUIC/H3, Brutal, Salamander obfs, TCP/UDP, hopping порта назначения            | `beta`         |
| **WireGuard**   | реализация рукопожатия Noise_IKpsk2, L3-туннель, `reserved`, `wg://`, `.conf` | `beta`         |
| **AmneziaWG**   | параметры AWG и шаблоны init-пакетов 2.0                                       | `experimental` |
| **Trojan**      | TLS TCP/UDP, WebSocket, HTTP Upgrade, gRPC/H2, XHTTP stream-one по H2, ECH | `beta` |
| **Shadowsocks** | AEAD + AEAD-2022, TCP/UDP                                                      | `beta`         |
| **Outline**     | вариант Shadowsocks, статический prefix (AEAD по TCP)                          | `beta`         |
| **Naive**       | нативный HTTP/2 CONNECT с padding по протоколу, только TCP                     | `beta`         |
| **TUIC**        | нативный v5, QUIC, TCP/UDP, фрагментация                                       | `experimental` |
| **AnyTLS**      | нативный v2, мультиплексирование, padding, TCP/UoT                             | `experimental` |
| **ShadowTLS**   | строгий v3 / TLS 1.3, внутри только Shadowsocks                                | `experimental` |
| **SOCKS5**      | CONNECT, UDP ASSOCIATE, авторизация                                            | `beta`         |
| **HTTP**        | CONNECT-прокси                                                                 | `beta`         |
| **Tor** | Arti, TCP, доступ к `.onion`, мосты и подключаемые транспорты | `beta` |
| **Публикация onion services** | API реализован и включён в стандартную Android-сборку; готовый сценарий интерфейса Guard и независимая приёмка публикации не заявляются | `experimental` |
| **I2P**         | TCP-only SOCKS5-адаптер к внешнему `i2pd`                                      | `experimental` |
| **Selector**    | именованная группа outbound'ов, connect failover, urltest                      | `beta`         |

`Selector` - служебная группа максимум из 64 outbound'ов с выбором участника,
переключением при ошибке подключения и `urltest`. Его использование зависит
от конфигурации клиента; Core также принимает отдельный outbound без Selector.

### Ограничения композиции транспортов

Списки выше - по протоколам, а не свободно сочетающееся меню:

- **Reality** - слой безопасности, взаимоисключимый с обычным TLS. Поверх него
  поддерживаются потоковые транспорты, включая WebSocket, HTTP Upgrade, gRPC/H2 и
  XHTTP stream-one. Vision требует raw TCP.
- **XHTTP** реализует только stream-one по HTTP/2; другие режимы и неподдерживаемые
  параметры отклоняются.
- **Vision** работает только по raw TCP и требует TLS 1.3 на внешнем слое и
  `packet_encoding = xudp` и отклоняет UDP на порт 443.
- **Outline** `prefix=` применяется к AEAD-шифрам по TCP; для AEAD-2022 и UDP
  не переносится.
- **Hysteria2 port hopping** меняет порт назначения в пределах настроенного
  набора, сохраняя один защищённый локальный UDP-сокет. Референсный клиент
  меняет также исходный порт, поэтому эта реализация намеренно уже.
- **ShadowTLS v3** несёт Shadowsocks и ничего больше; share-link-формы для
  него нет.

- **ECH** требует явно заданного `ECHConfigList`; автоматическое получение
  из DNS HTTPS-записей пока не реализовано. ECH GREASE не скрывает SNI.
  ECH недоступен для Hysteria2, TUIC и ShadowTLS и не совмещается с
  `tls.fingerprint`.

### TLS и ограничения

**TLS-отпечатки:** REALITY формирует ClientHello по десяти браузерным профилям:
семь перенесены из uTLS, два получены из собственных захватов, один описывает
конфигурацию Chromium156 по первичному source без Trust Anchor IDs.
Происхождение и измерения указаны в `fingerprints/`. Совпадение параметров
ClientHello не означает полного совпадения с сетевым поведением браузера.

REALITY сохраняет скомпилированный Fox-owned генератор ClientHello. Обычный
TCP TLS отдельно поддерживает `chrome_156` (source-derived, без Trust Anchor IDs) и исторический `chrome_151` через закреплённый fork
rustls; несовместимые TLS-настройки отклоняются. Оба механизма описаны в
[архитектуре TLS](architecture/02-cryptography.md#25-tls-fingerprinting--two-disjoint-mechanisms).

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
`H1`–`H4`), проверяемые диапазоны заголовков и шаблоны init-пакетов 2.0 `I1`–`I5`.
Для `RandomTrailers`, диапазонов content padding и `HeaderProtectionKey` действуют
явная валидация и ограничения выделения памяти. Endpoint roaming, серверный режим
и container-link imports не поддерживаются; AmneziaWG остаётся экспериментальным.

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

DNS поддерживает UDP/TCP, DoT, DoH по HTTP/2, DoQ и DoH по HTTP/3,
кэширование, использование устаревшего кэша по политике, fake-IP
и выбор маршрута для DNS-запросов. Для DoQ и DoH по HTTP/3 выбранный
маршрут должен поддерживать UDP.

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



Публикация onion services - отдельная экспериментальная возможность ядра.
Она скомпилирована в стандартной Android-сборке; её наличие не означает
готовый сценарий публикации в интерфейсе Guard. Статус проверки указан в [interop.md](interop.md).
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

<a id="quickstart"></a>

## 🧪 Сборка и проверки

Toolchain закреплён в `rust-toolchain.toml`.

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

Проверка crate `foxcore-android` со всеми Cargo features на текущей host-платформе:

```bash
cargo check --locked -p foxcore-android --all-features
```

Android-библиотеки собираются через `scripts/android-build.sh` с закреплёнными NDK и cargo-ndk. Скрипт по умолчанию собирает четыре ABI и запускает ELF-проверки. Для offline-режима зависимости должны быть доступны локально. Проверки на устройствах и совместимость протоколов описаны отдельно в [interop.md](interop.md).

---

<a id="details"></a>

## 🧭 Архитектура и модель работы

**Путь трафика на Android**

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

## 📡 События ядра и аудит

Приложение само вычитывает события из ограниченной очереди ядра; обратных
Java-вызовов для доставки этих событий нет. Очередь вмещает 512 событий,
а потери учитываются отдельным счётчиком `dropped`.

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

Сетевая библиотека Core не ведёт постоянный журнал безопасности и не запускает
FoxHole Sentinel: этими функциями управляет Android-приложение. В этом репозитории
также находится отдельный [нативный YARA-сканер](../native/sentinel-yara/README.md)
для изолированного процесса Sentinel; он собирается отдельно от сетевого ядра.

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
| Обмен файлами | всегда Tor; clearnet-fallback отсутствует |
| Прокси-сервер в локальной сети | component lease route отсутствует; пресет выбирает VPN/Tor-upstream |

Поставляемое ядро содержит реализацию хранилища, поддержку onion service и
совместимые JNI-точки, поэтому `share.compiled` сообщает о наличии кода. При этом
FoxHole Guard не вызывает эту поверхность.

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

Guard использует версионированный JNI-интерфейс `FoxholeNativeEngine`.
Устаревший старт без Android `Network` сохранён в ядре для совместимости,
но не объявлен в текущем приложении. Контракт и проверки экспортов описаны
в [abi.md](abi.md).
Атомарный
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

Релиз 1.0.1 использует профиль поставки `android4`:

```text
arm64-v8a
armeabi-v7a
x86
x86_64
```

`config/foxcore-android-delivery.json` и LAB release scope требуют актуальные JNI,
происхождение capabilities и ELF-проверки для всех четырёх ABI. Компиляция и
проверки упаковки не заменяют runtime-проверки каждого класса устройств.

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

Нативные сборки и полные релизные проверки выполняются в приватной LAB или на
разрешённом build host с закреплёнными Rust, NDK и lockfile. GitHub publisher
проверяет подписанные владельцем исходники, неизменяемый LAB handoff, выбранный
архив и обязательные свидетельства, затем публикует проверенные байты без
пересборки. Handoff отдельно связывает исходники поставки и фактический нативный
producer; правки документации не меняют идентичность нативного producer.

Архив `foxhole-core-v<version>.tar.gz` содержит четыре прошедшие гейт JNI-библиотеки,
Linux x86_64 DNS-компилятор и записи их producer,
их rollback-манифест, зафиксированные CycloneDX SBOM и `Cargo.lock`. Релиз
также содержит `SHA256SUMS` и keyless Sigstore provenance, привязанный к этому
репозиторию, workflow и релизному коммиту:

```bash
sha256sum -c SHA256SUMS
gh attestation verify foxhole-core-v<version>.tar.gz \
  --repo foxhole-team/foxhole-core
```

---

## 🗂️ Структура workspace

```text
crates/
├── foxcore-api
├── foxcore-runtime
├── foxcore-android
├── foxcore-cli
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

`native/sentinel-yara` - отдельный native workspace сканера Sentinel, не часть основного Cargo workspace.

---

## 📚 Документация

| Документ | Назначение |
| --- | --- |
| [Архитектура](architecture/README.md) | архитектура системы, границы доверия и доставка данных |
| [SECURITY.md](../SECURITY.md) | сообщение об уязвимости и security scope |
| [threat-model.md](threat-model.md) | модель угроз и границы безопасности |
| [abi.md](abi.md) | FFI-контракт: handles, потоки, паники, коды ошибок и лимиты |
| [interop.md](interop.md) | статус совместимости конкретных артефактов и ожидаемые проверки |
| [fingerprints/](../fingerprints/) | происхождение REALITY ClientHello fingerprints |

FoxHole VPN - отдельный потребитель того же ABI Core. Проверка данных подключения сравнивает
подписанный набор таблиц REALITY из FoxHole DB со встроенным набором закреплённого ядра;
изменения применяются только после действия пользователя. Загружаются данные известных
профилей, а не нативный код или остальные наборы Guard. Принятые ядром таблицы используются
будущими соединениями в процессе этого приложения без переподключения туннеля;
подробности - в [архитектуре VPN-клиента](architecture/06-vpn-client.md).

[FoxHole OpenWrt Client](https://github.com/foxhole-team/foxhole-openwrt-client)
использует Core в клиентских модулях роутера и доступен в публичной бета-версии.
Актуальные пакеты и ограничения платформ перечислены в
[выпусках OpenWrt Client](https://github.com/foxhole-team/foxhole-openwrt-client/releases).

---

<a id="ecosystem"></a>

## 🔗 Экосистема FoxHole

| Проект | Роль |
| --- | --- |
| [FoxHole Guard](https://github.com/foxhole-team/foxhole-guard) | Android: VPN, Tor/I2P, правила трафика и локальный мониторинг |
| [FoxHole VPN](https://github.com/foxhole-team/foxhole-vpn) | Android: простой VPN-клиент и управление сопряжённым OpenWrt |
| [**FoxHole Core**](https://github.com/foxhole-team/foxhole-core) | Общее сетевое ядро на Rust; состав зависит от сборки |
| [FoxHole OpenWrt](https://github.com/foxhole-team/foxhole-openwrt-client) | VPN для роутера и управление локальной сетью |
| [FoxHole DB](https://github.com/foxhole-team/foxhole-db) | Подписанные правила и справочные данные |

## 🤝 Участие в разработке

Сообщайте об ошибках и предлагайте изменения через [Issues](https://github.com/foxhole-team/foxhole-core/issues).

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
