# FoxCore measured baselines

These are host-lab measurements, not a substitute for profiling the final Android build. Commands,
machine and source revision must accompany every new comparison.

## 0. Bench shape

The testkit drives the real TUN flow engine through fixed-size objects and records throughput,
latency, active flows, errors, RSS, file descriptors and stop time. Network-impairment arms use
`scripts/netem-lab.sh`.

## 1. Unimpaired path

The historical clean arm moved 3317.6 MiB in 65 seconds (51.0 MiB/s), with p50 183 ms, p95
439 ms, zero timeouts, zero flow errors and zero backlog exceedances. Treat changes below 20% on
the shared development machine as noise unless repeated.

## 2. Lifecycle

Historical cold starts were below 100 ms. Idle stop was 3.3–9.3 ms; stop with active flows was
1002–1010 ms because it exercised the bounded drain window.

## 3. Network impairment

Loss, reorder, delay, MTU reduction and black-hole arms demonstrated that counters remain bounded
and memory follows active flows rather than cumulative flow count. A black-holed established TCP
flow originally stayed open without progress; the current stack has explicit idle/stall
reclamation tests.

## 3a. Upload backpressure

The original upload arm exposed two defects: a healthy large upload could reach the relay ceiling,
and a pre-dial queue could grow to hundreds of MiB against a dead outbound. The current packet path
uses advertised-window backpressure and bounded relay queues. Regression coverage lives in
`stack_window_closes.rs`, `stalled_flows_are_reclaimed.rs` and the packet-path benches.

## 4. Soak

A historical host soak opened more than 134,000 local flows while RSS stayed near 5.5 MiB after
allocator warm-up; a concurrent live VLESS run also stayed flat. Final acceptance still requires
Android process-memory evidence because allocator, JNI and system VPN costs are absent from the
host number.

## 6. Open measurement work

- repeat long soak on the final Android library and app generation;
- ~~capture network-switch behavior for proxy protocols~~ — done 2026-08-04 on a
  Pixel 7 Pro with a live VLESS tunnel, `scripts/device-network-sweep.sh`. Walked
  umbrella_corp → albert_wesker → umbrella_corp and cycled the radio, flows in
  flight. The same exit fingerprint came back on both networks with
  `reconnects=0 sock_err=0 flow_errors=0 rebinds=0 rebind_fail=0`, and
  `dial_errors` accumulated only while the radio was down — dials failing rather
  than leaking past the tunnel. **The packet-tunnel case is still open**;
- capture network-switch behavior for packet-tunnel protocols;
- compare memory before/after repeated start-stop cycles;
- keep the final Pixel profile and raw artifacts outside the source repository.

## 7. Packet-path allocations

`crates/foxcore-tun/benches/packet_path.rs`, run as
`cargo bench -p foxcore-tun --bench packet_path`. Apple Silicon, 10 cores (4
performance), release profile, `foxcore-tun` at the packet-arena change.

**Read this before quoting any number here.** Cross-run comparison on this
machine is worthless: a background code indexer moves the whole suite by a
factor of 2.3 between runs, in both directions, on benchmarks that were not
touched. `flow_key_from_packet/ipv4_udp` measured 25 ns, 3.1 ns and 7.0 ns on
three runs of code that never changed. Criterion's `--baseline` therefore
reported a 75% regression and a 70% improvement in the same run, both invented.
Every figure below is an **arm-against-arm comparison inside one run**, with the
old shape and the new one measured back to back; the benchmarks are written in
pairs for exactly that reason. Two independent runs are quoted so the pair can
be seen to reproduce, and a run is only used if the untouched controls
(`flow_key_from_packet`, `tun_read_to_vec`) land at their fastest observed
values — anything slower means the machine, not the code.

| Path | Old shape | New shape | Run 1 | Run 2 |
|---|---|---|---|---|
| tun → classifier, 1420 B | `read` + `to_vec` | arena | 80.8 → 60.1 ns (−26%) | 68.8 → 53.5 ns (−22%) |
| tun → classifier, 64 B | `read` + `to_vec` | arena | 34.0 → 34.8 ns (wash) | 34.2 → 35.4 ns (wash) |
| userspace stack hop, 1420 B | two `Vec`s | arena | 158 → 139 ns (−11%) | 161 → 133 ns (−18%) |
| userspace stack hop, 64 B | two `Vec`s | arena | 93.2 → 71.5 ns (−23%) | 89.8 → 71.3 ns (−21%) |
| WireGuard uplink, 64 B | owned `Vec` per send | borrowed | 316 → 289 ns (−8.6%) | 295 → 273 ns (−7.6%) |
| WireGuard uplink, 1420 B | owned `Vec` per send | borrowed | 2.78 → 2.82 µs (noise) | 2.68 → 2.67 µs (noise) |
| WireGuard downlink, 64 B | `mem::take` | arena | 294 → 285 ns (−3.0%) | 290 → 276 ns (−4.9%) |
| WireGuard downlink, 1420 B | `mem::take` | arena | 2.73 → 2.76 µs (noise) | 2.76 → 2.75 µs (noise) |

What the table says, and what it does not:

- The saving is a copy, and a copy is proportional to the packet. At 1420 bytes
  the tun hand-off drops by a quarter; at 64 bytes there is nothing to save and
  the arena's refcount work cancels the small allocation it removes.
- On the WireGuard path ChaCha20-Poly1305 costs 2.7 µs per full packet against
  tens of nanoseconds of allocator work. The allocations were removed there
  because the channel type required it and because per-packet churn is worth
  avoiding on a phone's allocator — not because the clock shows it.
- `receive_datagram_retained_buffer` is the floor for the downlink arm: the same
  call with the output buffer kept. The arena lands on it, which is the most that
  removing the allocation can be worth.
- Resident cost of the change: about 40 KiB of chunk across the three arenas
  (tun reader, stack device, relay), against a worst case a stalled consumer can
  pin of roughly 3 MiB — see the module header of `foxcore-tun/src/arena.rs` for
  that arithmetic.

### 7a. Трансформы AmneziaWG: аллокация на пакет

`crates/proto-wireguard/benches/wireguard_datapath.rs`, запуск
`cargo bench -p proto-wireguard --bench wireguard_datapath`. Та же машина и та же
дисциплина, что в §7: сравниваются **плечи внутри одного прогона**, два прогона
приведены, чтобы пару можно было увидеть дважды.

Оба плеча каждой пары — это старая и новая форма одного и того же преобразования:
`obfuscate` выделял `Vec` на каждый вызов, `obfuscate_into` пишет в буфер
вызывающего; `deobfuscate_transport` копировал датаграмму целиком, чтобы
переписать в ней четыре байта, теперь он возвращает вид на неё.

| Преобразование | Старая форма | Новая форма | Прогон 1 | Прогон 2 |
|---|---|---|---|---|
| `obfuscate`, vanilla, 64 B | свой `Vec` | буфер вызывающего | 82.2 → 3.85 нс (−95%) | 87.0 → 9.92 нс (−89%) |
| `obfuscate`, vanilla, 1420 B | свой `Vec` | буфер вызывающего | 48.8 → 20.6 нс (−58%) | 133 → 58.0 нс (−56%) |
| `obfuscate`, Amnezia, 64 B | свой `Vec` | буфер вызывающего | 32.6 → 5.25 нс (−84%) | 27.1 → 13.1 нс (−52%) |
| `obfuscate`, Amnezia, 1420 B | свой `Vec` | буфер вызывающего | 45.1 → 21.3 нс (−53%) | 124 → 35.5 нс (−71%) |
| `deobfuscate_transport`, 64 B | копия в новый `Vec` | на месте | 36.5 → 18.8 нс (−49%) | 101 → 40.8 нс (−60%) |
| `deobfuscate_transport`, 1420 B | копия в новый `Vec` | на месте | 50.3 → 17.9 нс (−64%) | 128 → — |

Что здесь можно утверждать, а что нельзя:

- **Абсолютные значения этого прогона недействительны.** Контрольные плечи
  разъехались в 2–3 раза между прогонами (`session_seal/1420b` — 6.8 мкс против
  2.7 мкс исторического минимума), потому что машину в это время занимал
  фоновый индексатор кода: load average 20+ при 10 ядрах, один процесс на 700%
  CPU. По правилу приёмки из §7 такой прогон отбраковывается.
- **Отношение внутри пары — можно.** Разрыв в 5–20 раз на 64 байтах и в 2–2.4
  раза на 1420 не изготавливается загрузкой машины: оба плеча меряются подряд, в
  одном и том же состоянии. Направление и порядок величины воспроизвелись оба
  раза.
- На vanilla-профилях продуктовый путь `obfuscate` вообще не зовёт — короткое
  замыкание в `obfuscate_owned` появилось раньше. Эти строки меряют цену, которой
  тот путь **избегает**; живые строки здесь — Amnezia.
- Разрыв больше на 64 байтах, чем на 1420, и это ожидаемо: снимается аллокация
  постоянного размера, а не копия, пропорциональная пакету.

### 7b. Буферы датаграмм WireGuard: измерить не удалось

`wireguard_outbound/{borrowed_packet,fresh_datagram_buffer}` в
`crates/foxcore-tun/benches/packet_path.rs` — пара, которая должна была показать
цену аллокации на пакет в связке `send_packet` + `poll_transmit`. На этой машине
**сегодня она ничего не показывает**: 256 нс против 805 нс в первом прогоне и 605
против 449 во втором, то есть порядок плеч перевернулся. Контроли перевернулись
вместе с ними (`stack_hop/arena_backed/64b`: 192 нс, затем 83 нс на нетронутом
коде; `flow_key_from_packet/ipv4_udp` — 7.6–8.1 нс против 3.1 нс лучшего
наблюдавшегося). Это ровно тот отказ, который §7 и описывает.

Что вместо числа: **детерминированное доказательство**. `PeerTunnel` возвращает
буфер вызывающего в свой список свободных вместо того, чтобы его уронить, и тест
`a_warm_uplink_stops_allocating_datagram_buffers` прогоняет 32 пакета и требует,
чтобы после разогрева они прошли ровно через **два адреса** — то есть чтобы
аллокатора на этом пути не было вовсе. Это проверяет то же утверждение и не
зависит от занятости машины. Время пересчитать на тихой машине.

## 8. ECH size cost

On the original pinned ARM build, enabling the implemented ECH path added 77,464 bytes on
arm64-v8a (+0.38%) and 60,484 bytes on armeabi-v7a (+0.42%). Re-measure after the final NDK r29
build before using these values in release copy.

## 9. Профиль каркасного пути и что он изменил в сравнении с sing-box

Снято 2026-08-04, Pixel 7 Pro, `simpleperf` по плечу `direct` (без протокола, то
есть только машинерия прокси), неострипованная сборка `foxcore-socks`.

| символ | доля циклов |
|---|---|
| `recvfrom` + `__sendto` | 25.0 % |
| `allocate` + `deallocate_small` | 8.7 % |
| tokio: запуск задач блокирующего пула | 5.0 % |
| `foxcore_socks::serve_raw` (сам харнесс) | 3.4 % |
| `__memset_aarch64` | 2.7 % |

Четверть — сисколлы сокетов, и это неустранимо для прокси. Дальше выяснилось,
что **две трети остального разрыва принадлежали инструменту, а не ядру**:

1. `copy_bidirectional` берёт буфер 8 КиБ, а `sing` из sing-box — 64 КиБ. Восемь
   раз больше сисколлов на байт. Выравнивание вернуло 15-17 % CPU.
2. `copy_bidirectional_with_sizes` выделяет буферы на каждый вызов; 6547
   соединений за 28 с это 838 МиБ обнулённой памяти, тогда как sing-box берёт их
   из пула. Пул вернул ещё 12-17 % CPU.

После обеих правок (медианы трёх повторов): `direct` c1 — 342 против 333 MiB/s,
то есть FoxCore **впереди**; `vless` c32 — 910 против 924, практически поровну.
Остаток разрыва настоящий и держится на среднем параллелизме: `direct` c8 даёт
1.13 против 0.59 с/ГиБ. Это следующая цель профилирования, и она уже локализована
в tokio-машинерии и аллокаторе, а не в маршрутизации: `route_decide` стоит 114 нс
с доменной подсказкой и 16 нс по IP, что на любом реальном потоке — доли
миллисекунды.

## 11. Релейные буферы: размер и пул

`crates/foxcore-relay/benches/relay_copy.rs`, запуск
`cargo bench -p foxcore-relay --bench relay_copy`. Apple Silicon, 10 ядер, профиль
release, петлевые TCP-сокеты. Три плеча в одном прогоне, потому что §9 нашла два
разных дефекта и их легко спутать:

* `tokio_8k` — `tokio::io::copy_bidirectional` ровно так, как её звал
  onion-publisher: 8 КиБ по умолчанию и пара свежих обнулённых буферов на
  соединение;
* `tokio_64k` — та же аллоцирующая форма на размере sing-box. Разрыв до
  `tokio_8k` — это **только** экономия сисколлов;
* `pooled_64k` — `foxcore-relay`. Разрыв до `tokio_64k` — это **только**
  экономия аллокаций.

### Размер буфера — измерено и воспроизвелось

`relay_bulk`: 4 МиБ через одно соединение, где размер буфера решает, сколько раз
ядро попросят про `read`/`write`.

| Плечо | Прогон 1 | Прогон 2 |
|---|---|---|
| `tokio_8k` | 28.8 мс (137 МиБ/с) | 28.6 мс |
| `tokio_64k` | 11.5 мс (354 МиБ/с) | 9.16 мс |
| `pooled_64k` | 11.3 мс (360 МиБ/с) | 11.1 мс |

8 КиБ → 64 КиБ: **−60% и −68%** времени. Это тот самый ×8 по сисколлам на байт из
§9, и он больше шумового порога с большим запасом.

`pooled_64k` против `tokio_64k` здесь — −1.2% и +21%, то есть **шум в обе
стороны**, и так и должно быть: две аллокации, размазанные по четырём мебибайтам,
ничего не стоят. Пул адресован не этой нагрузке.

### Пул — плечи внутри группы сравнивать нельзя

Первые прогоны `relay_churn` и `relay_parallel` показывали, что `pooled_64k`
**медленнее** аллоцирующего плеча — в двух случаях из трёх, и с узкими
интервалами. Это оказалось артефактом порядка, а не свойством кода.

Каждая итерация этих плеч открывает пару эфемерных портов и держит их
`TIME_WAIT`. Плечо, которое меряется третьим, стартует по таблице портов,
забитой двумя предыдущими, и `connect` дорожает. Проверено прямо: то же плечо
запущено первым в свежем процессе и вторым, `relay_parallel`, восемь
одновременных соединений, между запусками — минута на слив `TIME_WAIT`.

| Плечо | измерено первым | измерено вторым |
|---|---|---|
| `pooled_64k` | **2.59 мс** | 4.79 мс (+85%) |
| `tokio_64k` | **4.34 мс** | 5.15 мс (+19%) |

Два вывода, и второй важнее первого:

1. В единственном сравнимом положении — каждое плечо первым, на слитой таблице
   портов — пул **быстрее на 40%** (2.59 против 4.34 мс). Вторыми они сходятся к
   разнице в 7%, то есть в шум.
2. **Штраф за позицию (до +85%) больше измеряемого эффекта.** Значит, три плеча
   в одной группе на этой нагрузке не сравнимы вообще, и «pooled медленнее» из
   групповых прогонов — свойство инструмента. Гонять по одному, с паузой, и
   сравнивать одинаковые позиции.

Это же объясняет, почему `relay_churn` внутри группы давал противоречивые
порядки (365/414/647 мкс в одном прогоне, 466/1171/867 в другом): там та же
ловушка, наложенная на общий фон — машину занимал фоновый индексатор кода,
load average 20+ на 10 ядрах, один процесс на 700% CPU.

Поэтому 40% выше — **указание, а не итог**. Что не зависит от машины:

- «На коннект больше не приходится ни одной аллокации» проверяется
  детерминированно: `a_relay_reuses_the_buffers_a_previous_relay_returned`
  прогоняет четыре соединения подряд и требует, чтобы в пуле осталось ровно два
  буфера — то есть чтобы после первого соединения аллокатор не звался.
- Исходное основание правки — не этот бенч, а профиль §9 на Pixel 7 Pro:
  `allocate` + `deallocate_small` + `__memset_aarch64` = 11.4% циклов, 838 МиБ
  обнулённой памяти за 28 секунд.

### Ловушка бенча

Плечи `churn` и `parallel` открывают пару эфемерных портов на итерацию. На
дефолтах criterion это десятки тысяч соединений, и третье плечо падало с
`AddrNotAvailable` — бенч, исчерпывающий таблицу портов, меряет таблицу портов.
Бюджет задан явно (`bounded_by_ephemeral_ports`): его определяет **окно
измерения**, а не число выборок, поэтому выборки можно поднимать через
`RELAY_BENCH_SAMPLES`, не трогая бюджет. Плечи гонять по одному:

```sh
RELAY_BENCH_SAMPLES=60 cargo bench -p foxcore-relay --bench relay_copy -- relay_parallel/pooled_64k
sleep 60   # слив TIME_WAIT
RELAY_BENCH_SAMPLES=60 cargo bench -p foxcore-relay --bench relay_copy -- relay_parallel/tokio_64k
```

## 10. Плоскость TUN

`scripts/device-tun-plane.sh`. Пропускную способность там симметрично **измерить
нельзя**: Android намеренно держит uid `shell` вне VPN-захвата, поэтому
шелловый генератор не доходит ни до одного TUN — проверено прямо, sing-box за всё
окно нагрузки не записал ни одной попытки соединения, при том что тот же аутбаунд
минутой раньше возил трафик через свой SOCKS-инбаунд. У FoxCore есть
внутриприложенческий харнесс, чей uid захватывается, у приложения sing-box — нет.

Что сравнимо честно, при живом TUN на обоих и одном и том же сервере:
sing-box (SFA 1.13.16) — RSS 341 МБ, 47 потоков; FoxCore (coretest) — RSS 216 МБ,
39 потоков. Приложения не равноценны (SFA несёт полный продуктовый UI, coretest —
голый харнесс), поэтому цифра ограничивает разницу сверху, а не выделяет вклад
ядра.
