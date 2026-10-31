# freeturn-windows: план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Полный клиент FreeTurn для Windows с установщиком, встроенным WireGuard, kill switch и разделением трафика.

**Architecture:** Служба `FreeTurnService.exe` под SYSTEM импортирует пакет `mobile` ядра без изменений, поднимает amneziawg-go с wintun и ходит в ядро через UDP на `127.0.0.1`. Сокеты ядра обходят туннель через `SetProtect` и `IP_UNICAST_IF`. Окно `FreeTurn.exe` на Wails v3 общается со службой по именованному каналу.

**Tech Stack:** Go 1.26.10, Wails v3.0.0 + WebView2, TypeScript + Vite, amneziawg-go v3.1.20260814, wintun 0.14.1, `golang.zx2c4.com/wireguard/windows` v1.1.1 (`winipcfg`), Inno Setup 7.1.1.

**Spec:** `docs/superpowers/specs/2026-10-31-freeturn-windows-design.md`

## Global Constraints

- Модуль `github.com/vanbujhm/freeturn-windows`, `go 1.26.10`, сборка всегда с `CGO_ENABLED=0`.
- Ядро подключается только так:
  `require github.com/samosvalishe/free-turn-proxy v0.0.0` и
  `replace github.com/samosvalishe/free-turn-proxy => github.com/hackdiaz-dev/free-turn-proxy v0.0.0-20261028173317-562cfb4ba18b`.
  Из ядра импортируется только пакет `mobile`.
- Имена: служба `FreeTurnService`, адаптер `FreeTurn`, тип Wintun `FreeTurn`, канал `\\.\pipe\FreeTurnService`, GUID адаптера `{7E0B0F52-5C3D-4F1B-9A6E-3D1C2B7A4F10}`. С Amnezia ничего не пересекается.
- Настоящие ссылки `freeturn://`, ключи, Client ID и ссылки на звонок не попадают в репозиторий, тесты, логи и отчёты. В тестах только сгенерированные ключи: `base64(32 байта значения b)` и адреса `203.0.113.0/24`, `198.51.100.0/24`.
- Если для проверки нужна настоящая ссылка, попросить пользователя и держать её только во временной папке.
- Любой запуск, который меняет маршрут по умолчанию, включает блокировку брандмауэра или создаёт адаптер, выполняется только с явного согласия пользователя перед запуском.
- Код amnezia-client и turn-proxy-android (GPLv3) не копируется.
- Скопированный код сохраняет лицензионные заголовки: `internal/firewall` (MIT, WireGuard LLC), `internal/wgconf` (Happy Bunny License).
- Внешние репозитории рядом с проектом только для чтения.
- Скачанное проверяется по хэшу, загрузки докачиваются (`curl -C -`).
- Шаг Commit выполняется, только если пользователь разрешил коммиты на этапе выбора способа исполнения. Иначе шаг пропускается.
- Весь текст интерфейса на русском и лежит в `frontend/src/strings.ts`.
- Комментарии в коде на русском, как в ядре.

## Review Focus

1. Нажали «Отключить», пока идёт подключение или открыта капча: подключение отменяется, ничего не остаётся. Тест в Task 8.
2. Нет сети при нажатии «Подключить»: сообщение «нет подключения», адаптер не создаётся. Тест в Task 8.
3. Правило обхода шире туннеля или домен не разрешается: `0.0.0.0/0` в исключениях или несуществующий домен не ломают подключение, правило пропускается с предупреждением в журнале. Тесты в Task 4 и Task 8.
4. Ссылка из мессенджера обрезана или с переносом строки: пробелы и переносы убираются, обрезанная ссылка даёт понятный отказ, а не падение. Тест в Task 2.
5. Файл `profiles.dat` повреждён или зашифрован другим пользователем: программа запускается, сообщает об этом и предлагает импортировать заново, файл не перезаписывается молча. Тест в Task 13.

---

## Структура файлов

```
go.mod, go.sum, .gitignore, README.md, build.ps1, test.ps1, test-admin.ps1
cmd/freeturn-service/   main.go, service.go, install.go, logfile.go
cmd/freeturn/           main.go, api.go, tray.go, captcha.go, autostart.go
cmd/freeturnctl/        main.go                 проверка службы без окна, не поставляется
internal/model/         profile.go, status.go   общие типы
internal/link/          link.go
internal/wgconf/        config.go, parse.go, uapi.go (копия из ядра), single.go
internal/secretmask/    mask.go
internal/split/         rules.go, resolve.go
internal/protect/       protect.go
internal/netcfg/        physical.go, routes.go, watch.go
internal/tunnel/        device.go
internal/corehost/      config.go, host.go, classify.go
internal/firewall/      копия tunnel/firewall, options.go, allow.go
internal/engine/        engine.go, deps.go, monitor.go
internal/statefile/     state.go
internal/ipc/           protocol.go, server.go, client.go
internal/profile/       store.go, dpapi.go, settings.go
internal/update/        check.go
frontend/               embed.go, package.json, index.html, src/
installer/              freeturn.iss
third_party/wintun/     wintun.dll, LICENSE.txt
third_party/webview2/   MicrosoftEdgeWebview2Setup.exe
LICENSES/
```

## Этап 0. Проверка главного риска

### Task 1: Модуль, `protect` и опыт 1

Этот шаг решает судьбу схемы C. Дальше идти можно только после вывода опыта.

**Files:**
- Create: `go.mod`, `.gitignore`, `internal/protect/protect.go`, `internal/protect/protect_test.go`
- Create (временный, удаляется в этой же задаче): `spikes/unicast/main.go`
- Modify: `docs/research-notes.md`

**Interfaces:**
- Produces: `protect.New() *Protector`, `(*Protector).SetInterface(index4, index6 uint32)`, `(*Protector).Protect(fd int) bool`. Тип реализует `mobile.Protector`.

- [ ] **Step 1: Создать `go.mod` и `.gitignore`**

`go.mod` по Global Constraints. `.gitignore`: `build/`, `dist/`, `node_modules/`, `frontend/bindings/`, `spikes/`, `*.exe` кроме `third_party/**`, `*.freeturn`, `*.conf`.

- [ ] **Step 2: Написать падающий тест `TestProtect`**

```go
func TestEncodeIndex4IsNetworkOrder(t *testing.T) {
    if got := encodeIndex4(7); got != 0x07000000 { t.Fatalf("%#x", got) }
}
func TestProtectWithoutInterfaceFails(t *testing.T) {
    p := New()
    if p.Protect(int(mustSocket(t, windows.AF_INET))) { t.Fatal("должен отказать без интерфейса") }
}
func TestProtectIPv4Socket(t *testing.T) {
    p := New(); p.SetInterface(1, 1)
    if !p.Protect(int(mustSocket(t, windows.AF_INET))) { t.Fatal("IPv4") }
}
func TestProtectIPv6Socket(t *testing.T) {
    p := New(); p.SetInterface(1, 1)
    if !p.Protect(int(mustSocket(t, windows.AF_INET6))) { t.Fatal("IPv6") }
}
```

- [ ] **Step 3: Запустить: `go test ./internal/protect`**. Ожидается ошибка компиляции.

- [ ] **Step 4: Реализовать `internal/protect/protect.go`**

`IP_UNICAST_IF = 31` на уровне `IPPROTO_IP` со значением `encodeIndex4` (сетевой порядок байт), `IPV6_UNICAST_IF = 31` на уровне `IPPROTO_IPV6` со значением в порядке хоста. Индексы в `atomic.Uint32`. `Protect` пробует оба варианта, успех любого даёт `true`. При обоих индексах 0 возвращает `false`.

- [ ] **Step 5: Запустить: `go test ./internal/protect`**. Ожидается PASS.

- [ ] **Step 6: Написать `spikes/unicast/main.go`**

Программа требует прав администратора. Первой строкой ставит `time.AfterFunc(30*time.Second, func(){ os.Exit(2) })`: при выходе процесса адаптер и маршруты исчезают сами.

Порядок:

1. Запомнить индекс интерфейса с маршрутом по умолчанию, разрешить IP для `vk.ru`.
2. `tun.CreateTUN("FreeTurnSpike", 1280)`, адрес `10.255.255.2/32`, метрика интерфейса 0, маршрут `0.0.0.0/0`.
3. Проверка A: обычный TCP на `1.1.1.1:443` с таймаутом 3 с должен упасть. Это доказывает, что маршрут идёт в адаптер.
4. Проверка B: TLS к разрешённому IP `vk.ru` c `ServerName: "vk.ru"` и `Control`, вызывающим `Protect`, должен пройти.
5. Проверка C: `net.ListenConfig{Control}.ListenPacket(ctx, "udp", "")`, DNS-запрос на `1.1.1.1:53`, ответ должен прийти. Go создаёт здесь двухстековый сокет, это поведение `turndial/direct.go`.
6. Проверка D: `Dialer{Control}` по `udp4` на `1.1.1.1:53`, ответ должен прийти.
7. Печать PASS или FAIL по каждой проверке, закрытие адаптера.

- [ ] **Step 7: Получить согласие пользователя и запустить опыт**

Сказать пользователю: «Интернет пропадёт примерно на 15 секунд, нужен запрос UAC». Запуск через `Start-Process -Verb RunAs` с записью вывода в файл в scratchpad. Ожидается: A падает, B, C и D проходят. Работа хука внутри настоящего ядра проверяется в Task 12.

- [ ] **Step 8: Зафиксировать результат**

Записать таблицу результатов в `docs/research-notes.md`, удалить `spikes/`. Если B, C или D не прошли: остановиться, сообщить пользователю и перейти к запасному варианту раздела 12 спецификации (патч ядра, чтобы хук видел адрес, и маршруты `/32`). План в этом случае пересматривается.

- [ ] **Step 9: Commit**

```bash
git add go.mod .gitignore internal/protect docs/research-notes.md docs/superpowers
git commit -m "feat: обход туннеля через IP_UNICAST_IF, опыт с маршрутом по умолчанию"
```

## Этап 1. Чистая логика

### Task 2: Модель и разбор ссылки

**Files:**
- Create: `internal/model/profile.go`, `internal/model/status.go`, `internal/link/link.go`, `internal/link/link_test.go`

**Interfaces:**
- Produces:

```go
package model

type Profile struct {
    ID, Name, Provider, Peer, Transport string
    ObfProfile, ObfKey string
    ObfTimingMs, Threads, StreamsPerCred, MTU int
    ClientID, CallLink, DNSMode string
    DNSServers []string
    ManualCaptcha, GeneratedClientID bool
    WGConfig string
}
type Field string // FieldCallLink = "callLink", FieldWGConfig = "wgConfig"
func (p Profile) Missing() []Field

type RuleKind string // RuleIP = "ip", RuleSubnet = "subnet", RuleDomain = "domain"
type Rule struct { Kind RuleKind; Value string }

type Options struct {
    KillSwitch, AllowLAN bool
    Rules []Rule
}
type ConnectRequest struct { Profile Profile; Options Options }

type Phase string // "idle", "connecting", "captcha", "connected",
                  // "reconnecting", "error", "blocked"
type ErrorCode string // "no_network", "no_handshake", "server_silent", "invalid_call_link",
                      // "call_full", "anon_blocked", "captcha_failed", "adapter", "core",
                      // "bad_profile", "service_down"
type WarningCode string // "other_vpn", "rule_skipped", "domain_unresolved",
                        // "stale_handshake", "no_dns"
type Warning struct { Code WarningCode; Value string }
type Status struct {
    Phase Phase; Code ErrorCode; Detail string
    Streams, Total int
    TxRate, RxRate, TxTotal, RxTotal int64
    CaptchaURL string; ProfileID string; Warnings []Warning
    AwaitingProfile bool // служба перезапустилась и ждёт профиль от окна
}
type Physical struct {
    LUID uint64; Index4, Index6 uint32
    Gateway4, Gateway6 netip.Addr; DNS []netip.Addr
}
```

Константы называются `PhaseIdle`, `ErrNoNetwork`, `WarnOtherVPN` и так далее. `Status.CaptchaURL` непусто только в `PhaseCaptcha`. Текст для кодов находится в `frontend/src/strings.ts`, Go шлёт только коды и `Value`.

```go
package link
var ErrScheme, ErrPayload, ErrVersion, ErrRequired, ErrTCPMode error
func Parse(raw string) (model.Profile, error)
func NewClientID() string // 16 случайных байт в hex
```

- [ ] **Step 1: Написать падающие тесты `link_test.go`**

Вспомогательная `encode(map[string]any) string` собирает ссылку `base64.RawURLEncoding`. Сценарии из `CoreConfigTest` лайт-версии и новые:

```go
TestParseFull          // все поля; Peer "203.0.113.5:56000", Threads 10, CallLink, WGConfig, MTU 1300
TestParseNumbersAsStrings // {"n":"10","timing":"20"} -> Threads 10, ObfTimingMs 20
TestParseMcapBoolAndString // true и "true" -> ManualCaptcha true
TestParseIgnoresListenBondKcp // Profile без этих значений, ошибки нет
TestParseObfNoneByDefault // без obf -> ObfProfile "none"
TestParseDirectProvider // provider "direct", Threads 0 если нет n
TestParseUppercaseScheme // "FREETURN://..."
TestParseStripsFragmentAndQuery // "...#name", "...?x=1"
TestParseTrimsSpaceAndNewlines // "  ссылка\r\n", перенос строки в середине
TestParseTruncatedPayload // обрезанная на половине -> errors.Is(err, ErrPayload)
TestParseGarbage // "hello" -> ErrScheme; "freeturn://" -> ErrPayload
TestParseUnsupportedVersion // v=2 -> ErrVersion
TestParseRequired // без provider или peer -> ErrRequired
TestParseTCPMode // mode=tcp -> ErrTCPMode
TestMissing // provider=vk без vk -> [FieldCallLink]; без wg -> [FieldWGConfig]; direct без vk -> нет FieldCallLink
TestNewClientIDFormat // 32 hex-символа
```

- [ ] **Step 2: Запустить: `go test ./internal/link`**. Ожидается ошибка компиляции.

- [ ] **Step 3: Реализовать `internal/model/*.go` и `internal/link/link.go`**

Разбирать в `map[string]json.RawMessage`, чтение значения снимает кавычки у строк, а числа и булевы берёт как текст, поэтому `"n":10` и `"n":"10"` равноправны. Все пробельные символы удаляются из ссылки до декодирования. Base64 принимает и наличие, и отсутствие `=`. `Name` из поля `name`, иначе `Peer`.

- [ ] **Step 4: Запустить: `go test ./internal/link ./internal/model`**. Ожидается PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/model internal/link
git commit -m "feat: модель профиля и разбор ссылки freeturn"
```

### Task 3: WireGuard-конфиг

**Files:**
- Create: `internal/wgconf/config.go`, `parse.go`, `uapi.go`, `single.go`, `LICENSE-CORE.txt`, `single_test.go`

**Interfaces:**
- Produces: тип `wgconf.Config` (поля как `tunnel.Config` ядра) и

```go
func ParseForTunnel(text string, mtuOverride int) (*Config, error) // ErrPeerCount при len(Peers) != 1
func (c *Config) UAPIFor(endpoint netip.AddrPort) (string, error)
func (c *Config) AllowedPrefixes() []netip.Prefix
```

- [ ] **Step 1: Скопировать из ядра**

`internal/tunnel/config.go`, `internal/tunnel/uapi.go`, `internal/tunnel/wgconf/wgconf.go` объединить в пакет `wgconf`, заменив ссылки `tunnel.` на локальные типы. Сами алгоритмы не менять, чтобы новые версии переносились diff-ом. `LICENSE` ядра скопировать как `LICENSE-CORE.txt`, в начале каждого файла указать источник и коммит `562cfb4`.

- [ ] **Step 2: Написать падающие тесты `single_test.go`**

```go
TestParseForTunnelPlainWG  // ключ fakeKey(1), Address 10.0.0.2/32, DNS 1.1.1.1 -> MTU 1280 по умолчанию
TestParseForTunnelMTU      // conf MTU=1400, override 0 -> 1400; override 1300 -> 1300
TestParseForTunnelAmnezia  // Jc=4 S1=15 H1=1 -> UAPI содержит "jc=4\n", "s1=15\n", "h1=1\n"
TestParseForTunnelIgnoresScripts // PreUp/PostUp/PreDown/PostDown не дают ошибки и не меняют Config
TestParseForTunnelPeerCount // 0 пиров или 2 пира -> errors.Is(err, ErrPeerCount)
TestUAPIForSetsEndpoint    // UAPIFor(127.0.0.1:40123) содержит "endpoint=127.0.0.1:40123\n"; исходный Endpoint vps:51820 не встречается
TestUAPIHasHexPrivateKey   // "private_key=" + hex.EncodeToString(fakeKeyBytes(1))
```

- [ ] **Step 3: Запустить: `go test ./internal/wgconf`**. Ожидается FAIL.

- [ ] **Step 4: Реализовать `single.go`**

`UAPIFor` работает на копии конфига, исходный `Config` не меняет.

- [ ] **Step 5: Запустить: `go test ./internal/wgconf`**. Ожидается PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/wgconf
git commit -m "feat: разбор WireGuard-конфига, скопированный из ядра"
```

### Task 4: Правила обхода и маскировка секретов

**Files:**
- Create: `internal/split/rules.go`, `internal/split/rules_test.go`, `internal/secretmask/mask.go`, `internal/secretmask/mask_test.go`

**Interfaces:**
- Produces:

```go
package split
type Compiled struct {
    Prefixes []netip.Prefix  // ip и subnet
    Domains  []string
    Skipped  []Skip          // причина для журнала
}
type Skip struct { Rule model.Rule; Reason string }
func Compile(rules []model.Rule) Compiled
func Classify(value string) (model.Rule, error) // определяет тип по вводу пользователя

package secretmask
type Masker struct{ /* */ }
func New(secrets ...string) *Masker
func ForProfile(p model.Profile, c *wgconf.Config) *Masker
func (m *Masker) Mask(s string) string
```

- [ ] **Step 1: Написать падающие тесты**

```go
TestClassify // "203.0.113.7" -> ip; "203.0.113.0/24" -> subnet; "Example.COM." -> domain "example.com"
TestClassifyRejects // "", "not a domain!", "300.1.1.1/40" -> ошибка; "*.example.com" -> ошибка с текстом про шаблоны
TestCompilePrefixes // ip превращается в /32 и /128; подсеть маскируется: 203.0.113.9/24 -> 203.0.113.0/24
TestCompileSkipsDefaultRoute // 0.0.0.0/0, ::/0, 0.0.0.0/1 в Skipped, в Prefixes нет
TestCompileSkipsTooWide // префикс короче /8 в Skipped
TestCompileDedups // одно и то же правило дважды -> один префикс

TestMaskReplaces // New("secret") -> "a secret b" => "a *** b"
TestMaskEmptySecretIgnored // New("") не меняет строку
TestMaskLongestFirst // New("abc", "abcdef") -> "abcdef" => "***"
TestForProfileCoversEverything // приватный ключ base64 и hex, PSK, ObfKey, ClientID, CallLink и его последний сегмент пути
```

- [ ] **Step 2: Запустить: `go test ./internal/split ./internal/secretmask`**. Ожидается ошибка компиляции.

- [ ] **Step 3: Реализовать оба пакета**

Минимальная длина префикса `/8` для IPv4 и `/16` для IPv6: более широкие правила почти полностью обходят туннель. Значение маски `***`.

- [ ] **Step 4: Запустить тесты.** Ожидается PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/split internal/secretmask
git commit -m "feat: правила обхода и маскировка секретов"
```

## Этап 2. Системные части

### Task 5: Сеть

**Files:**
- Create: `internal/netcfg/physical.go`, `routes.go`, `watch.go`, `plan_test.go`, `netcfg_admin_test.go`, `test-admin.ps1`

**Interfaces:**
- Produces:

```go
var ErrNoNetwork error
func FindPhysical(exclude uint64) (model.Physical, error)
func ConfigureInterface(luid uint64, addrs []netip.Prefix, mtu int) error
func ApplyTunnelRoutes(luid uint64, allowed []netip.Prefix, dns []netip.Addr) error // шаг 5: маршруты и DNS вместе
func ClearTunnel(luid uint64) error
func SetBypass(ph model.Physical, prefixes []netip.Prefix) error // заменяет прошлый набор
func ClearBypass() error
func OtherTunnel(exclude uint64) (name string, found bool)
func WatchDefaultRoute(cb func()) (stop func(), err error)
```

- [ ] **Step 1: Написать падающие тесты на чистые функции в `plan_test.go`**

```go
TestPlanRoutesFullV4AddsV6Sink  // [0.0.0.0/0] -> 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1; самого /0 нет
TestPlanRoutesFullBoth          // [0.0.0.0/0, ::/0] -> те же четыре, без дублей
TestPlanRoutesSplit             // [10.0.0.0/24] -> только он, IPv6-маршрутов нет
TestPickDefault                 // таблица строк: выбирается наименьшая сумма метрик, исключённый LUID пропускается
TestPickDefaultSkipsTunnelTypes // строка с IfType tunnel/none не выбирается как физическая
TestPickDefaultNoRoutes         // пустая таблица -> ErrNoNetwork
```

- [ ] **Step 2: Запустить: `go test ./internal/netcfg`**. Ожидается ошибка компиляции.

- [ ] **Step 3: Реализовать пакет на `winipcfg`**

`LUID.SetIPAddressesForFamily`, `LUID.SetRoutesForFamily`, `LUID.SetDNS`, `LUID.IPInterface` (метрика 0, `UseAutomaticMetric=false`, MTU через `NLMTU`), `GetIPForwardTable2`, `GetAdaptersAddresses`, `RegisterRouteChangeCallback`. Чистые функции: `planRoutes` и `pickDefault`. `WatchDefaultRoute` гасит дребезг: вызывает `cb` спустя 2 секунды тишины.

`OtherTunnel` считает другим туннелем адаптер с маршрутом по умолчанию и типом интерфейса `IF_TYPE_PROP_VIRTUAL` или `IF_TYPE_TUNNEL`, кроме исключённого.

- [ ] **Step 4: Запустить: `go test ./internal/netcfg`**. Ожидается PASS.

- [ ] **Step 5: Написать `netcfg_admin_test.go` (`//go:build admin`) и `test-admin.ps1`**

Создаёт адаптер `FreeTurnTest`, ставит адрес, маршрут `198.51.100.0/24`, исключение `203.0.113.0/24`, проверяет их в таблице, удаляет, проверяет отсутствие. Маршрут по умолчанию не трогает, поэтому согласие на обрыв сети не нужно. Скрипт запускает `go test -tags admin ./internal/netcfg ./internal/tunnel ./internal/firewall`.

- [ ] **Step 6: Запустить через UAC: `pwsh -File test-admin.ps1`**. Ожидается PASS для `netcfg`.

- [ ] **Step 7: Commit**

```bash
git add internal/netcfg test-admin.ps1
git commit -m "feat: адрес, маршруты, DNS и наблюдение за сетью"
```

### Task 6: Адаптер, WireGuard и ядро

**Files:**
- Create: `internal/tunnel/device.go`, `internal/tunnel/device_admin_test.go`, `third_party/wintun/wintun.dll`, `third_party/wintun/LICENSE.txt`
- Create: `internal/corehost/config.go`, `host.go`, `classify.go`, `config_test.go`, `classify_test.go`

**Interfaces:**
- Consumes: `wgconf.Config`, `model.Profile`, `protect.Protector`.
- Produces:

```go
package tunnel
const AdapterName = "FreeTurn"
type Stats struct { RxBytes, TxBytes int64; LastHandshake time.Time }
type Device struct{ /* */ }
func Open(cfg *wgconf.Config, endpoint netip.AddrPort, logf func(string, ...any)) (*Device, error)
func (d *Device) LUID() uint64
func (d *Device) WaitHandshake(ctx context.Context) error
func (d *Device) Stats() (Stats, error)
func (d *Device) Close()
func RemoveStale() error

package corehost
type Sink = mobile.EventSink
func BuildConfigJSON(p model.Profile, listen netip.AddrPort) (string, error)
type Host struct{ /* */ }
func New(stateDir string, sink Sink, protector mobile.Protector) *Host
func (h *Host) Start(p model.Profile, listen netip.AddrPort) error
func (h *Host) Stop()
func (h *Host) Reconnect()
func (h *Host) Wake()
func (h *Host) Rates() (txTotal, rxTotal, txRate, rxRate int64)
func Classify(errMsg string) model.ErrorCode
func FreePort() (netip.AddrPort, error)
```

- [ ] **Step 1: Положить `wintun.dll` 0.14.1 в `third_party/wintun`**

Скачать `https://www.wintun.net/builds/wintun-0.14.1.zip` с докачкой, в отдельную пустую папку scratchpad. Источник медленный, поэтому запуск в фоне. Распаковать `wintun/bin/amd64/wintun.dll` и `LICENSE.txt`. Хэш DLL обязан быть `5e31cdae7d2e7b5e5daa32455e7742312a94b50573f7ac429dbc4bdfb829c79e`, а `Get-AuthenticodeSignature` должен показать `Valid` и `WireGuard LLC`. Эта копия совпадает с подписанной копией из другого VPN-клиента.

- [ ] **Step 2: Написать падающие тесты `corehost`**

```go
TestBuildConfigJSONValid // mobile.ValidateConfig(json) == "" для vk и для direct
TestBuildConfigHasNoTunnel // в JSON "tunnel" пустой, "routes" false, proxy.mode "udp"
TestBuildConfigListen // proxy.listen == "127.0.0.1:40123"
TestBuildConfigFields // links [CallLink], streamsPerCred, obf.profile/key/timingMs, dns.mode/servers, turn.n/transport, clientId
TestBuildConfigKeepsDefaults // поля, которых нет в профиле, берутся из mobile.DefaultConfigJSON()
TestClassify // "provider fatal...: INVALID_JOIN_LINK" -> ErrInvalidCallLink; CALL_FULL -> ErrCallFull;
             // ANON_BLOCKED -> ErrAnonBlocked; FATAL_CAPTCHA_FAILED_NO_STREAMS -> ErrCaptchaFailed;
             // "что-то другое" -> ErrCore
TestFreePortIsLoopback // адрес 127.0.0.1, порт не 0 и не 9000
```

- [ ] **Step 3: Запустить: `go test ./internal/corehost`**. Ожидается ошибка компиляции.

- [ ] **Step 4: Реализовать `corehost`**

`BuildConfigJSON` разбирает `mobile.DefaultConfigJSON()` в `map[string]any`, накладывает значения профиля и сериализует обратно: так новые поля ядра не ломают сборку, а строгий разбор ядра ловит ошибки имён. `Host.New` вызывает `mobile.SetStateDir`, `mobile.SetEventSink`, `mobile.SetProtect` один раз.

- [ ] **Step 5: Запустить: `go test ./internal/corehost`**. Ожидается PASS.

- [ ] **Step 6: Реализовать `internal/tunnel/device.go`**

В `init` присвоить `tun.WintunTunnelType = "FreeTurn"`. `Open`: `tun.CreateTUNWithRequestedGUID(AdapterName, &guid, cfg.MTU)`, `device.NewDevice(dev, conn.NewDefaultBind(), logger)`, `dev.IpcSet(cfg.UAPIFor(endpoint))`, `dev.Up()`. Любая ошибка закрывает созданное. `Stats` разбирает `IpcGet`, как `parseStats` в ядре. `WaitHandshake` опрашивает каждые 250 мс до `ctx.Done()`. `RemoveStale` открывает адаптер `wintun.OpenAdapter` и закрывает его, отсутствие адаптера не ошибка.

- [ ] **Step 7: Написать `device_admin_test.go`**

`TestOpenAndClose` (`//go:build admin`): конфиг с `fakeKey`, endpoint `127.0.0.1:9`, проверить `LUID() != 0`, `Close`, затем `net.InterfaceByName("FreeTurn")` возвращает ошибку.

- [ ] **Step 8: Запустить `pwsh -File test-admin.ps1` через UAC.** Ожидается PASS для `tunnel`.

- [ ] **Step 9: Commit**

```bash
git add internal/tunnel internal/corehost third_party/wintun
git commit -m "feat: адаптер WireGuard и обёртка над ядром"
```

### Task 7: Kill switch

**Files:**
- Create: `internal/firewall/*` (копия `tunnel/firewall` из `golang.zx2c4.com/wireguard/windows@v1.1.1`), `internal/firewall/LICENSE-WIREGUARD.txt`, `options.go`, `allow.go`, `options_test.go`, `firewall_admin_test.go`

**Interfaces:**
- Produces:

```go
package firewall
type Options struct {
    TunLUID  uint64      // 0: адаптера ещё нет, разрешение для него не ставится
    DNS      []netip.Addr
    AllowLAN bool
    Bypass   []netip.Prefix
}
func Enable(o Options) error
func Update(o Options) error // новая сессия, затем закрытие старой: блокировка не прерывается
func Disable()
func Enabled() bool
```

- [ ] **Step 1: Скопировать пакет, сохранив заголовки SPDX**

- [ ] **Step 2: Написать падающий тест `options_test.go`**

```go
TestLANPrefixes // lanPrefixes() содержит 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16,
                // 224.0.0.0/4, fc00::/7, fe80::/10, ff00::/8
TestBuildPermitsSkipsTunWhenZero // при TunLUID 0 список шагов без permitTunInterface
TestBuildPermitsIncludesBypassAndLAN // AllowLAN + Bypass -> шаги в порядке: service, DNS, loopback, tun, dhcp, ndp, lan, bypass, blockAll
```

- [ ] **Step 3: Запустить: `go test ./internal/firewall`**. Ожидается ошибка компиляции.

- [ ] **Step 4: Реализовать `options.go` и `allow.go`**

`buildSteps(o Options) []step` возвращает описание шагов, `EnableFirewall` из копии заменяется на `Enable`, выполняющий шаги в одной транзакции. `doNotRestrict` убирается. `permitSubnets(session, baseObjects, weight, prefixes)` использует `FWPM_CONDITION_IP_REMOTE_ADDRESS` с `FWP_V4_ADDR_MASK` и `FWP_V6_ADDR_MASK` на слоях `ALE_AUTH_CONNECT` и `ALE_AUTH_RECV_ACCEPT` по образцу `permitLoopback`. Вес LAN и исключений 12, как у `permitTunInterface`. `Update` создаёт новую сессию и только после успеха закрывает старую.

- [ ] **Step 5: Запустить: `go test ./internal/firewall`**. Ожидается PASS.

- [ ] **Step 6: Написать `firewall_admin_test.go`**

`TestEnableBlocksAndDisableRestores`: `Enable(Options{AllowLAN: true})`, TCP на `1.1.1.1:443` падает за 3 с, `Disable()`, тот же TCP проходит. Защита: `time.AfterFunc(10*time.Second, Disable)`.

- [ ] **Step 7: Получить согласие пользователя (интернет пропадёт на несколько секунд) и запустить `test-admin.ps1`.** Ожидается PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/firewall
git commit -m "feat: kill switch на WFP, код из wireguard-windows"
```

### Task 8: Движок подключения

**Files:**
- Create: `internal/engine/deps.go`, `engine.go`, `fakes_test.go`, `engine_test.go`

**Interfaces:**
- Consumes: `model.*`, `wgconf.ParseForTunnel`, `split.Compile`, `secretmask.ForProfile`, `firewall.Options`, `tunnel.Stats`.
- Produces:

```go
package engine
type Core interface {
    Start(p model.Profile, listen netip.AddrPort) error
    Stop(); Reconnect(); Wake()
    Rates() (txTotal, rxTotal, txRate, rxRate int64)
}
type TunnelDevice interface {
    LUID() uint64
    WaitHandshake(ctx context.Context) error
    Stats() (tunnel.Stats, error)
    Close()
}
type Tunnels interface {
    Open(cfg *wgconf.Config, ep netip.AddrPort) (TunnelDevice, error)
}
type Network interface {
    FindPhysical(exclude uint64) (model.Physical, error)
    ConfigureInterface(luid uint64, addrs []netip.Prefix, mtu int) error
    ApplyTunnelRoutes(luid uint64, allowed []netip.Prefix, dns []netip.Addr) error
    ClearTunnel(luid uint64) error
    SetBypass(ph model.Physical, p []netip.Prefix) error
    ClearBypass() error
    OtherTunnel(exclude uint64) (string, bool)
}
type Firewall interface { Enable(firewall.Options) error; Update(firewall.Options) error; Disable() }
type Protector interface { SetInterface(index4, index6 uint32) }
type Resolver interface {
    Resolve(ctx context.Context, domains []string, ph model.Physical) []netip.Addr
}
type Deps struct {
    Core Core; Tunnels Tunnels; Net Network; FW Firewall; Protect Protector; Resolver Resolver
    FreePort func() (netip.AddrPort, error)
    OnChange func(model.Status)
    Logf func(level, msg string)
    Now func() time.Time
    CoreTimeout, HandshakeTimeout time.Duration // 60 с и 20 с
}
type Engine struct{ /* */ }
func New(d Deps) *Engine
func (e *Engine) Connect(req model.ConnectRequest) error // запускает в горутине, ошибка только если уже занято
func (e *Engine) Disconnect()                            // ждёт завершения отката
func (e *Engine) Status() model.Status
func (e *Engine) OnCoreState(state string, streams, total int, errMsg string)
func (e *Engine) OnCaptcha(url string, manual bool)
func (e *Engine) ArmBlock(o model.Options) error         // падение службы: блокировка и AwaitingProfile
func (e *Engine) AwaitProfile()                          // падение службы без kill switch
```

- [ ] **Step 1: Написать `fakes_test.go`**

Заглушки реализуют интерфейсы `Deps` и пишут вызовы в общий `*[]string` имена вида `core.start`, `net.routes`, `fw.enable`. Каждая заглушка умеет падать на заданном шаге, блокироваться до сигнала и отдавать заданный результат.

- [ ] **Step 2: Написать падающие тесты `engine_test.go`**

```go
TestConnectOrder // журнал вызовов равен:
// protect.set, core.start, (OnCoreState connected), tunnel.open, net.configure, tunnel.handshake,
// fw.enable, net.bypass, net.routes -> Phase Connected
TestConnectKillSwitchOff // в журнале нет fw.enable
TestDisconnectOrder // net.clear, net.bypassClear, fw.disable, tunnel.close, core.stop -> Phase Idle

// откат: сбой на каждом шаге оставляет систему чистой
TestRollbackCoreStartFails       // Phase Error, ErrCore, tunnel.open не вызван
TestRollbackCoreTimeout          // 60 с без connected -> ErrServerSilent, core.stop вызван
TestRollbackTunnelOpenFails      // ErrAdapter, core.stop вызван
TestRollbackNoHandshake          // ErrNoHandshake, tunnel.close и core.stop вызваны, fw.enable не вызван
TestRollbackRoutesFail           // ErrAdapter, fw.disable, tunnel.close, core.stop вызваны

TestCaptchaManualPhase // OnCaptcha("http://127.0.0.1:1/", true) -> PhaseCaptcha, CaptchaURL задан
TestCaptchaSuspendsCoreTimeout // при открытой капче таймаут 60 с не срабатывает
TestCaptchaAutoHidden // OnCaptcha(url, false) -> фаза не меняется
TestCaptchaClosed // OnCaptcha("", false) -> CaptchaURL пуст, возврат к Connecting

TestDisconnectDuringConnecting // core.start завис в ожидании connected; Disconnect -> core.stop, tunnel.open не вызван, Phase Idle
TestDisconnectDuringCaptcha    // то же при открытой капче
TestDisconnectDuringHandshake  // WaitHandshake получает отмену ctx, tunnel.close, core.stop, Phase Idle
TestConnectWhileBusy           // второй Connect -> ошибка, первый не прерван

TestNoNetwork // FindPhysical -> ErrNoNetwork: Phase Error, Code ErrNoNetwork, tunnel.open не вызван, core.start не вызван
TestOtherVPNWarns // OtherTunnel=("AmneziaVPN",true): Warning{other_vpn, "AmneziaVPN"}, подключение продолжается
TestNoDNSWarns // конфиг без DNS: Warning{no_dns}, подключение успешно

TestFatalWithKillSwitch // OnCoreState("error",0,12,"... CALL_FULL") в Connected: Phase Blocked, Code ErrCallFull, fw.disable не вызван, net.clear и tunnel.close вызваны
TestFatalWithoutKillSwitch // то же: Phase Error, fw.disable вызван
TestDisconnectFromBlocked // Disconnect -> fw.disable, Phase Idle
TestArmBlock // ArmBlock: fw.enable с TunLUID 0, Phase Blocked, AwaitingProfile true
TestConnectFromBlockedKeepsBlock // после ArmBlock Connect разрешён: fw.update с настоящим LUID, fw.disable не вызван
TestFailedConnectFromBlockedStaysBlocked // сбой подключения из Blocked: Phase Blocked, блокировка не снята
TestAwaitProfile // AwaitProfile: Phase Idle, AwaitingProfile true; Connect сбрасывает флаг

TestBadWGConfig // WGConfig "мусор": Phase Error, ErrBadProfile, core.start не вызван
TestDomainNotResolvedIsSkipped // Resolve вернул пусто: подключение успешно, Warning{domain_unresolved, домен}
TestOversizedRuleIsSkipped // Rule 0.0.0.0/0: подключение успешно, в SetBypass его нет, Warning{rule_skipped, "0.0.0.0/0"}
TestSecretsNeverLogged // Logf не получает приватный ключ, ObfKey, ClientID, CallLink на протяжении полного цикла
```

- [ ] **Step 3: Запустить: `go test ./internal/engine`**. Ожидается ошибка компиляции.

- [ ] **Step 4: Реализовать `engine.go`**

Один рабочий поток на подключение с `context.WithCancel`. `Disconnect` отменяет контекст и ждёт выхода потока, поэтому откат выполняется в одном месте. Откат это стек функций: каждый успешный шаг кладёт свою обратную операцию. `Status` защищён мьютексом, каждое изменение вызывает `OnChange`. Весь текст журнала проходит через `Masker`.

- [ ] **Step 5: Запустить: `go test -race ./internal/engine`**. Ожидается PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/engine
git commit -m "feat: порядок подключения, откат и состояния"
```

### Task 9: Наблюдение и разрешение доменов

**Files:**
- Create: `internal/engine/monitor.go`, `monitor_test.go`, `internal/split/resolve.go`, `resolve_test.go`

**Interfaces:**
- Consumes: `engine.Engine`, `protect.Protector`.
- Produces:

```go
func (e *Engine) NetworkChanged()
func (e *Engine) Woke()
func (e *Engine) Tick(now time.Time) // таймер каждые 30 с
func (e *Engine) RefreshRates()       // таймер каждую секунду, только в Connected

package split
type DNSResolver struct{ /* */ }
func NewResolver(protect func(fd int) bool) *DNSResolver
func (r *DNSResolver) Resolve(ctx context.Context, domains []string, ph model.Physical) []netip.Addr
```

- [ ] **Step 1: Написать падающие тесты**

```go
TestNetworkChangedUpdatesEverything // FindPhysical вернул новый интерфейс: protect.set, net.bypass на новый Physical, fw.update, core.reconnect
TestNetworkChangedLostNetwork // ErrNoNetwork: маршруты на месте, Phase Reconnecting, core.reconnect не вызван
TestNetworkChangedSameInterface // тот же LUID и шлюз: ничего не вызывается
TestWokeCallsWake // Woke в Connected -> core.wake
TestRefreshRates // Rates попадают в Status, OnChange вызван; в Idle не вызывается
TestStaleHandshakeReconnects // Tick: ядро connected, LastHandshake старше 3 минут -> core.reconnect и предупреждение, второй Tick в ту же минуту не повторяет
TestDomainRefreshEveryFiveMinutes // Tick спустя 5 минут: новый адрес добавлен к старым, net.bypass и fw.update вызваны
TestDomainRefreshKeepsOldAddresses // Resolve вернул пусто: старые адреса остаются
TestReconnectingPhase // OnCoreState("connecting",0,12,"") в Connected -> PhaseReconnecting, маршруты не сняты
TestReconnectedPhase // затем OnCoreState("connected",3,12,"") -> PhaseConnected

TestResolverUsesPhysicalDNS // локальный UDP DNS-сервер на 127.0.0.1 отвечает A-записью, Resolve возвращает её; protect вызван
TestResolverUnknownDomain // NXDOMAIN -> пустой результат без ошибки
```

- [ ] **Step 2: Запустить тесты.** Ожидается ошибка компиляции.

- [ ] **Step 3: Реализовать**

`DNSResolver` использует `net.Resolver{PreferGo: true, Dial: ...}` с `Control`, вызывающим `protect`, и серверами `ph.DNS`. Если `ph.DNS` пуст, домены не разрешаются. Таймаут на домен 3 с.

- [ ] **Step 4: Запустить: `go test -race ./internal/engine ./internal/split`**. Ожидается PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/engine internal/split
git commit -m "feat: реакция на смену сети, сон и обновление доменов"
```

### Task 10: Канал и файл состояния

**Files:**
- Create: `internal/ipc/protocol.go`, `server.go`, `client.go`, `ipc_test.go`, `internal/statefile/state.go`, `state_test.go`

**Interfaces:**
- Produces:

```go
package ipc
const PipePath = `\\.\pipe\FreeTurnService`
const PipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"
type Handler interface {
    Connect(model.ConnectRequest) error
    Disconnect()
    Status() model.Status
    Logs() []string
}
type Server struct{ /* */ }
func Serve(path, sddl string, h Handler) (*Server, error)
func (s *Server) Broadcast(ev Event)
func (s *Server) Close()
type Event struct { Kind string; Status *model.Status; Log string } // Kind: "status", "log"
type Client struct{ /* */ }
func Dial(path string, timeout time.Duration, onEvent func(Event)) (*Client, error)
func (c *Client) Connect(r model.ConnectRequest) error
func (c *Client) Disconnect() error
func (c *Client) Status() (model.Status, error)
func (c *Client) Logs() ([]string, error)
func (c *Client) Done() <-chan struct{} // закрывается при обрыве канала
func (c *Client) Close()

package statefile
type State struct { Wanted, KillSwitch, AllowLAN bool; BootUnix int64 }
type Action int // ActionNone, ActionRearm, ActionAwaitProfile, ActionClear
func Decide(s State, bootNow int64) Action
func Load(path string) (State, error)
func Save(path string, s State) error  // атомарно: запись во временный файл и rename
func BootUnix() int64
```

- [ ] **Step 1: Написать падающие тесты**

```go
TestRoundTrip // Dial к уникальному имени канала, Status/Connect/Disconnect/Logs доходят до заглушки Handler
TestConnectErrorPropagates // Handler.Connect вернул ошибку -> Client.Connect её возвращает
TestBroadcastReachesAllClients // два клиента получают Event
TestClientDoneOnServerClose // Server.Close -> Done закрыт
TestOversizedMessageRejected // строка больше 1 МиБ закрывает соединение, сервер продолжает принимать
TestMalformedJSONDropsClient // мусор закрывает этого клиента, второй клиент работает
TestProfileNotInEvents // JSON события статуса не содержит полей профиля

TestDecideRearm // Wanted, KillSwitch, тот же boot -> ActionRearm
TestDecideAwaitProfile // Wanted без KillSwitch -> ActionAwaitProfile
TestDecideOtherBoot // BootUnix отличается больше чем на 60 с -> ActionClear
TestDecideBootJitter // разница 30 с считается той же загрузкой
TestDecideNotWanted // ActionNone
TestLoadMissingFile // нет файла -> нулевой State, без ошибки
TestLoadCorrupt // мусор -> нулевой State, без ошибки
```

- [ ] **Step 2: Запустить: `go test ./internal/ipc ./internal/statefile`**. Ожидается ошибка компиляции.

- [ ] **Step 3: Реализовать**

Канал через `github.com/amnezia-vpn/amneziawg-go/v3/ipc/namedpipe` (`ListenConfig{SecurityDescriptor}.Listen`, `DialTimeout`): новых зависимостей нет. Сообщения это JSON по строкам с полем `type` (`req`, `resp`, `event`) и `id`. `bufio.Scanner` с пределом 1 МиБ. Медленный клиент не блокирует службу: у каждого клиента своя очередь на 256 событий, при переполнении события статуса заменяют предыдущие, а логи отбрасываются.

- [ ] **Step 4: Запустить: `go test -race ./internal/ipc ./internal/statefile`**. Ожидается PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/ipc internal/statefile
git commit -m "feat: именованный канал и файл состояния службы"
```

### Task 11: Служба

**Files:**
- Create: `cmd/freeturn-service/main.go`, `service.go`, `install.go`, `logfile.go`, `logfile_test.go`, `cmd/freeturnctl/main.go`

**Interfaces:**
- Consumes: всё из Task 5–10.
- Produces: команды `FreeTurnService.exe install`, `uninstall`, `console`. Без аргументов exe работает как служба. `freeturnctl status|connect <файл.json>|disconnect|logs` для проверки без окна.

- [ ] **Step 1: Написать падающий тест `logfile_test.go`**

```go
TestRotateAtLimit // запись больше 1 МиБ -> service.log, service.1.log, service.2.log; файлов не больше 3
TestRingKeepsLast // кольцо на 2000 строк отдаёт последние
```

- [ ] **Step 2: Запустить: `go test ./cmd/freeturn-service`**. Ожидается ошибка компиляции.

- [ ] **Step 3: Реализовать `logfile.go`**. Запустить тест, ожидается PASS.

- [ ] **Step 4: Реализовать `service.go`**

Сборка зависимостей `engine.Deps` из настоящих пакетов. Функция `run(ctx)` общая для службы и `console`:

1. Создать `%ProgramData%\FreeTurn` и выставить права: SYSTEM и администраторы полный доступ, наследование отключено (`windows.SetNamedSecurityInfo`).
2. Вызвать `tunnel.RemoveStale`.
3. `statefile.Load`, `statefile.Decide`: при `ActionRearm` вызвать `engine.ArmBlock`, при `ActionAwaitProfile` вызвать `engine.AwaitProfile`, при `ActionClear` сохранить пустое состояние.
4. `ipc.Serve`, подписка `engine.OnChange` на `Broadcast`, `netcfg.WatchDefaultRoute` на `engine.NetworkChanged`, таймер 30 с на `Tick`, таймер 1 с на `RefreshRates`.
5. Запись `Wanted=true` при `Connect` и `Wanted=false` при `Disconnect`.

`svc.Handler` принимает `Stop`, `Shutdown`, `PowerEvent`. `PBT_APMRESUMEAUTOMATIC` (`0x12`) вызывает `engine.Woke`. `Stop` и `Shutdown` выполняют `Disconnect` и сбрасывают `Wanted`.

`corehost.New` получает каталог `%ProgramData%\FreeTurn\core`. `mobile.Protector` у `Host` это `protect.Protector`, `Sink` направляет события в `engine.OnCoreState` и `engine.OnCaptcha`. Интерфейсы `engine.Network`, `engine.Tunnels`, `engine.Firewall` закрываются тонкими обёртками над функциями `netcfg`, `tunnel`, `firewall` в `service.go`.

- [ ] **Step 5: Реализовать `install.go`**

`install`: `mgr.CreateService("FreeTurnService", exe, mgr.Config{StartType: StartAutomatic, DisplayName: "FreeTurn", Description: "Туннель FreeTurn"})`, `SetRecoveryActions` с перезапуском через 1, 5, 30 секунд, запуск. Если служба уже есть, обновить конфигурацию. `uninstall`: `Disconnect` через остановку службы, ожидание до 15 с, `DeleteService`, `wintun.Uninstall()` с игнорированием ошибки занятости, удаление `%ProgramData%\FreeTurn`.

- [ ] **Step 6: Реализовать `cmd/freeturnctl/main.go`**

`connect` читает файл `{"link":"...","wgConfig":"...","callLink":"...","manualCaptcha":false,"options":{...}}` из временной папки, собирает `ConnectRequest` через `link.Parse` и накладывает непустые поля. Файл живёт только во временной папке, в репозиторий не попадает.

- [ ] **Step 7: Проверить сборку: `go build ./...`**. Ожидается успех.

- [ ] **Step 8: Commit**

```bash
git add cmd/freeturn-service cmd/freeturnctl
git commit -m "feat: служба FreeTurnService и инструмент проверки"
```

### Task 12: Сквозная проверка без окна и опыт 2

Первая проверка настоящего туннеля. Нужны настоящая ссылка от пользователя и его согласие.

**Files:**
- Modify: `docs/research-notes.md`, при необходимости `docs/superpowers/specs/2026-10-31-freeturn-windows-design.md`

**Interfaces:**
- Consumes: `FreeTurnService.exe console`, `freeturnctl`.

- [ ] **Step 1: Собрать и запустить службу в консоли через UAC**

Рядом положить `wintun.dll`. `FreeTurnService.exe console` с записью вывода в scratchpad.

- [ ] **Step 2: Запросить у пользователя ссылку во временный файл и согласие на смену маршрутов**

Файл только в scratchpad, удалить после проверки.

- [ ] **Step 3: Подключиться без kill switch: `freeturnctl connect <файл>`**

Ожидается в `freeturnctl status`: `connected`, потоки больше 0. Внешний IP, полученный запросом к сервису определения IP через браузер, равен адресу VPS. `route print 0.0.0.0` показывает адаптер `FreeTurn`.

- [ ] **Step 4: Переподключение**

`freeturnctl` не умеет рвать сеть, поэтому выключить и включить Wi-Fi. Ожидается переход в `reconnecting` и возврат в `connected`. Это доказывает, что VK API и DNS ядра обходят туннель при живых маршрутах, чего нельзя было проверить в Task 1.

- [ ] **Step 5: Отключиться и сравнить таблицу маршрутов**

Снимок `route print` до подключения и после отключения совпадает, адаптера нет.

- [ ] **Step 6: Опыт 2: капча при включённом kill switch**

Подключиться с `killSwitch: true` и `manualCaptcha: true`, затем вызвать переподключение. Открыть присланный `CaptchaURL` в браузере. Капчу запрашивает VK, поэтому она может не появиться: тогда повторить несколько раз, а если не появилась, записать «не воспроизведено» и проверить этот случай в приёмке Task 18. Ожидается, что страница загружается и капча проходит, потому что браузер ходит только на `127.0.0.1`. Проверить, что на странице нет ресурсов с внешних адресов: вкладка Network инструментов разработчика.

Если не прошло: добавить в `internal/firewall` разрешение для процесса `FreeTurn.exe` и WebView2 на время `PhaseCaptcha` и обновить раздел 12 спецификации.

- [ ] **Step 7: Записать результаты в `docs/research-notes.md`, удалить временный файл ссылки**

- [ ] **Step 8: Commit**

```bash
git add docs
git commit -m "docs: результаты сквозной проверки туннеля и капчи"
```

## Этап 3. Интерфейс

### Task 13: Хранение профилей и настроек

**Files:**
- Create: `internal/profile/dpapi.go`, `store.go`, `settings.go`, `store_test.go`

**Interfaces:**
- Produces:

```go
package profile
var ErrCorrupt error
type Store struct{ /* */ }
func Open(path string) (*Store, error) // ErrCorrupt: файл нечитаем, Store пустой и только для чтения до Reset
func (s *Store) List() []model.Profile
func (s *Store) Get(id string) (model.Profile, bool)
func (s *Store) Save(p model.Profile) error // пустой ID -> новый UUID
func (s *Store) Delete(id string) error
func (s *Store) Reset() error // переименовывает повреждённый файл в profiles.dat.bad

type Settings struct {
    Options model.Options // KillSwitch и AllowLAN по умолчанию true
    Autostart, ConnectOnLaunch bool // Autostart по умолчанию true
    LastProfileID string
}
func LoadSettings(path string) (Settings, error) // нет файла -> значения по умолчанию
func SaveSettings(path string, s Settings) error
```

- [ ] **Step 1: Написать падающие тесты**

```go
TestProtectRoundTrip // protect + unprotect возвращает исходные байты, зашифрованные байты не содержат исходной строки
TestStoreSaveAndReopen // профиль с Cyrillic именем переживает Open заново
TestStoreFileHasNoSecrets // файл на диске не содержит ObfKey и WGConfig
TestStoreCorruptFile // случайные байты -> ErrCorrupt, файл на диске не изменён, Save вернул ошибку
TestStoreEmptyFile // файл нулевой длины -> ErrCorrupt
TestStoreReset // после Reset есть profiles.dat.bad, Save работает
TestStoreAtomicWrite // сбой записи не портит прошлый файл: временный файл + rename
TestDefaults // LoadSettings без файла: KillSwitch true, AllowLAN true, Autostart true
TestSettingsCorruptGivesDefaults // мусор -> значения по умолчанию
```

- [ ] **Step 2: Запустить: `go test ./internal/profile`**. Ожидается ошибка компиляции.

- [ ] **Step 3: Реализовать**

`windows.CryptProtectData` и `windows.CryptUnprotectData` без диалогов (`CRYPTPROTECT_UI_FORBIDDEN`). Формат файла: зашифрованный JSON списка профилей.

- [ ] **Step 4: Запустить: `go test ./internal/profile`**. Ожидается PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/profile
git commit -m "feat: хранение профилей под DPAPI и настройки"
```

### Task 14: Приложение Wails и API для интерфейса

**Files:**
- Create: `cmd/freeturn/main.go`, `api.go`, `api_test.go`, `tray.go`, `autostart.go`, `frontend/embed.go`, `frontend/package.json`, `frontend/index.html`, `frontend/vite.config.ts`

**Interfaces:**
- Consumes: `ipc.Client`, `profile.Store`, `link.Parse`, `link.NewClientID`.
- Produces: привязанный сервис `API`. Секреты в интерфейс не передаются.

```go
type ProfileView struct {
    ID, Name, Peer, Provider, ClientID string
    GeneratedClientID bool
    Missing []model.Field
}
type ImportPreview struct { Token string; Name, Peer string; Missing []model.Field; GeneratedClientID string }

func (a *API) ListProfiles() ([]ProfileView, error)
func (a *API) PreviewLink(raw string) (ImportPreview, error)
func (a *API) ConfirmImport(token string) (ProfileView, error)
func (a *API) SetCallLink(id, link string) error
func (a *API) SetWGConfig(id, text string) error
func (a *API) DeleteProfile(id string) error
func (a *API) ResetProfiles() error
func (a *API) Connect(id string) error
func (a *API) Disconnect() error
func (a *API) Status() (model.Status, error)
func (a *API) Settings() profile.Settings
func (a *API) SaveSettings(s profile.Settings) error
func (a *API) ClassifyRule(value string) (model.Rule, error)
func (a *API) Logs() ([]string, error)
func (a *API) SaveDiagnostics() (string, error)
func (a *API) OpenCaptchaInBrowser() error
```

События Wails: `status` (`model.Status`), `log` (строка), `import` (`ImportPreview`), `service-down`, `update`.

- [ ] **Step 1: Написать падающие тесты `api_test.go`**

Сервисный канал подменён интерфейсом `Service` (методы `ipc.Client`), хранилище во временной папке.

```go
TestPreviewDoesNotSave // PreviewLink не меняет ListProfiles
TestConfirmImportSaves // ConfirmImport добавляет профиль, повторный токен отвергается
TestPreviewGeneratesClientID // ссылка без cid: GeneratedClientID 32 hex, ConfirmImport сохраняет тот же ID
TestViewsHaveNoSecrets // json.Marshal(ListProfiles()) не содержит ObfKey, CallLink, WGConfig
TestConnectRejectsIncomplete // профиль без WGConfig -> ошибка с FieldWGConfig, Service.Connect не вызван
TestConnectSendsOptions // в ConnectRequest попадают настройки KillSwitch, AllowLAN, Rules
TestConnectRemembersProfile // SaveSettings хранит LastProfileID
TestStatusServiceDown // ошибка Service -> code "service_down"
TestPreviewTCPMode // ссылка с mode=tcp -> ошибка, errors.Is(err, link.ErrTCPMode)
```

- [ ] **Step 2: Запустить: `go test ./cmd/freeturn`**. Ожидается ошибка компиляции.

- [ ] **Step 3: Реализовать `api.go`**

`Service` переподключается к каналу: при закрытии `Done()` идут попытки `Dial` каждые 2 секунды и шлётся событие `service-down`. После восстановления, если `Status.AwaitingProfile` истинно, окно отправляет `LastProfileID` заново (раздел 5 спецификации). Токен превью хранится в памяти и живёт 10 минут. `SaveDiagnostics` пишет журнал службы в `%USERPROFILE%\Desktop\freeturn-diagnostics-<дата>.txt`, логи уже замаскированы службой.

- [ ] **Step 4: Запустить: `go test ./cmd/freeturn`**. Ожидается PASS.

- [ ] **Step 5: Реализовать `main.go`, `tray.go`, `autostart.go`, `frontend/embed.go`**

`application.New(application.Options{Name: "FreeTurn", Services: ..., Assets: application.AssetOptions{Handler: application.BundledAssetFileServer(frontend.Assets)}, SingleInstance: &application.SingleInstanceOptions{UniqueID: "com.freeturn.windows", OnSecondInstanceLaunch: ...}})`.

При `ConnectOnLaunch` и известном `LastProfileID` окно подключается после старта. Второй запуск с аргументом `freeturn://...` передаёт ссылку первому, тот вызывает `PreviewLink` и шлёт событие `import`. Окно 420×640 создаётся `app.Window.NewWithOptions`. Хук `events.Common.WindowClosing` скрывает окно и отменяет закрытие. Трей через `app.SystemTray.New()`: значок по фазе, меню «Подключить/Отключить», «Открыть», «Выход». «Выход» вызывает `Disconnect`, затем завершает приложение.

`autostart.go`: значение `FreeTurn` в `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` с аргументом `--tray`. С этим аргументом окно при запуске скрыто, кроме состояния `PhaseBlocked`.

- [ ] **Step 6: Собрать заглушку интерфейса и запустить приложение**

`frontend/index.html` с текстом «FreeTurn». `npm install`, `npm run build`, `go build ./cmd/freeturn`, запуск. Ожидается окно и значок в трее, крестик сворачивает, «Выход» закрывает. Служба в это время может быть выключена, окно получает `service-down`.

- [ ] **Step 7: Commit**

```bash
git add cmd/freeturn frontend
git commit -m "feat: приложение Wails, трей и API для интерфейса"
```

### Task 15: Экраны

**Files:**
- Create: `frontend/src/main.ts`, `strings.ts`, `state.ts`, `state.test.ts`, `screens/home.ts`, `screens/profiles.ts`, `screens/rules.ts`, `screens/settings.ts`, `screens/journal.ts`, `style.css`

**Interfaces:**
- Consumes: привязки `wails3 generate bindings` в `frontend/bindings`, события Task 14.
- Produces: `describeStatus(s: Status): {title: string; detail: string; button: "connect"|"disconnect"|"disabled"}`, `describeError(code: string): string`, `describeWarning(w: Warning): string`.

Стек: TypeScript + Vite без фреймворка, тесты на Vitest.

- [ ] **Step 1: Написать падающие тесты `state.test.ts`**

```ts
test("блокировка показывает причину и кнопку отключения", () => {
  const v = describeStatus({Phase: "blocked", Code: "call_full"} as Status);
  expect(v.title).toBe("Интернет заблокирован");
  expect(v.detail).toBe("В звонке нет свободных мест");
  expect(v.button).toBe("disconnect");
});
// каждая фаза model.Phase: idle -> connect, connecting -> disconnect, captcha -> disconnect,
// connected -> disconnect, reconnecting -> disconnect, error -> connect, blocked -> disconnect
// каждый ErrorCode и WarningCode имеет непустой текст в strings.ts
// describeWarning подставляет Value: other_vpn с "AmneziaVPN" содержит это имя
// неизвестный код -> Detail из ядра без падения
```

Тексты ошибок берутся из раздела 11 спецификации дословно.

- [ ] **Step 2: Запустить: `npx vitest run`**. Ожидается FAIL.

- [ ] **Step 3: Реализовать `strings.ts` и `state.ts`**. Запустить тесты, ожидается PASS.

- [ ] **Step 4: Реализовать экраны**

- **Главный:** кнопка, `describeStatus`, выбор профиля, скорость, потоки `8 из 12`, баннер обновления, предупреждения из `Status.Warnings` через `describeWarning`.
- **Профили:** «Вставить из буфера», поле ввода, карточка подтверждения по `PreviewLink`, ввод ссылки на звонок, вставка конфига и выбор `.conf`, показ сгенерированного Client ID с кнопкой копирования, удаление. При `profile.ErrCorrupt` баннер с `ResetProfiles`.
- **Исключения:** поле ввода с `ClassifyRule`, список с типом и удалением, подсказка про ограничения доменов из раздела 6 спецификации.
- **Настройки:** четыре переключателя.
- **Журнал:** поток логов, «Копировать», «Сохранить диагностику».

- [ ] **Step 5: Проверить вручную со службой из Task 12**

Запустить `FreeTurnService.exe console` и `FreeTurn.exe`. Импортировать выдуманную ссылку, увидеть отсутствующие поля, удалить профиль. Подключение на настоящей ссылке только с согласия пользователя.

- [ ] **Step 6: Commit**

```bash
git add frontend
git commit -m "feat: экраны интерфейса"
```

### Task 16: Капча и проверка обновлений

**Files:**
- Create: `cmd/freeturn/captcha.go`, `internal/update/check.go`, `internal/update/check_test.go`

**Interfaces:**
- Produces:

```go
package update
type Release struct { Version, URL string }
func Check(ctx context.Context, c *http.Client, repo, current string) (Release, bool, error)
func Newer(a, b string) bool
```

Переменные сборки в `main`: `version` и `updateRepo`, задаются через `-ldflags -X`.

- [ ] **Step 1: Написать падающие тесты `check_test.go`**

```go
TestNewer // 1.2.0 > 1.1.9; 1.10.0 > 1.9.0; v1.0.0 == 1.0.0; "мусор" не новее
TestCheckNewVersion // httptest отдаёт {"tag_name":"v1.1.0","html_url":"..."} -> Release, true
TestCheckSameVersion // false
TestCheckEmptyRepo // repo "" -> false без запроса
TestCheckNetworkError // ошибка возвращается, вызывающий молчит
TestCheckRateLimit // 403 -> ошибка без падения
```

- [ ] **Step 2: Запустить: `go test ./internal/update`**. Ожидается ошибка компиляции.

- [ ] **Step 3: Реализовать `check.go`**. Запрос `GET https://api.github.com/repos/<repo>/releases/latest`, таймаут 10 с. Запустить тесты, ожидается PASS.

- [ ] **Step 4: Реализовать `captcha.go`**

При `Status.Phase == captcha` с новым `CaptchaURL` открыть окно WebView2 с этим адресом и кнопкой «Открыть в браузере» в главном окне. Когда `CaptchaURL` становится пустым, окно закрывается. Закрытие окна человеком не отменяет подключение. Адрес принимается только с хостом `127.0.0.1` или `localhost`: окно не должно открывать внешние адреса из канала.

- [ ] **Step 5: Подключить проверку обновлений**

При старте и раз в 24 часа, успех шлёт событие `update`, ошибки только в журнал окна.

- [ ] **Step 6: Commit**

```bash
git add cmd/freeturn internal/update
git commit -m "feat: окно капчи и проверка новой версии"
```

## Этап 4. Поставка

### Task 17: Установщик и сборка

**Files:**
- Create: `build.ps1`, `test.ps1`, `installer/freeturn.iss`, `third_party/webview2/MicrosoftEdgeWebview2Setup.exe`, `LICENSES/*`, `README.md`

**Interfaces:**
- Consumes: `FreeTurnService.exe install|uninstall`.
- Produces: `dist/FreeTurnSetup-<версия>.exe`.

- [ ] **Step 1: Установить инструменты с проверкой хэша**

Inno Setup 7.1.1 из `github.com/jrsoftware/issrc/releases/download/is-7_1_1/innosetup-7.1.1-x64.exe`, хэш записать в `build.ps1`. Wails CLI: `go install github.com/wailsapp/wails/v3/cmd/wails3@v3.0.0`. Загрузчик WebView2 из `https://go.microsoft.com/fwlink/p/?LinkId=2124703` в `third_party/webview2`, проверить подпись Microsoft.

Установка Inno Setup требует согласия пользователя: это установка программы на его машину.

- [ ] **Step 2: Написать `test.ps1` и `build.ps1`**

`test.ps1`: `go vet ./...`, `go test ./...`, `npx vitest run`.

`build.ps1 -Version 1.0.0 [-UpdateRepo owner/repo]`:

1. Проверить хэш `third_party/wintun/wintun.dll`.
2. `wails3 generate bindings`, `npm ci`, `npm run build`.
3. `go build -trimpath -ldflags "-s -w -H=windowsgui -X main.version=... -X main.updateRepo=..." -o build/FreeTurn.exe ./cmd/freeturn`.
4. `go build -trimpath -ldflags "-s -w" -o build/FreeTurnService.exe ./cmd/freeturn-service`.
5. Сборка установщика: `ISCC.exe /DAppVersion=... installer/freeturn.iss`.

`CGO_ENABLED=0` задаётся в начале.

- [ ] **Step 3: Написать `installer/freeturn.iss`**

- `AppId={{B3D1A6C4-2F5E-4C7A-8E19-6A0F4D2C9E31}`, `PrivilegesRequired=admin`, `ArchitecturesAllowed=x64compatible`, `ArchitecturesInstallIn64BitMode=x64compatible`, `MinVersion=10.0.17763`, `DefaultDirName={autopf}\FreeTurn`, `CloseApplications=force`, `OutputBaseFilename=FreeTurnSetup-{#AppVersion}`.
- `[Files]`: оба exe, `wintun.dll`, `LICENSES\*`, загрузчик WebView2 с `Flags: deleteafterinstall`.
- `[Registry]`: схема `HKCR\freeturn` с `URL Protocol` и командой `"{app}\FreeTurn.exe" "%1"`, `Flags: uninsdeletekey`.
- `[Icons]`: меню «Пуск» и рабочий стол.
- `[Run]`: `FreeTurnService.exe install` с ожиданием, загрузчик WebView2 `/silent /install`, если его нет, и запуск `FreeTurn.exe` галочкой в конце.
- `[Code]`: `PrepareToInstall` останавливает `FreeTurn.exe` и службу. `CheckWebView2` читает `pv` в `HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}` и `HKCU` с тем же путём без `WOW6432Node`. `CurUninstallStepChanged`: на `usUninstall` закрыть `FreeTurn.exe`, выполнить `FreeTurnService.exe uninstall`, удалить значение автозапуска, спросить про `%LOCALAPPDATA%\FreeTurn` с ответом «Да» по умолчанию.

- [ ] **Step 4: Заполнить `LICENSES` и `README.md`**

`LICENSES`: ядро (Happy Bunny License), Wintun, amneziawg-go, wireguard-windows, Wails. README: что это, требования, как пройти SmartScreen («Подробнее» и «Выполнить в любом случае»), что делать при срабатывании антивируса, как прислать диагностику, что режим TCP находится в лайт-версии, отсылка к `build.ps1`.

- [ ] **Step 5: Собрать: `pwsh -File build.ps1 -Version 1.0.0`**

Ожидается `dist/FreeTurnSetup-1.0.0.exe`. Проверить `Get-AuthenticodeSignature build/wintun.dll` и что установщик не содержит строку `freeturn://` с настоящими данными: `Select-String` по `README.md` и `docs` не находит `eyJ2Ijo`.

- [ ] **Step 6: Commit**

```bash
git add build.ps1 test.ps1 installer third_party/webview2 LICENSES README.md
git commit -m "feat: установщик, сборка и лицензии"
```

### Task 18: Приёмка

Выполняется на машине пользователя, каждый шаг с его согласия. Запуск установщика, смена маршрутов и блокировка сети меняют его систему.

**Files:**
- Create: `docs/acceptance-2026.md`

- [ ] **Step 1: Снять базовое состояние**

`route print`, `sc query` для служб других VPN-клиентов, список адаптеров. Сохранить в scratchpad.

- [ ] **Step 2: Установить через `dist/FreeTurnSetup-1.0.0.exe`**

Ожидается: `sc query FreeTurnService` показывает `RUNNING`, адаптера `FreeTurn` нет, ярлык запускает окно без UAC.

- [ ] **Step 3: Импортировать настоящую ссылку кликом по `freeturn://` и подключиться**

Ссылку даёт пользователь. Ожидается: внешний IP равен адресу VPS, значок и статус «Подключено», потоки считаются.

- [ ] **Step 4: Отключить и сравнить `route print` с базовым**

Ожидается совпадение, адаптера нет.

- [ ] **Step 5: Kill switch**

При включённом kill switch:

1. Завершить `FreeTurn.exe` через диспетчер задач, затем `taskkill /F /IM FreeTurnService.exe`: служба перезапускается, блокировка возвращается, сайты не открываются.
2. Запустить `FreeTurn.exe`: окно само подключается заново.
3. Повторить пункт 1, открыть окно и нажать «Отключить» до повторного подключения: сеть возвращается.
4. При подключении DNS: `nslookup example.com 8.8.8.8` не получает ответа.
5. Перезагрузить Windows после пункта 1: блокировки нет, сеть работает.

Фатальная ошибка при живом туннеле вручную не воспроизводится, её проверяет `TestFatalWithKillSwitch`.

- [ ] **Step 6: Смена сети, сон, пробуждение**

Переключиться между Wi-Fi и другой сетью, если есть, и усыпить ноутбук. Ожидается возврат в «Подключено» без действий пользователя.

- [ ] **Step 7: Исключения**

IP, подсеть и домен идут напрямую: `tracert -d`, и на ресурсе определения IP виден адрес провайдера для добавленного домена.

- [ ] **Step 8: Обновление поверх**

Собрать версию `1.0.1`, установить поверх при подключённом туннеле. Профили и настройки на месте, служба работает.

- [ ] **Step 9: Удаление**

Ожидается: `sc query FreeTurnService` даёт `1060`, адаптера нет, `%ProgramData%\FreeTurn` нет, схема `freeturn://` снята, профили удалены после подтверждения. Другой VPN-клиент подключается как раньше.

- [ ] **Step 10: Записать результаты в `docs/acceptance-2026.md`**

Отметить отдельно: установка на чистой Windows не проверялась, она ждёт отзывов знакомых (раздел 12 спецификации).

- [ ] **Step 11: Commit**

```bash
git add docs/acceptance-2026.md
git commit -m "docs: результаты приёмки первой версии"
```
