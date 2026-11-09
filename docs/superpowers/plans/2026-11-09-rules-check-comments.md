# Правила: проверка адреса, комментарии, выключение. План реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** У правил маршрутизации появляются комментарий и выключатель, а на экране правил проверка адреса: какое правило совпало и куда трафик идёт на самом деле.

**Architecture:** Модель `model.Rule` получает поля `Comment` и `Off`. Сопоставление ввода с правилами делает чистая функция `split.Explain`. Факт маршрута даёт новая команда IPC `Probe`: служба разрешает домен и спрашивает `GetBestRoute2` для каждого адреса. Окно (Go-часть, `cmd/freeturn`) собирает оба ответа в `CheckResult`, фронтенд только рисует.

**Tech Stack:** Go 1.26 (`net/netip`, `golang.org/x/sys/windows`, `winipcfg`), Wails v3, TypeScript, vitest.

**Spec:** `docs/superpowers/specs/2026-11-09-rules-check-comments-design.md`

## Global Constraints

- Комментарий: пробелы по краям обрезаются, управляющие символы удаляются, не длиннее 80 рун.
- `Off == false` означает «включено»: старые настройки без новых полей читаются как раньше.
- Выключенное правило не попадает ни в `Compiled`, ни в `Skipped`, предупреждения о нём нет.
- Повторы правил ищутся по нормализованному `Kind+Value`; при повторе остаётся первое правило со своими `Comment` и `Off`.
- Доменное правило в этой части сопоставляется только по точному имени.
- Изменения правил действуют при следующем подключении.
- Служба комментарии в журнал не пишет.
- Команда `Probe` ничего не меняет в сети; срок разрешения домена 3 с (как у `split.DNSResolver`).
- Тексты интерфейса только в `frontend/src/strings.ts`, на русском.
- Сборка с `CGO_ENABLED=0`. Все проверки: `pwsh -File test.ps1`. Админ-тесты: `pwsh -File test-admin.ps1 <файл>` в окне с правами администратора.
- Привязки Wails после изменения API окна: `cd frontend && npm run bindings` (в git не лежат).

## Review Focus

- Ввод с пробелами, заглавными буквами, точкой на конце или юникод-доменом (`Почта.РФ.`) в проверке должен совпасть с правилом `xn--80a1acny.xn--p1ai`. Тест в задаче 2.
- Сохранение настроек со старым правилом без `Comment`/`Off` и с повтором, отличающимся только регистром (`Example.com` и `example.com`), даёт одно правило с комментарием первого. Тест в задаче 1.
- Проверка во время фазы `connecting` или без службы не должна показывать блок «Сейчас» и не должна падать. Тест в задаче 6.
- Домен, который при подключении не разрешился, показывает «не разрешился», а не пустой блок. Тест в задаче 6.
- Комментарий из одних пробелов или переводов строк превращается в пустой и убирает строку комментария на карточке. Тесты в задачах 1 и 7.

---

### Task 1: Поля правила и их очистка

**Files:**
- Modify: `internal/model/profile.go` (тип `Rule`)
- Create: `internal/split/comment.go`
- Modify: `internal/split/rules.go` (`Compile`)
- Modify: `cmd/freeturn/api.go` (`sanitizeRules`)
- Test: `internal/split/comment_test.go`, `internal/split/rules_test.go`, `cmd/freeturn/api_test.go`

**Interfaces:**
- Produces: `model.Rule{Kind RuleKind; Value string; Comment string; Off bool}`; `split.CleanComment(s string) string`; константа `split.MaxComment = 80`.

- [ ] **Step 1: Написать падающие тесты**

`internal/split/comment_test.go`:

```go
func TestCleanComment(t *testing.T) {
	long := strings.Repeat("я", 90)
	cases := map[string]string{
		"  работа  ":        "работа",
		"a\tb\nc\x00d":      "abcd",
		" \n\t ":            "",
		long:                strings.Repeat("я", 80),
	}
	for in, want := range cases {
		if got := CleanComment(in); got != want {
			t.Errorf("CleanComment(%q) = %q, want %q", in, got, want)
		}
	}
}
```

`internal/split/rules_test.go`, новый тест:

```go
func TestCompileSkipsOff(t *testing.T) {
	c := Compile([]model.Rule{
		{Value: "1.2.3.4", Off: true},
		{Value: "example.com", Off: true},
		{Value: "0.0.0.0/0", Off: true}, // выключенное неверное правило тоже не в Skipped
		{Value: "5.6.7.8"},
	})
	if len(c.Prefixes) != 1 || c.Prefixes[0] != netip.MustParsePrefix("5.6.7.8/32") { t.Fatalf("Prefixes = %v", c.Prefixes) }
	if len(c.Domains) != 0 || len(c.Skipped) != 0 { t.Fatalf("Domains = %v, Skipped = %v", c.Domains, c.Skipped) }
}
```

`cmd/freeturn/api_test.go`, новый тест `TestSanitizeRulesKeepsCommentAndOff`: вход
`[{Value:"Example.com", Comment:"  работа\n", Off:true}, {Value:"example.com", Comment:"другой"}, {Value:"1.2.3.4"}]`,
ожидается `[{Kind:"domain", Value:"example.com", Comment:"работа", Off:true}, {Kind:"ip", Value:"1.2.3.4"}]`.
Второй тест `TestSaveSettingsOldRulesJSON`: файл настроек с `"Rules":[{"Kind":"domain","Value":"example.com"}]` без новых полей читается через `profile.LoadSettings`, правило получает `Comment == ""` и `Off == false`.

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `go test ./internal/split/ ./cmd/freeturn/ -run "CleanComment|CompileSkipsOff|SanitizeRulesKeeps|OldRulesJSON" -count=1`
Expected: FAIL, сборка не находит `CleanComment`, `Comment`, `Off`.

- [ ] **Step 3: Реализовать**

- `model.Rule`: добавить поля `Comment string` и `Off bool` с комментариями из спецификации (раздел 3).
- `split.CleanComment`: удалить руны, для которых `unicode.IsControl`, затем `strings.TrimSpace`, затем обрезать до `MaxComment` рун.
- `split.Compile`: `if r.Off { continue }` до `Classify`.
- `sanitizeRules`: ключ повтора `model.Rule{Kind: c.Kind, Value: c.Value}`; в выход идёт `c` с `Comment: split.CleanComment(r.Comment)` и `Off: r.Off`.

- [ ] **Step 4: Убедиться, что тесты проходят**

Run: `go test ./internal/split/ ./cmd/freeturn/ -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/model/profile.go internal/split/comment.go internal/split/comment_test.go internal/split/rules.go internal/split/rules_test.go cmd/freeturn/api.go cmd/freeturn/api_test.go
git commit -m "feat: комментарий и выключение у правил маршрутизации"
```

---

### Task 2: `split.Explain`

**Files:**
- Create: `internal/split/explain.go`
- Test: `internal/split/explain_test.go`

**Interfaces:**
- Consumes: `model.Rule` с `Off` (задача 1), `split.Classify`.
- Produces:

```go
type Verdict string
const (
	VerdictTunnel Verdict = "tunnel"
	VerdictDirect Verdict = "direct"
)
type Match struct {
	Rule model.Rule // нулевое: не совпало
	Addr netip.Addr // адрес, по которому совпало правило IP или подсети; пуст для совпадения по имени
}
type Explanation struct {
	Input    model.Rule
	Verdict  Verdict
	Match    Match
	OffMatch Match
	SplitOff bool
}
var ErrSubnetInput = errors.New("проверяется адрес или сайт, а не подсеть")
func Explain(o model.Options, input string, addrs []netip.Addr) (Explanation, error)
```

- [ ] **Step 1: Написать падающие тесты**

Табличный `TestExplain`, в каждом случае `Options`, ввод, адреса и ожидаемые `Verdict`, `Match.Rule.Value`, `Match.Addr`, `OffMatch.Rule.Value`, `SplitOff`. Обязательные случаи:

| Случай | Options | Ввод / адреса | Ожидание |
| --- | --- | --- | --- |
| IP по правилу IP, обход | Rules `1.2.3.4` | `1.2.3.4` | direct, Match `1.2.3.4`, Addr `1.2.3.4` |
| Тот же, режим only | то же + `SplitMode: only` | `1.2.3.4` | tunnel, Match `1.2.3.4` |
| Нет совпадения, обход | Rules `1.2.3.4` | `5.5.5.5` | tunnel, Match пуст |
| Нет совпадения, only | то же + only | `5.5.5.5` | direct |
| Самая узкая подсеть | `10.0.0.0/8`, `10.1.0.0/16` | `10.1.2.3` | Match `10.1.0.0/16` |
| IP узже подсети | `10.0.0.0/8`, `10.1.2.3` | `10.1.2.3` | Match `10.1.2.3` |
| IPv6 | `2001:db8::/32` | `2001:db8::1` | direct, Match `2001:db8::/32` |
| Домен по имени | `example.com` | ` Example.COM. ` | direct, Match `example.com`, Addr пуст |
| Юникод-домен | `почта.рф` (хранится как punycode) | `Почта.РФ.` | direct, Match `xn--80a1acny.xn--p1ai` |
| Поддомен не совпадает | `example.com` | `www.example.com` | tunnel, Match пуст |
| Адрес домена в подсети | `93.184.0.0/16` | `example.org`, addrs `93.184.216.34` | direct, Match `93.184.0.0/16`, Addr `93.184.216.34` |
| Выключенное правило | `{1.2.3.4, Off}` | `1.2.3.4` | tunnel, Match пуст, OffMatch `1.2.3.4` |
| Действующее важнее выключенного | `{10.0.0.0/8}`, `{10.1.2.3, Off}` | `10.1.2.3` | Match `10.0.0.0/8`, OffMatch пуст |
| SplitOff | `SplitOff: true`, Rules `1.2.3.4` | `1.2.3.4` | tunnel, SplitOff true, Match пуст |

Отдельно `TestExplainErrors`: `""` и `"x y"` дают `ErrInvalid`, `"*.example.com"` даёт `ErrWildcard`, `"10.0.0.0/8"` даёт `ErrSubnetInput`.

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `go test ./internal/split/ -run Explain -count=1`
Expected: FAIL, `Explain` не определена.

- [ ] **Step 3: Реализовать `Explain` в `internal/split/explain.go`**

Порядок из спецификации (раздел 5.1). Правила классифицируются через `Classify`; неверные правила пропускаются молча. Поиск идёт отдельно по включённым и по выключенным правилам одной функцией `find(rules, input, addrs) Match`: сначала доменное правило с тем же именем, затем для IP-ввода и каждого адреса из `addrs` самый длинный префикс, содержащий адрес (правило IP это префикс полной длины). `OffMatch` заполняется только при пустом `Match`. Направление: совпадение даёт `direct` в режиме обхода и `tunnel` в режиме only, отсутствие наоборот.

- [ ] **Step 4: Убедиться, что тесты проходят**

Run: `go test ./internal/split/ -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/split/explain.go internal/split/explain_test.go
git commit -m "feat: split.Explain сопоставляет адрес с правилами"
```

---

### Task 3: `netcfg.BestRoute`

**Files:**
- Create: `internal/netcfg/bestroute.go`
- Test: `internal/netcfg/netcfg_admin_test.go` (тег `admin`)

**Interfaces:**
- Produces: `func BestRoute(dst netip.Addr) (luid uint64, err error)`.

- [ ] **Step 1: Написать админ-тест `TestBestRoute`**

- `BestRoute(netip.MustParseAddr("127.0.0.1"))` возвращает LUID без ошибки, и интерфейс с этим LUID имеет `IfType == IF_TYPE_SOFTWARE_LOOPBACK` (через `winipcfg.LUID(luid).Interface()`).
- Для `8.8.8.8` LUID равен LUID физического интерфейса из `FindPhysical(0)`.
- Для невалидного `netip.Addr{}` ошибка.

- [ ] **Step 2: Убедиться, что тест падает**

Run (в окне администратора): `go test -tags admin ./internal/netcfg/ -run TestBestRoute -count=1 -v`
Expected: FAIL, `BestRoute` не определена.

- [ ] **Step 3: Реализовать**

`GetBestRoute2` из `iphlpapi.dll` через `windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetBestRoute2")`. Аргументы: `InterfaceLuid` nil, `InterfaceIndex` 0, `SourceAddress` nil, `DestinationAddress` указатель на `winipcfg.RawSockaddrInet` с `SetAddr(dst)`, `AddressSortOptions` 0, `BestRoute` указатель на `winipcfg.MibIPforwardRow2`, `BestSourceAddress` указатель на ещё один `RawSockaddrInet`. Ненулевой код возврата превращается в `windows.Errno`. Возвращается `uint64(row.InterfaceLUID)`. Невалидный адрес даёт ошибку без вызова.

- [ ] **Step 4: Убедиться, что тест проходит**

Run (в окне администратора): `pwsh -File test-admin.ps1 $env:TEMP\admin.txt`; в файле `--- PASS: TestBestRoute`.
Также `go vet ./internal/netcfg/` без тега: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/netcfg/bestroute.go internal/netcfg/netcfg_admin_test.go
git commit -m "feat: netcfg.BestRoute через GetBestRoute2"
```

---

### Task 4: `Engine.Probe`

**Files:**
- Create: `internal/model/probe.go`
- Modify: `internal/engine/deps.go` (`Network.BestRoute`)
- Create: `internal/engine/probe.go`
- Modify: `internal/engine/fakes_test.go` (`fakeNet.BestRoute`)
- Modify: `cmd/freeturn-service/service.go` (`sysNet.BestRoute`)
- Test: `internal/engine/probe_test.go`

**Interfaces:**
- Consumes: `netcfg.BestRoute` (задача 3), `split.Classify`, `Resolver.Resolve`.
- Produces:

```go
// internal/model/probe.go
type Via string
const (
	ViaTunnel Via = "tunnel"
	ViaDirect Via = "direct"
	ViaOther  Via = "other"
)
type ProbeHop struct {
	Addr netip.Addr
	Via  Via    // пусто, если маршрут узнать не удалось
}

// internal/engine
var ErrNotConnected = errors.New("not_connected")
// Network получает метод:
BestRoute(dst netip.Addr) (uint64, error)
func (e *Engine) Probe(ctx context.Context, value string) ([]model.ProbeHop, error)
```

- [ ] **Step 1: Написать падающие тесты в `probe_test.go`**

Тесты используют существующий способ поднять подключённую сессию в `engine_test.go` (поддельные ядро, сеть, резолвер). `fakeNet` получает поле `routes map[netip.Addr]uint64` и `routeErr map[netip.Addr]error`.

- `TestProbeNotConnected`: без сессии `Probe` возвращает `ErrNotConnected`; во время фазы `connecting` (шаг 3 ещё ждёт) тоже `ErrNotConnected`.
- `TestProbeIP`: подключено, LUID туннеля `t`, физического `p`; `routes{1.1.1.1: t}` → `[{1.1.1.1, tunnel}]`.
- `TestProbeDomain`: резолвер отвечает на `example.com` адресами `2.2.2.2` и `3.3.3.3`; `routes{2.2.2.2: p, 3.3.3.3: 99}` → `[{2.2.2.2, direct}, {3.3.3.3, other}]` в порядке ответа.
- `TestProbeRouteError`: `routeErr{4.4.4.4: errors.New("x")}` → `[{4.4.4.4, ""}]` без ошибки вызова.
- `TestProbeUnresolved`: резолвер ничего не вернул → пустой список, ошибки нет.
- `TestProbeBadInput`: `"10.0.0.0/8"` → `split.ErrSubnetInput`; `"*.a"` → `split.ErrWildcard`.

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `go test ./internal/engine/ -run Probe -count=1`
Expected: FAIL, `Probe` не определена.

- [ ] **Step 3: Реализовать**

- `Probe`: классификация через `split.Classify`, подсеть даёт `split.ErrSubnetInput`. Под `e.mu` взять сессию, `established`, `luid`, `ph`; нет сессии или не `established` даёт `ErrNotConnected`. Для домена `e.d.Resolver.Resolve(ctx, []string{name}, ph)`, для IP один адрес. Для каждого адреса `e.d.Net.BestRoute`; LUID туннеля даёт `ViaTunnel`, `ph.LUID` даёт `ViaDirect`, иной `ViaOther`, ошибка даёт пустой `Via`. Ничего в журнал не пишет.
- `sysNet.BestRoute` вызывает `netcfg.BestRoute`.

- [ ] **Step 4: Убедиться, что тесты проходят**

Run: `go test ./internal/engine/ ./cmd/freeturn-service/ -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/model/probe.go internal/engine/deps.go internal/engine/probe.go internal/engine/probe_test.go internal/engine/fakes_test.go cmd/freeturn-service/service.go
git commit -m "feat: Engine.Probe узнаёт маршрут адреса"
```

---

### Task 5: Команда IPC `Probe`

**Files:**
- Modify: `internal/ipc/protocol.go`, `internal/ipc/server.go`, `internal/ipc/client.go`
- Modify: `cmd/freeturn-service/commands.go` (`tunnelControl`, `commands.Probe`)
- Test: `internal/ipc/ipc_test.go`, `cmd/freeturn-service/commands_test.go`

**Interfaces:**
- Consumes: `Engine.Probe`, `engine.ErrNotConnected` (задача 4).
- Produces:
  - `methodProbe = "Probe"`; `request.Probe string` (`json:"probe,omitempty"`); `response.Hops []model.ProbeHop` и `serverMsg.Hops` (`json:"hops,omitempty"` / `json:"hops"`).
  - `ipc.Handler` получает `Probe(value string) ([]model.ProbeHop, error)`.
  - `var ipc.ErrNotConnected = errors.New("ipc: туннель не подключён")`; сервер кладёт в `resp.Err` текст ошибки обработчика как есть; текст `"not_connected"` совпадает с `engine.ErrNotConnected`, поэтому `ipc` не зависит от `engine`; клиент превращает `"not_connected"` в `ErrNotConnected`.
  - `func (c *Client) Probe(value string) ([]model.ProbeHop, error)`.
  - `commands.Probe(value string)` вызывает `eng.Probe` с `context.WithTimeout(context.Background(), 5*time.Second)`; `commands.mu` не берёт: команда только читает.

- [ ] **Step 1: Написать падающие тесты**

- `ipc_test.go` `TestProbeRoundTrip`: поддельный обработчик на `"example.com"` отвечает `[{1.2.3.4, tunnel}, {::1, ""}]`; клиент получает тот же список (адреса сравниваются через `==`).
- `TestProbeNotConnected`: обработчик возвращает `errors.New("not_connected")`; клиент получает ошибку, для которой `errors.Is(err, ipc.ErrNotConnected)`.
- `TestProbeOtherError`: обработчик возвращает `split.ErrSubnetInput`; клиент получает ошибку с тем же текстом, не `ErrNotConnected`.
- `commands_test.go` `TestCommandsProbe`: поддельный `tunnelControl` получает значение и контекст со сроком не позже 5 с.

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `go test ./internal/ipc/ ./cmd/freeturn-service/ -run Probe -count=1`
Expected: FAIL

- [ ] **Step 3: Реализовать по Interfaces выше**

- [ ] **Step 4: Убедиться, что тесты проходят**

Run: `go test ./internal/ipc/ ./cmd/freeturn-service/ -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/ipc cmd/freeturn-service/commands.go cmd/freeturn-service/commands_test.go
git commit -m "feat: команда канала Probe"
```

---

### Task 6: `API.CheckAddress` в окне

**Files:**
- Modify: `cmd/freeturn/api.go` (`Service`, `API.Connect`, новый `CheckAddress`)
- Modify: `cmd/freeturn/supervisor.go` (`supervisor.Probe`)
- Test: `cmd/freeturn/api_test.go` (`fakeService.Probe`), `cmd/freeturn/supervisor_test.go` при необходимости поддельного соединения

**Interfaces:**
- Consumes: `split.Explain`, `split.Verdict`, `ipc.ErrNotConnected`, `model.ProbeHop`.
- Produces:

```go
type CheckHop struct {
	Addr   string
	Expect split.Verdict
	Match  model.Rule
	Via    model.Via
	Reason string // "", "rules_changed", "new_address", "other_route", "route_error"
}
type CheckResult struct {
	Rules      split.Explanation // по сохранённым настройкам, без адресов
	Live       bool              // блок «Сейчас» показывается
	Unresolved bool              // Live, ввод домен, адресов нет
	Hops       []CheckHop
}
func (a *API) CheckAddress(value string) (CheckResult, error)
```

`Service` получает `Probe(value string) ([]model.ProbeHop, error)`. `API` получает поле `connected *model.Options` (копия `Options` последнего успешного `Connect`, под `a.mu`).

- [ ] **Step 1: Написать падающие тесты**

`fakeService` получает поля `hops []model.ProbeHop` и `probeErr error`. Тесты:

- `TestCheckAddressOffline`: `probeErr = ipc.ErrNotConnected`; правило `1.2.3.4`; результат `Rules.Verdict == direct`, `Live == false`, `Hops` пуст, ошибки нет.
- `TestCheckAddressServiceDown`: `probeErr = ipc.ErrClosed` → `Live == false`, ошибки нет.
- `TestCheckAddressBadInput`: `"10.0.0.0/8"` → ошибка API с кодом `bad_rule`, сервис не вызывался.
- `TestCheckAddressMatches`: правило `example.com`, подключение прошло с теми же настройками, `hops = [{93.184.216.34, direct}]` → один `CheckHop{Expect: direct, Via: direct, Reason: ""}`.
- `TestCheckAddressRulesChanged`: подключились без правил, потом сохранили правило `1.2.3.4`; `hops = [{1.2.3.4, tunnel}]` → `Expect: direct`, `Reason: "rules_changed"`.
- `TestCheckAddressNewAddress`: правило `example.com` и при подключении, и сейчас; `hops = [{5.5.5.5, tunnel}]` → `Expect: direct`, `Reason: "new_address"`.
- `TestCheckAddressOtherRoute`: `hops = [{1.1.1.1, other}]` → `Reason: "other_route"`.
- `TestCheckAddressRouteError`: `hops = [{1.1.1.1, ""}]` → `Reason: "route_error"`.
- `TestCheckAddressUnresolved`: ввод домена, `hops` пуст, ошибки нет → `Live && Unresolved`.

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `go test ./cmd/freeturn/ -run CheckAddress -count=1`
Expected: FAIL

- [ ] **Step 3: Реализовать**

- `Connect` после успешного `svc.Connect` сохраняет копию `opts` в `a.connected`.
- `CheckAddress`: `Explain(settings.Options, value, nil)`; ошибка разбора даёт `newError(codeBadRule, ...)`. Затем `svc.Probe(value)`; любая ошибка даёт `Live == false` без ошибки вызова. Для каждого hop: `Explain(settings.Options, value, []netip.Addr{hop.Addr})` даёт `Expect` и `Match`. Причина по порядку:
  1. `Via == ""` → `route_error`;
  2. `Via == other` → `other_route`;
  3. `Via` совпадает с `Expect` → `""`;
  4. `a.connected != nil` и `Explain(*a.connected, value, [addr]).Verdict != Expect` → `rules_changed`;
  5. `Match.Rule.Kind == domain` → `new_address`;
  6. иначе `other_route`.
- `supervisor.Probe` по образцу `supervisor.Logs`.

- [ ] **Step 4: Убедиться, что тесты проходят**

Run: `go test ./cmd/freeturn/ -count=1`
Expected: PASS

- [ ] **Step 5: Сгенерировать привязки и проверить типы**

Run: `cd frontend; npm run bindings; npm run typecheck`
Expected: привязки содержат `CheckAddress`, `CheckResult`, `CheckHop`; typecheck без ошибок.

- [ ] **Step 6: Commit**

```bash
git add cmd/freeturn/api.go cmd/freeturn/supervisor.go cmd/freeturn/api_test.go
git commit -m "feat: API.CheckAddress собирает правило и факт маршрута"
```

---

### Task 7: Карточка правила: переключатель и комментарий

**Files:**
- Modify: `frontend/src/screens/rules.ts`
- Modify: `frontend/src/strings.ts` (`rules`)
- Modify: `frontend/src/style.css` при необходимости стиля строки комментария
- Test: `frontend/src/screens/rules.test.ts`

**Interfaces:**
- Consumes: `Rule.Comment`, `Rule.Off` из привязок (задача 6, шаг 5).
- Produces: строки `S.rules.commentPlaceholder = "Комментарий"`, `S.rules.editComment = "Комментарий"`, `S.rules.ruleOn = "Правило действует"`. Разметка: у карточки правила `input.switch-input` с `aria-label` `${S.rules.ruleOn}: ${Value}`, элемент `.rule-comment`, кнопка `.rule-edit`; поле добавления комментария `#rules-comment`.

- [ ] **Step 1: Написать падающие тесты**

- `test("переключатель правила сохраняет Off")`: клик по переключателю первого правила → в сохранённых настройках `Rules[0].Off === true`, `Value` прежний; пока запись идёт, переключатель `disabled`.
- `test("выключенное правило тусклое")`: настройки с `Off: true` → карточка имеет класс `dim`, переключатель не отмечен.
- `test("комментарий: Enter сохраняет, Esc отменяет")`: клик `.rule-edit` → появляется поле; ввод `"дом"` и Enter → сохранено `Comment: "дом"`. Повтор с Esc → `SaveSettings` не вызван, текст прежний.
- `test("пустой комментарий убирает строку")`: правило с `Comment: "x"`, поле очищено, Enter → сохранено `Comment: ""`, после перечитывания `.rule-comment` отсутствует.
- `test("добавление с комментарием")`: `ClassifyRule` мок возвращает `{Kind:"ip", Value:"1.2.3.4"}`; ввод значения и `#rules-comment` = `"работа"`, Enter в поле комментария → сохранено правило с `Comment: "работа"`, оба поля очищены.
- Существующий тест удаления остаётся зелёным: удаление ищет правило по `Kind+Value`.

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `cd frontend; npx vitest run src/screens/rules.test.ts`
Expected: FAIL

- [ ] **Step 3: Реализовать в `rules.ts`**

Изменения правила идут через общий `updateRule(rule, patch: Partial<Rule>)`, который ищет правило по `Kind+Value` и вызывает `saveRules` под флагом `busy`. Редактирование комментария держит в замыкании одно открытое поле: повторный `render` во время редактирования не теряет ввод (рендер пропускает карточку, пока поле открыто).

- [ ] **Step 4: Убедиться, что тесты проходят**

Run: `cd frontend; npx vitest run; npm run typecheck`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/screens/rules.ts frontend/src/screens/rules.test.ts frontend/src/strings.ts frontend/src/style.css
git commit -m "feat: переключатель и комментарий у правила на экране"
```

---

### Task 8: Карточка «Проверить адрес»

**Files:**
- Create: `frontend/src/screens/check.ts` (карточка проверки как отдельный компонент экрана правил)
- Modify: `frontend/src/screens/rules.ts` (вставить карточку над списком)
- Modify: `frontend/src/strings.ts` (`check`)
- Test: `frontend/src/screens/check.test.ts`

**Interfaces:**
- Consumes: `API.CheckAddress` и типы `CheckResult`, `CheckHop` (задача 6).
- Produces: `createCheck(): HTMLElement`. Строки:

```ts
export const check = {
  title: "Проверить адрес",
  placeholder: "Адрес или сайт",
  run: "Проверить",
  byRules: "По правилам",
  now: "Сейчас",
  tunnel: "через VPN",
  direct: "напрямую",
  other: "другой адаптер",
  noMatch: "ни одно правило не совпало",
  rule: (v: string) => `правило ${v}`,
  offRule: (v: string) => `совпало бы с выключенным правилом ${v}`,
  splitOff: "раздельное туннелирование выключено, всё идёт через VPN",
  unresolved: "домен не разрешился",
  reasons: {
    rules_changed: "правила изменены, подействуют при переподключении",
    new_address: "новый адрес домена, маршрут появится при следующем обновлении доменов",
    other_route: "маршрут другой программы",
    route_error: "не удалось узнать маршрут",
  },
};
```

Комментарий совпавшего правила выводится после значения в скобках.

- [ ] **Step 1: Написать падающие тесты**

Мок `API.CheckAddress`. Случаи:
- без подключения (`Live: false`): виден блок «По правилам» с «напрямую» и «правило 1.2.3.4 (работа)», блока «Сейчас» нет;
- `SplitOff: true`: текст `S.check.splitOff`;
- `OffMatch`: текст `offRule`;
- `Live` с одним совпадающим hop: строка адреса без класса `.mismatch`;
- hop с `Reason: "rules_changed"`: строка с классом `.mismatch` и текстом причины;
- `Unresolved`: текст `S.check.unresolved`;
- ошибка вызова: `fail` вызван, прежний ответ убран;
- пустой ввод: `CheckAddress` не вызывается; Enter в поле запускает проверку.

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `cd frontend; npx vitest run src/screens/check.test.ts`
Expected: FAIL

- [ ] **Step 3: Реализовать `createCheck` и вставить в `createRules` перед строкой добавления**

Повторный запуск во время идущей проверки игнорируется; ответ, пришедший после более нового запроса, отбрасывается (счётчик запросов).

- [ ] **Step 4: Убедиться, что все проверки проходят**

Run: `pwsh -File test.ps1`
Expected: `Все проверки прошли`

- [ ] **Step 5: Commit**

```bash
git add frontend/src/screens/check.ts frontend/src/screens/check.test.ts frontend/src/screens/rules.ts frontend/src/strings.ts
git commit -m "feat: проверка адреса на экране маршрутизации"
```

---

### Task 9: Приёмка на машине автора

**Files:** нет изменений кода.

- [ ] **Step 1: Собрать**

Run: `pwsh -File build.ps1 -SkipInstaller`
Expected: `build\freeturn.exe` и `build\freeturn-service.exe` собраны.

- [ ] **Step 2: Проверить вручную после установки поверх**

- Старые правила на месте, все включены, комментариев нет.
- Выключить правило, подключиться: в журнале службы нет строки «правило пропущено» про него, маршрута к адресу нет (`Find-NetRoute -RemoteIPAddress <адрес>` идёт через туннель в режиме обхода).
- Проверка `1.1.1.1` без подключения: только «По правилам».
- Подключиться, проверить домен из правил: «Сейчас» показывает «напрямую» для каждого адреса.
- Добавить новое правило, не переподключаясь, проверить его адрес: «правила изменены, подействуют при переподключении».

- [ ] **Step 3: Записать итог приёмки в описание ветки или PR**
