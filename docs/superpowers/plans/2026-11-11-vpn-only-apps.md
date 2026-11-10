# Приложения только через VPN. План реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Человек выбирает программы, которые во время сеанса FreeTurn выходят в сеть только через адаптер туннеля, а без туннеля остаются без сети.

**Architecture:** В настройках появляется список `Options.Apps`. Сессия WFP получает фильтры запрета по `ALE_APP_ID` с весом 11: ниже разрешений туннеля, loopback и LAN, выше обхода. Kill switch перестаёт быть синонимом сессии: `blockAll` и запрет DNS ставятся только при `firewall.Options.KillSwitch`. Движок ставит блок программ на шаге 1 (до ядра и адаптера), добавляет адаптер на шаге 5 и снимает сессию при отключении.

**Tech Stack:** Go 1.26 (`golang.org/x/sys/windows`, WFP через `fwpuclnt`), Wails v3 (`app.Dialog.OpenFile`), TypeScript, vitest.

**Spec:** `docs/superpowers/specs/2026-11-09-vpn-only-apps-design.md`

## Global Constraints

- Блок программ действует только во время сеанса: от «Подключить» до «Отключить» или сбоя без kill switch.
- Программа строже обхода: адрес из обхода для неё закрыт. Loopback, адаптер туннеля и LAN (при `AllowLAN`) открыты.
- Не больше 50 программ. Путь абсолютный, без `..`, кончается на `.exe` без учёта регистра, не длиннее 1024 рун, без управляющих символов. Повторы ищутся без учёта регистра по виду `filepath.Clean`.
- Существование файла при сохранении не проверяется. Отсутствующий файл при подключении пропускается с предупреждением `app_skipped`, подключение идёт.
- Сбой установки сессии WFP срывает подключение с кодом `ErrAdapter`.
- Веса шагов брандмауэра: service 15, dns 15/14, loopback 13, tun/dhcp/ndp/lan 12, apps 11, bypass 10, blockAll 0.
- Без `KillSwitch` сессия не ставит dns, dhcp, ndp, bypass и blockAll: трафик остальных программ не меняется.
- Изменения списка действуют при следующем подключении.
- `Off == false` означает «включено». Старые настройки без `Apps` читаются как раньше.
- Тексты интерфейса только в `frontend/src/strings.ts`, на русском.
- Сборка с `CGO_ENABLED=0`. Все проверки: `pwsh -File test.ps1`. Админ-тесты: `pwsh -File test-admin.ps1 <файл>` в окне с правами администратора.
- Привязки Wails после изменения API окна: `cd frontend && npm run bindings` (в git не лежат).
- Файлы `internal/model/status.go` и `internal/netcfg/physical.go` хранятся с CRLF. Правьте их, не меняя концы строк в остальных строках.

## Review Focus

- Один и тот же файл записан по-разному (`C:\Apps\App.exe` и `c:/apps/./APP.EXE` с пробелом на конце): в списке остаётся одна программа с комментарием первой. Тест в задаче 1.
- Файл программы удалён или переехал после обновления (каталог `app-1.2.3`): подключение идёт, в статусе одно предупреждение `app_skipped` с путём, остальные программы ограничены. Тесты в задачах 2 и 3.
- Подключение из состояния «Заблокировано» с выключенным kill switch и программами: после успеха `blockAll` снят, блок программ остался; при сбое блокировка остаётся. Тесты в задаче 3.
- Смена сети и обновление доменов во время сеанса: пересборка сессии сохраняет программы и не включает kill switch, которого не было. Тест в задаче 3.
- Диалог выбора закрыт без файла или выбран файл, который уже в списке: настройки не записываются, во втором случае есть сообщение. Тесты в задаче 5.

---

### Task 1: Модель и проверка списка программ

**Files:**
- Modify: `internal/model/profile.go`, `internal/model/status.go`
- Create: `internal/split/apps.go`
- Test: `internal/split/apps_test.go`, `internal/model/profile_test.go`

**Interfaces:**
- Consumes: `split.CleanComment(s string) string`.
- Produces:
  - `model.AppRule{Path string; Comment string; Off bool}`, поле `model.Options.Apps []AppRule`.
  - `func (o model.Options) ActiveApps() []string`: пути программ без `Off`, в порядке списка.
  - `func (o model.Options) AppsActive() bool`.
  - `model.WarnAppSkipped model.WarningCode = "app_skipped"`.
  - `split.MaxApps = 50`, `split.MaxAppPath = 1024`.
  - `split.ErrAppPath = errors.New("нужен полный путь к файлу .exe")`, `split.ErrTooManyApps = errors.New("слишком много программ: не больше 50")`.
  - `func split.CleanApps(in []model.AppRule) ([]model.AppRule, error)`.

- [ ] **Step 1: Тесты**

`internal/model/profile_test.go`, `TestActiveApps`:

```go
o := model.Options{SplitOff: true, Apps: []model.AppRule{{Path: `C:\one.exe`}, {Path: `C:\two.exe`, Off: true}, {Path: `C:\three.exe`}}}
// ActiveApps() == []string{`C:\one.exe`, `C:\three.exe`}; AppsActive() == true
// Options{Apps: []AppRule{{Path: `C:\two.exe`, Off: true}}}.AppsActive() == false
// Options{}.AppsActive() == false, ActiveApps() пуст
```

`internal/split/apps_test.go`, табличные тесты `TestCleanApps`:

| Ввод | Ожидание |
| --- | --- |
| `C:\Program Files\App\app.exe` | тот же путь |
| `c:/Program Files/App/./APP.EXE` с пробелами по краям | `c:\Program Files\App\APP.EXE` |
| `\\server\share\app.exe` | тот же путь |
| `C:\Apps\App.exe` (комментарий «первая», `Off: true`), затем `c:/apps/./APP.EXE` (комментарий «вторая») | одна запись: путь первой, комментарий «первая», `Off: true` |
| комментарий из пробелов, слова «дом» и перевода строки | `дом` |
| комментарий из 100 рун | 80 рун |
| `app.exe`, `.\app.exe`, `\app.exe`, `C:app.exe`, `C:\App\..\app.exe`, `C:\App\app.dll`, `C:\App\app`, пустая строка, путь с символом NUL внутри, путь из 1025 рун | `errors.Is(err, ErrAppPath)` |
| 50 разных путей | 50 записей |
| 51 разный путь | `errors.Is(err, ErrTooManyApps)` |
| 50 разных путей и повтор одного из них | 50 записей |
| `nil` | пустой срез не `nil`, ошибки нет |

- [ ] **Step 2: Запустить, убедиться в провале**

Run: `CGO_ENABLED=0 go test ./internal/model/ ./internal/split/`
Expected: FAIL, не определены `AppRule`, `CleanApps`.

- [ ] **Step 3: Реализация**

Порядок проверки одного пути в `CleanApps`: `strings.TrimSpace`; отказ при пустом пути, длине больше `MaxAppPath` рун, управляющем символе (`unicode.IsControl`), элементе `..` (путь делится по `/` и `\` до `Clean`), `!filepath.IsAbs`, расширении не `.exe` (`strings.EqualFold`). Потом `filepath.Clean`. Ключ повтора: `strings.ToLower` от чистого пути, остаётся первая запись. Предел `MaxApps` проверяется после удаления повторов. Ошибка пути: `fmt.Errorf("%w: %s", ErrAppPath, путь)`.

- [ ] **Step 4: Тесты проходят**

Run: `CGO_ENABLED=0 go test ./internal/model/ ./internal/split/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/model internal/split
git commit -m "feat: список программ только через VPN в настройках"
```

---

### Task 2: Брандмауэр: kill switch отдельно от сессии, фильтры программ

**Files:**
- Modify: `internal/firewall/options.go`, `internal/firewall/blocker.go`, `internal/firewall/helpers.go`
- Create: `internal/firewall/apps.go`
- Modify: `internal/engine/deps.go`, `internal/engine/engine.go`, `internal/engine/fakes_test.go`, `cmd/freeturn-service/service.go` (только подписи и `KillSwitch: true`, поведение прежнее)
- Test: `internal/firewall/options_test.go`, `internal/firewall/firewall_admin_test.go`

**Interfaces:**
- Produces:
  - `firewall.Options` получает поля `KillSwitch bool` и `Apps []string`.
  - `func firewall.Enable(o Options) (skipped []string, err error)`, `func firewall.Update(o Options) (skipped []string, err error)`. `skipped`: пути программ, для которых не получен app id.
  - `engine.Firewall`: `Enable(firewall.Options) ([]string, error)`, `Update(firewall.Options) ([]string, error)`, `Disable()`.
  - В движке: `fwInstall` и `fwApply` возвращают `([]string, error)`, `fwRefresh` по-прежнему `error`.
  - `fakeFirewall` в `internal/engine/fakes_test.go` получает поле `skipped []string`, его возвращают `Enable` и `Update`.
- Внутри пакета:
  - `func appIDFromPath(path string) (*wtFwpByteBlob, error)` в `helpers.go`; `getCurrentProcessAppID` переходит на неё.
  - `func missingApps(paths []string) []string`: пути, для которых `appIDFromPath` вернула ошибку, в порядке списка.
  - `func blockApps(session uintptr, bo *baseObjects, weight uint8, paths []string) error` в `apps.go`.
  - `installSession(o Options) (uintptr, []string, error)`, `guard.install func(o Options) (uintptr, []string, error)`.

- [ ] **Step 1: Тесты без WFP в `options_test.go`**

`allSteps` получает `KillSwitch: true` и `Apps` с одним путём `C:\Apps\one.exe`. Ожидания:

```go
// buildSteps(allSteps): service, dns, loopback, tun, dhcp, ndp, lan, apps, bypass, blockAll
// allSteps без KillSwitch:   service, loopback, tun, lan, apps
// Options{Apps: ...}:        service, loopback, apps
// Options{KillSwitch: true}: service, loopback, dhcp, ndp, blockAll (шага apps нет)
// Веса: service 15, dns 15 (denyWeight 14), loopback 13, tun 12, dhcp 12, ndp 12, lan 12,
//       apps 11, bypass 10, blockAll 0
// TestAppsBelowPermitsAboveBypass: вес apps меньше service, loopback, tun, lan и больше bypass
```

`TestMissingApps`: на вход путь `os.Executable()` и путь несуществующего файла `C:\no-such-dir\missing.exe`; ответ содержит только второй. Права администратора не нужны.

Тесты `guard`: поддельная `install` возвращает `skipped`, `enable` и `update` отдают его вызывающему; при ошибке `skipped` пуст.

- [ ] **Step 2: Запустить, убедиться в провале**

Run: `CGO_ENABLED=0 go test ./internal/firewall/`
Expected: FAIL (нет полей и функций).

- [ ] **Step 3: Реализация `buildSteps`**

| Шаг | Вес | Условие |
| --- | --- | --- |
| service | 15 | всегда |
| dns | 15 / 14 | `KillSwitch` и есть `DNS` |
| loopback | 13 | всегда |
| tun | 12 | `TunLUID != 0` |
| dhcp, ndp | 12 | `KillSwitch` |
| lan | 12 | `AllowLAN` |
| apps | 11 | есть `Apps` |
| bypass | 10 | `KillSwitch` и есть `Bypass` |
| blockAll | 0 | `KillSwitch` |

- [ ] **Step 4: Реализация `blockApps`, `missingApps`, подписей**

`blockApps`: для каждого пути `appIDFromPath`; при ошибке путь молча пропускается (список пропущенных собирает `missingApps`). Фильтр: действие `cFWP_ACTION_BLOCK`, одно условие `cFWPM_CONDITION_ALE_APP_ID == blob` (`cFWP_BYTE_BLOB_TYPE`), вес из шага, без флагов, как у `blockAll`. Слои: `ALE_AUTH_CONNECT_V4/V6`, `ALE_AUTH_RECV_ACCEPT_V4/V6`. Имена: `Block app outside tunnel (IPv4 outbound)` и три аналогичных. Blob освобождается через `fwpmFreeMemory0(unsafe.Pointer(&id))` после добавления его фильтров.

`installSession` вызывает `missingApps(o.Apps)` до транзакции и возвращает результат вместе с сессией. `replace` при ошибке и при `errDisabledDuringInstall` возвращает `nil` вместо списка.

В движке поведение не меняется: `session.firewallOptions()` и `ArmBlock` передают `KillSwitch: true`, списки пропущенных пока отбрасываются.

- [ ] **Step 5: Все тесты без прав проходят**

Run: `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./internal/firewall/ ./internal/engine/ ./cmd/...`
Expected: PASS, существующие тесты движка не менялись, кроме подписей `fakeFirewall`.

- [ ] **Step 6: Админ-тест в `firewall_admin_test.go`**

Существующие вызовы `Enable` и `Update` получают `KillSwitch: true`.

`TestAppsBlockedWithoutKillSwitch`:

```go
// curl := filepath.Join(os.Getenv("SystemRoot"), "System32", "curl.exe"); нет файла: t.Skip
// run := func(url string) error { return exec.Command(curl, "-s", "-o", "NUL", "--connect-timeout", "3", url).Run() }
// local := httptest.NewServer(...) на 127.0.0.1
// missing := `C:\no-such-dir\missing.exe`
// setup(t, blockedTarget); run("http://1.1.1.1/") == nil до блокировки
// skipped, err := Enable(Options{Apps: []string{curl, missing}})
// err == nil; skipped == []string{missing}
// run("http://1.1.1.1/") != nil               программа мимо туннеля не выходит
// run(local.URL) == nil                       loopback ей открыт
// probe(blockedTarget, 3*time.Second) == nil  процесс теста не в списке, сеть у него есть
// Disable(); run("http://1.1.1.1/") == nil
```

- [ ] **Step 7: Сборка админ-тестов**

Run: `CGO_ENABLED=0 go vet -tags admin ./internal/firewall/`
Expected: без ошибок. Сам прогон с правами администратора идёт в задаче 6.

- [ ] **Step 8: Commit**

```bash
git add internal/firewall internal/engine cmd/freeturn-service
git commit -m "feat: фильтры WFP для программ, kill switch отделён от сессии"
```

---

### Task 3: Движок: время жизни блока программ

**Files:**
- Modify: `internal/engine/engine.go`
- Test: `internal/engine/apps_test.go` (новый), при необходимости `internal/engine/fakes_test.go`

**Interfaces:**
- Consumes: `split.CleanApps`, `model.Options.ActiveApps`, `model.WarnAppSkipped`, `fwApply(o) ([]string, error)`, `fakeFirewall.skipped`.
- Produces: поля `session.apps []string` и `session.kill bool`; `session.firewallOptions()` отдаёт `KillSwitch: s.kill`, `Apps: s.apps`, а `DNS` только при `s.luid != 0`.

Правила, которые тесты ниже фиксируют:

1. `prepare` чистит список через `split.CleanApps(s.req.Options.Apps)`. Ошибка: `failure{code: model.ErrBadProfile, msg: "список программ: " + err.Error()}`. В `s.apps` идут пути записей без `Off`.
2. После `prepare`, до `startCore`: `s.kill = s.holdBlock` (держится блокировка от прошлого подключения или `ArmBlock`). Если `len(s.apps) > 0`: на стек отката кладётся снятие сессии (как на шаге 5, с учётом `keepBlock`), затем `fwApply(s.firewallOptions())`. Ошибка: `failed(model.ErrAdapter, err)`. Каждый путь из `skipped` даёт `e.warn(model.WarnAppSkipped, путь)` и строку журнала уровня warn `программа пропущена (файл не найден): <путь>`. Предупреждения выдаются только здесь, один раз за сеанс.
3. Шаг 5: `s.kill = s.kill || Blocks()`. `fwApply` вызывается, если `Blocks()` или есть программы.
4. После шага 5, перед `s.holdBlock = Blocks()`: если `!Blocks()`, `s.kill` и есть программы, то `s.kill = false` и `fwApply(s.firewallOptions())`; ошибка: `failed(model.ErrAdapter, err)`. Затем `s.holdBlock = Blocks()` и `s.kill = s.holdBlock`; `fwClear()` только если `!s.holdBlock` и программ нет.
5. `finish`, `Disconnect`, `fwRefresh` не меняются. При сбое с `keepBlock` сессия остаётся как есть, вместе с фильтрами программ.
6. Запись `s.kill` и `s.apps` идёт под `e.mu`: монитор читает `firewallOptions()` под ним же.

- [ ] **Step 1: Тесты в `apps_test.go`**

Общие данные: `appOne` это путь `C:\Apps\one.exe`; `appsRequest(kill bool)` это `testRequest()` с `Options.KillSwitch = kill` и двумя программами: `appOne` и выключенной `C:\Apps\two.exe`.

```go
// TestAppsWithoutKillSwitch
//   connect(appsRequest(false)) -> Connected
//   h.fw.opts[0] == {Apps: [appOne], AllowLAN: true}  (TunLUID 0, DNS nil, KillSwitch false)
//   h.fw.last()  == {TunLUID: testLUID, Apps: [appOne], AllowLAN: true, KillSwitch: false}, DNS задан
//   порядок журнала: "fw.enable" раньше "core.start"; "fw.update" после "tunnel.handshake"
//   Disconnect -> в журнале "fw.disable", Status().Phase == Idle

// TestAppsWithKillSwitch
//   connect(appsRequest(true)) -> Connected
//   h.fw.opts[0].KillSwitch == false, TunLUID == 0, Apps == [appOne]
//   h.fw.last().KillSwitch == true, TunLUID == testLUID, Apps == [appOne]

// TestAppsAllOffNoSession
//   единственная программа с Off: true, KillSwitch false -> Connected
//   h.wantNotCalled("fw.enable", "fw.update")

// TestAppsFailureClearsSession
//   а) h.log.failOn("core.start", errBoom); connect(appsRequest(false)) -> Error; вызван "fw.disable"
//   б) connect(appsRequest(false)) -> Connected; фатальная ошибка ядра по образцу
//      TestFatalWithoutKillSwitch -> Error; вызван "fw.disable"

// TestAppsEnableFailsAbortsConnect
//   h.log.failOn("fw.enable", errBoom); connect(appsRequest(false)) -> Error, Code == ErrAdapter
//   h.wantNotCalled("core.start")

// TestAppsSkippedWarnsOnce
//   h.fw.skipped = []string{appOne}; connect(appsRequest(false)) -> Connected
//   в Warnings ровно одно {Code: WarnAppSkipped, Value: appOne}; в журнале строка с appOne

// TestAppsBadListFailsConnect
//   Apps = {{Path: "app.exe"}} -> Error, Code == ErrBadProfile; h.wantNotCalled("fw.enable", "core.start")

// TestAppsFromBlockedKillSwitchOff
//   ArmBlock(model.Options{KillSwitch: true}); connect(appsRequest(false)) -> Connected
//   h.fw.opts[1] == шаг 1: KillSwitch true, Apps [appOne], TunLUID 0
//   h.fw.opts[2] == шаг 5: KillSwitch true, Apps [appOne], TunLUID testLUID
//   h.fw.last()  == KillSwitch false, Apps [appOne], TunLUID testLUID
//   h.wantNotCalled("fw.disable")

// TestAppsFromBlockedFailureStaysBlocked
//   ArmBlock(...); h.log.failOn("net.bypass", errBoom); connect(appsRequest(false)) -> Blocked
//   h.wantNotCalled("fw.disable"); h.fw.last().KillSwitch == true

// TestAppsSurviveNetworkChange
//   up(appsRequest(false)); смена сети по образцу TestNetworkChangedKillSwitchOff
//   последний вызов "fw.update" после смены: Apps == [appOne], KillSwitch == false
```

- [ ] **Step 2: Запустить, убедиться в провале**

Run: `CGO_ENABLED=0 go test ./internal/engine/ -run TestApps`
Expected: FAIL.

- [ ] **Step 3: Реализация по правилам 1-6**

Установка шага 1 живёт в отдельном методе `(e *Engine) guardApps(s *session) error`, который `establish` вызывает между `prepare` и `startCore`. Понижение из правила 4: метод `(e *Engine) settleBlock(s *session) error`.

- [ ] **Step 4: Тесты движка проходят целиком**

Run: `CGO_ENABLED=0 go test ./internal/engine/ -count=1`
Expected: PASS. Существующие тесты не меняются: без программ порядок и аргументы вызовов брандмауэра прежние.

- [ ] **Step 5: Commit**

```bash
git add internal/engine
git commit -m "feat: движок держит блок программ на время сеанса"
```

---

### Task 4: Окно: сохранение списка и выбор файла

**Files:**
- Modify: `cmd/freeturn/api.go`, `cmd/freeturn/main.go`
- Test: `cmd/freeturn/api_test.go`

**Interfaces:**
- Consumes: `split.CleanApps`, `split.ErrTooManyApps`.
- Produces:
  - Коды ошибок `codeBadApp = "bad_app"`, `codeTooManyApps = "too_many_apps"`.
  - `apiDeps.PickFile func(title, filterName, pattern string) (string, error)`; пустая строка означает отмену.
  - `func (a *API) PickApp() (string, error)`: чистый путь выбранного файла или пустая строка при отмене.

- [ ] **Step 1: Тесты в `api_test.go`**

```go
// TestSaveSettingsCleansApps
//   Apps: {{Path: `C:\Apps\App.exe`, Comment: " дом "}, {Path: `c:/apps/APP.EXE`}} -> ошибки нет
//   Settings().Options.Apps == {{Path: `C:\Apps\App.exe`, Comment: "дом"}}; то же в файле настроек
// TestSaveSettingsRejectsBadApp
//   Apps: {{Path: "app.exe"}} -> ошибка с кодом "bad_app"; файл настроек не изменился
// TestSaveSettingsTooManyApps
//   51 разный путь -> код "too_many_apps"
// TestSettingsCopiesApps
//   правка среза, который вернул Settings(), не меняет настройки API
// TestOldSettingsWithoutApps
//   JSON настроек без поля Apps читается; Options.AppsActive() == false
// TestConnectSendsApps
//   после SaveSettings с программой Connect передаёт службе Options.Apps с ней
// TestPickApp
//   PickFile возвращает ("", nil)                    -> ("", nil)
//   PickFile возвращает (`c:/apps/./App.exe`, nil)   -> (`c:\apps\App.exe`, nil)
//   PickFile возвращает (`C:\Apps\readme.txt`, nil)  -> ошибка с кодом "bad_app"
//   PickFile получает аргументы ("Выберите программу", "Программы", "*.exe")
```

- [ ] **Step 2: Запустить, убедиться в провале**

Run: `CGO_ENABLED=0 go test ./cmd/freeturn/ -run 'Apps|PickApp'`
Expected: FAIL.

- [ ] **Step 3: Реализация**

`SaveSettings` чистит `s.Options.Apps` сразу после правил: `errors.Is(err, split.ErrTooManyApps)` даёт `codeTooManyApps`, остальное `codeBadApp` с текстом ошибки. `Settings()` копирует срез `Apps`. `PickApp` проверяет один путь через `CleanApps`. Сбой диалога: `newError(codeSettings, "не удалось открыть выбор файла", err)`.

В `main.go`: `PickFile` это `app.Dialog.OpenFile().SetTitle(title).AddFilter(filterName, pattern).AttachToWindow(главное окно).PromptForSingleSelection()`.

- [ ] **Step 4: Тесты проходят, привязки пересобраны**

Run: `CGO_ENABLED=0 go test ./cmd/freeturn/ -count=1`
Expected: PASS

Run: `cd frontend && npm run bindings`
Expected: в `frontend/bindings` появились `PickApp` и `AppRule`.

- [ ] **Step 5: Commit**

```bash
git add cmd/freeturn
git commit -m "feat: окно сохраняет список программ и открывает выбор файла"
```

---

### Task 5: Экран: раздел «Только через VPN»

**Files:**
- Create: `frontend/src/screens/comment-editor.ts`, `frontend/src/screens/apps.ts`
- Modify: `frontend/src/screens/rules.ts`, `frontend/src/strings.ts`, `frontend/src/style.css`
- Test: `frontend/src/screens/apps.test.ts` (новый), `frontend/src/screens/rules.test.ts`, `frontend/src/state.test.ts`

**Interfaces:**
- Consumes: `API.PickApp(): Promise<string>`, `API.SaveSettings`, тип `AppRule` из привязок.
- Produces:

```ts
// comment-editor.ts: поле комментария, вынесенное из rules.ts без изменения поведения.
export interface CommentEditor<T> {
  start(item: T): void; // открыть поле для item, поле одно на редактор
  field(item: T): HTMLInputElement | null; // поле, если сейчас редактируется item
  // rebuild заменяет детей списка и возвращает фокус и курсор открытому полю.
  rebuild(list: HTMLElement, children: HTMLElement[]): void;
}
export function createCommentEditor<T>(o: {
  same(a: T, b: T): boolean;
  comment(item: T): string;
  label(item: T): string; // aria-label поля
  busy(): boolean; // идёт запись: Enter ничего не делает, поле остаётся открытым
  save(item: T, comment: string): void;
  render(): void;
}): CommentEditor<T>;

// apps.ts
export interface SaveControl {
  busy(): boolean;
  // exclusive выполняет запись, если другая не идёт, и перерисовывает экран до и после.
  exclusive(fn: () => Promise<void>): Promise<void>;
  save(next: Settings): Promise<boolean>; // save из rules.ts
}
export function createApps(ctl: SaveControl): { el: HTMLElement; render(): void };
```

Разметка, на которую опираются тесты: раздел `section.apps`, кнопка `.apps-add`, карточка `.app` (выключенная с классом `dim`) с `.switch-input`, `.app-name` (имя файла), `.app-path` (полный путь, приглушён), `.rule-comment`, `.rule-edit`, `.danger-text`; пустой список `.apps-empty`; подсказки `.apps-hint p`. Раздел стоит на экране маршрутизации после списка правил, перед общей подсказкой.

Тексты в `strings.ts`:

```ts
export const apps = {
  title: "Только через VPN",
  add: "Добавить программу",
  empty: "Программ нет. Добавленная программа во время подключения выходит в сеть только через VPN. Если VPN недоступен, она остаётся без сети.",
  appOn: "Программа только через VPN",
  remove: "Убрать",
  duplicate: "Эта программа уже в списке",
  added: "Программа добавлена",
  hint: [
    "Пока FreeTurn не подключён, программы работают как обычно.",
    "В режиме «Через VPN» программе доступны только адреса из списка.",
    "Если в пути программы есть версия (app-1.2.3), после обновления добавьте её заново.",
    "Дочерние процессы с другим exe-файлом не ограничиваются.",
  ],
};
// warnings
app_skipped: (v) => (v ? `Программа «${v}» не найдена и не ограничена.` : "Одна из программ не найдена и не ограничена."),
// apiErrors
bad_app: "Программа не подошла",
too_many_apps: "Слишком много программ: не больше 50",
// apiErrorsWithReason получает "bad_app"
```

- [ ] **Step 1: Вынести поле комментария в `comment-editor.ts`**

`rules.ts` переходит на `createCommentEditor<Rule>`. Класс поля `input rule-comment-input`, `maxlength` 80, Enter сохраняет обрезанное значение, Esc отменяет.

Run: `cd frontend && npx vitest run src/screens/rules.test.ts`
Expected: PASS, файл тестов не менялся.

- [ ] **Step 2: Тесты раздела в `apps.test.ts`**

`../api` подменён: `API.PickApp` это `vi.fn()`. `ctl` поддельный: `save` запоминает настройки и кладёт их в `state.settings`. Путь в примерах: `C:\Apps\App.exe`.

```ts
// пустой список: есть .apps-empty с S.apps.empty и 4 подсказки S.apps.hint
// карточка: .app-name == "App.exe", .app-path == полный путь; у выключенной класс dim
// добавление: PickApp возвращает путь; save получил Apps == [{Path, Comment: "", Off: false}]; toast S.apps.added
// отмена: PickApp возвращает ""; save не вызван, toast нет
// повтор: путь уже в списке, PickApp возвращает его же в нижнем регистре; save не вызван, toast S.apps.duplicate
// переключатель: save получил Off: true у этой программы, остальные не тронуты
// удаление: save получил список без программы
// комментарий: кнопка .rule-edit, ввод "игра", Enter -> save получил Comment: "игра"
// ctl.busy() == true: .apps-add и переключатели disabled, PickApp по нажатию не вызывается
```

В `rules.test.ts`:

```ts
// на экране есть section.apps после списка правил
// пока идёт запись правила (SaveSettings не завершён), нажатие .apps-add не вызывает PickApp
```

В `state.test.ts`: `describeWarning` для кода `app_skipped` с путём в `Value` содержит этот путь.

- [ ] **Step 3: Запустить, убедиться в провале**

Run: `cd frontend && npx vitest run`
Expected: FAIL в новых тестах.

- [ ] **Step 4: Реализация `apps.ts` и подключение в `rules.ts`**

Добавление целиком идёт внутри `ctl.exclusive`: диалог, проверка повтора (сравнение путей без учёта регистра), запись. `rules.ts` заводит `exclusive` поверх своего `busy`, передаёт его в `createApps` и вызывает `apps.render()` из своего `render()` в обеих ветках (в том числе при пустом списке правил). Когда фаза живая, раздел показывает `S.rules.appliesNext`.

- [ ] **Step 5: Проверки фронтенда проходят**

Run: `cd frontend && npx vitest run && npx tsc --noEmit`
Expected: PASS, ошибок типов нет.

- [ ] **Step 6: Commit**

```bash
git add frontend/src
git commit -m "feat: раздел «Только через VPN» на экране маршрутизации"
```

---

### Task 6: Сквозная проверка

**Files:** нет новых.

- [ ] **Step 1: Все проверки без прав**

Run: `pwsh -File test.ps1`
Expected: `Все проверки прошли`, код выхода 0.

- [ ] **Step 2: Админ-тесты**

Run в окне с правами администратора: `pwsh -File test-admin.ps1 admin-out.txt`
Expected: в файле `exit code: 0`, среди прошедших `TestAppsBlockedWithoutKillSwitch`. Если окна с правами нет, шаг передаётся человеку и отмечается как непроверенный.

- [ ] **Step 3: Сборка**

Run: `pwsh -File build.ps1 -SkipInstaller`
Expected: код выхода 0, обновлены `build\FreeTurn.exe` и `build\FreeTurnService.exe`.

- [ ] **Step 4: Ручная приёмка после установки поверх старой версии**

1. Добавить `curl.exe` из `C:\Windows\System32`, kill switch выключен, режим «Напрямую», в списке правил адрес `1.1.1.1`.
2. До подключения `curl http://1.1.1.1/` отвечает.
3. Нажать «Подключить»: пока идёт подключение, `curl http://1.1.1.1/` не проходит. Браузер работает.
4. После подключения `curl http://1.1.1.1/` по-прежнему не проходит (адрес в обходе, программе он закрыт), `curl https://example.com/` проходит через туннель.
5. Выключить Wi-Fi и включить: после возвращения сети поведение то же.
6. «Отключить»: `curl http://1.1.1.1/` отвечает.
7. Добавить несуществующий путь правкой файла настроек: подключение проходит, в статусе предупреждение с путём.
8. Режим «Через VPN» со списком `example.com`: `curl https://example.com/` проходит, `curl http://1.1.1.1/` нет.
