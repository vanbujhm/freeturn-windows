package firewall

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Все тесты здесь работают без WFP: блокировку не ставят и прав не требуют.

// allSteps включает все необязательные шаги.
var allSteps = Options{
	TunLUID:  7,
	DNS:      []netip.Addr{netip.MustParseAddr("203.0.113.53")},
	AllowLAN: true,
	Bypass:   []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
}

func stepNames(steps []step) []string {
	names := make([]string, 0, len(steps))
	for _, s := range steps {
		names = append(names, s.name)
	}
	return names
}

func TestLANPrefixes(t *testing.T) {
	want := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
		"224.0.0.0/4", "fc00::/7", "fe80::/10", "ff00::/8",
	}
	var got []string
	for _, p := range lanPrefixes() {
		got = append(got, p.String())
	}
	if !slices.Equal(got, want) {
		t.Fatalf("lanPrefixes() = %v, ожидалось %v", got, want)
	}
}

func TestBuildPermitsSkipsTunWhenZero(t *testing.T) {
	names := stepNames(buildSteps(Options{TunLUID: 0}))
	if slices.Contains(names, "tun") {
		t.Fatalf("шаг tun не должен ставиться при TunLUID 0: %v", names)
	}
	if !slices.Contains(stepNames(buildSteps(Options{TunLUID: 7})), "tun") {
		t.Fatal("при ненулевом TunLUID шаг tun нужен")
	}
}

func TestBuildPermitsIncludesBypassAndLAN(t *testing.T) {
	want := []string{"service", "dns", "loopback", "tun", "dhcp", "ndp", "lan", "bypass", "blockAll"}
	if got := stepNames(buildSteps(allSteps)); !slices.Equal(got, want) {
		t.Fatalf("шаги %v, ожидалось %v", got, want)
	}
}

func TestBuildStepsMinimal(t *testing.T) {
	want := []string{"service", "loopback", "dhcp", "ndp", "blockAll"}
	if got := stepNames(buildSteps(Options{})); !slices.Equal(got, want) {
		t.Fatalf("шаги %v, ожидалось %v", got, want)
	}
}

// checkCondition проверяет условие на удалённый адрес и что оно указывает на значение
// из того же набора: обратное приведение uintptr к указателю запрещает go vet.
func checkCondition(t *testing.T, c wtFwpmFilterCondition0, want wtFwpDataType, value unsafe.Pointer) {
	t.Helper()
	if c.fieldKey != cFWPM_CONDITION_IP_REMOTE_ADDRESS || c.matchType != cFWP_MATCH_EQUAL {
		t.Fatalf("условие не на удалённый адрес: %+v", c)
	}
	if c.conditionValue._type != want {
		t.Fatalf("тип условия %d, ожидался %d", c.conditionValue._type, want)
	}
	if c.conditionValue.value != uintptr(value) {
		t.Fatal("условие указывает не на своё значение")
	}
}

func TestStepWeights(t *testing.T) {
	type weights struct {
		name         string
		weight, deny uint8
	}
	want := []weights{
		{"service", 15, 0},
		{"dns", 15, 14},
		{"loopback", 13, 0},
		{"tun", 12, 0},
		{"dhcp", 12, 0},
		{"ndp", 12, 0},
		{"lan", 12, 0},
		{"bypass", 12, 0},
		{"blockAll", 0, 0},
	}
	var got []weights
	for _, s := range buildSteps(allSteps) {
		got = append(got, weights{s.name, s.weight, s.denyWeight})
	}
	if !slices.Equal(got, want) {
		t.Fatalf("веса %v, ожидалось %v", got, want)
	}
}

// Запрет DNS должен стоять выше разрешений подсетей, иначе DNS уйдёт мимо туннеля
// на любой адрес из локальной сети или исключений.
func TestLANAndBypassStayBelowDNSDeny(t *testing.T) {
	steps := buildSteps(allSteps)
	dns := steps[slices.IndexFunc(steps, func(s step) bool { return s.name == "dns" })]
	for _, s := range steps {
		if (s.name == "lan" || s.name == "bypass") && s.weight >= dns.denyWeight {
			t.Fatalf("%s: вес %d не ниже запрета DNS %d", s.name, s.weight, dns.denyWeight)
		}
	}
}

func v4Mask(t *testing.T, set *subnetSet, i int) wtFwpV4AddrAndMask {
	t.Helper()
	checkCondition(t, set.v4[i], cFWP_V4_ADDR_MASK, unsafe.Pointer(&set.v4Values[i]))
	return set.v4Values[i]
}

func v6Mask(t *testing.T, set *subnetSet, i int) wtFwpV6AddrAndMask {
	t.Helper()
	checkCondition(t, set.v6[i], cFWP_V6_ADDR_MASK, unsafe.Pointer(&set.v6Values[i]))
	return set.v6Values[i]
}

func TestSubnetConditionsV4HostOrder(t *testing.T) {
	c, err := subnetConditions([]netip.Prefix{netip.MustParsePrefix("192.168.1.5/16")})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.v4) != 1 || len(c.v6) != 0 {
		t.Fatalf("v4 %d, v6 %d", len(c.v4), len(c.v6))
	}
	// Адрес и маска в порядке байт хоста, биты хоста сброшены.
	got := v4Mask(t, c, 0)
	if got.addr != 0xC0A80000 || got.mask != 0xFFFF0000 {
		t.Fatalf("адрес %08x, маска %08x", got.addr, got.mask)
	}
}

func TestSubnetConditionsV4Boundaries(t *testing.T) {
	c, err := subnetConditions([]netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("203.0.113.7/32"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := v4Mask(t, c, 0); got.addr != 0 || got.mask != 0 {
		t.Fatalf("/0: адрес %08x, маска %08x", got.addr, got.mask)
	}
	if got := v4Mask(t, c, 1); got.addr != 0xCB007107 || got.mask != 0xFFFFFFFF {
		t.Fatalf("/32: адрес %08x, маска %08x", got.addr, got.mask)
	}
}

func TestSubnetConditionsV6(t *testing.T) {
	c, err := subnetConditions([]netip.Prefix{netip.MustParsePrefix("2001:db8:1::5/48")})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.v4) != 0 || len(c.v6) != 1 {
		t.Fatalf("v4 %d, v6 %d", len(c.v4), len(c.v6))
	}
	got := v6Mask(t, c, 0)
	if got.prefixLength != 48 {
		t.Fatalf("длина префикса %d", got.prefixLength)
	}
	if want := netip.MustParseAddr("2001:db8:1::").As16(); got.addr != want {
		t.Fatalf("адрес %x, ожидался %x", got.addr, want)
	}
}

func TestSubnetConditionsMappedV4GoesToV4(t *testing.T) {
	c, err := subnetConditions([]netip.Prefix{netip.MustParsePrefix("::ffff:198.51.100.0/120")})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.v4) != 1 || len(c.v6) != 0 {
		t.Fatalf("v4 %d, v6 %d", len(c.v4), len(c.v6))
	}
	if got := v4Mask(t, c, 0); got.addr != 0xC6336400 || got.mask != 0xFFFFFF00 {
		t.Fatalf("адрес %08x, маска %08x", got.addr, got.mask)
	}
}

func TestSubnetConditionsMixedKeepsEveryValue(t *testing.T) {
	c, err := subnetConditions(lanPrefixes())
	if err != nil {
		t.Fatal(err)
	}
	if len(c.v4) != 5 || len(c.v6) != 3 {
		t.Fatalf("v4 %d, v6 %d", len(c.v4), len(c.v6))
	}
	if got := v4Mask(t, c, 1); got.addr != 0xAC100000 || got.mask != 0xFFF00000 {
		t.Fatalf("172.16.0.0/12: адрес %08x, маска %08x", got.addr, got.mask)
	}
	if got := v6Mask(t, c, 1); got.prefixLength != 10 || got.addr[0] != 0xfe {
		t.Fatalf("fe80::/10: %+v", got)
	}
}

func TestSubnetConditionsRejectsInvalidPrefix(t *testing.T) {
	if _, err := subnetConditions([]netip.Prefix{{}}); err == nil {
		t.Fatal("нулевой префикс должен давать ошибку")
	}
}

// fakeEngine подменяет WFP и записывает порядок вызовов.
type fakeEngine struct {
	log     []string
	next    uintptr
	fail    error
	hold    func() // вызывается внутри install, чтобы задержать установку
	options []Options
	closed  []uintptr
}

func (f *fakeEngine) guard() *guard {
	return &guard{
		install: func(o Options) (uintptr, error) {
			f.log = append(f.log, "install")
			if f.hold != nil {
				f.hold()
			}
			if f.fail != nil {
				return 0, f.fail
			}
			f.options = append(f.options, o)
			f.next++
			return f.next, nil
		},
		closeSession: func(session uintptr) {
			f.log = append(f.log, "close")
			f.closed = append(f.closed, session)
		},
	}
}

func TestEnableTwiceIsAnError(t *testing.T) {
	f := &fakeEngine{}
	g := f.guard()
	if err := g.enable(Options{}); err != nil {
		t.Fatal(err)
	}
	if err := g.enable(Options{}); err == nil {
		t.Fatal("повторное включение должно давать ошибку")
	}
	if !slices.Equal(f.log, []string{"install"}) || !g.enabled() {
		t.Fatalf("журнал %v, enabled %v", f.log, g.enabled())
	}
}

func TestUpdateWhenDisabledActsLikeEnable(t *testing.T) {
	f := &fakeEngine{}
	g := f.guard()
	if err := g.update(Options{AllowLAN: true}); err != nil {
		t.Fatal(err)
	}
	if !g.enabled() || !slices.Equal(f.log, []string{"install"}) {
		t.Fatalf("журнал %v, enabled %v", f.log, g.enabled())
	}
}

func TestUpdateInstallsNewBeforeClosingOld(t *testing.T) {
	f := &fakeEngine{}
	g := f.guard()
	if err := g.enable(Options{}); err != nil {
		t.Fatal(err)
	}
	if err := g.update(Options{TunLUID: 7}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"install", "install", "close"}; !slices.Equal(f.log, want) {
		t.Fatalf("журнал %v, ожидалось %v", f.log, want)
	}
	if f.options[1].TunLUID != 7 {
		t.Fatalf("новые настройки не дошли: %+v", f.options[1])
	}
	if g.session != 2 {
		t.Fatalf("сессия %d, ожидалась новая", g.session)
	}
	if !slices.Equal(f.closed, []uintptr{1}) {
		t.Fatalf("закрыты %v, ожидалась старая сессия 1", f.closed)
	}
}

func TestUpdateFailureKeepsOldSession(t *testing.T) {
	f := &fakeEngine{}
	g := f.guard()
	if err := g.enable(Options{}); err != nil {
		t.Fatal(err)
	}
	f.fail = errors.New("отказ")
	if err := g.update(Options{}); !errors.Is(err, f.fail) {
		t.Fatalf("ошибка %v", err)
	}
	if want := []string{"install", "install"}; !slices.Equal(f.log, want) {
		t.Fatalf("журнал %v, ожидалось %v", f.log, want)
	}
	if !g.enabled() || g.session != 1 || len(f.closed) != 0 {
		t.Fatalf("старая сессия потеряна: %d, закрыты %v", g.session, f.closed)
	}

	// После сбоя следующая попытка проходит и заменяет старую сессию.
	f.fail = nil
	if err := g.update(Options{}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"install", "install", "install", "close"}; !slices.Equal(f.log, want) {
		t.Fatalf("журнал %v, ожидалось %v", f.log, want)
	}
	if g.session != 2 || !slices.Equal(f.closed, []uintptr{1}) {
		t.Fatalf("сессия %d, закрыты %v", g.session, f.closed)
	}
}

func TestDisable(t *testing.T) {
	f := &fakeEngine{}
	g := f.guard()
	g.disable() // без сессии ничего не закрывается
	if len(f.log) != 0 {
		t.Fatalf("журнал %v", f.log)
	}
	if err := g.enable(Options{}); err != nil {
		t.Fatal(err)
	}
	g.disable()
	g.disable()
	if g.enabled() || !slices.Equal(f.log, []string{"install", "close"}) {
		t.Fatalf("журнал %v, enabled %v", f.log, g.enabled())
	}
	if !slices.Equal(f.closed, []uintptr{1}) {
		t.Fatalf("закрыты %v, ожидалась сессия 1", f.closed)
	}
	if err := g.enable(Options{}); err != nil {
		t.Fatalf("после отключения включение снова работает: %v", err)
	}
}

// disableWhileStuck задерживает установку, зовёт disable и проверяет, что тот вернулся,
// не дождавшись её. Возвращает ошибку установки после её завершения.
func disableWhileStuck(t *testing.T, f *fakeEngine, g *guard, start func() error) error {
	t.Helper()
	started, release := make(chan struct{}), make(chan struct{})
	f.hold = func() {
		close(started)
		<-release
	}
	result := make(chan error, 1)
	go func() { result <- start() }()
	<-started

	disabled := make(chan struct{})
	go func() {
		g.disable()
		close(disabled)
	}()
	select {
	case <-disabled:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("Disable ждёт зависшую установку")
	}
	if g.enabled() {
		t.Fatal("после Disable блокировка осталась")
	}

	close(release)
	return <-result
}

func TestDisableDoesNotWaitForStuckEnable(t *testing.T) {
	f := &fakeEngine{}
	g := f.guard()
	err := disableWhileStuck(t, f, g, func() error { return g.enable(Options{}) })
	if !errors.Is(err, errDisabledDuringInstall) {
		t.Fatalf("ошибка %v", err)
	}
	// Опоздавшая сессия закрывается: кнопка «Отключить» уже нажата.
	if g.enabled() || !slices.Equal(f.closed, []uintptr{1}) {
		t.Fatalf("enabled %v, закрыты %v", g.enabled(), f.closed)
	}
}

func TestDisableDoesNotWaitForStuckUpdate(t *testing.T) {
	f := &fakeEngine{}
	g := f.guard()
	if err := g.enable(Options{}); err != nil {
		t.Fatal(err)
	}
	err := disableWhileStuck(t, f, g, func() error { return g.update(Options{}) })
	if !errors.Is(err, errDisabledDuringInstall) {
		t.Fatalf("ошибка %v", err)
	}
	if g.enabled() || !slices.Equal(f.closed, []uintptr{1, 2}) {
		t.Fatalf("enabled %v, закрыты %v", g.enabled(), f.closed)
	}

	f.hold = nil
	if err := g.enable(Options{}); err != nil {
		t.Fatalf("после отменённой установки включение снова работает: %v", err)
	}
}

func TestDisableDuringFailedInstallReturnsInstallError(t *testing.T) {
	f := &fakeEngine{fail: errors.New("отказ")}
	g := f.guard()
	err := disableWhileStuck(t, f, g, func() error { return g.enable(Options{}) })
	if !errors.Is(err, f.fail) || len(f.closed) != 0 {
		t.Fatalf("ошибка %v, закрыты %v", err, f.closed)
	}
}

// Тест идёт вне службы, поэтому без UseProcessUserSID дескриптор не строится.
// WFP здесь не участвует: дескриптор только собирается в памяти.
func TestUseProcessUserSID(t *testing.T) {
	realSID := serviceSID
	t.Cleanup(func() { serviceSID = realSID })

	if _, err := getCurrentProcessSecurityDescriptor(); !errors.Is(err, windows.ERROR_NO_SUCH_GROUP) {
		t.Fatalf("вне службы ожидалась ERROR_NO_SUCH_GROUP, получено %v", err)
	}

	UseProcessUserSID()

	got, err := serviceSID()
	if err != nil {
		t.Fatal(err)
	}
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equals(user.User.Sid) {
		t.Fatalf("SID %v, ожидался SID владельца %v", got, user.User.Sid)
	}
	if _, err := getCurrentProcessSecurityDescriptor(); err != nil {
		t.Fatalf("дескриптор с SID владельца: %v", err)
	}
}
