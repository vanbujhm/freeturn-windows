package engine

import (
	"errors"
	"slices"
	"time"

	"github.com/vanbujhm/freeturn-windows/internal/firewall"
	"github.com/vanbujhm/freeturn-windows/internal/model"
	"github.com/vanbujhm/freeturn-windows/internal/netcfg"
)

const (
	// staleHandshake - сколько ядро может считать себя подключённым без рукопожатия. Этот же
	// срок выдерживается после Reconnect и Wake: им нужно время, чтобы дать результат.
	staleHandshake = 3 * time.Minute
	// domainRefresh - как часто домены из исключений разрешаются заново.
	domainRefresh = 5 * time.Minute
)

// watched возвращает сессию, если монитору есть что в ней делать. ctl не берётся, поэтому
// идущие подключение и откат таймеры не держат. Connected и Reconnecting бывают только после
// шага 5. На откате фаза ещё старая, поэтому отмена проверяется отдельно.
func (e *Engine) watched(phases ...model.Phase) *session {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.sess
	if s == nil || s.ctx.Err() != nil || !slices.Contains(phases, e.st.Phase) {
		return nil
	}
	return s
}

// NetworkChanged приводит туннель к текущей сети. Вызывается из наблюдателя за маршрутом по
// умолчанию, в том числе на обновлениях от роутера, поэтому без перемены ничего не делает.
func (e *Engine) NetworkChanged() {
	if s := e.watched(model.PhaseConnected, model.PhaseReconnecting); s != nil {
		e.reconcile(s)
	}
}

// reconcile сверяет сессию с сетью и приводит фазу в соответствие. Фаза меняется уже без
// netMu: откат не должен ждать OnChange.
func (e *Engine) reconcile(s *session) {
	e.followNetwork(s)
	e.update(func(st *model.Status) bool {
		if e.sess != s || s.ctx.Err() != nil || (st.Phase != model.PhaseConnected && st.Phase != model.PhaseReconnecting) {
			return false
		}
		next := s.restingPhase(st.Streams)
		changed := next != st.Phase
		st.Phase = next
		return changed
	})
}

// followNetwork находит текущий интерфейс и переносит на него сессию.
func (e *Engine) followNetwork(s *session) {
	s.netMu.Lock()
	defer s.netMu.Unlock()
	if s.stopped() != nil {
		return
	}
	ph, err := e.d.Net.FindPhysical(s.luid)
	switch {
	case errors.Is(err, netcfg.ErrNoNetwork):
		e.networkLost(s)
	case err != nil:
		// Сеть не прочитана, это не значит, что её нет: туннель работает дальше.
		e.logf(levelWarn, "сеть не прочитана: "+err.Error())
	default:
		e.moveTo(s, ph)
	}
}

// networkLost оставляет всё на месте: сеть вернётся, а ядру пока некуда переподключаться.
func (e *Engine) networkLost(s *session) {
	e.mu.Lock()
	first := !s.netLost
	s.netLost = true
	e.mu.Unlock()
	if first {
		e.logf(levelWarn, "физической сети нет, ждём возвращения")
	}
}

// moveTo переносит исключения на ph и переподключает ядро. Сбой переноса не фатален: домен
// пойдёт через туннель, а сокетам ядра важнее новый интерфейс. Такой сбой чинит следующая
// сверка, уже без Reconnect: постоянная ошибка маршрута иначе сбрасывала бы ядро на каждом
// такте. Новый DNS без смены пути запоминается молча, он нужен только разрешению доменов.
func (e *Engine) moveTo(s *session, ph model.Physical) {
	e.mu.Lock()
	returned := s.netLost
	same := samePath(s.ph, ph)
	dirty := s.bypassDirty
	s.netLost = false
	s.ph = ph
	opts := s.firewallOptions()
	e.mu.Unlock()
	if same && !returned {
		if dirty {
			e.applyAddresses(s, ph, opts)
		}
		return
	}

	e.logf(levelInfo, "сеть сменилась, переносим исключения")
	e.d.Protect.SetInterface(ph.Index4, ph.Index6)
	if returned {
		// Windows снимает маршруты вместе с интерфейсом, а SetBypass добавляет только то,
		// чего нет в его списке. Без очистки на том же интерфейсе маршруты не вернутся.
		e.logFailure("снятие маршрутов обхода", e.d.Net.ClearBypass())
	}
	err := e.d.Net.SetBypass(ph, opts.Bypass)
	if s.stopped() != nil {
		return
	}
	e.noteBypass(s, errors.Join(err, e.fwRefresh(opts)))
	if s.stopped() != nil {
		return
	}
	e.nudge(s, e.d.Core.Reconnect, e.d.Now())
}

// noteBypass запоминает, дошли ли исключения до системы. Сбой повторит следующая сверка.
func (e *Engine) noteBypass(s *session, err error) {
	if err != nil {
		e.logf(levelWarn, "исключения не применены: "+err.Error())
	}
	e.mu.Lock()
	s.bypassDirty = err != nil
	e.mu.Unlock()
}

// samePath: трафик идёт тем же путём. DNS на путь не влияет.
func samePath(a, b model.Physical) bool {
	return a.LUID == b.LUID && a.Index4 == b.Index4 && a.Index6 == b.Index6 &&
		a.Gateway4 == b.Gateway4 && a.Gateway6 == b.Gateway6
}

// nudge будит ядро и запоминает когда: проверка рукопожатия ждёт результата. Вызывается под
// netMu после проверки отмены, поэтому не попадёт в ядро уже следующей сессии.
func (e *Engine) nudge(s *session, call func(), now time.Time) {
	e.mu.Lock()
	s.nudgedAt = now
	e.mu.Unlock()
	call()
}

// Woke сообщает ядру о выходе из сна. Живы ли аллокации, ядро решает само.
func (e *Engine) Woke() {
	s := e.watched(model.PhaseConnected, model.PhaseReconnecting)
	if s == nil {
		return
	}
	s.netMu.Lock()
	defer s.netMu.Unlock()
	if s.stopped() == nil {
		e.nudge(s, e.d.Core.Wake, e.d.Now())
	}
}

// Tick - таймер службы, каждые 30 секунд. Домены могут занять до срока разрешения, но отмена
// сессии прерывает их, так что Disconnect такт не ждёт.
//
// Сверка с сетью идёт первой: событие могло пропасть. Под капчей NetworkChanged не действует,
// а наблюдатель выжидает тишину, и ядро успевает открыть капчу раньше его сообщения. Чтение
// сети тоже может сорваться. Без сверки такая сессия осталась бы в Reconnecting до конца.
func (e *Engine) Tick(now time.Time) {
	s := e.watched(model.PhaseConnected, model.PhaseReconnecting)
	if s == nil {
		return
	}
	e.reconcile(s)
	if e.reviveStale(s, now) {
		e.logf(levelWarn, "пакеты уходят, а рукопожатия нет дольше 3 минут, переподключаем")
		e.warnOnce(model.Warning{Code: model.WarnStaleHandshake})
	}
	e.refreshDomains(s, now)
}

// reviveStale переподключает ядро, если оно считает себя подключённым, пакеты уходят, а
// рукопожатие старое. Сообщает, что переподключение было. Как directSnapshot в ядре: на
// простаивающем туннеле WireGuard рукопожатий не делает, и старое само по себе не сбой.
// TxBytes считает и keepalive, и повторы рукопожатия, поэтому мёртвый пир виден без трафика
// пользователя.
//
// Счётчик сравнивается только с прошлым тактом, поэтому запоминается и во время паузы после
// Reconnect. Пока идёт переподключение или капча, ядро занято этим само, а Reconnect сбил бы
// ему подбор реквизитов. Первый такт после них только запоминает: туннелю нужно время, чтобы
// договориться заново, а повторы рукопожатия за это время выглядят как трафик.
func (e *Engine) reviveStale(s *session, now time.Time) bool {
	s.netMu.Lock()
	defer s.netMu.Unlock()
	if s.stopped() != nil {
		return false
	}
	e.mu.Lock()
	live := e.st.Phase == model.PhaseConnected && s.coreState == coreConnected
	if !live {
		s.txSeen = false
	}
	e.mu.Unlock()
	if !live {
		return false
	}
	stats, err := s.dev.Stats()
	if err != nil {
		e.logf(levelWarn, "рукопожатие не прочитано: "+err.Error())
		return false
	}
	e.mu.Lock()
	sending := s.txSeen && stats.TxBytes > s.txBytes
	s.txBytes, s.txSeen = stats.TxBytes, true
	quiet := now.Sub(s.nudgedAt) < staleHandshake
	e.mu.Unlock()
	old := !stats.LastHandshake.IsZero() && now.Sub(stats.LastHandshake) > staleHandshake
	if !sending || !old || quiet {
		return false
	}
	e.nudge(s, e.d.Core.Reconnect, now)
	return true
}

// warnOnce добавляет предупреждение, если его ещё нет: таймер повторяет его часами.
func (e *Engine) warnOnce(w model.Warning) {
	e.update(func(st *model.Status) bool {
		if slices.Contains(st.Warnings, w) {
			return false
		}
		st.Warnings = append(st.Warnings, w)
		return true
	})
}

// refreshDomains разрешает домены заново и добавляет новые адреса к старым. Запросы идут без
// netMu: они долгие, а откат и смена сети их не ждут. Без сети срок не расходуется. Адреса
// держатся до отключения и при сбое применения: его чинит следующая сверка.
func (e *Engine) refreshDomains(s *session, now time.Time) {
	e.mu.Lock()
	due := len(s.rules.Domains) > 0 && !s.netLost && now.Sub(s.domainsAt) >= domainRefresh
	if due {
		s.domainsAt = now
	}
	ph := s.ph
	e.mu.Unlock()
	if !due {
		return
	}
	answers := e.lookupDomains(s, ph)

	s.netMu.Lock()
	defer s.netMu.Unlock()
	if s.stopped() != nil {
		return
	}
	e.mu.Lock()
	added := s.addResolved(slices.Concat(answers...))
	opts := s.firewallOptions()
	ph = s.ph
	e.mu.Unlock()
	if added {
		e.applyAddresses(s, ph, opts)
	}
}

// applyAddresses сначала разрешает адреса в блокировке, потом ставит маршруты, как шаг 5:
// маршрут без разрешения увёл бы адрес из работающего туннеля в блокировку. SetBypass ставит
// только недостающее, так что повтор после частичного сбоя безопасен.
func (e *Engine) applyAddresses(s *session, ph model.Physical, opts firewall.Options) {
	err := e.fwRefresh(opts)
	if s.stopped() != nil {
		return
	}
	if err == nil {
		err = e.d.Net.SetBypass(ph, opts.Bypass)
	}
	e.noteBypass(s, err)
}

// RefreshRates - таймер службы, каждую секунду. Rates читается без блокировок, поэтому сессия
// проверяется ещё раз: за это время она могла закончиться.
func (e *Engine) RefreshRates() {
	s := e.watched(model.PhaseConnected)
	if s == nil {
		return
	}
	txTotal, rxTotal, txRate, rxRate := e.d.Core.Rates()
	e.update(func(st *model.Status) bool {
		if e.sess != s || s.ctx.Err() != nil || st.Phase != model.PhaseConnected {
			return false
		}
		if st.TxTotal == txTotal && st.RxTotal == rxTotal && st.TxRate == txRate && st.RxRate == rxRate {
			return false
		}
		st.TxTotal, st.RxTotal, st.TxRate, st.RxRate = txTotal, rxTotal, txRate, rxRate
		return true
	})
}
