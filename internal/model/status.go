package model

// Phase — этап жизненного цикла подключения.
type Phase string

const (
	PhaseIdle         Phase = "idle"
	PhaseConnecting   Phase = "connecting"
	PhaseCaptcha      Phase = "captcha"
	PhaseConnected    Phase = "connected"
	PhaseReconnecting Phase = "reconnecting"
	PhaseError        Phase = "error"
	PhaseBlocked      Phase = "blocked"
)

// ErrorCode — код ошибки. Текст для кодов лежит в frontend/src/strings.ts.
type ErrorCode string

const (
	ErrNoNetwork       ErrorCode = "no_network"
	ErrNoHandshake     ErrorCode = "no_handshake"
	ErrServerSilent    ErrorCode = "server_silent"
	ErrInvalidCallLink ErrorCode = "invalid_call_link"
	ErrCallFull        ErrorCode = "call_full"
	ErrAnonBlocked     ErrorCode = "anon_blocked"
	ErrCaptchaFailed   ErrorCode = "captcha_failed"
	ErrAdapter         ErrorCode = "adapter"
	ErrCore            ErrorCode = "core"
	ErrBadProfile      ErrorCode = "bad_profile"
	ErrServiceDown     ErrorCode = "service_down"
)

// WarningCode — код предупреждения.
type WarningCode string

const (
	WarnOtherVPN         WarningCode = "other_vpn"
	WarnRuleSkipped      WarningCode = "rule_skipped"
	WarnDomainUnresolved WarningCode = "domain_unresolved"
	WarnStaleHandshake   WarningCode = "stale_handshake"
	WarnNoDNS            WarningCode = "no_dns"
)

// Warning — предупреждение с необязательным значением (правило, домен).
type Warning struct {
	Code  WarningCode
	Value string
}

// Status — снимок состояния, который служба отдаёт окну.
type Status struct {
	Phase                            Phase
	Code                             ErrorCode
	Detail                           string
	Streams, Total                   int
	TxRate, RxRate, TxTotal, RxTotal int64
	// CaptchaURL непусто только в PhaseCaptcha.
	CaptchaURL string
	ProfileID  string
	Warnings   []Warning
	// AwaitingProfile: служба перезапустилась и ждёт профиль от окна.
	AwaitingProfile bool
}
