package main

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
)

// Окно капчи показывает страницу ВК, а её скрипты приходят через локальный прокси и
// недоверенные. Wails на рабочем столе принимает вызовы среды выполнения и привязанных
// методов (POST /wails/runtime) от любой страницы любого окна, поэтому защита ставится
// здесь, в application.AssetOptions.Middleware: эта цепочка стоит перед всеми внутренними
// обработчиками Wails. WebView2 сам добавляет к каждому запросу заголовок x-wails-window-id
// с номером окна, страница подменить его не может.

// assetHost - хост собственного источника страниц Wails в Windows (internal/assetserver).
const assetHost = "wails.localhost"

// mainWindowID - номер главного окна. Пока он 0 (окно ещё не создано), вызовы не принимаются.
var mainWindowID atomic.Uint32

// runtimeRequestAllowed решает, пропустить ли запрос к служебным путям Wails. Статичные
// скрипты среды выполнения и всё, что не под /wails/, пропускаются. Остальное под /wails/
// (вызовы /wails/runtime, /wails/eventpayload/, /wails/stream/) принимается, только если
// запрос идёт из главного окна (windowID), не назван чужим окном (windowName), не пришёл
// с чужого источника (origin) и не помечен браузером как межсайтовый (fetchSite).
func runtimeRequestAllowed(path, windowID, windowName, origin, fetchSite string, mainID uint32) bool {
	if !strings.HasPrefix(path, "/wails/") {
		return true
	}
	switch path {
	case "/wails/runtime.js", "/wails/transport.js", "/wails/custom.js":
		return true
	}
	id, err := strconv.ParseUint(windowID, 10, 32)
	if err != nil || mainID == 0 || uint32(id) != mainID {
		return false
	}
	if windowName != "" && windowName != "main" {
		return false
	}
	if origin != "" {
		u, err := url.Parse(origin)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !strings.EqualFold(u.Host, assetHost) {
			return false
		}
	}
	switch fetchSite {
	case "cross-site", "same-site":
		return false
	}
	return true
}

// runtimeGuard - Middleware для application.AssetOptions: отвечает 403 на вызовы, которые
// не прошли runtimeRequestAllowed.
func runtimeGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header
		if !runtimeRequestAllowed(r.URL.Path, h.Get("x-wails-window-id"), h.Get("x-wails-window-name"),
			h.Get("Origin"), h.Get("Sec-Fetch-Site"), mainWindowID.Load()) {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
