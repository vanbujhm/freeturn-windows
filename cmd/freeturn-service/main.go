// FreeTurnService.exe - служба FreeTurn: ядро, WireGuard, сеть и брандмауэр.
//
//	FreeTurnService.exe                  работает как служба, запускает её SCM
//	FreeTurnService.exe install          регистрирует и запускает службу
//	FreeTurnService.exe uninstall        останавливает и удаляет службу
//	FreeTurnService.exe console [-debug] работает в консоли для проверки
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"golang.org/x/sys/windows/svc"

	"github.com/vanbujhm/freeturn-windows/internal/firewall"
	"github.com/vanbujhm/freeturn-windows/internal/ipc"
)

var errUsage = errors.New("использование: FreeTurnService.exe [install | uninstall | console [-debug]]")

func main() {
	if err := dispatch(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func dispatch(args []string) error {
	if len(args) == 0 {
		isService, err := svc.IsWindowsService()
		if err != nil {
			return err
		}
		if !isService {
			return errUsage
		}
		return svc.Run(serviceName, &serviceHandler{run: run, report: reportFailure})
	}
	switch args[0] {
	case "install":
		return install()
	case "uninstall":
		return uninstall()
	case "console":
		return console(slices.Contains(args[1:], debugFlag))
	}
	return errUsage
}

// console запускает службу в консоли. У такого процесса нет SID службы, и разрешение
// брандмауэра привязывается к его пользователю. Владельца канала не задаём: повышенный процесс
// не SYSTEM и задать его не сможет, поэтому freeturnctl подключается с флагом -console.
// Пробуждений от SCM здесь нет. Строки debug идут только на экран, см. serviceLog.write.
func console(debug bool) error {
	firewall.UseProcessUserSID()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, runOptions{pipeSDDL: ipc.PipeSDDL, debug: debug, echo: os.Stdout})
}
