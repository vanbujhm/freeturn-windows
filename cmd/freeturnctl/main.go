// freeturnctl проверяет службу без окна. В установщик не входит.
//
//	freeturnctl [-owner-system] status
//	freeturnctl [-owner-system] connect <файл.json>
//	freeturnctl [-owner-system] disconnect
//	freeturnctl [-owner-system] logs
//
// Файл подключения хранит ключи и лежит только во временной папке, не в репозитории:
//
//	{"link":"...","wgConfig":"...","callLink":"...","manualCaptcha":false,"options":{...}}
//
// Содержимое файла и текст ссылки на экран не выводятся никогда.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/windows"

	"github.com/vanbujhm/freeturn-windows/internal/ipc"
	"github.com/vanbujhm/freeturn-windows/internal/link"
	"github.com/vanbujhm/freeturn-windows/internal/model"
)

const dialTimeout = 5 * time.Second

const usage = "использование: freeturnctl [-owner-system] status | connect <файл.json> | disconnect | logs"

// linkCategories - отказы разбора ссылки. Их текст постоянный, а обёртка цитирует ссылку.
var linkCategories = []error{link.ErrScheme, link.ErrPayload, link.ErrVersion, link.ErrRequired, link.ErrTCPMode}

// connectFile - содержимое файла подключения.
type connectFile struct {
	Link          string        `json:"link"`
	WGConfig      string        `json:"wgConfig"`
	CallLink      string        `json:"callLink"`
	ManualCaptcha bool          `json:"manualCaptcha"`
	Options       model.Options `json:"options"`
}

// parseConnectFile собирает запрос: профиль из ссылки, поверх него непустые поля файла. Текст
// ошибки разбора JSON цитирует файл, поэтому наружу идёт только постоянное сообщение.
func parseConnectFile(data []byte) (model.ConnectRequest, error) {
	var f connectFile
	if json.Unmarshal(data, &f) != nil {
		return model.ConnectRequest{}, errors.New("файл подключения не разобран: нужен JSON")
	}
	p, err := link.Parse(f.Link)
	if err != nil {
		return model.ConnectRequest{}, rejected(err)
	}
	if f.WGConfig != "" {
		p.WGConfig = f.WGConfig
	}
	if f.CallLink != "" {
		p.CallLink = f.CallLink
	}
	if f.ManualCaptcha {
		p.ManualCaptcha = true
	}
	return model.ConnectRequest{Profile: p, Options: f.Options}, nil
}

// rejected оставляет от ошибки разбора только категорию.
func rejected(err error) error {
	for _, category := range linkCategories {
		if errors.Is(err, category) {
			return fmt.Errorf("ссылка отвергнута: %w", category)
		}
	}
	return errors.New("ссылка отвергнута")
}

// controller - команды службы. Настоящая реализация - ipc.Client.
type controller interface {
	Connect(model.ConnectRequest) error
	Disconnect() error
	Status() (model.Status, error)
	Logs() ([]string, error)
}

// validCommand проверяет команду и число аргументов до подключения к службе.
func validCommand(cmd []string) bool {
	if len(cmd) == 0 {
		return false
	}
	switch cmd[0] {
	case "status", "disconnect", "logs":
		return len(cmd) == 1
	case "connect":
		return len(cmd) == 2
	}
	return false
}

func execute(cmd []string, c controller, out io.Writer) error {
	switch cmd[0] {
	case "status":
		st, err := c.Status()
		if err != nil {
			return err
		}
		text, err := json.MarshalIndent(st, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(out, string(text))
		return nil
	case "connect":
		data, err := os.ReadFile(cmd[1])
		if err != nil {
			return err
		}
		req, err := parseConnectFile(data)
		if err != nil {
			return err
		}
		if err := c.Connect(req); err != nil {
			return err
		}
		fmt.Fprintln(out, "подключение запущено, ход виден в freeturnctl status")
		return nil
	case "disconnect":
		return c.Disconnect()
	case "logs":
		lines, err := c.Logs()
		if err != nil {
			return err
		}
		for _, line := range lines {
			fmt.Fprintln(out, line)
		}
		return nil
	}
	return errors.New(usage)
}

// dial подключается к каналу. Службу в консоли создаёт не SYSTEM, поэтому по умолчанию
// владелец не проверяется. -owner-system проверяет установленную службу как окно.
func dial(ownerSystem bool) (*ipc.Client, error) {
	var owner *windows.SID
	if ownerSystem {
		sid, err := ipc.ServiceOwner()
		if err != nil {
			return nil, err
		}
		owner = sid
	}
	return ipc.Dial(ipc.PipePath, dialTimeout, owner, nil)
}

func main() { os.Exit(cli()) }

func cli() int {
	fs := flag.NewFlagSet("freeturnctl", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, usage) }
	ownerSystem := fs.Bool("owner-system", false, "требовать, чтобы владельцем канала был LocalSystem")
	fs.Parse(os.Args[1:])

	cmd := fs.Args()
	if !validCommand(cmd) {
		fs.Usage()
		return 2
	}
	c, err := dial(*ownerSystem)
	if err != nil {
		fmt.Fprintln(os.Stderr, "служба недоступна:", err)
		return 1
	}
	defer c.Close()
	if err := execute(cmd, c, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
