//go:build devconsole

package main

import "os"

// Сборка для разработки (go build -tags devconsole). FREETURN_DEV_CONSOLE=1 включает
// режим: окно не проверяет владельца канала и не пишет себя в автозапуск, так что можно
// проверить окно со службой, запущенной командой console, без установки.
const devConsoleEnv = "FREETURN_DEV_CONSOLE"

func devConsoleEnabled() bool { return os.Getenv(devConsoleEnv) == "1" }
