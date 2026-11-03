//go:build !devconsole

package main

// devConsoleEnabled в обычной сборке всегда false и не читает окружение: проверка
// владельца канала службы отключить нельзя.
func devConsoleEnabled() bool { return false }
