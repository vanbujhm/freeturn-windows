// Package frontend встраивает собранный интерфейс в exe.
package frontend

import "embed"

// Assets - содержимое dist после npm run build. Без сборки там только .gitkeep, этого хватает
// для go vet и go test.
//
//go:embed all:dist
var Assets embed.FS
