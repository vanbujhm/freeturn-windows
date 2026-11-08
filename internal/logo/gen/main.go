// Команда gen пишет иконку программы для build.ps1:
//
//	go run ./internal/logo/gen -ico build/freeturn.ico [-png build/freeturn.png]
//
// Крупные кадры берутся из ribbon.png: рисунок ленты 1024 x 1024 на тёмном фоне.
package main

import (
	"bytes"
	_ "embed"
	"flag"
	"image/png"
	"log"
	"os"

	"github.com/vanbujhm/freeturn-windows/internal/logo"
)

//go:embed ribbon.png
var ribbonPNG []byte

func main() {
	ico := flag.String("ico", "", "куда записать .ico")
	pngPath := flag.String("png", "", "куда записать PNG 256x256, необязательно")
	flag.Parse()
	if *ico == "" {
		log.Fatal("нужен ключ -ico")
	}
	ribbon, err := png.Decode(bytes.NewReader(ribbonPNG))
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*ico, logo.AppIcon(ribbon), 0o644); err != nil {
		log.Fatal(err)
	}
	if *pngPath != "" {
		if err := os.WriteFile(*pngPath, logo.Encode(logo.Tile(ribbon, 256)), 0o644); err != nil {
			log.Fatal(err)
		}
	}
}
