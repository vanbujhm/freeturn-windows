package logo

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"testing"
)

// flat - квадратный рисунок одного цвета вместо рисунка ленты.
func flat(size int, c color.NRGBA) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			img.SetNRGBA(x, y, c)
		}
	}
	return img
}

func TestAppIconFrames(t *testing.T) {
	red := color.NRGBA{R: 200, A: 255}
	raw := AppIcon(flat(1024, red))
	if binary.LittleEndian.Uint16(raw[2:]) != 1 || int(binary.LittleEndian.Uint16(raw[4:])) != len(IconSizes) {
		t.Fatalf("заголовок % x", raw[:6])
	}
	for i, want := range IconSizes {
		e := raw[6+16*i:]
		size := binary.LittleEndian.Uint32(e[8:])
		off := binary.LittleEndian.Uint32(e[12:])
		img, err := png.Decode(bytes.NewReader(raw[off : off+size]))
		if err != nil {
			t.Fatalf("кадр %d: %v", want, err)
		}
		if b := img.Bounds(); b.Dx() != want || b.Dy() != want {
			t.Fatalf("кадр %d: размер %v", want, b)
		}
		side := int(e[0])
		if side == 0 {
			side = 256
		}
		if side != want {
			t.Fatalf("в каталоге %d вместо %d", side, want)
		}
		// Мелкие кадры - плоский знак на тёмном фоне, крупные - из рисунка.
		c := color.NRGBAModel.Convert(img.At(want/2, want-want/8)).(color.NRGBA)
		isRed := c.R == red.R && c.G == 0 && c.B == 0
		if (want > SmallMax) != isRed {
			t.Errorf("кадр %d: цвет %v", want, c)
		}
	}
}

// Знак цвета fg, фон цвета bg, угол прозрачный.
func TestGlyphShape(t *testing.T) {
	img := Glyph(100, Background, Ribbon)
	if c := img.NRGBAAt(0, 0); c.A != 0 {
		t.Errorf("угол %v", c)
	}
	opaque := func(c color.RGBA) color.NRGBA { return color.NRGBA{R: c.R, G: c.G, B: c.B, A: 255} }
	for _, p := range []struct {
		x, y int
		want color.RGBA
		what string
	}{
		{30, 30, Ribbon, "верхняя перекладина"},
		{82, 30, Ribbon, "наконечник"},
		{38, 70, Ribbon, "ножка"},
		{55, 55, Ribbon, "средняя перекладина"},
		{70, 80, Background, "фон справа внизу"},
		{50, 15, Background, "фон над буквой"},
	} {
		if c := img.NRGBAAt(p.x, p.y); c != opaque(p.want) {
			t.Errorf("%s (%d,%d): %v", p.what, p.x, p.y, c)
		}
	}
}

// Tile сохраняет цвет рисунка и скругляет углы.
func TestTile(t *testing.T) {
	c := color.NRGBA{R: 10, G: 120, B: 230, A: 255}
	img := Tile(flat(300, c), 64)
	if got := img.NRGBAAt(32, 32); got != c {
		t.Errorf("центр %v", got)
	}
	if got := img.NRGBAAt(0, 0); got.A != 0 {
		t.Errorf("угол %v", got)
	}
}
