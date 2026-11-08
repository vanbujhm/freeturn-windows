// Package logo собирает значки FreeTurn. Знак - буква «F», верхняя перекладина которой
// уходит в стрелку. В крупных размерах это рисунок ленты (internal/logo/gen/ribbon.png), а
// в мелких (до 40 px) и в трее - упрощённый плоский знак, который рисуется здесь кодом:
// тонкая лента в 16-32 px сливается в пятно.
package logo

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
)

// Цвета знака, сняты с рисунка ленты: тёмный фон и голубая лента.
var (
	Background = color.RGBA{R: 0x16, G: 0x1b, B: 0x23, A: 0xff}
	Ribbon     = color.RGBA{R: 0x81, G: 0xbc, B: 0xe7, A: 0xff}
	White      = color.RGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff}
)

// IconSizes - размеры кадров в файле .ico программы. Кадры до SmallMax включительно -
// плоский знак, крупнее - рисунок ленты.
var IconSizes = []int{16, 20, 24, 32, 40, 48, 64, 128, 256}

// SmallMax - самый крупный кадр, который рисуется плоским знаком.
const SmallMax = 40

const (
	corner      = 0.22 // радиус скругления квадрата в долях стороны
	samplesSide = 4    // выборок на сторону пикселя для сглаживания
)

// Плоский знак в долях стороны: отрезки с круглыми концами толщиной stroke и наконечник.
const stroke = 0.13

type segment struct{ x1, y1, x2, y2 float64 }

var glyphSegments = []segment{
	{0.20, 0.30, 0.66, 0.30},    // верхняя перекладина, уходит в стрелку
	{0.43, 0.30, 0.34, 0.80},    // наклонная ножка
	{0.385, 0.555, 0.64, 0.555}, // средняя перекладина
}

// Наконечник стрелки на конце верхней перекладины.
var head = [6]float64{0.62, 0.135, 0.62, 0.465, 0.87, 0.30}

// Glyph рисует плоский знак size x size: буква цвета fg на скруглённом квадрате цвета bg.
func Glyph(size int, bg, fg color.RGBA) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	n := float64(samplesSide * samplesSide)
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var r, g, b, a float64
			for sy := 0; sy < samplesSide; sy++ {
				for sx := 0; sx < samplesSide; sx++ {
					x := (float64(px) + (float64(sx)+0.5)/samplesSide) / float64(size)
					y := (float64(py) + (float64(sy)+0.5)/samplesSide) / float64(size)
					if !inRoundedSquare(x, y) {
						continue
					}
					a++
					c := bg
					if inGlyph(x, y) {
						c = fg
					}
					r, g, b = r+float64(c.R), g+float64(c.G), b+float64(c.B)
				}
			}
			if a == 0 {
				continue
			}
			img.SetNRGBA(px, py, color.NRGBA{
				R: uint8(math.Round(r / a)), G: uint8(math.Round(g / a)), B: uint8(math.Round(b / a)),
				A: uint8(math.Round(255 * a / n)),
			})
		}
	}
	return img
}

func inRoundedSquare(x, y float64) bool {
	dx := math.Max(math.Max(corner-x, x-(1-corner)), 0)
	dy := math.Max(math.Max(corner-y, y-(1-corner)), 0)
	return dx*dx+dy*dy <= corner*corner
}

func inGlyph(x, y float64) bool {
	for _, s := range glyphSegments {
		if distToSegment(x, y, s) <= stroke/2 {
			return true
		}
	}
	return inTriangle(x, y, head[0], head[1], head[2], head[3], head[4], head[5])
}

func distToSegment(px, py float64, s segment) float64 {
	dx, dy := s.x2-s.x1, s.y2-s.y1
	t := ((px-s.x1)*dx + (py-s.y1)*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(px-(s.x1+t*dx), py-(s.y1+t*dy))
}

func inTriangle(px, py, ax, ay, bx, by, cx, cy float64) bool {
	side := func(x1, y1, x2, y2 float64) float64 { return (px-x2)*(y1-y2) - (x1-x2)*(py-y2) }
	d1, d2, d3 := side(ax, ay, bx, by), side(bx, by, cx, cy), side(cx, cy, ax, ay)
	neg := d1 < 0 || d2 < 0 || d3 < 0
	pos := d1 > 0 || d2 > 0 || d3 > 0
	return !(neg && pos)
}

// Tile уменьшает квадратный рисунок src до size x size усреднением по площади и
// скругляет углы так же, как у плоского знака.
func Tile(src image.Image, size int) *image.NRGBA {
	sb := src.Bounds()
	scale := float64(sb.Dx()) / float64(size)
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	n := float64(samplesSide * samplesSide)
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			r, g, b, a := area(src, sb, scale, px, py)
			// Доля пикселя внутри скруглённого квадрата.
			var in float64
			for sy := 0; sy < samplesSide; sy++ {
				for sx := 0; sx < samplesSide; sx++ {
					x := (float64(px) + (float64(sx)+0.5)/samplesSide) / float64(size)
					y := (float64(py) + (float64(sy)+0.5)/samplesSide) / float64(size)
					if inRoundedSquare(x, y) {
						in++
					}
				}
			}
			if a == 0 || in == 0 {
				continue
			}
			img.SetNRGBA(px, py, color.NRGBA{
				R: uint8(math.Round(r / a)), G: uint8(math.Round(g / a)), B: uint8(math.Round(b / a)),
				A: uint8(math.Round(a * in / n)),
			})
		}
	}
	return img
}

// area усредняет пиксели src, накрытые пикселем (px, py) уменьшенного рисунка, с весом по
// площади перекрытия. Возвращает цвет, умноженный на альфу, и альфу 0..255.
func area(src image.Image, sb image.Rectangle, scale float64, px, py int) (r, g, b, a float64) {
	x0, x1 := float64(px)*scale, float64(px+1)*scale
	y0, y1 := float64(py)*scale, float64(py+1)*scale
	var wsum float64
	for sy := int(y0); float64(sy) < y1 && sy < sb.Dy(); sy++ {
		wy := math.Min(y1, float64(sy+1)) - math.Max(y0, float64(sy))
		for sx := int(x0); float64(sx) < x1 && sx < sb.Dx(); sx++ {
			wx := math.Min(x1, float64(sx+1)) - math.Max(x0, float64(sx))
			w := wx * wy
			c := color.NRGBAModel.Convert(src.At(sb.Min.X+sx, sb.Min.Y+sy)).(color.NRGBA)
			ca := float64(c.A)
			r += float64(c.R) * ca * w
			g += float64(c.G) * ca * w
			b += float64(c.B) * ca * w
			a += ca * w
			wsum += w
		}
	}
	if wsum == 0 {
		return 0, 0, 0, 0
	}
	return r / wsum, g / wsum, b / wsum, a / wsum
}

// Encode кодирует рисунок в PNG.
func Encode(img image.Image) []byte {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		panic(err) // кодирование в память не должно падать
	}
	return buf.Bytes()
}

// TrayPNG - значок трея 32 x 32: белый знак на фоне цвета состояния.
func TrayPNG(bg color.RGBA) []byte { return Encode(Glyph(32, bg, White)) }

// AppIcon собирает .ico программы: мелкие кадры - плоский знак, крупные - рисунок ленты.
func AppIcon(ribbon image.Image) []byte {
	frames := make([]image.Image, len(IconSizes))
	for i, s := range IconSizes {
		if s <= SmallMax {
			frames[i] = Glyph(s, Background, Ribbon)
		} else {
			frames[i] = Tile(ribbon, s)
		}
	}
	return ICO(frames)
}

// ICO собирает файл .ico из квадратных кадров, каждый хранится как PNG. Windows Vista и
// новее читает такие кадры любого размера.
func ICO(frames []image.Image) []byte {
	data := make([][]byte, len(frames))
	for i, f := range frames {
		data[i] = Encode(f)
	}
	var buf bytes.Buffer
	le := func(v any) { _ = binary.Write(&buf, binary.LittleEndian, v) }
	le(uint16(0))           // зарезервировано
	le(uint16(1))           // тип: значок
	le(uint16(len(frames))) // число кадров
	offset := 6 + 16*len(frames)
	for i, f := range frames {
		s := f.Bounds().Dx()
		side := uint8(s)
		if s >= 256 {
			side = 0 // 0 означает 256
		}
		buf.WriteByte(side)
		buf.WriteByte(side)
		buf.WriteByte(0) // цветов в палитре
		buf.WriteByte(0) // зарезервировано
		le(uint16(1))    // плоскостей
		le(uint16(32))   // бит на пиксель
		le(uint32(len(data[i])))
		le(uint32(offset))
		offset += len(data[i])
	}
	for _, d := range data {
		buf.Write(d)
	}
	return buf.Bytes()
}
