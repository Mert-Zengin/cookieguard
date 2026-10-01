// Command genicon generates assets/cookieguard.ico from code so the icon is
// reproducible and reviewable rather than an opaque binary blob in history.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
)

const base = 256

func main() {
	img := render(base)
	sizes := []int{16, 24, 32, 48, 64, 128, 256}
	type entry struct {
		size int
		data []byte
	}
	var entries []entry
	for _, s := range sizes {
		var buf bytes.Buffer
		if err := png.Encode(&buf, scale(img, s)); err != nil {
			panic(err)
		}
		entries = append(entries, entry{s, buf.Bytes()})
	}

	var out bytes.Buffer
	// ICONDIR
	binary.Write(&out, binary.LittleEndian, uint16(0))
	binary.Write(&out, binary.LittleEndian, uint16(1))
	binary.Write(&out, binary.LittleEndian, uint16(len(entries)))
	offset := 6 + 16*len(entries)
	for _, e := range entries {
		b := byte(e.size)
		if e.size >= 256 {
			b = 0
		}
		out.WriteByte(b)                                    // width
		out.WriteByte(b)                                    // height
		out.WriteByte(0)                                    // color count
		out.WriteByte(0)                                    // reserved
		binary.Write(&out, binary.LittleEndian, uint16(1))  // planes
		binary.Write(&out, binary.LittleEndian, uint16(32)) // bit count
		binary.Write(&out, binary.LittleEndian, uint32(len(e.data)))
		binary.Write(&out, binary.LittleEndian, uint32(offset))
		offset += len(e.data)
	}
	for _, e := range entries {
		out.Write(e.data)
	}

	if err := os.MkdirAll("assets", 0o755); err != nil {
		panic(err)
	}
	target := filepath.Join("assets", "cookieguard.ico")
	if err := os.WriteFile(target, out.Bytes(), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("wrote %s (%d bytes, %d sizes)\n", target, out.Len(), len(entries))
}

func render(n int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, n, n))
	navy := color.NRGBA{0x0B, 0x1F, 0x3A, 0xFF}
	green := color.NRGBA{0x1F, 0xB1, 0x6B, 0xFF}
	dark := color.NRGBA{0x0E, 0x7A, 0x47, 0xFF}
	white := color.NRGBA{0xFF, 0xFF, 0xFF, 0xFF}

	// Rounded background.
	radius := n / 6
	fillRounded(img, 0, 0, n, n, radius, navy)

	// Shield body (polygon) with a darker outline drawn first.
	shield := func(c color.NRGBA, inset float64) {
		p := []point{
			{0.22, 0.16}, {0.78, 0.16}, {0.78, 0.56}, {0.50, 0.88}, {0.22, 0.56},
		}
		for i := range p {
			p[i].x = 0.5 + (p[i].x-0.5)*(1-inset)
			p[i].y = 0.5 + (p[i].y-0.5)*(1-inset)
		}
		fillPolygon(img, p, n, c)
	}
	shield(dark, -0.03)
	shield(green, 0.04)

	// Keyhole: circle plus tapered stem.
	fillCircle(img, 0.5*float64(n), 0.42*float64(n), 0.075*float64(n), white)
	fillPolygon(img, []point{{0.47, 0.44}, {0.53, 0.44}, {0.555, 0.66}, {0.445, 0.66}}, n, white)
	return img
}

type point struct{ x, y float64 }

func fillRounded(img *image.NRGBA, x0, y0, x1, y1, r int, c color.NRGBA) {
	for y := y0; y < y1; y++ {
		for x := x0; x < x1; x++ {
			if insideRounded(x, y, x0, y0, x1, y1, r) {
				img.SetNRGBA(x, y, c)
			}
		}
	}
}

func insideRounded(x, y, x0, y0, x1, y1, r int) bool {
	cx := clamp(x, x0+r, x1-1-r)
	cy := clamp(y, y0+r, y1-1-r)
	dx, dy := x-cx, y-cy
	return dx*dx+dy*dy <= r*r
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func fillCircle(img *image.NRGBA, cx, cy, r float64, c color.NRGBA) {
	for y := int(cy - r); y <= int(cy+r); y++ {
		for x := int(cx - r); x <= int(cx+r); x++ {
			dx, dy := float64(x)-cx, float64(y)-cy
			if dx*dx+dy*dy <= r*r && image.Pt(x, y).In(img.Bounds()) {
				img.SetNRGBA(x, y, c)
			}
		}
	}
}

func fillPolygon(img *image.NRGBA, pts []point, n int, c color.NRGBA) {
	for i := range pts {
		pts[i].x *= float64(n)
		pts[i].y *= float64(n)
	}
	for y := 0; y < n; y++ {
		yc := float64(y) + 0.5
		var xs []float64
		for i := range pts {
			a, b := pts[i], pts[(i+1)%len(pts)]
			if (a.y <= yc && b.y > yc) || (b.y <= yc && a.y > yc) {
				t := (yc - a.y) / (b.y - a.y)
				xs = append(xs, a.x+t*(b.x-a.x))
			}
		}
		for i := 0; i+1 < len(xs); i += 2 {
			x0, x1 := int(xs[i]), int(xs[i+1])
			if x0 > x1 {
				x0, x1 = x1, x0
			}
			for x := x0; x <= x1; x++ {
				if image.Pt(x, y).In(img.Bounds()) {
					img.SetNRGBA(x, y, c)
				}
			}
		}
	}
}

func scale(src *image.NRGBA, n int) *image.NRGBA {
	dst := image.NewNRGBA(image.Rect(0, 0, n, n))
	b := src.Bounds()
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			sx := b.Min.X + x*b.Dx()/n
			sy := b.Min.Y + y*b.Dy()/n
			dst.SetNRGBA(x, y, src.NRGBAAt(sx, sy))
		}
	}
	return dst
}
