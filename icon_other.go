//go:build !darwin

package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
)

func makeIcon() []byte {
	const size = 22
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	cx, cy := float64(size)/2, float64(size)/2

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx := float64(x) - cx + 0.5
			dy := float64(y) - cy + 0.5
			if dx*dx+dy*dy <= 36 {
				img.SetNRGBA(x, y, color.NRGBA{0, 0, 0, 255})
			}
		}
	}

	var buf bytes.Buffer
	png.Encode(&buf, img)
	return buf.Bytes()
}
