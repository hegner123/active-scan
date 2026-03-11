package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"log"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"fyne.io/systray"
)

func main() {
	port := flag.Int("port", 9847, "dashboard port")
	interval := flag.Int("interval", 30, "scan interval in seconds")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	state := NewState(time.Duration(*interval)*time.Second, *port)

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		log.Printf("received %s, shutting down", sig)
		cancel()
		systray.Quit()
	}()

	systray.Run(
		func() { onReady(ctx, cancel, state) },
		func() { cancel() },
	)
}

func onReady(ctx context.Context, cancel context.CancelFunc, state *State) {
	icon := makeIcon()
	systray.SetTemplateIcon(icon, icon)
	systray.SetTooltip("Active Scan — Malware Monitor")

	mStatus := systray.AddMenuItem("Status: starting...", "")
	mStatus.Disable()
	mLastScan := systray.AddMenuItem("Last scan: never", "")
	mLastScan.Disable()
	systray.AddSeparator()
	mDashboard := systray.AddMenuItem("Open Dashboard", "")
	mScan := systray.AddMenuItem("Scan Now", "")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Quit", "")

	go RunScanner(ctx, state)
	go RunServer(ctx, state)

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				state.mu.RLock()
				switch {
				case state.scanCount == 0:
					mStatus.SetTitle("Status: starting...")
					mLastScan.SetTitle("Last scan: never")
				case state.totalAlerts == 0:
					mStatus.SetTitle("Status: Clean")
					mLastScan.SetTitle(fmt.Sprintf("Last scan: %s ago", time.Since(state.lastScanTime).Round(time.Second)))
				default:
					mStatus.SetTitle(fmt.Sprintf("Status: %d threat(s) detected", state.totalAlerts))
					mLastScan.SetTitle(fmt.Sprintf("Last scan: %s ago", time.Since(state.lastScanTime).Round(time.Second)))
				}
				state.mu.RUnlock()
			}
		}
	}()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-mDashboard.ClickedCh:
				openBrowser(fmt.Sprintf("http://localhost:%d", state.port))
			case <-mScan.ClickedCh:
				state.TriggerScan()
			case <-mQuit.ClickedCh:
				cancel()
				systray.Quit()
			}
		}
	}()
}

func openBrowser(url string) {
	switch runtime.GOOS {
	case "darwin":
		exec.Command("open", url).Start()
	case "linux":
		exec.Command("xdg-open", url).Start()
	}
}

func makeIcon() []byte {
	const size = 22
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	cx, cy := float64(size)/2, float64(size)/2

	// Outer ring
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx := float64(x) - cx + 0.5
			dy := float64(y) - cy + 0.5
			dist := math.Sqrt(dx*dx + dy*dy)
			if dist >= 7.5 && dist <= 9.5 {
				img.SetNRGBA(x, y, color.NRGBA{0, 0, 0, 255})
			}
			if dist <= 3.0 {
				img.SetNRGBA(x, y, color.NRGBA{0, 0, 0, 255})
			}
		}
	}

	var buf bytes.Buffer
	png.Encode(&buf, img)
	return buf.Bytes()
}
