package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"fyne.io/systray"
)

func main() {
	// Handle service subcommands (install/uninstall) before flag parsing
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		if handleServiceCommand(os.Args[1], os.Args[2:]) {
			return
		}
	}

	port := flag.Int("port", 9847, "dashboard port")
	interval := flag.Int("interval", 30, "scan interval in seconds")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	state := NewState(time.Duration(*interval)*time.Second, *port)

	// Windows Service mode: no systray, SCM handles lifecycle
	if isWindowsService() {
		runWindowsService(ctx, cancel, state)
		return
	}

	// Interactive mode: systray + signal handling
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
				case len(state.results) > 0 && !state.results[0].Clean:
					active := len(state.results[0].Detections)
					mStatus.SetTitle(fmt.Sprintf("Status: %d active threat(s)", active))
					mLastScan.SetTitle(fmt.Sprintf("Last scan: %s ago", time.Since(state.lastScanTime).Round(time.Second)))
				default:
					mStatus.SetTitle("Status: Clean")
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
	case "windows":
		exec.Command("cmd", "/c", "start", url).Start()
	}
}
