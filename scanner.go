package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// --- Types ---

type Detection struct {
	Time     time.Time `json:"time"`
	Category string    `json:"category"`
	Detail   string    `json:"detail"`
	Action   string    `json:"action"`
	PID      int       `json:"pid,omitempty"`
}

type ScanResult struct {
	Time       time.Time   `json:"time"`
	Duration   string      `json:"duration"`
	Detections []Detection `json:"detections"`
	Clean      bool        `json:"clean"`
}

type ThreatEvent struct {
	Time     time.Time `json:"time"`
	Category string    `json:"category"`
	Detail   string    `json:"detail"`
	Action   string    `json:"action"`
	PID      int       `json:"pid,omitempty"`
	Status   string    `json:"status"` // "detected" or "resolved"
}

// --- State ---

type State struct {
	mu           sync.RWMutex
	interval     time.Duration
	port         int
	scanNow      chan struct{}
	results      []ScanResult
	lastScanTime time.Time
	totalKills   int
	totalAlerts  int
	scanCount    int
	threatLog    []ThreatEvent

	subMu       sync.RWMutex
	subscribers map[chan string]struct{}
}

func NewState(interval time.Duration, port int) *State {
	return &State{
		interval:    interval,
		port:        port,
		scanNow:     make(chan struct{}, 1),
		subscribers: make(map[chan string]struct{}),
	}
}

func (s *State) TriggerScan() {
	select {
	case s.scanNow <- struct{}{}:
	default:
	}
}

func (s *State) Subscribe() chan string {
	ch := make(chan string, 32)
	s.subMu.Lock()
	s.subscribers[ch] = struct{}{}
	s.subMu.Unlock()
	return ch
}

func (s *State) Unsubscribe(ch chan string) {
	s.subMu.Lock()
	delete(s.subscribers, ch)
	close(ch)
	s.subMu.Unlock()
}

func (s *State) publishEvent(eventType string, data any) {
	payload, err := json.Marshal(data)
	if err != nil {
		return
	}
	msg := fmt.Sprintf("event: %s\ndata: %s\n\n", eventType, payload)
	s.subMu.RLock()
	defer s.subMu.RUnlock()
	for ch := range s.subscribers {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (s *State) addResult(r ScanResult) {
	s.mu.Lock()

	// Capture previous state before prepending
	prevHadThreats := len(s.results) > 0 && !s.results[0].Clean
	var prevDetections []Detection
	if prevHadThreats {
		prevDetections = make([]Detection, len(s.results[0].Detections))
		copy(prevDetections, s.results[0].Detections)
	}

	s.results = append([]ScanResult{r}, s.results...)
	if len(s.results) > 1000 {
		s.results = s.results[:1000]
	}
	s.lastScanTime = r.Time
	s.scanCount++
	for _, d := range r.Detections {
		s.totalAlerts++
		if d.Action == "killed" {
			s.totalKills++
		}
	}

	// Record detection events
	for _, d := range r.Detections {
		s.threatLog = append([]ThreatEvent{{
			Time:     d.Time,
			Category: d.Category,
			Detail:   d.Detail,
			Action:   d.Action,
			PID:      d.PID,
			Status:   "detected",
		}}, s.threatLog...)
	}

	// Record resolution events when previous scan had threats and current is clean
	var resolved []ThreatEvent
	if r.Clean && prevHadThreats {
		for _, d := range prevDetections {
			evt := ThreatEvent{
				Time:     r.Time,
				Category: d.Category,
				Detail:   d.Detail,
				Action:   d.Action,
				PID:      d.PID,
				Status:   "resolved",
			}
			s.threatLog = append([]ThreatEvent{evt}, s.threatLog...)
			resolved = append(resolved, evt)
		}
	}

	if len(s.threatLog) > 1000 {
		s.threatLog = s.threatLog[:1000]
	}

	s.mu.Unlock()

	s.publishEvent("status", s.Status())
	for _, evt := range resolved {
		s.publishEvent("resolved", evt)
	}
}

func (s *State) Status() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()

	activeThreats := 0
	if len(s.results) > 0 && !s.results[0].Clean {
		activeThreats = len(s.results[0].Detections)
	}

	status := map[string]any{
		"scanCount":     s.scanCount,
		"totalKills":    s.totalKills,
		"totalAlerts":   s.totalAlerts,
		"activeThreats": activeThreats,
		"interval":      s.interval.Seconds(),
		"lastScan":      s.lastScanTime,
	}
	if len(s.results) > 0 {
		status["lastResult"] = s.results[0]
	}
	return status
}

func (s *State) History(limit int) []ScanResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > len(s.results) {
		limit = len(s.results)
	}
	out := make([]ScanResult, limit)
	copy(out, s.results[:limit])
	return out
}

func (s *State) ThreatLog(limit int) []ThreatEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > len(s.threatLog) {
		limit = len(s.threatLog)
	}
	out := make([]ThreatEvent, limit)
	copy(out, s.threatLog[:limit])
	return out
}

// --- Indicators ---

var c2Hosts = []string{
	"trongrid",
	"aptoslabs",
	"bsc-dataseed",
	"publicnode",
	"136.0.9.8",
}

var walletStrings = []string{
	"TMfKQEd7TJJa5xNZJZ2Lep",
	"TXfxHUet9pJVU1BgVkBAb",
	"TLmj13VL4p6NQ7jpxz8d9",
	"0xbe037400670fbf1c",
	"0x3f0e5781d0855fb",
	"0x9bc1355344b54de",
	"A7-2259",
	"5-022526",
	"C5-022526",
}

var persistKeywords = []string{"trongrid", "binance"}

var configMarkers = []string{`global["!"]`, "_$_c266", "fromCharCode(127)"}

// --- Matching (testable, pure functions) ---

type processHit struct {
	PID    int
	Cmd    string
	Reason string
}

type networkHit struct {
	PID  int
	Host string
	Dest string
}

func matchProcessCmd(cmd string) (string, bool) {
	switch {
	case strings.Contains(cmd, "-e") && strings.Contains(cmd, "global["):
		return "node eval with global[] access", true
	case strings.Contains(cmd, "_V") && strings.Contains(cmd, "=-22"):
		return "node with _V=-22 signature", true
	case strings.Contains(cmd, "Gez("):
		return "node with Gez() call", true
	}
	return "", false
}

func matchNetworkLine(line string) (string, bool) {
	lower := strings.ToLower(line)
	if !strings.Contains(lower, "node") {
		return "", false
	}
	for _, host := range c2Hosts {
		if strings.Contains(lower, strings.ToLower(host)) {
			return host, true
		}
	}
	return "", false
}

func matchPersistenceLine(line string) (string, bool) {
	lower := strings.ToLower(line)
	if strings.Contains(lower, "node") && strings.Contains(lower, "-e") {
		return "node -e", true
	}
	for _, kw := range persistKeywords {
		if strings.Contains(lower, kw) {
			return kw, true
		}
	}
	return "", false
}

func matchConfigContent(content string) (string, bool) {
	for _, marker := range configMarkers {
		if strings.Contains(content, marker) {
			return marker, true
		}
	}
	return "", false
}

// --- Scanner ---

func RunScanner(ctx context.Context, state *State) {
	log.Printf("scanner started (interval: %s)", state.interval)

	runScan(ctx, state, true)

	ticker := time.NewTicker(state.interval)
	defer ticker.Stop()

	configCycle := 0
	for {
		select {
		case <-ctx.Done():
			log.Println("scanner stopped")
			return
		case <-ticker.C:
			configCycle++
			runScan(ctx, state, configCycle%10 == 0)
		case <-state.scanNow:
			runScan(ctx, state, true)
		}
	}
}

func runScan(ctx context.Context, state *State, includeConfigs bool) {
	start := time.Now()
	var detections []Detection

	detections = append(detections, scanProcesses(ctx)...)
	if ctx.Err() != nil {
		return
	}
	detections = append(detections, scanNetwork(ctx)...)
	if ctx.Err() != nil {
		return
	}
	detections = append(detections, scanPersistence()...)
	if ctx.Err() != nil {
		return
	}
	if includeConfigs {
		detections = append(detections, scanConfigs(ctx)...)
	}

	result := ScanResult{
		Time:       start,
		Duration:   time.Since(start).Round(time.Millisecond).String(),
		Detections: detections,
		Clean:      len(detections) == 0,
	}

	state.addResult(result)

	for _, d := range detections {
		notifyOS(d.Category, d.Detail)
		state.publishEvent("detection", d)
	}
}

func scanConfigs(ctx context.Context) []Detection {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	scanDirs := []string{
		filepath.Join(home, "Documents"),
		filepath.Join(home, "projects"),
		filepath.Join(home, "code"),
		filepath.Join(home, "Code"),
		filepath.Join(home, "repos"),
		filepath.Join(home, "src"),
		filepath.Join(home, "dev"),
	}

	var detections []Detection
	skipDirs := map[string]bool{
		"node_modules": true, ".git": true, "vendor": true, ".next": true,
	}

	for _, dir := range scanDirs {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}

		filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || ctx.Err() != nil {
				return filepath.SkipAll
			}
			if d.IsDir() {
				if skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				rel, _ := filepath.Rel(dir, path)
				if strings.Count(rel, string(os.PathSeparator)) > 6 {
					return filepath.SkipDir
				}
				return nil
			}

			if !strings.HasPrefix(d.Name(), "next.config.") {
				return nil
			}

			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			content := string(data)

			for _, marker := range configMarkers {
				if strings.Contains(content, marker) {
					detections = append(detections, Detection{
						Time:     time.Now(),
						Category: "config",
						Detail:   fmt.Sprintf("infected config: %s (marker: %s)", path, marker),
						Action:   "notified",
					})
					break
				}
			}

			return nil
		})
	}

	return detections
}

// --- Helpers ---

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
