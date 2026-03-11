package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	s.mu.Unlock()

	s.publishEvent("status", s.Status())
}

func (s *State) Status() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status := map[string]any{
		"scanCount":   s.scanCount,
		"totalKills":  s.totalKills,
		"totalAlerts": s.totalAlerts,
		"interval":    s.interval.Seconds(),
		"lastScan":    s.lastScanTime,
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

func parseProcessOutput(output string, myPID int) []processHit {
	var hits []processHit
	s := bufio.NewScanner(strings.NewReader(output))
	for s.Scan() {
		line := s.Text()
		if !strings.Contains(line, "node") || strings.Contains(line, "active-scan") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 11 {
			continue
		}
		pid, err := strconv.Atoi(fields[1])
		if err != nil || pid == myPID {
			continue
		}
		cmd := strings.Join(fields[10:], " ")
		reason, matched := matchProcessCmd(cmd)
		if !matched {
			continue
		}
		hits = append(hits, processHit{PID: pid, Cmd: cmd, Reason: reason})
	}
	return hits
}

func parseNetworkOutput(output string) []networkHit {
	var hits []networkHit
	s := bufio.NewScanner(strings.NewReader(output))
	for s.Scan() {
		line := s.Text()
		host, matched := matchNetworkLine(line)
		if !matched {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		dest := ""
		if len(fields) >= 9 {
			dest = fields[8]
		}
		hits = append(hits, networkHit{PID: pid, Host: host, Dest: dest})
	}
	return hits
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

func scanProcesses(ctx context.Context) []Detection {
	out, err := exec.CommandContext(ctx, "ps", "aux").Output()
	if err != nil {
		return nil
	}

	hits := parseProcessOutput(string(out), os.Getpid())
	var detections []Detection
	for _, h := range hits {
		action := "killed"
		if killErr := exec.Command("kill", "-9", strconv.Itoa(h.PID)).Run(); killErr != nil {
			action = "kill failed"
		}
		log.Printf("THREAT: %s (PID %d) — %s", h.Reason, h.PID, action)
		detections = append(detections, Detection{
			Time:     time.Now(),
			Category: "process",
			Detail:   fmt.Sprintf("%s — PID %d — %s", h.Reason, h.PID, truncate(h.Cmd, 120)),
			Action:   action,
			PID:      h.PID,
		})
	}
	return detections
}

func scanNetwork(ctx context.Context) []Detection {
	out, err := exec.CommandContext(ctx, "lsof", "-i", "-nP").Output()
	if err != nil {
		return nil
	}

	hits := parseNetworkOutput(string(out))
	var detections []Detection
	for _, h := range hits {
		action := "killed"
		if killErr := exec.Command("kill", "-9", strconv.Itoa(h.PID)).Run(); killErr != nil {
			action = "kill failed"
		}
		log.Printf("THREAT: C2 connection to %s (PID %d) — %s", h.Host, h.PID, action)
		detections = append(detections, Detection{
			Time:     time.Now(),
			Category: "network",
			Detail:   fmt.Sprintf("C2 connection to %s — PID %d — %s", h.Host, h.PID, h.Dest),
			Action:   action,
			PID:      h.PID,
		})
	}
	return detections
}

func scanPersistence() []Detection {
	var detections []Detection

	out, err := exec.Command("crontab", "-l").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "node") && strings.Contains(lower, "-e") {
				detections = append(detections, Detection{
					Time:     time.Now(),
					Category: "persistence",
					Detail:   fmt.Sprintf("suspicious crontab: %s", truncate(line, 120)),
					Action:   "notified",
				})
			}
			for _, kw := range persistKeywords {
				if strings.Contains(lower, kw) {
					detections = append(detections, Detection{
						Time:     time.Now(),
						Category: "persistence",
						Detail:   fmt.Sprintf("crontab contains '%s': %s", kw, truncate(line, 120)),
						Action:   "notified",
					})
					break
				}
			}
		}
	}

	laDir := filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents")
	entries, err := os.ReadDir(laDir)
	if err != nil {
		return detections
	}

	for _, entry := range entries {
		if entry.IsDir() || strings.Contains(entry.Name(), "activescan") {
			continue
		}
		path := filepath.Join(laDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := strings.ToLower(string(data))

		for _, kw := range persistKeywords {
			if strings.Contains(content, kw) {
				detections = append(detections, Detection{
					Time:     time.Now(),
					Category: "persistence",
					Detail:   fmt.Sprintf("LaunchAgent '%s' contains '%s'", entry.Name(), kw),
					Action:   "notified",
				})
				break
			}
		}
		if strings.Contains(content, "node") && strings.Contains(content, "-e") {
			detections = append(detections, Detection{
				Time:     time.Now(),
				Category: "persistence",
				Detail:   fmt.Sprintf("LaunchAgent '%s' runs suspicious node command", entry.Name()),
				Action:   "notified",
			})
		}
	}

	return detections
}

func scanConfigs(ctx context.Context) []Detection {
	home := os.Getenv("HOME")
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

// --- Notifications ---

func notifyOS(title, message string) {
	script := fmt.Sprintf(
		`display notification %q with title %q sound name "Sosumi"`,
		message, "Active Scan: "+title,
	)
	exec.Command("osascript", "-e", script).Run()
}

// --- Helpers ---

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
