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

var configFileExtensions = []string{".js", ".mjs", ".cjs", ".ts"}

// isBuildConfigFile reports whether name looks like a JS/TS build-pipeline
// config file (e.g. next.config.js, postcss.config.js, tailwind.config.mjs).
// The check is case-insensitive and pattern-based, not a fixed filename list,
// so payloads that rotate between config files (next.config -> postcss.config)
// remain in scope.
func isBuildConfigFile(name string) bool {
	lower := strings.ToLower(name)
	var hasExt bool
	for _, ext := range configFileExtensions {
		if strings.HasSuffix(lower, ext) {
			hasExt = true
			break
		}
	}
	if !hasExt {
		return false
	}
	return strings.Index(lower, ".config.") > 0
}

// matchWalletString returns the longest walletStrings entry contained in s.
// Longest-match avoids substring collisions between overlapping entries
// (e.g. "C5-022526" contains "5-022526"), so list order does not matter.
func matchWalletString(s string) (string, bool) {
	var best string
	for _, w := range walletStrings {
		if strings.Contains(s, w) && len(w) > len(best) {
			best = w
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
}

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

// matchProcessCmd is intentionally NOT scoped to "node" processes.  The
// indicator strings here (global[, _V=-22, Gez() and the wallet/campaign
// list) are specific enough that we apply them to every process command
// line; this catches the malware even when its binary has been renamed
// or run via npx/bun/deno/tsx.
func matchProcessCmd(cmd string) (string, bool) {
	switch {
	case strings.Contains(cmd, "-e") && strings.Contains(cmd, "global["):
		return "eval with global[] access", true
	case strings.Contains(cmd, "_V") && strings.Contains(cmd, "=-22"):
		return "_V=-22 signature in command", true
	case strings.Contains(cmd, "Gez("):
		return "Gez() call in command", true
	}
	if w, ok := matchWalletString(cmd); ok {
		return "wallet/campaign id in command: " + w, true
	}
	return "", false
}

// matchNetworkLine matches any process line with a known C2 host substring.
// The "node" pre-filter that used to live here was deliberately removed:
// a renamed loader binary (or one launched via npx/bun/deno) still calls
// the same C2 endpoints, and we want those caught.
func matchNetworkLine(line string) (string, bool) {
	lower := strings.ToLower(line)
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
	if strings.Contains(lower, "curl") {
		if strings.Contains(lower, "| sh") || strings.Contains(lower, "|sh") ||
			strings.Contains(lower, "| bash") || strings.Contains(lower, "|bash") {
			return "curl | sh", true
		}
	}
	if strings.Contains(lower, "wget") {
		if strings.Contains(lower, "| sh") || strings.Contains(lower, "|sh") ||
			strings.Contains(lower, "| bash") || strings.Contains(lower, "|bash") {
			return "wget | sh", true
		}
	}
	for _, kw := range persistKeywords {
		if strings.Contains(lower, kw) {
			return kw, true
		}
	}
	if w, ok := matchWalletString(line); ok {
		return "wallet/campaign id: " + w, true
	}
	return "", false
}

func matchConfigContent(content string) (string, bool) {
	for _, marker := range configMarkers {
		if strings.Contains(content, marker) {
			return marker, true
		}
	}
	if w, ok := matchWalletString(content); ok {
		return "wallet/campaign id: " + w, true
	}
	return "", false
}

// --- Persistence content matching (shared across platforms) ---

// scanContentForPersistence emits detections for known indicators found
// in content.  identifier is included in the Detail string (typically a
// file path or login-item name).  Each indicator class emits at most one
// Detection; persistKeywords stops at the first match.
func scanContentForPersistence(content, descriptor, identifier string) []Detection {
	lower := strings.ToLower(content)
	var detections []Detection

	if strings.Contains(lower, "node") && strings.Contains(lower, "-e") {
		detections = append(detections, Detection{
			Time:     time.Now(),
			Category: "persistence",
			Detail:   fmt.Sprintf("%s %s contains 'node -e'", descriptor, identifier),
			Action:   "notified",
		})
	}
	if strings.Contains(lower, "curl") &&
		(strings.Contains(lower, "| sh") || strings.Contains(lower, "|sh") ||
			strings.Contains(lower, "| bash") || strings.Contains(lower, "|bash")) {
		detections = append(detections, Detection{
			Time:     time.Now(),
			Category: "persistence",
			Detail:   fmt.Sprintf("%s %s contains 'curl | sh' style pipe", descriptor, identifier),
			Action:   "notified",
		})
	}
	for _, kw := range persistKeywords {
		if strings.Contains(lower, kw) {
			detections = append(detections, Detection{
				Time:     time.Now(),
				Category: "persistence",
				Detail:   fmt.Sprintf("%s %s contains '%s'", descriptor, identifier, kw),
				Action:   "notified",
			})
			break
		}
	}
	if w, ok := matchWalletString(content); ok {
		detections = append(detections, Detection{
			Time:     time.Now(),
			Category: "persistence",
			Detail:   fmt.Sprintf("%s %s contains wallet/campaign id '%s'", descriptor, identifier, w),
			Action:   "notified",
		})
	}
	if marker, ok := matchConfigContent(content); ok && !strings.HasPrefix(marker, "wallet/campaign id") {
		detections = append(detections, Detection{
			Time:     time.Now(),
			Category: "persistence",
			Detail:   fmt.Sprintf("%s %s contains JS payload marker '%s'", descriptor, identifier, marker),
			Action:   "notified",
		})
	}

	return detections
}

// scanFileForPersistence reads path and delegates to
// scanContentForPersistence.  Missing files are silently skipped so this
// is safe to call against an opportunistic path list.
func scanFileForPersistence(path, descriptor string) []Detection {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return scanContentForPersistence(string(data), descriptor, path)
}

// --- Scanner ---

func RunScanner(ctx context.Context, state *State) {
	log.Printf("scanner started (interval: %s)", state.interval)

	runScan(ctx, state, true)

	ticker := time.NewTicker(state.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("scanner stopped")
			return
		case <-ticker.C:
			runScan(ctx, state, true)
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
		detections = append(detections, scanGitHooks(ctx)...)
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

			if !isBuildConfigFile(d.Name()) && d.Name() != "package.json" {
				return nil
			}

			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			if marker, matched := matchConfigContent(string(data)); matched {
				detections = append(detections, Detection{
					Time:     time.Now(),
					Category: "config",
					Detail:   fmt.Sprintf("infected config: %s (marker: %s)", path, marker),
					Action:   "notified",
				})
			}

			return nil
		})
	}

	return detections
}

// scanGitHooksInDir walks one root directory looking for executable
// hooks under <repo>/.git/hooks/.  Hooks are a classic persistence
// surface: a malicious post-checkout or pre-commit hook runs every
// time git operates on the repo.  Git's bundled sample hooks have a
// .sample suffix and are not executed, so they're skipped.
func scanGitHooksInDir(ctx context.Context, root string) []Detection {
	var detections []Detection
	skipDirs := map[string]bool{
		"node_modules": true, "vendor": true, ".next": true,
	}

	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || ctx.Err() != nil {
			return filepath.SkipAll
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			rel, _ := filepath.Rel(root, path)
			if strings.Count(rel, string(os.PathSeparator)) > 6 {
				return filepath.SkipDir
			}
			return nil
		}

		parent := filepath.Base(filepath.Dir(path))
		grandparent := filepath.Base(filepath.Dir(filepath.Dir(path)))
		if parent != "hooks" || grandparent != ".git" {
			return nil
		}
		if strings.HasSuffix(d.Name(), ".sample") {
			return nil
		}

		detections = append(detections, scanFileForPersistence(path, "git hook")...)
		return nil
	})

	return detections
}

// scanGitHooks scans the standard developer code directories under the
// user's home for malicious git hooks.  See scanGitHooksInDir.
func scanGitHooks(ctx context.Context) []Detection {
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
	for _, dir := range scanDirs {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		detections = append(detections, scanGitHooksInDir(ctx, dir)...)
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
