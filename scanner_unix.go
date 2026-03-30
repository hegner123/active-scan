//go:build !windows

package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// --- Output Parsers ---

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

// --- Platform Scan Functions ---

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

	// LaunchAgents check (macOS only, silently skipped on Linux)
	if runtime.GOOS == "darwin" {
		home, err := os.UserHomeDir()
		if err != nil {
			return detections
		}
		laDir := filepath.Join(home, "Library", "LaunchAgents")
		entries, err := os.ReadDir(laDir)
		if err != nil {
			return detections
		}

		for _, entry := range entries {
			if entry.IsDir() || strings.Contains(entry.Name(), "activescan") {
				continue
			}
			path := filepath.Join(laDir, entry.Name())
			data, readErr := os.ReadFile(path)
			if readErr != nil {
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
	}

	return detections
}

// --- Notifications ---

func notifyOS(title, message string) {
	if runtime.GOOS != "darwin" {
		return
	}
	script := fmt.Sprintf(
		`display notification %q with title %q sound name "Sosumi"`,
		message, "Active Scan: "+title,
	)
	exec.Command("osascript", "-e", script).Run()
}
