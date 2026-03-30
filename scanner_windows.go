//go:build windows

package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// --- Output Parsers ---

// parseProcessOutput parses wmic "process where name='node.exe'" /value output.
// Each record is separated by blank lines with Key=Value pairs.
func parseProcessOutput(output string, myPID int) []processHit {
	var hits []processHit
	var currentCmd string
	var currentPID int
	hasRecord := false

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			if hasRecord && currentPID != 0 && currentPID != myPID {
				if strings.Contains(currentCmd, "active-scan") {
					// skip self
				} else if reason, matched := matchProcessCmd(currentCmd); matched {
					hits = append(hits, processHit{PID: currentPID, Cmd: currentCmd, Reason: reason})
				}
			}
			currentCmd = ""
			currentPID = 0
			hasRecord = false
			continue
		}
		if strings.HasPrefix(line, "CommandLine=") {
			currentCmd = strings.TrimPrefix(line, "CommandLine=")
			hasRecord = true
		} else if strings.HasPrefix(line, "ProcessId=") {
			pid, err := strconv.Atoi(strings.TrimPrefix(line, "ProcessId="))
			if err == nil {
				currentPID = pid
			}
			hasRecord = true
		}
	}
	// Handle last record (if output doesn't end with blank line)
	if hasRecord && currentPID != 0 && currentPID != myPID {
		if !strings.Contains(currentCmd, "active-scan") {
			if reason, matched := matchProcessCmd(currentCmd); matched {
				hits = append(hits, processHit{PID: currentPID, Cmd: currentCmd, Reason: reason})
			}
		}
	}
	return hits
}

// parseNetworkOutput parses netstat -nao output and cross-references with
// a set of known node.exe PIDs to find C2 connections.
func parseNetworkOutput(output string, nodePIDs map[int]bool) []networkHit {
	var hits []networkHit
	s := bufio.NewScanner(strings.NewReader(output))
	for s.Scan() {
		line := s.Text()
		fields := strings.Fields(strings.TrimSpace(line))
		// Expect: Proto LocalAddress ForeignAddress State PID
		if len(fields) < 5 {
			continue
		}
		pid, err := strconv.Atoi(fields[4])
		if err != nil || !nodePIDs[pid] {
			continue
		}
		foreignAddr := fields[2]
		for _, host := range c2Hosts {
			if strings.Contains(strings.ToLower(foreignAddr), strings.ToLower(host)) {
				hits = append(hits, networkHit{PID: pid, Host: host, Dest: foreignAddr})
				break
			}
		}
	}
	return hits
}

// --- Platform Scan Functions ---

func scanProcesses(ctx context.Context) []Detection {
	out, err := exec.CommandContext(ctx, "wmic", "process", "where", "name='node.exe'",
		"get", "ProcessId,CommandLine", "/value").Output()
	if err != nil {
		return nil
	}

	hits := parseProcessOutput(string(out), os.Getpid())
	var detections []Detection
	for _, h := range hits {
		action := "killed"
		if killErr := exec.Command("taskkill", "/F", "/PID", strconv.Itoa(h.PID)).Run(); killErr != nil {
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
	// Step 1: Identify node.exe PIDs
	procOut, err := exec.CommandContext(ctx, "wmic", "process", "where", "name='node.exe'",
		"get", "ProcessId", "/value").Output()
	if err != nil {
		return nil
	}
	nodePIDs := make(map[int]bool)
	for _, line := range strings.Split(string(procOut), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ProcessId=") {
			pid, parseErr := strconv.Atoi(strings.TrimPrefix(line, "ProcessId="))
			if parseErr == nil {
				nodePIDs[pid] = true
			}
		}
	}
	if len(nodePIDs) == 0 {
		return nil
	}

	// Step 2: Get network connections
	netOut, err := exec.CommandContext(ctx, "netstat", "-nao").Output()
	if err != nil {
		return nil
	}

	hits := parseNetworkOutput(string(netOut), nodePIDs)
	var detections []Detection
	for _, h := range hits {
		action := "killed"
		if killErr := exec.Command("taskkill", "/F", "/PID", strconv.Itoa(h.PID)).Run(); killErr != nil {
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

	// Check Windows Scheduled Tasks
	out, err := exec.Command("schtasks", "/Query", "/FO", "CSV", "/NH").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			keyword, matched := matchPersistenceLine(line)
			if matched {
				detections = append(detections, Detection{
					Time:     time.Now(),
					Category: "persistence",
					Detail:   fmt.Sprintf("scheduled task contains '%s': %s", keyword, truncate(line, 120)),
					Action:   "notified",
				})
			}
		}
	}

	// Check Registry Run keys
	regPaths := []string{
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
	}
	for _, regPath := range regPaths {
		out, err := exec.Command("reg", "query", regPath).Output()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			keyword, matched := matchPersistenceLine(line)
			if matched {
				detections = append(detections, Detection{
					Time:     time.Now(),
					Category: "persistence",
					Detail:   fmt.Sprintf("registry Run key contains '%s': %s", keyword, truncate(line, 120)),
					Action:   "notified",
				})
			}
		}
	}

	// Check Startup folder
	appData := os.Getenv("APPDATA")
	if appData != "" {
		startupDir := filepath.Join(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
		entries, err := os.ReadDir(startupDir)
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				path := filepath.Join(startupDir, entry.Name())
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
							Detail:   fmt.Sprintf("startup item '%s' contains '%s'", entry.Name(), kw),
							Action:   "notified",
						})
						break
					}
				}
				if strings.Contains(content, "node") && strings.Contains(content, "-e") {
					detections = append(detections, Detection{
						Time:     time.Now(),
						Category: "persistence",
						Detail:   fmt.Sprintf("startup item '%s' runs suspicious node command", entry.Name()),
						Action:   "notified",
					})
				}
			}
		}
	}

	return detections
}

// --- Notifications ---

func notifyOS(title, message string) {
	// PowerShell balloon notification — fire-and-forget, errors ignored
	ps := fmt.Sprintf(
		`Add-Type -AssemblyName System.Windows.Forms;`+
			`$n=New-Object System.Windows.Forms.NotifyIcon;`+
			`$n.Icon=[System.Drawing.SystemIcons]::Shield;`+
			`$n.BalloonTipTitle='Active Scan: %s';`+
			`$n.BalloonTipText='%s';`+
			`$n.Visible=$true;$n.ShowBalloonTip(5000);`+
			`Start-Sleep 6;$n.Dispose()`,
		escapePowerShellSingleQuote(title),
		escapePowerShellSingleQuote(message),
	)
	exec.Command("powershell", "-WindowStyle", "Hidden", "-Command", ps).Start()
}

func escapePowerShellSingleQuote(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
