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

// parseProcessOutput parses the output of:
//
//	ps -wwaxo pid=,user=,command=
//
// The "=" suffix on each column suppresses the header row, and -ww
// disables command-line truncation.  Format per row:
//
//	<pid> <user> <command and args...>
//
// We do NOT pre-filter by binary name.  Every process line is fed to
// matchProcessCmd; only the self-exclusion check survives.
func parseProcessOutput(output string, myPID int) []processHit {
	var hits []processHit
	s := bufio.NewScanner(strings.NewReader(output))
	// Long obfuscated payloads can blow past bufio's default 64KB line cap.
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		line := s.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.Contains(line, "active-scan") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil || pid == myPID {
			continue
		}
		cmd := strings.Join(fields[2:], " ")
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
	// -ww disables column truncation (default ps aux truncates COMMAND on
	// macOS, hiding the long obfuscated payload that contains the markers
	// we match on); -ax includes all processes including those without a
	// controlling terminal; -o pid=,user=,command= gives us only the
	// columns we need with no header row.
	out, err := exec.CommandContext(ctx, "ps", "-wwaxo", "pid=,user=,command=").Output()
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

// scanLaunchDir scans a launchd plist directory.  Skips active-scan's own
// plist, skips directories, only reads files ending in .plist.
func scanLaunchDir(dir, descriptor string) []Detection {
	var detections []Detection
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		nameLower := strings.ToLower(entry.Name())
		if !strings.HasSuffix(nameLower, ".plist") {
			continue
		}
		if strings.Contains(nameLower, "activescan") || strings.Contains(nameLower, "active-scan") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		detections = append(detections, scanFileForPersistence(path, descriptor)...)
	}
	return detections
}

func scanPersistence() []Detection {
	var detections []Detection

	// 1. User crontab.
	if out, err := exec.Command("crontab", "-l").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if kw, matched := matchPersistenceLine(line); matched {
				detections = append(detections, Detection{
					Time:     time.Now(),
					Category: "persistence",
					Detail:   fmt.Sprintf("crontab contains '%s': %s", kw, truncate(line, 120)),
					Action:   "notified",
				})
			}
		}
	}

	if runtime.GOOS != "darwin" {
		// 2. Linux-only: shell rc still applies, but no LaunchAgents.
		detections = append(detections, scanUserConfigFiles()...)
		return detections
	}

	// 3. macOS: LaunchAgents and LaunchDaemons, user + system-wide.
	//    /Library/LaunchDaemons is where a "kill it and it comes back"
	//    daemon would live, because launchd will respawn it under root.
	home, err := os.UserHomeDir()
	if err == nil {
		detections = append(detections,
			scanLaunchDir(filepath.Join(home, "Library", "LaunchAgents"), "user LaunchAgent")...)
	}
	detections = append(detections,
		scanLaunchDir("/Library/LaunchAgents", "system LaunchAgent")...)
	detections = append(detections,
		scanLaunchDir("/Library/LaunchDaemons", "system LaunchDaemon")...)

	// 4. Shell rc and other user config files.
	detections = append(detections, scanUserConfigFiles()...)

	// 5. macOS login items (binary plist; convert via plutil first).
	detections = append(detections, scanLoginItems()...)

	return detections
}

// scanLoginItems reads macOS's backgrounditems.btm (a binary plist that
// records login items and background tasks), converts it to XML via
// plutil, and scans the result for persistence indicators.  Silently
// returns nil on Linux or when the file or plutil is unavailable.
func scanLoginItems() []Detection {
	if runtime.GOOS != "darwin" {
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	path := filepath.Join(home, "Library", "Application Support",
		"com.apple.backgroundtaskmanagementagent", "backgrounditems.btm")
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	out, err := exec.Command("plutil", "-convert", "xml1", "-o", "-", path).Output()
	if err != nil {
		return nil
	}
	return scanContentForPersistence(string(out), "macOS login item", path)
}

// scanUserConfigFiles checks shell startup files, npm config, and ssh
// files for the persistence indicator set.  Each path is opportunistic;
// non-existent files are silently skipped.
func scanUserConfigFiles() []Detection {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	shellFiles := []string{
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".zprofile"),
		filepath.Join(home, ".zshenv"),
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".bash_profile"),
		filepath.Join(home, ".profile"),
	}
	npmFile := filepath.Join(home, ".npmrc")
	sshAuthKeys := filepath.Join(home, ".ssh", "authorized_keys")
	sshConfig := filepath.Join(home, ".ssh", "config")

	var detections []Detection
	for _, p := range shellFiles {
		detections = append(detections, scanFileForPersistence(p, "shell rc")...)
	}
	detections = append(detections, scanFileForPersistence(npmFile, "npm config")...)
	detections = append(detections, scanFileForPersistence(sshAuthKeys, "ssh authorized_keys")...)
	detections = append(detections, scanFileForPersistence(sshConfig, "ssh config")...)
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
