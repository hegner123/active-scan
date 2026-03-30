//go:build !windows

package main

import (
	"context"
	"testing"
)

func TestParseProcessOutput(t *testing.T) {
	output := `USER               PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND
root                 1   0.0  0.1 34291712  12288   ??  Ss   Mon08AM   0:30.00 /sbin/launchd
user              1234   0.5  1.2 45678900 123456   ??  S    10:00AM   0:05.00 node -e global["!"] something malicious
user              5678   0.1  0.5 34567890  56789   ??  S    10:01AM   0:01.00 node /usr/local/bin/legit-app
user              9012   0.3  0.8 45678901  98765   ??  S    10:02AM   0:03.00 node app.js _V something =-22 payload
user              3456   0.2  0.4 34567891  45678   ??  S    10:03AM   0:02.00 node server.js Gez(encoded)
user              7777   0.1  0.3 34567892  34567   ??  S    10:04AM   0:01.00 node active-scan --port 9847`

	hits := parseProcessOutput(output, 99999)

	if len(hits) != 3 {
		t.Fatalf("got %d hits, want 3", len(hits))
	}

	if hits[0].PID != 1234 {
		t.Errorf("hit[0].PID = %d, want 1234", hits[0].PID)
	}
	if hits[0].Reason != "node eval with global[] access" {
		t.Errorf("hit[0].Reason = %q", hits[0].Reason)
	}

	if hits[1].PID != 9012 {
		t.Errorf("hit[1].PID = %d, want 9012", hits[1].PID)
	}
	if hits[1].Reason != "node with _V=-22 signature" {
		t.Errorf("hit[1].Reason = %q", hits[1].Reason)
	}

	if hits[2].PID != 3456 {
		t.Errorf("hit[2].PID = %d, want 3456", hits[2].PID)
	}
	if hits[2].Reason != "node with Gez() call" {
		t.Errorf("hit[2].Reason = %q", hits[2].Reason)
	}
}

func TestParseProcessOutputSkipsSelf(t *testing.T) {
	output := `USER               PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND
user              1234   0.5  1.2 45678900 123456   ??  S    10:00AM   0:05.00 node -e global["!"] payload`

	hits := parseProcessOutput(output, 1234)
	if len(hits) != 0 {
		t.Errorf("should skip own PID, got %d hits", len(hits))
	}
}

func TestParseProcessOutputSkipsActiveScan(t *testing.T) {
	output := `USER               PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND
user              7777   0.1  0.3 34567892  34567   ??  S    10:04AM   0:01.00 node active-scan --port 9847`

	hits := parseProcessOutput(output, 99999)
	if len(hits) != 0 {
		t.Errorf("should skip active-scan processes, got %d hits", len(hits))
	}
}

func TestParseProcessOutputEmpty(t *testing.T) {
	hits := parseProcessOutput("", 1)
	if len(hits) != 0 {
		t.Errorf("empty input should return nil, got %d hits", len(hits))
	}
}

func TestParseNetworkOutput(t *testing.T) {
	output := `COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
node      12345   user   20u  IPv4 0x1234567890     0t0  TCP 192.168.1.5:54321->trongrid.io:443 (ESTABLISHED)
node      12346   user   21u  IPv4 0x1234567891     0t0  TCP 192.168.1.5:54322->google.com:443 (ESTABLISHED)
Safari    12347   user   22u  IPv4 0x1234567892     0t0  TCP 192.168.1.5:54323->example.com:443 (ESTABLISHED)
node      12348   user   23u  IPv4 0x1234567893     0t0  TCP 192.168.1.5:54324->136.0.9.8:8080 (ESTABLISHED)`

	hits := parseNetworkOutput(output)

	if len(hits) != 2 {
		t.Fatalf("got %d hits, want 2", len(hits))
	}

	if hits[0].PID != 12345 || hits[0].Host != "trongrid" {
		t.Errorf("hit[0] = {PID:%d Host:%q}, want {PID:12345 Host:trongrid}", hits[0].PID, hits[0].Host)
	}

	if hits[1].PID != 12348 || hits[1].Host != "136.0.9.8" {
		t.Errorf("hit[1] = {PID:%d Host:%q}, want {PID:12348 Host:136.0.9.8}", hits[1].PID, hits[1].Host)
	}
}

func TestParseNetworkOutputEmpty(t *testing.T) {
	hits := parseNetworkOutput("")
	if len(hits) != 0 {
		t.Errorf("empty input should return nil, got %d hits", len(hits))
	}
}

func TestScanProcessesReturnsClean(t *testing.T) {
	ctx := context.Background()
	detections := scanProcesses(ctx)
	if len(detections) != 0 {
		t.Logf("WARNING: detected %d suspicious processes on this system", len(detections))
	}
}

func TestScanNetworkReturnsClean(t *testing.T) {
	ctx := context.Background()
	detections := scanNetwork(ctx)
	if len(detections) != 0 {
		t.Logf("WARNING: detected %d suspicious network connections on this system", len(detections))
	}
}
