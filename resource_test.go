package main

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"
)

func TestMemoryAtRest(t *testing.T) {
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	state := NewState(30*time.Second, 9847)
	_ = state.Status()
	_ = state.History(0)

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	// State at rest: allocated heap should stay well under 1MB
	delta := after.TotalAlloc - before.TotalAlloc
	t.Logf("state at rest: allocated %d bytes", delta)
	if delta > 1024*1024 {
		t.Errorf("state at rest allocated %d bytes, want < 1MB", delta)
	}
}

func TestMemoryAfterManyCycles(t *testing.T) {
	state := NewState(time.Second, 0)

	// Simulate 2000 scan cycles with detections
	for i := range 2000 {
		state.addResult(ScanResult{
			Time:     time.Now(),
			Duration: "1ms",
			Detections: []Detection{
				{
					Time:     time.Now(),
					Category: "test",
					Detail:   fmt.Sprintf("simulated detection %d with padding to simulate real data", i),
					Action:   "notified",
				},
			},
			Clean: false,
		})
	}

	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	t.Logf("heap after 2000 cycles (1000 retained): Alloc=%dKB Sys=%dKB", m.Alloc/1024, m.Sys/1024)

	// With 1000 capped results, heap should be well under 10MB
	if m.Alloc > 10*1024*1024 {
		t.Errorf("heap = %d MB after 2000 cycles, want < 10MB", m.Alloc/1024/1024)
	}

	// Verify cap is enforced
	history := state.History(0)
	if len(history) != 1000 {
		t.Errorf("history len = %d, want 1000", len(history))
	}
}

func TestMemoryStabilizes(t *testing.T) {
	state := NewState(time.Second, 0)

	// Fill to cap
	for range 1200 {
		state.addResult(ScanResult{
			Time:     time.Now(),
			Duration: "1ms",
			Detections: []Detection{
				{Category: "test", Detail: "padding data for memory test", Action: "notified"},
			},
		})
	}

	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)

	// Add 500 more — memory should NOT grow since old entries are evicted
	for range 500 {
		state.addResult(ScanResult{
			Time:     time.Now(),
			Duration: "1ms",
			Detections: []Detection{
				{Category: "test", Detail: "padding data for memory test", Action: "notified"},
			},
		})
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	// Allow 1MB growth tolerance (GC timing, runtime overhead)
	growth := int64(after.Alloc) - int64(baseline.Alloc)
	t.Logf("memory growth after 500 additional cycles: %d bytes", growth)
	if growth > 1024*1024 {
		t.Errorf("memory grew by %d bytes after cap was reached, want < 1MB growth", growth)
	}
}

func TestGoroutineCleanupScanner(t *testing.T) {
	runtime.GC()
	baseline := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	state := NewState(100*time.Millisecond, 0)

	go RunScanner(ctx, state)

	// Wait for at least one full scan cycle to complete
	time.Sleep(1500 * time.Millisecond)

	cancel()
	// Context-aware scanning should stop quickly
	time.Sleep(500 * time.Millisecond)

	runtime.GC()
	after := runtime.NumGoroutine()
	t.Logf("goroutines: baseline=%d after=%d", baseline, after)

	if after > baseline+2 {
		t.Errorf("goroutine leak: baseline=%d after=%d (delta=%d)", baseline, after, after-baseline)
	}

	// Verify scans actually ran
	if state.Status()["scanCount"].(int) == 0 {
		t.Error("scanner did not run any scans")
	}
}

func TestGoroutineCleanupSubscribers(t *testing.T) {
	state := NewState(time.Second, 0)
	baseline := runtime.NumGoroutine()

	// Subscribe and unsubscribe 200 times
	for range 200 {
		ch := state.Subscribe()
		state.Unsubscribe(ch)
	}

	runtime.GC()
	after := runtime.NumGoroutine()

	if after > baseline+2 {
		t.Errorf("subscriber goroutine leak: baseline=%d after=%d", baseline, after)
	}

	state.subMu.RLock()
	count := len(state.subscribers)
	state.subMu.RUnlock()
	if count != 0 {
		t.Errorf("leaked %d subscribers", count)
	}
}

func TestGoroutineCleanupServer(t *testing.T) {
	runtime.GC()
	baseline := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	state := NewState(time.Second, 0)
	// Use port 0 to let OS assign a free port via the server
	state.port = 0

	go RunServer(ctx, state)
	time.Sleep(100 * time.Millisecond)

	cancel()
	time.Sleep(200 * time.Millisecond)

	runtime.GC()
	after := runtime.NumGoroutine()
	t.Logf("server goroutines: baseline=%d after=%d", baseline, after)

	if after > baseline+2 {
		t.Errorf("server goroutine leak: baseline=%d after=%d", baseline, after)
	}
}

func TestScanCycleCPUTime(t *testing.T) {
	ctx := context.Background()
	state := NewState(time.Second, 0)

	start := time.Now()
	runScan(ctx, state, false) // without config scan
	elapsed := time.Since(start)

	t.Logf("single scan (no config): %s", elapsed)

	// A single scan cycle (ps + lsof + crontab + launchagents) should be fast
	if elapsed > 2*time.Second {
		t.Errorf("scan took %s, want < 2s", elapsed)
	}
}

func TestScanCycleWithConfigsCPUTime(t *testing.T) {
	ctx := context.Background()
	state := NewState(time.Second, 0)

	start := time.Now()
	runScan(ctx, state, true) // with config scan
	elapsed := time.Since(start)

	t.Logf("single scan (with config): %s", elapsed)

	// Config scan walks filesystem, allow more time
	if elapsed > 10*time.Second {
		t.Errorf("scan with configs took %s, want < 10s", elapsed)
	}
}

func TestSustainedOperationMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sustained operation test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	state := NewState(200*time.Millisecond, 0)
	go RunScanner(ctx, state)

	// Let it run for ~3 seconds (~15 scan cycles)
	time.Sleep(3 * time.Second)

	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	// Run 3 more seconds
	time.Sleep(3 * time.Second)

	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	cancel()

	growth := int64(m2.Alloc) - int64(m1.Alloc)
	scans := state.Status()["scanCount"].(int)

	t.Logf("sustained: %d scans, memory growth=%d bytes, heap=%dKB", scans, growth, m2.Alloc/1024)

	// Memory should not grow unboundedly between measurement windows
	if growth > 2*1024*1024 {
		t.Errorf("memory grew %d bytes over %d scans, want < 2MB", growth, scans)
	}
}

// --- Benchmarks ---

func BenchmarkMatchProcessCmd(b *testing.B) {
	cmds := []string{
		`node -e global["!"] something`,
		`node app.js _V something =-22 payload`,
		`node server.js Gez(encoded)`,
		`node /usr/local/bin/serve`,
		`node app.js --port 3000`,
	}
	b.ResetTimer()
	for range b.N {
		for _, cmd := range cmds {
			matchProcessCmd(cmd)
		}
	}
}

func BenchmarkMatchNetworkLine(b *testing.B) {
	lines := []string{
		"node      12345   user   20u  IPv4 0x1234   0t0  TCP 192.168.1.5:54321->trongrid.io:443",
		"node      12345   user   20u  IPv4 0x1234   0t0  TCP 192.168.1.5:54321->google.com:443",
		"Safari    12345   user   20u  IPv4 0x1234   0t0  TCP 192.168.1.5:54321->trongrid.io:443",
	}
	b.ResetTimer()
	for range b.N {
		for _, line := range lines {
			matchNetworkLine(line)
		}
	}
}

func BenchmarkParseProcessOutput(b *testing.B) {
	output := `USER               PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND
root                 1   0.0  0.1 34291712  12288   ??  Ss   Mon08AM   0:30.00 /sbin/launchd
user              1234   0.5  1.2 45678900 123456   ??  S    10:00AM   0:05.00 node -e global["!"] something
user              5678   0.1  0.5 34567890  56789   ??  S    10:01AM   0:01.00 node /usr/local/bin/legit-app
user              9012   0.3  0.8 45678901  98765   ??  S    10:02AM   0:03.00 node app.js _V something =-22 payload
user              3456   0.2  0.4 34567891  45678   ??  S    10:03AM   0:02.00 node server.js Gez(encoded)
user              4444   0.1  0.2 12345678  23456   ??  S    10:05AM   0:01.00 /usr/bin/python3 server.py
user              5555   0.1  0.2 12345678  23456   ??  S    10:06AM   0:01.00 node express-app/server.js
user              6666   0.1  0.2 12345678  23456   ??  S    10:07AM   0:01.00 node next start`

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		parseProcessOutput(output, 99999)
	}
}

func BenchmarkParseNetworkOutput(b *testing.B) {
	output := `COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
node      12345   user   20u  IPv4 0x1234567890     0t0  TCP 192.168.1.5:54321->trongrid.io:443 (ESTABLISHED)
node      12346   user   21u  IPv4 0x1234567891     0t0  TCP 192.168.1.5:54322->google.com:443 (ESTABLISHED)
Safari    12347   user   22u  IPv4 0x1234567892     0t0  TCP 192.168.1.5:54323->example.com:443 (ESTABLISHED)
node      12348   user   23u  IPv4 0x1234567893     0t0  TCP 192.168.1.5:54324->136.0.9.8:8080 (ESTABLISHED)
node      12349   user   24u  IPv4 0x1234567894     0t0  TCP 192.168.1.5:54325->npmjs.org:443 (ESTABLISHED)
Chrome    12350   user   25u  IPv4 0x1234567895     0t0  TCP 192.168.1.5:54326->cdn.example.com:443 (ESTABLISHED)`

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		parseNetworkOutput(output)
	}
}

func BenchmarkScanProcesses(b *testing.B) {
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		scanProcesses(ctx)
	}
}

func BenchmarkScanNetwork(b *testing.B) {
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		scanNetwork(ctx)
	}
}

func BenchmarkFullScanCycle(b *testing.B) {
	ctx := context.Background()
	state := NewState(time.Second, 0)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		runScan(ctx, state, false)
	}
}

func BenchmarkStateAddResult(b *testing.B) {
	state := NewState(time.Second, 0)
	result := ScanResult{
		Time:     time.Now(),
		Duration: "1ms",
		Clean:    true,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		state.addResult(result)
	}
}

func BenchmarkStateAddResultWithDetections(b *testing.B) {
	state := NewState(time.Second, 0)
	result := ScanResult{
		Time:     time.Now(),
		Duration: "1ms",
		Detections: []Detection{
			{Category: "process", Detail: "test detection", Action: "killed", PID: 1234},
			{Category: "network", Detail: "test network", Action: "killed", PID: 5678},
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		state.addResult(result)
	}
}

func BenchmarkStatusRead(b *testing.B) {
	state := NewState(time.Second, 0)
	for range 100 {
		state.addResult(ScanResult{Time: time.Now(), Duration: "1ms", Clean: true})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = state.Status()
	}
}
