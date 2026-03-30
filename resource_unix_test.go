//go:build !windows

package main

import (
	"context"
	"testing"
)

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
