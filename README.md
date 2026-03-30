# Active Scan

A cross-platform system tray application that monitors for blockchain C2 backdoor malware (A7-2259 / 5-022526 / C5-022526). It continuously scans for malicious Node.js processes, C2 network connections, persistence mechanisms, and infected config files. Detected threats are auto-killed and reported via OS notifications and a real-time web dashboard.

## What it detects

| Category | What | How |
|----------|------|-----|
| **Processes** | Malicious `node` processes with eval+global[], _V=-22, or Gez() signatures | `ps aux` (Unix) / `wmic` (Windows) |
| **Network** | C2 connections to trongrid, aptoslabs, bsc-dataseed, publicnode, 136.0.9.8 | `lsof` (Unix) / `netstat` (Windows) |
| **Persistence** | Suspicious crontab entries, LaunchAgents (macOS), Registry Run keys, Scheduled Tasks, Startup folder (Windows) | Platform-native tools |
| **Configs** | Infected `next.config.*` files containing obfuscation markers | Filesystem walk |

Detected malicious processes are killed automatically. Everything else is reported for manual review.

## Installation

Download the latest binary from the [releases page](https://github.com/hegner123/active-scan/releases/latest), or build from source.

| Platform | Binary |
|----------|--------|
| macOS Intel | `active-scan-darwin-amd64` |
| macOS Apple Silicon | `active-scan-darwin-arm64` |
| Linux x86_64 | `active-scan-linux-amd64` |
| Linux ARM64 | `active-scan-linux-arm64` |
| Windows x86_64 | `active-scan-windows-amd64.exe` |
| Windows ARM64 | `active-scan-windows-arm64.exe` |

### macOS

```bash
# Download (Apple Silicon — use darwin-amd64 for Intel)
curl -LO https://github.com/hegner123/active-scan/releases/latest/download/active-scan-darwin-arm64
chmod +x active-scan-darwin-arm64

# Run directly
./active-scan-darwin-arm64
```

To install as a LaunchAgent (starts on login, restarts if stopped):

```bash
# Requires just and Go 1.22+ (builds from source)
just install
just enable
```

Management:

```bash
just start      # Start the agent
just stop       # Stop the agent
just status     # Check if running
just disable    # Remove the LaunchAgent
just logs       # Tail stderr log
```

### Windows

```powershell
# Download (x86_64 — use windows-arm64.exe for ARM)
Invoke-WebRequest -Uri "https://github.com/hegner123/active-scan/releases/latest/download/active-scan-windows-amd64.exe" -OutFile "active-scan.exe"

# Run directly
.\active-scan.exe
```

Install as a Windows Service (run as Administrator):

```powershell
# Install with default settings (auto-start, restarts on failure)
.\active-scan.exe install

# Install with custom port and interval
.\active-scan.exe install --port 8080 --interval 15

# Start the service
sc start ActiveScan

# Stop the service
sc stop ActiveScan

# Remove the service
.\active-scan.exe uninstall
```

The service runs headlessly (no system tray). The web dashboard is still available at the configured port.

### Linux

```bash
# Download (x86_64 — use linux-arm64 for ARM)
curl -LO https://github.com/hegner123/active-scan/releases/latest/download/active-scan-linux-amd64
chmod +x active-scan-linux-amd64

# Run directly
./active-scan-linux-amd64
```

### Build from source

Requires Go 1.22+.

```bash
go build -o active-scan .
```

## Usage

```bash
# Run interactively (system tray + dashboard)
active-scan

# Custom port and scan interval (seconds)
active-scan --port 9847 --interval 30
```

The app appears in the system tray. Click to open the dashboard, trigger a manual scan, or quit.

### Dashboard

The web dashboard is served at `http://localhost:9847` by default. It shows:

- Current threat status
- Scan history and timing
- Real-time detection events via Server-Sent Events

### API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web dashboard |
| `/api/status` | GET | Current scan status and stats |
| `/api/history` | GET | Last 100 scan results |
| `/api/threats` | GET | Last 200 threat events |
| `/api/scan` | POST | Trigger an immediate scan |
| `/api/events` | GET | SSE stream of live events |

## Development

```bash
just build    # Build for current platform
just test     # Run tests
just clean    # Remove build artifacts
```
