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

### macOS

Requires [just](https://github.com/casey/just) and Go 1.22+.

```bash
# Build and install to /usr/local/bin
just install

# Enable as a LaunchAgent (starts on login, restarts if stopped)
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

Requires Go 1.22+. Build from source or download a release binary.

```powershell
# Build
go build -o active-scan.exe .

# Or cross-compile from macOS/Linux
just build-windows       # amd64
just build-windows-arm   # arm64
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
# Build
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o active-scan .

# Run directly
./active-scan
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
