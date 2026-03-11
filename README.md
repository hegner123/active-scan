# active-scan

macOS menu bar application that monitors for blockchain C2 backdoor malware (A7-2259 / 5-022526 / C5-022526). Detects malicious processes and network connections, auto-kills threats, and sends OS notifications.

## Installation

```bash
just install
```

## Usage

```bash
# Run directly
active-scan

# Custom port and scan interval
active-scan --port 9847 --interval 30
```

The app appears in the macOS menu bar. Click to open the dashboard, trigger manual scans, or quit.

## Detection

- Malicious `node` processes (eval+global[], _V=-22, Gez() signatures)
- C2 network connections (trongrid, aptoslabs, bsc-dataseed, publicnode, 136.0.9.8)
- Persistence mechanisms (crontab, LaunchAgents)
- Infected `next.config.*` files
