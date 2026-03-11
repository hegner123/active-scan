default: build

build:
    go build -o active-scan .
    codesign -f -s - active-scan

test:
    go test ./...

install: build
    cp active-scan /usr/local/bin/active-scan
    @echo "Installed to /usr/local/bin/active-scan"
    @echo "Run 'just enable' to start on login"

enable: install
    @mkdir -p ~/Library/LaunchAgents
    cp com.hegner123.active-scan.plist ~/Library/LaunchAgents/
    launchctl load ~/Library/LaunchAgents/com.hegner123.active-scan.plist
    @echo "Enabled — starts on login, restarts if stopped"

disable:
    -launchctl unload ~/Library/LaunchAgents/com.hegner123.active-scan.plist
    rm -f ~/Library/LaunchAgents/com.hegner123.active-scan.plist
    @echo "Disabled"

start:
    launchctl start com.hegner123.active-scan

stop:
    launchctl stop com.hegner123.active-scan

status:
    @launchctl list com.hegner123.active-scan 2>/dev/null && echo "Running" || echo "Not running"

logs:
    tail -f /tmp/active-scan.err.log

clean:
    rm -f active-scan
