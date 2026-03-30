default: build

build:
    go build -o active-scan .
    codesign -f -s - active-scan

build-windows:
    GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o active-scan-amd64.exe .

build-windows-arm:
    GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -o active-scan-arm64.exe .

build-linux:
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o active-scan-linux .

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
    rm -f active-scan active-scan-amd64.exe active-scan-arm64.exe active-scan-linux
