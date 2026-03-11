default: build

build:
    go build -o active-scan .
    codesign -s - active-scan

test:
    go test ./...

install: build
    cp active-scan /usr/local/bin/active-scan
    @echo "Installed to /usr/local/bin/active-scan"
    @echo "Run 'just enable' to start on login"

enable: install
    @mkdir -p ~/Library/LaunchAgents
    @cat > ~/Library/LaunchAgents/com.hegner123.active-scan.plist << 'PLIST'
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>Label</key>
        <string>com.hegner123.active-scan</string>
        <key>ProgramArguments</key>
        <array>
            <string>/usr/local/bin/active-scan</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
        <key>KeepAlive</key>
        <true/>
        <key>StandardOutPath</key>
        <string>/tmp/active-scan.out.log</string>
        <key>StandardErrorPath</key>
        <string>/tmp/active-scan.err.log</string>
    </dict>
    </plist>
    PLIST
    launchctl load ~/Library/LaunchAgents/com.hegner123.active-scan.plist
    @echo "Enabled — active-scan will start on login and restart if stopped"

disable:
    -launchctl unload ~/Library/LaunchAgents/com.hegner123.active-scan.plist
    rm -f ~/Library/LaunchAgents/com.hegner123.active-scan.plist
    @echo "Disabled — active-scan will no longer start on login"

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
