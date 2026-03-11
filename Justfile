default: build

build:
    go build -o active-scan .
    codesign -s - active-scan

test:
    go test ./...

install: build
    cp active-scan /usr/local/bin/active-scan
