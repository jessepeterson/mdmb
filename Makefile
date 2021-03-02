VERSION = $(shell git describe --tags --always --dirty)

build:
	go build ./cmd/mdmb

clean: xp-clean
	rm -f mdmb

xp-build:
	GOOS=darwin GOARCH=amd64 go build -o ./mdmb-darwin-amd64-${VERSION} ./cmd/mdmb
	GOOS=linux GOARCH=amd64 go build -o ./mdmb-linux-amd64-${VERSION} ./cmd/mdmb
	GOOS=windows GOARCH=amd64 go build -o ./mdmb-windows-amd64-${VERSION} ./cmd/mdmb

xp-clean:
	rm -f \
	 mdmb-darwin-amd64-* \
	 mdmb-linux-amd64-* \
	 mdmb-windows-amd64-*

.PHONY: build clean xp-build xp-clean
