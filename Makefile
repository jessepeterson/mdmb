VERSION = $(shell git describe --tags --always --dirty)
BUILD_VERSION = "-X main.version=${VERSION}"

build:
	go build -ldflags ${BUILD_VERSION} ./cmd/mdmb

clean: clean-release
	rm -f mdmb

release:
	GOOS=darwin GOARCH=amd64 go build -ldflags ${BUILD_VERSION} -o mdmb ./cmd/mdmb
	zip mdmb-darwin-amd64-${VERSION}.zip mdmb
	GOOS=linux GOARCH=amd64 go build -ldflags ${BUILD_VERSION} -o mdmb ./cmd/mdmb
	zip mdmb-linux-amd64-${VERSION}.zip mdmb
	GOOS=windows GOARCH=amd64 go build -ldflags ${BUILD_VERSION} -o mdmb.exe ./cmd/mdmb
	zip mdmb-windows-amd64-${VERSION}.zip mdmb.exe

clean-release:
	rm -f \
		mdmb-darwin-amd64-*.zip \
		mdmb-linux-amd64-*.zip \
		mdmb.exe \
		mdmb-windows-amd64-*.zip

.PHONY: build clean release clean-release
