VERSION = $(shell git describe --tags --always --dirty)
LDFLAGS=-ldflags "-X main.version=$(VERSION)"
OSARCH=$(shell go env GOHOSTOS)-$(shell go env GOHOSTARCH)

BINARIES=\
	mdmb-darwin-amd64 \
	mdmb-linux-amd64 \
	mdmb-windows-amd64.exe

my: mdmb-$(OSARCH)

$(BINARIES):
	GOOS=$(word 2,$(subst -, ,$@)) GOARCH=$(word 3,$(subst -, ,$(subst .exe,,$@))) go build $(LDFLAGS) -o $@ ./cmd/mdmb

%-$(VERSION).zip: %.exe
	rm -f $@
	zip $@ $<

%-$(VERSION).zip: %
	rm -f $@
	zip $@ $<

clean:
	rm -f mdmb-*

release: $(foreach bin,$(BINARIES),$(subst .exe,,$(bin))-$(VERSION).zip)

.PHONY: my $(BINARIES) clean release
