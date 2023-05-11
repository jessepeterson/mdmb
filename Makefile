VERSION = $(shell git describe --tags --always --dirty)
LDFLAGS=-ldflags "-X main.version=$(VERSION)"
OSARCH=$(shell go env GOHOSTOS)-$(shell go env GOHOSTARCH)

MDMB=\
	mdmb-darwin-amd64 \
	mdmb-darwin-arm64 \
	mdmb-linux-amd64 \
	mdmb-windows-amd64.exe

my: mdmb-$(OSARCH)

$(MDMB): cmd/mdmb
	GOOS=$(word 2,$(subst -, ,$@)) GOARCH=$(word 3,$(subst -, ,$(subst .exe,,$@))) go build $(LDFLAGS) -o $@ ./$<

%-$(VERSION).zip: %.exe
	rm -f $@
	zip $@ $<

%-$(VERSION).zip: %
	rm -f $@
	zip $@ $<

clean:
	rm -f mdmb-*

release: $(foreach bin,$(MDMB),$(subst .exe,,$(bin))-$(VERSION).zip)

.PHONY: my $(MDMB) clean release
