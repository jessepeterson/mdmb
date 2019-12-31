build:
	go build ./cmd/mdmb

clean:
	rm -f mdmb

.PHONY: build clean