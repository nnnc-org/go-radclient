GO_DIRS=$(shell find . -type d)
GO_FILES=$(shell find . -type f -name '*.go')

# Stamped into probe.version so a metrics document can be tied to a build.
# Without it the version falls back to the VCS revision recorded by go build.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo devel)
LDFLAGS = -X github.com/nnnc-org/go-radclient/cmd.version=$(VERSION)

./bin/radius-client: $(GO_DIRS) $(GO_FILES)
	@mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o ./bin/radius-client

test:
	go test -race ./...

checks:
	go fmt ./...
	go vet ./...
	go mod tidy
	golangci-lint run
	go test ./...

clean:
	rm -rf bin
