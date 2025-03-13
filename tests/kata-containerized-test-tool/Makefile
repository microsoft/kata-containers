BINARY_NAME=kata-containerized-test-tool

.PHONY: build
build:
	go build -o $(BINARY_NAME) cmd/katatest/main.go

.PHONY: docker
docker: build
	docker build -t kata-test-container .

.PHONY: clean
clean:
	rm -f $(BINARY_NAME)

.PHONY: all
all: clean build docker