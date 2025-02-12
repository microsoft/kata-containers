.PHONY: build docker clean

BINARY_NAME=kata-containerized-test-tool

build:
	go build -o $(BINARY_NAME) cmd/katatest/main.go

docker:
	docker build -t kata-test-container .

clean:
	rm -f $(BINARY_NAME)

all: clean build docker