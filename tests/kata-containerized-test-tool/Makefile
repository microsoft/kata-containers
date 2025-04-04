.PHONY: build docker clean

BINARY_NAME=kata-containerized-test-tool
CONTAINER_NAME=sdl-test-container:local

build:
	go build -o $(BINARY_NAME) cmd/katatest/main.go

docker: build
	docker build -t $(CONTAINER_NAME) .

clean:
	rm -f $(BINARY_NAME)

all: clean build docker