.PHONY: build docker clean

BINARY_NAME=kata-containerized-test-tool
CONTAINER_NAME=marinerconfpodstest.azurecr.io/sdl-test-container:v1

build:
	go build -o $(BINARY_NAME) cmd/katatest/main.go

docker: build
	docker build -t $(CONTAINER_NAME) .

clean:
	rm -f $(BINARY_NAME)

all: clean build docker