#!/bin/bash

# Copyright (c) 2023 Microsoft Corporation

# This script aims to adapt the system for the genpolicy tool to be able to use containerd pull function properly.
# This is needed for managed identity based authentication to private registries using an identity token.

# This script needs 'sudo' access. It will:
# - install containerd if not installed already. Genpolicy tool uses containerd to pull image when using -d option
# - ensure cri plugin is NOT disabled in containerd config. This is needed for policy tool to pull image
# - restart containerd or start it if not running already. 
# - print containerd socket file location. Use this when running genpolicy tool. Eg genpolicy -d=$SOCKET_FILE_LOCATION -y foo.yaml
# - fix containerd socket file permissions if needed. This is so genpolicy tool is able to access containerd socket file without 'sudo'
# - adapt docker config.json if needed. This is done so 'az acr login' command saves identity token to the docker config

set -e -x

# Function to check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Utility function for error messages and exit
error_exit() {
    echo "$1" 1>&2
    exit 1
}

# Function to ensure a command is installed
ensure_command_installed() {
    if ! command_exists "$1"; then
        echo "$1 could not be found, installing..."
        sudo apt-get install -y "$1"
        if ! command_exists "$1"; then
            error_exit "Failed to install $1"
        fi
    else
        echo "$1 is already installed"
    fi
}

sudo apt-get update

ensure_command_installed containerd

# Modify containerd config if needed
CONTAINERD_CONFIG_FILE="/etc/containerd/config.toml"

if [ ! -f "$CONTAINERD_CONFIG_FILE" ]; then
    error_exit "Containerd config file not found: $CONTAINERD_CONFIG_FILE. Please update CONTAINERD_CONFIG_FILE in this script to point to the correct containerd config file."
fi

if grep -qE 'disabled_plugins.*\["cri"\]' "$CONTAINERD_CONFIG_FILE" || grep -qE "disabled_plugins.*\['cri'\]" "$CONTAINERD_CONFIG_FILE"; then
    echo "Modifying containerd config to enable cri plugin..."
    sudo sed -i -E "s/disabled_plugins.*(\['cri'\]|\[\"cri\"\])/disabled_plugins = []/g" "$CONTAINERD_CONFIG_FILE"
else
    echo "CRI plugin is already enabled in containerd config"
fi

# Restart containerd using systemctl
echo "Restarting containerd service..."
if systemctl is-active --quiet containerd; then
    sudo systemctl restart containerd
else
    sudo systemctl start containerd
fi

# Print containerd status
echo "Containerd status:"
sudo systemctl status containerd --no-pager

# Print containerd socket file location found in config
SOCKET_FILE_LOCATION=$(awk '/\[grpc\]/ {found=1} found && /address *= */ {print $3; exit}' "$CONTAINERD_CONFIG_FILE" | tr -d '"')

if [ -z "$SOCKET_FILE_LOCATION" ]; then
    error_exit "Socket file location not found in config"
fi
echo "Containerd socket file location: $SOCKET_FILE_LOCATION"

# Wait for the socket file to be created
echo "Waiting for containerd socket file to be created..."
for i in {1..10}; do
    if [ -e "$SOCKET_FILE_LOCATION" ]; then
        echo "Containerd socket file found: $SOCKET_FILE_LOCATION"
        break
    fi
    echo "Attempt $i: Socket file not found, waiting..."
    sleep 1
done

if [ ! -e "$SOCKET_FILE_LOCATION" ]; then
    error_exit "Socket file not found after waiting: $SOCKET_FILE_LOCATION"
fi

# Fix containerd socket file permissions
echo "Ensuring containerd socket file permissions are set correctly..."
sudo chmod a+rw "$SOCKET_FILE_LOCATION"

if ! command_exists docker; then
    echo "$1 could not be found, installing..."
    sudo apt-get install -y docker.io
    if ! command_exists docker; then
        error_exit "Failed to install docker.io"
    fi
else
    echo "docker is already installed"
fi

ensure_command_installed jq

# Adapt Docker config if needed
DOCKER_CONFIG_FILE="$HOME/.docker/config.json"
echo "Checking Docker config file: $DOCKER_CONFIG_FILE"

if [ -f "$DOCKER_CONFIG_FILE" ]; then
    if grep -q '"credstore":' "$DOCKER_CONFIG_FILE"; then
        echo "Modifying Docker config to remove 'credstore' key..."
        jq 'del(.credstore)' "$DOCKER_CONFIG_FILE" > "$DOCKER_CONFIG_FILE.tmp" && mv "$DOCKER_CONFIG_FILE.tmp" "$DOCKER_CONFIG_FILE"
    else
        echo "'credstore' key not found in Docker config"
    fi
else
    error_exit "Docker config file not found. Please update DOCKER_CONFIG_FILE in this script to point to the correct Docker config file."
fi

echo "Script execution completed. Please use $SOCKET_FILE_LOCATION as socker file location."
echo "Eg. genpolicy -d=$SOCKET_FILE_LOCATION -y foo.yaml"