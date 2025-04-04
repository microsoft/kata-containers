#!/bin/bash

set -e  # exit immediately if a command fails
set -o pipefail  # exit if any command in a pipeline fails

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --tests=*)
      TESTS="${1#*=}"
      shift
      ;;
    --target=*)
      TARGET="${1#*=}"
      shift
      ;;
    --output-dir=*)
      OUTPUT_DIR="${1#*=}"
      shift
      ;;
    --binaries-dir=*)
      BINARIES_DIR="${1#*=}"
      shift
      ;;
    --source-dir=*)
      SOURCE_DIR="${1#*=}"
      shift
      ;;
    --tool-path=*)
      TOOL_PATH="${1#*=}"
      shift
      ;;
    *)
      echo "Unknown parameter: $1"
      echo "Usage: $0 [--tests=TESTS] [--target=TARGET] [--output-dir=DIR] [--binaries-dir=DIR] [--source-dir=DIR] [--tool-path=PATH]"
      exit 1
      ;;
  esac
done

# Default values
TESTS=${TESTS:-"cpu memory sdl"}  # Default tests if none specified
TARGET=${TARGET:-"host"}  # Default target environment: "host" or "uvm"
OUTPUT_DIR=${OUTPUT_DIR:-"/results"}  # Default output directory
BINARIES_DIR=${BINARIES_DIR:-"/kata-binaries"}  # Default binaries directory
SOURCE_DIR=${SOURCE_DIR:-"/kata-source"}  # Default source directory
TOOL_PATH=${TOOL_PATH:-"/app/kata-containerized-test-tool"}  # Path to the test tool binary

echo "🔹 Running tests: $TESTS in $TARGET environment"
echo "🔹 Output directory: $OUTPUT_DIR"
echo "🔹 Binaries directory: $BINARIES_DIR"
echo "🔹 Source directory: $SOURCE_DIR"
echo "🔹 Tool path: $TOOL_PATH"

mkdir -p $OUTPUT_DIR
export KATA_BINARIES_DIR=$BINARIES_DIR
export KATA_SOURCE_DIR=$SOURCE_DIR

# Run the tests
echo "🔹 Starting test execution..."
$TOOL_PATH --output $OUTPUT_DIR "$TESTS" 

# Copy results to stdout for kubectl logs to capture
echo "=== TEST RESULTS ==="
for result_file in $OUTPUT_DIR/results_*.json; do
    if [ -f "$result_file" ]; then
        echo "Results from $result_file:"
        cat "$result_file"
        echo ""
    fi
done

echo "Test execution completed"