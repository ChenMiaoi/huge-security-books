#!/usr/bin/bash

# Script to build the autocorrect binary and lint source files

# Change directory to packages/autocorrect
echo "Changing directory to packages/autocorrect..."
pushd packages/autocorrect || {
    echo "Error: Failed to change directory to packages/autocorrect"
    exit 1
}

# Build the autocorrect package using cargo
echo "Building autocorrect package with cargo..."
cargo build || {
    echo "Error: Failed to build autocorrect package"
    exit 1
}

popd || {
  echo "Error: Failed to change directory to root"
    exit 1
}

# Find the path to the compiled autocorrect binary in the target directory
# Assuming it's a debug build, looking for target/debug/autocorrect
AUTOCORRECT="packages/autocorrect/target/debug/autocorrect"

# Verify if the binary exists
if [ ! -f "$AUTOCORRECT" ]; then
    # If not found in debug, try release
    AUTOCORRECT="packages/autocorrect/target/release/autocorrect"
    if [ ! -f "$AUTOCORRECT" ]; then
        echo "Error: Could not find autocorrect binary in target/debug or target/release"
        exit 1
    fi
fi

echo "Found autocorrect binary at: $AUTOCORRECT"

# Run the lint command on all files in the src directory
echo "Running autocorrect lint on src directory files..."
"$AUTOCORRECT" --lint src || {
    echo "Error: Failed to run autocorrect lint command"
    exit 1
}

echo "Linting completed successfully"
