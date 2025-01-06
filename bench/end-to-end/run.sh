#!/bin/bash

# Check if arguments are provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <k> <poly_degree> <log_file>"
    exit 1
fi

# Assign arguments
K="$1"
POLY_DEGREE="$2"
LOG_FILE="$3"

# Build the Rust program in release mode
echo "Building the program with --release..."
cargo build --release

# Run the program with the specified parameters and log the output
echo "Running the program with k=$K and poly_degree=$POLY_DEGREE..."
echo "Logging output to $LOG_FILE..."

./target/release/end-to-end "$K" "$POLY_DEGREE" | tee "$LOG_FILE"
