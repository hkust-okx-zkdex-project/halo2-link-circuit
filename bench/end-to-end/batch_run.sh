#!/bin/bash

# Check if the correct number of arguments are provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <log_file_prefix>"
    exit 1
fi

# Log file prefix
LOG_PREFIX="$1"

# Parameter pairs
declare -a PARAM_PAIRS=(
    "11 1024"
    "12 2048"
    "13 4096"
    "14 8192"
    "15 16384"
)

# Number of iterations
ITERATIONS=5

# Build the Rust program in release mode
echo "Building the program with --release..."
cargo build --release

# Check if build was successful
if [ $? -ne 0 ]; then
    echo "Build failed. Exiting."
    exit 1
fi

# Run tests for each parameter pair
for PAIR in "${PARAM_PAIRS[@]}"; do
    K=$(echo "$PAIR" | awk '{print $1}')
    POLY_DEGREE=$(echo "$PAIR" | awk '{print $2}')

    # Combined log file for this parameter pair
    COMBINED_LOG_FILE="${LOG_PREFIX}_k${K}_deg${POLY_DEGREE}.log"
    echo "Logging all iterations for k=$K, poly_degree=$POLY_DEGREE to $COMBINED_LOG_FILE"
    echo "=== Testing k=$K, poly_degree=$POLY_DEGREE ===" > "$COMBINED_LOG_FILE"
    echo "Start time: $(date)" >> "$COMBINED_LOG_FILE"

    for i in $(seq 1 $ITERATIONS); do
        echo "=== Iteration $i ===" | tee -a "$COMBINED_LOG_FILE"
        echo "Iteration $i: Running test..." >> "$COMBINED_LOG_FILE"

        ./target/release/end-to-end "$K" "$POLY_DEGREE" >> "$COMBINED_LOG_FILE" 2>&1

        if [ $? -ne 0 ]; then
            echo "Iteration $i: Error occurred. Check logs for details." | tee -a "$COMBINED_LOG_FILE"
        else
            echo "Iteration $i: Completed successfully." | tee -a "$COMBINED_LOG_FILE"
        fi

        echo "----------------------------" >> "$COMBINED_LOG_FILE"
    done

    echo "End time: $(date)" >> "$COMBINED_LOG_FILE"
    echo "All iterations for k=$K, poly_degree=$POLY_DEGREE completed." | tee -a "$COMBINED_LOG_FILE"
done

echo "All tests completed."
