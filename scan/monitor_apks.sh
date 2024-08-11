#!/bin/bash

WATCH_DIR="../uploads"
ANALYSIS_DIR="../apk_analysis"
PARALLEL_SCRIPT="../code_static/parallel.py"
REPORTS_HTML_DIR="/var/www/html/reports_html"
LOG_DIR="../logs"
PROCESSED_FILES_LOG="$LOG_DIR/processed_files.log"
MAX_WORKERS=4

# Tạo các thư mục nếu chưa tồn tại
mkdir -p "$WATCH_DIR"
mkdir -p "$ANALYSIS_DIR"
mkdir -p "$REPORTS_HTML_DIR"
mkdir -p "$LOG_DIR"

# Khởi tạo file log processed_files nếu chưa tồn tại
touch "$PROCESSED_FILES_LOG"

process_apk() {
    NEW_FILE="$1"
    FILE_PATH="$WATCH_DIR/$NEW_FILE"
    echo "Processing new APK file: $NEW_FILE"

    # Wait until the file is fully written
    while [ ! -s "$FILE_PATH" ]; do
        echo "Waiting for the file to be fully written: $FILE_PATH"
        sleep 1
    done
    
    # Verify that the file is fully written by checking if its size stabilizes
    while true; do
        FILE_SIZE=$(stat -c%s "$FILE_PATH")
        sleep 1
        NEW_FILE_SIZE=$(stat -c%s "$FILE_PATH")
        if [ "$FILE_SIZE" -eq "$NEW_FILE_SIZE" ]; then
            break
        fi
        echo "File size is changing. Waiting for it to stabilize: $FILE_PATH"
    done
    
    # Calculate the hash of the APK file
    FILE_HASH=$(sha256sum "$FILE_PATH" | awk '{print $1}')
    echo "File hash: $FILE_HASH"
    
    # Define the directory path named with the file hash
    HTML_FILE_PATH="$REPORTS_HTML_DIR/${FILE_HASH}.html"

    # Check if the directory already exists
    if [ -f "$HTML_FILE_PATH" ]; then
        echo "HTML report $HTML_FILE_PATH already exists. Skipping processing."
        # Delete the APK file since the report already exists
        rm "$FILE_PATH"
    else
        NEW_DIR="$ANALYSIS_DIR/$FILE_HASH"
        mkdir -p "$NEW_DIR"
        # Move the new APK file into the new directory
        mv "$FILE_PATH" "$NEW_DIR/$NEW_FILE"
        echo "Moved $NEW_FILE to $NEW_DIR"
        
        # Run the processing script
        python3 "$PARALLEL_SCRIPT" "$NEW_DIR/$NEW_FILE" "$NEW_DIR" "$FILE_HASH" &> "$LOG_DIR/$FILE_HASH.log"
        
        # Check the exit status of the process
        if [ $? -eq 0 ]; then
            echo "Processing completed successfully for $NEW_FILE"
            echo "$FILE_HASH" >> "$PROCESSED_FILES_LOG"
        else
            echo "Processing failed for $NEW_FILE"
        fi
    fi
}

monitor_and_process() {
    inotifywait -m -e create --format "%f" "$WATCH_DIR" | while read NEW_FILE
    do
        if [[ "$NEW_FILE" == *.apk ]]
        then
            echo "New APK file detected: $NEW_FILE"
            process_apk "$NEW_FILE" &
        fi
    done
}

# Sử dụng một mảng để theo dõi PID của các tiến trình
declare -a PIDS

while true
do
    monitor_and_process &
    PIDS+=($!)
    
    # Giới hạn số lượng tiến trình chạy cùng lúc
    if [ ${#PIDS[@]} -ge $MAX_WORKERS ]; then
        # Đợi cho một trong các tiến trình hoàn thành
        wait -n
        
        # Loại bỏ PID của tiến trình đã hoàn thành khỏi mảng
        for i in "${!PIDS[@]}"; do
            if ! kill -0 "${PIDS[$i]}" 2>/dev/null; then
                unset 'PIDS[$i]'
            fi
        done
        PIDS=("${PIDS[@]}")
    fi
    
    sleep 1
done
