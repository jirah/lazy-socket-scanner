#!/bin/bash

# Generate the filename using the current hostname and date/time
filename=$(hostname)-$(date +"%Y-%m-%d-%H-%M-%S").csv

# Print the headers to the file
echo "Protocol,Local IP,Local Port,PID,Binary,Full Path" > "$filename"

# Get the data using ss and process it with awk
ss -tunapl | awk 'NR > 1 {  # Skip the first line which is header information
    protocol=$1;
    split($5, addr, ":");
    local_ip=addr[1];
    local_port=addr[2];
    peer=$6;
    process_info=$7;

    # Extracting the PID and Binary from the process_info
    if (match(process_info, /"([^"]+)"/, arr)) {
        binary = arr[1];
    }
    if (match(process_info, /pid=([0-9]+)/, pid_arr)) {
        pid = pid_arr[1];
    }

    # Construct a command to get the full path of the binary from /proc/[pid]/exe
    cmd = "readlink -f /proc/" pid "/exe";
    cmd | getline binary_full_path;
    close(cmd);

    # Output in the format: Protocol, Local IP, Local Port, PID, Binary, Full Path
    # Explicitly separate each field with commas
    print protocol "," local_ip "," local_port "," pid "," binary "," binary_full_path
}' >> "$filename"

echo "Data has been saved to $filename"

