#!/bin/bash
# Authors: Ricardo Fuentes <ricardo@cloudera.com>, Vivek Aggarwal <vivekagg@cloudera.com>
# Date: January 13, 2025
# Purpose: Tests supported TLS versions and ciphers across sockets on a RHEL system with ss.
# Usage Manual:
# This script scans the listening sockets on all network interfaces, identifies the TLS versions and ciphers supported by each socket, and outputs the results to the screen and a CSV file.
#
# Output Format:
# - CSV output contain the following columns:
#   Protocol,Local IP,Local Port,PID,Binary,Full Path,Cipher Info
#
# Example Usage:
# - Run the script with sudo:
#   sudo ./listener_process_port.sh
# - Results are saved in a file named <hostname>-<date>.csv.
#
# Required Binaries:
# - The following binaries must be installed on a RHEL system:
#   1. net-tools: Provides the `ss` command.
#      Install with: sudo yum install -y net-tools
#   2. openssl: Provides the `openssl` command for TLS and cipher checks.
#      Install with: sudo yum install -y openssl
#   3. iproute: Provides the `ip` command to list network interfaces.
#      Install with: sudo yum install -y iproute
#   4. coreutils: Provides the `readlink` command to resolve full binary paths.
#      Install with: sudo yum install -y coreutils
#
# Example Output:
# On the screen and in the CSV file:
#   IP,Port,PID,Binary,TLS Version,Cipher,Status
#   192.168.1.10,443,1234,/usr/sbin/nginx,tls1_2,AES128-SHA
#   192.168.1.10,443,1234,/usr/sbin/nginx,tls1_2,ECDHE-RSA-AES256-GCM-SHA384
#   192.168.1.10,443,1234,/usr/sbin/nginx,tls1_3,AES256-GCM-SHA384
#   192.168.1.10,80,5678,/usr/sbin/httpd,N/A,N/A

# Generate the filename using the current hostname and date/time
filename=$(hostname)-$(date +"%Y-%m-%d-%H-%M-%S").csv

# Print the headers to the file
echo "Protocol,Local IP,Local Port,PID,Binary,Full Path,Cipher Info" > "$filename"

# Get the data using ss and process it with awk
ss -tunapl | while read -r line; do
    # Skip the first line which is header information
    if [[ $line =~ ^State ]]; then
        continue
    fi

    protocol=$(echo "$line" | awk '{print $1}')
    local_ip=$(echo "$line" | awk '{split($5, addr, ":"); print addr[1]}')
    local_port=$(echo "$line" | awk '{split($5, addr, ":"); print addr[2]}')
    process_info=$(echo "$line" | awk '{print $7}')

    # Extracting the PID and Binary from the process_info
    if [[ $process_info =~ \"([^\"]+)\" ]]; then
        binary="${BASH_REMATCH[1]}"
    else
        binary="Unknown"
    fi
    if [[ $process_info =~ pid=([0-9]+) ]]; then
        pid="${BASH_REMATCH[1]}"
    else
        pid="Unknown"
    fi

    # Construct a command to get the full path of the binary only if PID is valid
    if [[ $pid != "Unknown" ]]; then
        binary_full_path=$(readlink -f "/proc/$pid/exe")
    else
        binary_full_path="Unknown"
    fi

    # Call openssl to get TLS or SSL version and Cipher
    # This will capture the Protocol and Cipher from the openssl s_client output
    protocol_and_cipher=$(timeout 5 openssl s_client -connect "$local_ip:$local_port" < /dev/null 2>/dev/null | \
    awk '/Protocol[[:space:]]*:/ {match($0, /Protocol[[:space:]]*:[[:space:]]*(.*)/, arr); protocol=arr[1]} \
         /Cipher[[:space:]]*:/ {match($0, /Cipher[[:space:]]*:[[:space:]]*(.*)/, arr); cipher=arr[1]} \
         END {if (!protocol) protocol="Unknown"; if (!cipher) cipher="Unknown"; print protocol ", " cipher}')

    # Output in the format: Protocol, Local IP, Local Port, PID, Binary, Full Path, Cipher Info
    echo "$protocol,$local_ip,$local_port,$pid,$binary,$binary_full_path,$protocol_and_cipher" >> "$filename"
done

