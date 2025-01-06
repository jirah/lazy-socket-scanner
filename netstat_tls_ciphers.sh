#!/bin/bash
# By Ricardo Fuentes <ricardo@cloudera.com>
#
# Usage Manual:
# This script scans the listening sockets on all network interfaces, identifies the TLS versions and ciphers supported by each socket, and outputs the results to the screen and a CSV file.
#
# Output Format:
# - CSV and screen output contain the following columns:
#   IP, Port, PID, Binary, TLS Version, Cipher, Status
#
# Example Usage:
# - Run the script with sudo:
#   sudo ./netstat_tls_ciphers.sh
# - Results are saved in a file named <hostname>-<date>.csv.
#
# Required Binaries:
# - The following binaries must be installed on a RHEL system:
#   1. net-tools: Provides the `netstat` command.
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
#   192.168.1.10,443,1234,/usr/sbin/nginx,tls1_2,AES128-SHA,Supported
#   192.168.1.10,443,1234,/usr/sbin/nginx,tls1_2,ECDHE-RSA-AES256-GCM-SHA384,Supported
#   192.168.1.10,443,1234,/usr/sbin/nginx,tls1_3,AES256-GCM-SHA384,Supported
#   192.168.1.10,80,5678,/usr/sbin/httpd,N/A,N/A,Not Supported

# Function to check supported TLS versions and ciphers
check_tls_and_ciphers() {
    local TARGET=$1
    local PORT=$2
    local TLS_VERSIONS=("tls1" "tls1_1" "tls1_2" "tls1_3")

    for TLS in "${TLS_VERSIONS[@]}"; do
        if echo | openssl s_client -connect $TARGET:$PORT -$TLS 2>/dev/null | grep -q "SSL handshake"; then
            TLS_STATUS="Supported"
            for CIPHER in $(openssl ciphers | tr ':' ' '); do
                if echo | openssl s_client -connect $TARGET:$PORT -cipher $CIPHER 2>/dev/null | grep -q "Cipher is"; then
                    CIPHER_STATUS="Supported"
                else
                    CIPHER_STATUS="Not Supported"
                fi
                echo "$TARGET,$PORT,$PID,$BINARY,$TLS,$CIPHER,$CIPHER_STATUS" | tee -a $OUTPUT_FILE
            done
        else
            TLS_STATUS="Not Supported"
            echo "$TARGET,$PORT,$PID,$BINARY,$TLS,N/A,$TLS_STATUS" | tee -a $OUTPUT_FILE
        fi
    done
}

# Main script
HOSTNAME=$(hostname)
DATE=$(date +"%Y-%m-%d_%H-%M-%S")
OUTPUT_FILE="${HOSTNAME}-${DATE}.csv"
echo "IP,Port,PID,Binary,TLS Version,Cipher,Status" > $OUTPUT_FILE

# Get the list of network interfaces
INTERFACES=$(ip -o -4 addr show | awk '{print $2 "," $4}' | sed 's/\/.*/ /')

if [ -z "$INTERFACES" ]; then
    echo "No network interfaces found."
    exit 1
fi

echo "Gathering listening sockets for all network interfaces..."

# Loop through each interface and gather sockets
for CUR_INTERFACE in $INTERFACES; do
    IP=$(echo $CUR_INTERFACE | cut -d',' -f2)
    INTERFACE=$(echo $CUR_INTERFACE | cut -d',' -f1)

    echo "\nScanning interface $INTERFACE ($IP)..."
    LISTENING_SOCKETS=$(sudo netstat -ntpl | grep LISTEN | grep "$IP" | awk '{print $4 " " $7}' | sed 's/::://;s/0.0.0.0://')

    if [ -z "$LISTENING_SOCKETS" ]; then
        echo "No listening sockets found for $INTERFACE."
        continue
    fi

    # Loop through each socket and scan
    while IFS= read -r SOCKET_INFO; do
        SOCKET=$(echo $SOCKET_INFO | awk '{print $1}')
        PID_BINARY=$(echo $SOCKET_INFO | awk '{print $2}')
        PORT=$(echo $SOCKET | awk -F: '{print $NF}')
        PID=$(echo $PID_BINARY | awk -F'/' '{print $1}')
        BINARY=$(readlink -f /proc/$PID/exe 2>/dev/null)

        echo "\nScanning port $PORT on $IP (PID: $PID, Binary: $BINARY)"

        # Check TLS versions and ciphers
        check_tls_and_ciphers $IP $PORT
    done <<< "$LISTENING_SOCKETS"

done

echo "\nScan complete. Results saved to $OUTPUT_FILE."
