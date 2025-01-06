#!/bin/bash
# By Ricardo Fuentes <ricardo@cloudera.com>
#
# Usage Manual:
# This script scans all listening sockets on a RHEL 8 system, checks for supported SSL and TLS versions and their ciphers, and outputs detailed information about each process, including JARs if applicable.
#
# Output Format:
# - CSV and screen output contain the following columns:
#   IP, Port, PID, Full Process, SSL/TLS Version, Cipher, Status, JARs
#
# Example Usage:
# - Run the script with sudo:
#   sudo ./rhel8_sockets_scan.sh
# - Results are saved in a file named <hostname>-<date>.csv.
#
# Required Binaries:
# - The following binaries must be installed on the system:
#   1. net-tools: Provides the `netstat` command.
#      Install with: sudo yum install -y net-tools
#   2. openssl: Provides the `openssl` command for SSL/TLS and cipher checks.
#      Install with: sudo yum install -y openssl
#   3. iproute: Provides the `ip` command to list network interfaces.
#      Install with: sudo yum install -y iproute
#   4. coreutils: Provides the `readlink` command to resolve full binary paths.
#      Install with: sudo yum install -y coreutils
#
# Example Output:
# On the screen and in the CSV file:
#   IP,Port,PID,Full Process,SSL/TLS Version,Cipher,Status,JARs
#   192.168.1.10,443,1234,"/usr/sbin/nginx -g 'daemon off;'",tls1_2,AES128-SHA,Supported,N/A
#   192.168.1.10,443,1234,"/usr/sbin/nginx -g 'daemon off;'",tls1_2,AES256-SHA,Supported,N/A
#   192.168.1.10,443,1234,"/usr/sbin/nginx -g 'daemon off;'",tls1_2,DES-CBC3-SHA,Not Supported,N/A
#   192.168.1.10,443,1234,"/usr/sbin/nginx -g 'daemon off;'",tls1_3,AES128-GCM-SHA256,Supported,N/A
#   192.168.1.10,443,1234,"/usr/sbin/nginx -g 'daemon off;'",tls1_3,AES256-GCM-SHA384,Supported,N/A
#   192.168.1.10,8080,5678,"java -jar /opt/myapp/app.jar",tls1_2,AES128-SHA,Supported,"/opt/myapp/app.jar,/opt/myapp/lib/util.jar"
#   192.168.1.10,8080,5678,"java -jar /opt/myapp/app.jar",tls1_2,AES256-SHA,Supported,"/opt/myapp/app.jar,/opt/myapp/lib/util.jar"
#   192.168.1.10,8080,5678,"java -jar /opt/myapp/app.jar",ssl3,DES-CBC3-SHA,Not Supported,"/opt/myapp/app.jar,/opt/myapp/lib/util.jar"
#
# TODO: FIX OUTPUT <06/01/2025>


# Function to check SSL and TLS versions and ciphers
check_ssl_tls_and_ciphers() {
    local TARGET=$1
    local PORT=$2
    local VERSIONS=("ssl2" "ssl3" "tls1" "tls1_1" "tls1_2" "tls1_3")

    for VERSION in "${VERSIONS[@]}"; do
        if echo | openssl s_client -connect $TARGET:$PORT -$VERSION 2>/dev/null | grep -q "SSL handshake"; then
            VERSION_STATUS="Supported"
            for CIPHER in $(openssl ciphers | tr ':' ' '); do
                if echo | openssl s_client -connect $TARGET:$PORT -cipher $CIPHER -$VERSION 2>/dev/null | grep -q "Cipher is"; then
                    CIPHER_STATUS="Supported"
                else
                    CIPHER_STATUS="Not Supported"
                fi
                echo "$TARGET,$PORT,$PID,\"$FULL_PROCESS\",$VERSION,$CIPHER,$CIPHER_STATUS,\"$JARS\"" | tee -a $OUTPUT_FILE
            done
        else
            VERSION_STATUS="Not Supported"
            echo "$TARGET,$PORT,$PID,\"$FULL_PROCESS\",$VERSION,N/A,$VERSION_STATUS,\"$JARS\"" | tee -a $OUTPUT_FILE
        fi
    done
}

# Function to gather JARs used by a process
get_jars() {
    local PID=$1
    local JARS_OUTPUT=""

    if [ -d "/proc/$PID/fd" ]; then
        JARS_OUTPUT=$(ls -l /proc/$PID/fd 2>/dev/null | grep '\.jar$' | awk '{print $NF}' | tr '\n' ',' | sed 's/,$//')
    fi

    echo "$JARS_OUTPUT"
}

# Main script
HOSTNAME=$(hostname)
DATE=$(date +"%Y-%m-%d_%H-%M-%S")
OUTPUT_FILE="${HOSTNAME}-${DATE}.csv"
echo "IP,Port,PID,Full Process,SSL/TLS Version,Cipher,Status,JARs" > $OUTPUT_FILE

# Get the list of network interfaces
INTERFACES=$(ip -o -4 addr show | awk '{print $2, $4}' | sed 's/\/.*/ /')

if [ -z "$INTERFACES" ]; then
    echo "No network interfaces found."
    exit 1
fi

echo "Gathering listening sockets for all network interfaces..."

# Loop through each interface and gather sockets
for INTERFACE in $INTERFACES; do
    IP=$(echo $INTERFACE | awk '{print $2}')

    echo "\nScanning interface $INTERFACE ($IP)..."
    LISTENING_SOCKETS=$(netstat -ntpl | grep LISTEN | grep "$IP" | awk '{print $4 " " $7}' | sed 's/::://;s/0.0.0.0://')

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
        FULL_PROCESS=$(ps -p $PID -o args= 2>/dev/null | tr '\n' ' ' | sed 's/ $//')
        JARS=$(get_jars $PID)

        echo "\nScanning port $PORT on $IP (PID: $PID, Process: $FULL_PROCESS, JARs: $JARS)"

        # Check SSL and TLS versions and ciphers
        check_ssl_tls_and_ciphers $IP $PORT
    done <<< "$LISTENING_SOCKETS"

done

echo "\nScan complete. Results saved to $OUTPUT_FILE."
