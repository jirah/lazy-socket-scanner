# lazy-socket-scanner
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
#   sudo ./rhel8_ssl_tls_scan.sh
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
