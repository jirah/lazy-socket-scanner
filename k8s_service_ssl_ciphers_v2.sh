#!/bin/bash
# Author: Patrick Hart <phart@cloudera.com>
# Date: January 13, 2025
# Purpose: Connects to a pod with a debug image and tests supported TLS ciphers
# Requires: - kubectl cli w/ valid config
#           - yq
#           - A debug image with openssl (KUBE_DEBUG_IMG)
# Limitations: - does not obtain process information (cmdline)
#              - does not test for ssl2 ssl3 (openssl compiled without them)
#              - creates many terminated ephemeral debug containers and makes a mess of `kubectl describe pod`
#              - only tests pods which have k8s service entries
#              - only tests ClusterIP and LoadBalancer service types
#              - hardcoded debug image
#              - no error handling or other *good* programming practices (cmdline args, functions ;)
# Tested on: DWX
# Example output csv:
#   NAMESPACE,POD,PORT,TLS_VERSION,TLS_CIPHER,SUPPORTED
#   calico-system,calico-typha-dc95555f7-mpj8q,5473,tls1_2,ECDHE-ECDSA-AES256-GCM-SHA384,No
#   calico-system,calico-typha-dc95555f7-mpj8q,5473,tls1_2,ECDHE-RSA-AES256-GCM-SHA384,Yes
#   calico-system,calico-typha-dc95555f7-mpj8q,5473,tls1_2,ECDHE-ECDSA-CHACHA20-POLY1305,No
#   calico-system,calico-typha-dc95555f7-mpj8q,5473,tls1_2,ECDHE-RSA-CHACHA20-POLY1305,Yes
#   calico-system,calico-typha-dc95555f7-mpj8q,5473,tls1_2,ECDHE-ECDSA-AES256-CCM,No
#   calico-system,calico-typha-dc95555f7-mpj8q,5473,tls1_2,ECDHE-ECDSA-AES128-GCM-SHA256,No
#   calico-system,calico-typha-dc95555f7-mpj8q,5473,tls1_2,ECDHE-RSA-AES128-GCM-SHA256,Yes
#   calico-system,calico-typha-dc95555f7-mpj8q,5473,tls1_2,ECDHE-ECDSA-AES128-CCM,No


HOSTNAME=$(hostname)
DATE=$(date +"%Y-%m-%d_%H-%M-%S")
OUTPUT_FILE="${HOSTNAME}-${DATE}.csv"
VERSIONS=("tls1" "tls1_1" "tls1_2" "tls1_3")

KUBE_DEBUG_IMG="docker-private.infra.cloudera.com/cloudera_sre/sre-utils:v1.31.3"

echo "NAMESPACE,POD,PORT,TLS_VERSION,TLS_CIPHER,SUPPORTED" | tee -a $OUTPUT_FILE

kubectl get svc -A | tail -n +2 | grep -e ClusterIP -e LoadBalancer | awk '{print $1" "$2" "$4" "$6}' | while read -r NAMESPACE SVC IPS PORTS ; do
  IPS=$(echo $IPS | tr -d "None")
  PORTS=$(echo $PORTS | sed 's/,/ /g' | tr -d "<none>" | sed 's/.*://g')
  SELECTOR=$(kubectl get svc -n $NAMESPACE $SVC -o yaml | yq '.spec.selector' | tr \\n , | sed 's/: /=/g;s/,$//')
  POD=$(kubectl get po -n $NAMESPACE --selector=$SELECTOR | tail -n +2 | awk '{print $1}' | head -n 1)
  POD_NAME=$(kubectl get po -n $NAMESPACE $POD -o yaml | yq .spec.containers[].name)

  if [[ $SELECTOR == 'null' ]]; then
    SELECTOR=""
  fi

  echo "========================"
  echo "SVC: $SVC"
  echo "IPS: $IPS"
  echo "PORTS: $PORTS"
  echo "NAMESPACE: $NAMESPACE"
  echo "SELECTOR: $SELECTOR"
  echo "POD: $POD"
  echo "POD_NAME: $POD_NAME"
  echo "========================"

  if [[ ! -z "$IPS" && ! -z "$PORTS" && ! -z "$POD" ]]; then

    OPENSSL_SCRIPT=`cat <<EOF
VERSIONS=("tls1" "tls1_1" "tls1_2" "tls1_3")
VERSIONS_UDP=("dtls1" "dtls1_2")
CIPHERS="\\$(openssl ciphers | tr ':' ' ')"

IPS="\${IPS}"
PORTS="\${PORTS}"
POD_NAME="\${POD_NAME}"
NAMESPACE="\${NAMESPACE}"
for IP in \\$IPS ; do
  for PORT in \\$PORTS ; do
    echo \\$PORT | tr / " " | while read -r PORT PROTOCOL ; do
      if [[ \\$PROTOCOL == "TCP" ]] ; then
        for VERSION in "\\${VERSIONS[@]}" ; do
          for CIPHER in \\$CIPHERS; do
            if [[ \\$VERSION == "tls1_3" ]]; then
              OUTPUT=\\$(echo | openssl s_client -connect \\$IP:\\$PORT -\\$VERSION -ciphersuites \\$CIPHER 2>/dev/null | grep "^New" | awk -F"New" '{print \\$2}' | tr -d , | awk '{print \\$1" "\\$4}')
              echo \\$OUTPUT | while read -r TLS_VERSION TLS_CIPHER; do
                if [[ \\$TLS_VERSION == "(NONE)" ]] ; then
                  TLS_VERSION=""
                fi
                if [[ \\$TLS_CIPHER == "(NONE)" ]] ; then
                  TLS_CIPHER=""
                fi
                if [[ ! -z \\$TLS_VERSION && ! -z \\$TLS_CIPHER ]]; then
                  SUPPORTED="yes"
                else
                  SUPPORTED="no"
                fi
                echo "\\$NAMESPACE,\\$POD_NAME,\\$PORT,\\$VERSION,\\$CIPHER,\\$SUPPORTED"
              done
            else
              OUTPUT=\\$(echo | openssl s_client -connect \\$IP:\\$PORT -\\$VERSION -cipher \\$CIPHER 2>/dev/null | grep "^New" | awk -F"New" '{print \\$2}' | tr -d , | awk '{print \\$1" "\\$4}')
              echo \\$OUTPUT | while read -r TLS_VERSION TLS_CIPHER; do
                if [[ \\$TLS_VERSION == "(NONE)" ]] ; then
                  TLS_VERSION=""
                fi
                if [[ \\$TLS_CIPHER == "(NONE)" ]] ; then
                  TLS_CIPHER=""
                fi
                if [[ ! -z \\$TLS_VERSION && ! -z \\$TLS_CIPHER ]]; then
                  SUPPORTED="yes"
                else
                  SUPPORTED="no"
                fi
                echo "\\$NAMESPACE,\\$POD_NAME,\\$PORT,\\$VERSION,\\$CIPHER,\\$SUPPORTED"
              done
            fi
          done
        done
      elif [[ \\$PROTOCOL == "UDP" ]] ; then
        for VERSION in "\\${VERSIONS_UDP[@]}" ; do
          for CIPHER in \\$CIPHERS; do
            OUTPUT=\\$(echo | openssl s_client -connect \\$IP:\\$PORT -\\$VERSION -cipher \\$CIPHER 2>/dev/null | grep "^New" | awk -F"New" '{print \\$2}' | tr -d , | awk '{print \\$1" "\\$4}')
            echo \\$OUTPUT | while read -r TLS_VERSION TLS_CIPHER; do
                if [[ \\$TLS_VERSION == "(NONE)" ]] ; then
                  TLS_VERSION=""
                fi
                if [[ \\$TLS_CIPHER == "(NONE)" ]] ; then
                  TLS_CIPHER=""
                fi
                if [[ ! -z \\$TLS_VERSION && ! -z \\$TLS_CIPHER ]]; then
                  SUPPORTED="yes"
                else
                  SUPPORTED="no"
                fi
              echo "\\$NAMESPACE,\\$POD_NAME,\\$PORT,\\$VERSION,\\$CIPHER,\\$SUPPORTED"
              done
          done
        done
      fi
    done
  done
done
EOF
`
    #echo "${OPENSSL_SCRIPT}"

    OUTPUT=$(kubectl debug -qit -n $NAMESPACE $POD --image=$KUBE_DEBUG_IMG -- /bin/bash -c "$OPENSSL_SCRIPT" 2>/dev/null)
    echo "$OUTPUT" | tee -a $OUTPUT_FILE

  fi
done
