#!/bin/bash
# ===================================================================================
# OpenShift Dynamic TLS & Certificate Audit (V13.4 - UX Spinner Edition)
# Authors: Chris Tawfik & toughIQ | Support: Gemini AI
# -----------------------------------------------------------------------------------
# Usage:
#   ./ocp-tls-audit.sh          -> Infrastructure Audit (Deep Dive)
#   ./ocp-tls-audit.sh -u       -> User Certificates Only (Fast, No Infra Check)
# ===================================================================================

# Check Arguments
SCAN_USER_ONLY=false
if [[ "$1" == "--user-certs" || "$1" == "-u" ]]; then
    SCAN_USER_ONLY=true
fi

# Colors
BOLD="\033[1m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
CYAN="\033[36m"
RESET="\033[0m"

# Prerequisites check
command -v oc >/dev/null 2>&1 || { echo -e "${RED}Error: 'oc' client not found.${RESET}"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo -e "${RED}Error: 'jq' not found.${RESET}"; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo -e "${RED}Error: 'openssl' not found.${RESET}"; exit 1; }

# UX Helpers
spinner_pid=0
start_spinner() {
    echo -ne "${CYAN}  Processing... ${RESET}"
    (while :; do for c in / - \\ \|; do echo -ne "\b$c"; sleep 0.1; done; done) &
    spinner_pid=$!
}

stop_spinner() {
    if [ $spinner_pid -gt 0 ]; then
        kill $spinner_pid >/dev/null 2>&1
        wait $spinner_pid 2>/dev/null
        echo -ne "\b${GREEN}Done.${RESET}\n"
    fi
}

# ===================================================================================
# STANDARD HEADER
# ===================================================================================
echo -e "${BOLD}Starting OpenShift TLS Audit (Dynamic Security & Config Audit)...${RESET}"
if [ "$SCAN_USER_ONLY" = true ]; then
    echo -e "Scan Scope: ${CYAN}User Certificates Only (App Workloads)${RESET}"
else
    echo -e "Scan Scope: ${GREEN}Infrastructure Audit (Deep Dive)${RESET}"
fi
echo "Cluster:    $(oc whoami --show-server)"
OCP_VERSION=$(oc version -o json 2>/dev/null | jq -r '.openshiftVersion // "Unknown"')
echo -e "Version:    ${BOLD}$OCP_VERSION${RESET}"
echo "Date:       $(date)"
echo "-----------------------------------------------------------------------------------"

# Helper Function for Cert Checking (Shared)
check_cert_expiry() {
    local ns=$1
    local name=$2
    
    cert_data=$(oc get secret -n "$ns" "$name" -o jsonpath='{.data.tls\.crt}' 2>/dev/null | base64 -d 2>/dev/null)
    if [ ! -z "$cert_data" ]; then
        enddate=$(echo "$cert_data" | openssl x509 -noout -enddate 2>/dev/null | head -n 1 | cut -d= -f2)
        if [ ! -z "$enddate" ]; then
            if date -d "$enddate" +%s >/dev/null 2>&1; then ts=$(date -d "$enddate" +%s); else ts=$(date -j -f "%b %d %T %Y %Z" "$enddate" +%s 2>/dev/null); fi
            now=$(date +%s)
            days=$(( ($ts - $now) / 86400 ))
            
            if [ $days -lt 30 ]; then STATUS="${RED}EXPIRING ($days d)${RESET}";
            elif [ $days -lt 90 ]; then STATUS="${YELLOW}OK ($days d)${RESET}";
            else STATUS="${GREEN}OK ($days d)${RESET}"; fi
            
            printf "%-12s %-50s %b\n" "$(date -d @$ts +%Y-%m-%d 2>/dev/null || echo $enddate)" "$ns/$name" "$STATUS"
        fi
    fi
}

# ===================================================================================
# MODE SWITCH
# ===================================================================================

if [ "$SCAN_USER_ONLY" = true ]; then
    # ===============================================================================
    # MODE A: USER CERTIFICATES ONLY
    # ===============================================================================
    echo -e "Scanning for User Workload Certificates..."
    echo -e "${YELLOW}(Excluding namespaces starting with: openshift-, kube-, redhat-, istio-system)${RESET}"
    echo "----------------------------------------------------------------------------------------------------"
    printf "%-12s %-50s %-30s\n" "EXPIRY" "NAMESPACE/NAME" "STATUS"
    echo "----------------------------------------------------------------------------------------------------"

    # 1. Fetch Candidates (With Spinner)
    # We print a temporary line that gets overwritten by stop_spinner logic or simply appended
    echo -ne "  ${CYAN}Querying API Server for TLS secrets... ${RESET}"
    
    # Start animation in background
    (while :; do for c in / - \\ \|; do echo -ne "\b$c"; sleep 0.1; done; done) &
    SPIN_PID=$!
    
    # The Heavy Lifting
    CANDIDATES=$(oc get secrets -A --field-selector type=kubernetes.io/tls -o json 2>/dev/null | \
                 jq -r '.items[] | "\(.metadata.namespace) \(.metadata.name)"' | \
                 grep -vE "^openshift-|^kube-|^redhat-|^istio-system|^default")
    
    # Stop animation
    kill $SPIN_PID >/dev/null 2>&1
    wait $SPIN_PID 2>/dev/null
    echo -ne "\b \n" # Clear the spinner char

    # 2. Process or Report Empty
    if [ -z "$CANDIDATES" ]; then
        echo -e "\r  ${YELLOW}No user-defined TLS secrets found in the cluster.${RESET}                      "
    else
        # Clear the "Querying..." line visually by carriage return if needed, or just list below
        echo "$CANDIDATES" | while read ns name; do
            [ -z "$ns" ] && continue
            check_cert_expiry "$ns" "$name"
        done
    fi
    
    echo "----------------------------------------------------------------------------------------------------"
    echo -e "User Scan Complete."
    exit 0
fi

# ===================================================================================
# MODE B: INFRASTRUCTURE AUDIT (The full technical check)
# ===================================================================================

echo -ne "Loading cluster security definitions (Source of Truth)... "
(while :; do for c in / - \\ \|; do echo -ne "\b$c"; sleep 0.1; done; done) &
SPIN_PID=$!

# Helper to fetch ciphers
get_profile_regex() {
    local p_key=$1
    oc explain apiserver.spec.tlsSecurityProfile."$p_key" 2>/dev/null | \
    grep -oE "(TLS|ECDHE|AES|DHE)[A-Z0-9_-]+" | sort | uniq | tr -d ' ' | tr '\n' '|' | sed 's/|$//'
}

# 1. Load Standard Profiles
REF_MODERN=$(get_profile_regex "modern")
REF_INTERM=$(get_profile_regex "intermediate")
REF_OLD=$(get_profile_regex "old")

# 2. Check for Active Custom Profile
APISERVER_JSON=$(oc get apiserver cluster -o json 2>/dev/null)
REF_CUSTOM=""
if [[ "$(echo "$APISERVER_JSON" | jq -r '.spec.tlsSecurityProfile.type // empty')" == "Custom" ]]; then
    # echo -e "  -> ${BLUE}Notice: Cluster is running with a 'Custom' API Server profile.${RESET}"
    REF_CUSTOM=$(echo "$APISERVER_JSON" | jq -r '.spec.tlsSecurityProfile.custom.ciphers[]' | sort | uniq | tr '\n' '|' | sed 's/|$//')
fi

kill $SPIN_PID >/dev/null 2>&1; wait $SPIN_PID 2>/dev/null; echo -ne "\b${GREEN}Done.${RESET}\n"

# Rating Function
rate_cipher() {
    local cipher=$1
    if [[ ! -z "$REF_MODERN" ]] && echo "$cipher" | grep -qE "$REF_MODERN"; then echo "${GREEN}[Modern]${RESET}"; return; fi
    if [[ ! -z "$REF_INTERM" ]] && echo "$cipher" | grep -qE "$REF_INTERM"; then echo "${YELLOW}[Intermediate]${RESET}"; return; fi
    if [[ ! -z "$REF_OLD" ]] && echo "$cipher" | grep -qE "$REF_OLD"; then echo "${RED}[Old/Legacy]${RESET}"; return; fi
    echo "${RED}[Unknown/Unsafe]${RESET}"
}

if [[ "$(echo "$APISERVER_JSON" | jq -r '.spec.tlsSecurityProfile.type // empty')" == "Custom" ]]; then
    echo -e "  -> ${BLUE}Notice: Cluster is running with a 'Custom' API Server profile.${RESET}"
fi

# [1] API SERVER
echo -e "\n${BOLD}[1] Component: API Server${RESET}"
PROFILE_TYPE=$(echo "$APISERVER_JSON" | jq -r '.spec.tlsSecurityProfile.type // "Intermediate (Default)"')
echo -e "  Configured Profile: ${CYAN}$PROFILE_TYPE${RESET}"

KUBE_CONFIG=$(oc get cm config -n openshift-kube-apiserver -o jsonpath='{.data.config\.yaml}' 2>/dev/null)
LIVE_TLS_VER=$(echo "$KUBE_CONFIG" | grep "minTLSVersion:" | awk '{print $2}' | tr -d '"')
if [ -z "$LIVE_TLS_VER" ]; then
    key=$(echo "$PROFILE_TYPE" | awk '{print tolower($1)}')
    LIVE_TLS_VER=$(oc explain apiserver.spec.tlsSecurityProfile."$key" 2>/dev/null | grep -o "VersionTLS[0-9]\+" | head -n 1)
fi
echo -e "  Minimum TLS Version: ${BOLD}$LIVE_TLS_VER${RESET}"

echo "  Active Ciphers:"
if [[ "$PROFILE_TYPE" == "Custom" ]]; then
    echo "$APISERVER_JSON" | jq -r '.spec.tlsSecurityProfile.custom.ciphers[]' | while read c; do
        RATING=$(rate_cipher "$c")
        echo -e "    - $c $RATING"
    done
else
    LIVE_CIPHERS=$(echo "$KUBE_CONFIG" | grep -A 30 "cipherSuites:" | grep -m 1 -B 30 "minTLSVersion" | grep -v "cipherSuites:" | grep -v "minTLSVersion" | sed 's/^[ \t-]*//' | sed '/^$/d' | grep -v ":")
    if [ ! -z "$LIVE_CIPHERS" ]; then
        echo "$LIVE_CIPHERS" | while read c; do
            RATING=$(rate_cipher "$c")
            echo -e "    - $c $RATING"
        done
    else
         # Fallback to defaults
         get_explain_ciphers() { oc explain apiserver.spec.tlsSecurityProfile."$1" 2>/dev/null | grep -oE "(TLS|ECDHE|AES|DHE)[A-Z0-9_-]+" | sort | uniq; }
         key=$(echo "$PROFILE_TYPE" | awk '{print tolower($1)}')
         get_explain_ciphers "$key" | while read c; do
            RATING=$(rate_cipher "$c")
            echo -e "    - $c $RATING"
         done
    fi
fi

# [2] INGRESS CONTROLLER
echo -e "\n${BOLD}[2] Component: Ingress Controller (Router)${RESET}"
oc get ingresscontrollers -n openshift-ingress-operator -o json | jq -c '.items[]' | while read -r ic; do
    IC_NAME=$(echo "$ic" | jq -r '.metadata.name')
    SPEC_PROFILE=$(echo "$ic" | jq -r '.spec.tlsSecurityProfile.type // "Intermediate (Default)"')
    echo -e "  Controller: ${BOLD}$IC_NAME${RESET} (Profile: $SPEC_PROFILE)"

    ROUTER_POD=$(oc get pods -n openshift-ingress -l ingresscontroller.operator.openshift.io/deployment-ingresscontroller="$IC_NAME" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    if [ ! -z "$ROUTER_POD" ]; then
        HAPROXY_CONF=$(oc exec "$ROUTER_POD" -n openshift-ingress -- cat /var/lib/haproxy/conf/haproxy.config 2>/dev/null)
        if [ ! -z "$HAPROXY_CONF" ]; then
            EFFECTIVE_TLS=$(echo "$HAPROXY_CONF" | grep "ssl-default-bind-options" | head -n 1 | sed 's/global//' | xargs)
            echo -e "    Runtime Config: ${YELLOW}$EFFECTIVE_TLS${RESET}"
            if [[ "$EFFECTIVE_TLS" == *"ssl-min-ver TLSv1.3"* ]]; then
                 RAW_CIPHERS=$(echo "$HAPROXY_CONF" | grep "ssl-default-bind-ciphersuites" | head -n 1 | awk '{print $2}' | tr ':' '\n')
            else
                 RAW_CIPHERS=$(echo "$HAPROXY_CONF" | grep "ssl-default-bind-ciphers " | head -n 1 | awk '{print $2}' | tr ':' '\n')
            fi
            echo "    Active Ciphers (Runtime):"
            echo "$RAW_CIPHERS" | while read c; do
                RATING=$(rate_cipher "$c")
                echo -e "      - $c $RATING"
            done
        fi
    fi
    echo "  -------------------------------------------------"
done

# [3] SERVICE MESH
echo -e "\n${BOLD}[3] Component: Service Mesh (Istio) - Hybrid Audit${RESET}"
SERVICE_MESH_NS=$(oc get servicemeshcontrolplane -A -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null)
if [ -z "$SERVICE_MESH_NS" ]; then
    echo -e "  Result: No Service Mesh Control Plane found."
else
    echo -e "  Status: Control Plane found in namespace '${CYAN}$SERVICE_MESH_NS${RESET}'"
    INGRESS_HOST=$(oc get route -n "$SERVICE_MESH_NS" -l istio=ingressgateway -o jsonpath='{.items[0].spec.host}' 2>/dev/null)
    if [ -z "$INGRESS_HOST" ]; then INGRESS_HOST=$(oc get svc -n "$SERVICE_MESH_NS" -l istio=ingressgateway -o jsonpath='{.items[0].status.loadBalancer.ingress[0].ip}' 2>/dev/null); fi

    GATEWAYS_FOUND=$(oc get gateway -n "$SERVICE_MESH_NS" --no-headers 2>/dev/null | wc -l)
    if [ "$GATEWAYS_FOUND" -eq 0 ]; then
        echo -e "  Result: ${YELLOW}No active gateways defined.${RESET}"
    else
        oc get gateway -n "$SERVICE_MESH_NS" -o json | jq -c '.items[]' | while read -r gw; do
            GW_NAME=$(echo "$gw" | jq -r '.metadata.name')
            GW_HOSTS=$(echo "$gw" | jq -r '.spec.servers[] | .hosts[]')
            GW_MODES=$(echo "$gw" | jq -r '.spec.servers[] | "\(.tls.mode // "NONE")"' | tr '\n' ' ')
            echo -e "\n  Gateway: ${BOLD}$GW_NAME${RESET} (Mode: $GW_MODES)"
            if [ ! -z "$INGRESS_HOST" ]; then
                for host in $GW_HOSTS; do
                    if [[ "$host" == "*" ]]; then target_host="$INGRESS_HOST"; display_host="* (Wildcard)"; else target_host="$host"; display_host="$host"; fi
                    if [[ "$GW_MODES" == *"SIMPLE"* || "$GW_MODES" == *"MUTUAL"* ]]; then
                        echo "    Active Check Target: $display_host"
                        BEST_CONN=$(timeout 3 openssl s_client -connect "$INGRESS_HOST:443" -servername "$target_host" < /dev/null 2>/dev/null)
                        if [ $? -eq 0 ]; then
                            BEST_PROTO=$(echo "$BEST_CONN" | grep "Protocol" | awk '{print $3}' | tr -d ',')
                            BEST_CIPHER=$(echo "$BEST_CONN" | grep -i "Cipher" | grep -v "New" | head -n 1 | sed 's/.*://' | xargs)
                            BEST_RATING=$(rate_cipher "$BEST_CIPHER")
                            echo -e "      -> Highest Supported: ${GREEN}$BEST_PROTO${RESET} using $BEST_CIPHER $BEST_RATING"
                            for proto in "tls1" "tls1_1" "tls1_2" "tls1_3"; do
                                case "$proto" in "tls1") l="TLSv1.0";; "tls1_1") l="TLSv1.1";; "tls1_2") l="TLSv1.2";; "tls1_3") l="TLSv1.3";; esac
                                CHECK=$(timeout 3 openssl s_client -connect "$INGRESS_HOST:443" -servername "$target_host" -"$proto" < /dev/null 2>/dev/null)
                                if [ $? -eq 0 ]; then
                                    WEAK_CIPHER=$(echo "$CHECK" | grep -i "Cipher" | grep -v "New" | head -n 1 | sed 's/.*://' | xargs)
                                    WEAK_RATING=$(rate_cipher "$WEAK_CIPHER")
                                    if [[ "$proto" == "tls1" || "$proto" == "tls1_1" ]]; then P_COLOR=$RED; else P_COLOR=$YELLOW; fi; if [[ "$proto" == "tls1_3" ]]; then P_COLOR=$GREEN; fi
                                    echo -e "      -> Weakest Allowed:   ${P_COLOR}$l${RESET}   using $WEAK_CIPHER $WEAK_RATING"
                                    break
                                fi
                            done
                        else
                             echo -e "      -> ${RED}Connection Failed${RESET} (Network issue or Invalid Cert)"
                        fi
                    fi
                done
            else
                echo -e "    ${YELLOW}No external IP/Route found. Showing Configuration only:${RESET}"
                echo "    Hosts: $GW_HOSTS"
            fi
        done
    fi
fi

# [4] KUBELET
echo -e "\n${BOLD}[4] Component: Kubelet (Node Pools)${RESET}"
KC_DUMP=$(oc get kubeletconfig -o json 2>/dev/null)
oc get mcp -o json | jq -c '.items[]' | while read mcp; do
    MCP_NAME=$(echo "$mcp" | jq -r '.metadata.name')
    MATCHING_KC=$(echo "$KC_DUMP" | jq -r --arg pool "$MCP_NAME" '.items[] | select(.spec.machineConfigPoolSelector.matchLabels["pools.operator.machineconfiguration.openshift.io/" + $pool] != null) | {profile: .spec.kubeletConfig.tlsSecurityProfile.type}')
    if [ ! -z "$MATCHING_KC" ]; then
        KC_PROFILE=$(echo "$MATCHING_KC" | jq -r '.profile')
        if [[ "$KC_PROFILE" == "Old" ]]; then K_COLOR=$RED; elif [[ "$KC_PROFILE" == "Intermediate" ]]; then K_COLOR=$YELLOW; elif [[ "$KC_PROFILE" == "Modern" ]]; then K_COLOR=$GREEN; else K_COLOR=$BLUE; fi
        echo -e "  Pool: ${BOLD}$MCP_NAME${RESET} -> Profile: ${K_COLOR}$KC_PROFILE${RESET} (KubeletConfig Override)"
    else
        echo -e "  Pool: ${BOLD}$MCP_NAME${RESET} -> Profile: ${YELLOW}Intermediate${RESET} (Default/Inherited)"
    fi
done

# [5] REFERENCE
echo -e "\n-----------------------------------------------------------------------------------"
echo -e "${BOLD}[5] Reference: Standard Profile Definitions${RESET}"
print_regex_list() { echo "$1" | tr '|' '\n' | sed 's/^/      - /'; }
if [ ! -z "$REF_CUSTOM" ]; then
    echo -e "\n  ${BOLD}Profile: ${BLUE}Custom (Cluster Active)${RESET}"; print_regex_list "$REF_CUSTOM"
fi
echo -e "\n  ${BOLD}Profile: ${GREEN}Modern${RESET}"; echo "    Defined Ciphers:"; print_regex_list "$REF_MODERN"
echo -e "\n  ${BOLD}Profile: ${YELLOW}Intermediate${RESET}"; echo "    Defined Ciphers:"; print_regex_list "$REF_INTERM"
echo -e "\n  ${BOLD}Profile: ${RED}Old${RESET}"; echo "    Defined Ciphers:"; print_regex_list "$REF_OLD"

# [6] INFRA CERTS
echo -e "\n-----------------------------------------------------------------------------------"
echo -e "${BOLD}[6] Certificate Expiration Audit (Infrastructure Only)${RESET}"
echo -e "Tip: Use ${CYAN}-u${RESET} to scan user workload certificates only."
printf "%-12s %-50s %-30s\n" "EXPIRY" "NAMESPACE/NAME" "STATUS"
echo "----------------------------------------------------------------------------------------------------"
NAMESPACES="openshift-ingress openshift-kube-apiserver openshift-etcd openshift-monitoring openshift-config openshift-authentication"
for ns in $NAMESPACES; do
    oc get secrets -n "$ns" --field-selector type=kubernetes.io/tls -o json 2>/dev/null | jq -r --arg ns "$ns" '.items[] | "\(.metadata.name)"' | while read name; do
        check_cert_expiry "$ns" "$name"
    done
done
echo "----------------------------------------------------------------------------------------------------"
# Fast count for infra
TOTAL=0
for ns in $NAMESPACES; do c=$(oc get secrets -n "$ns" --field-selector type=kubernetes.io/tls --no-headers 2>/dev/null | wc -l); TOTAL=$((TOTAL + c)); done
echo -e "Total Infra Secrets Scanned: ${BOLD}$TOTAL${RESET}"
echo -e "Audit Complete."
