#!/bin/bash
# ===================================================================================
# OpenShift Dynamic TLS & Certificate Audit (V11.5 - International/English)
# Created by Chris Tawfik (ctawfik@redhat.com) | toughIQ (toughiq@gmail.com)
# with support from Gemini AI
# Updates: 
#  - Full localization to Technical English (Comments & Outputs).
#  - [3] Service Mesh logic: Validates "Status Quo" without enforcing rules.
#  - [1] Dynamic cipher lookup (No hardcoded values).
# ===================================================================================

# Colors
BOLD="\033[1m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
RESET="\033[0m"

# Prerequisites check
command -v oc >/dev/null 2>&1 || { echo -e "${RED}Error: 'oc' client not found.${RESET}"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo -e "${RED}Error: 'jq' not found.${RESET}"; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo -e "${RED}Error: 'openssl' not found.${RESET}"; exit 1; }

echo -e "${BOLD}Starting OpenShift TLS Audit (Dynamic Mode)...${RESET}"
echo "Cluster: $(oc whoami --show-server)"
echo "Date: $(date)"
echo "-----------------------------------------------------------------------------------"

# Helpers
get_explain_tls_version() {
    local profile_key=$1
    local explain_out=$(oc explain apiserver.spec.tlsSecurityProfile."$profile_key" 2>/dev/null)
    echo "$explain_out" | grep -o "VersionTLS[0-9]\+" | head -n 1
}
get_explain_ciphers() {
    local profile_key=$1
    local explain_out=$(oc explain apiserver.spec.tlsSecurityProfile."$profile_key" 2>/dev/null)
    echo "$explain_out" | grep -oE "(TLS|ECDHE|AES|DHE)[A-Z0-9_-]+" | sort | uniq
}

# ===================================================================================
# [1] API SERVER
# ===================================================================================
echo -e "\n${BOLD}[1] Component: API Server${RESET}"
APISERVER_CR=$(oc get apiserver cluster -o json)
PROFILE_TYPE=$(echo "$APISERVER_CR" | jq -r '.spec.tlsSecurityProfile.type // "Intermediate (Default)"')
PROFILE_KEY=$(echo "$PROFILE_TYPE" | awk '{print tolower($1)}')

echo -e "  Configured Profile: ${GREEN}$PROFILE_TYPE${RESET}"

if [[ "$PROFILE_TYPE" == "Custom" ]]; then
    echo -e "  ${YELLOW}Source: Custom Configuration in CR${RESET}"
    echo -ne "  Minimum TLS Version: "
    echo "$APISERVER_CR" | jq -r '.spec.tlsSecurityProfile.custom.minTLSVersion'
    echo "  Ciphers:"
    echo "$APISERVER_CR" | jq -r '.spec.tlsSecurityProfile.custom.ciphers[]' | sed 's/^/    - /'
else
    KUBE_CONFIG=$(oc get cm config -n openshift-kube-apiserver -o jsonpath='{.data.config\.yaml}' 2>/dev/null)
    LIVE_TLS_VER=$(echo "$KUBE_CONFIG" | grep "minTLSVersion:" | awk '{print $2}' | tr -d '"')
    
    if [ -z "$LIVE_TLS_VER" ]; then
        LIVE_TLS_VER=$(get_explain_tls_version "$PROFILE_KEY")
        SOURCE_MSG="(Source: API Documentation / Default)"
    else
        SOURCE_MSG="(Source: Active ConfigMap)"
    fi
    echo -e "  Minimum TLS Version: ${GREEN}${LIVE_TLS_VER:-Unknown}${RESET} $SOURCE_MSG"

    echo "  Active Ciphers:"
    # Logic: Try fetching from ConfigMap first. If empty (default profiles usually omit this), use oc explain.
    LIVE_CIPHERS=$(echo "$KUBE_CONFIG" | grep -A 30 "cipherSuites:" | grep -m 1 -B 30 "minTLSVersion" | grep -v "cipherSuites:" | grep -v "minTLSVersion" | sed 's/^[ \t-]*//' | sed '/^$/d' | grep -v ":")
    
    if [ ! -z "$LIVE_CIPHERS" ]; then
        echo "$LIVE_CIPHERS" | while read line; do echo "    - $line"; done
    else
        # Fallback to dynamic documentation lookup based on profile key (works for intermediate, modern/tls1.3, etc.)
        get_explain_ciphers "$PROFILE_KEY" | sed 's/^/    - /'
    fi
fi

# ===================================================================================
# [2] INGRESS CONTROLLER
# ===================================================================================
echo -e "\n${BOLD}[2] Component: OpenShift Ingress Controller${RESET}"
oc get ingresscontrollers -n openshift-ingress-operator -o json | jq -c '.items[]' | while read -r ic; do
    IC_NAME=$(echo "$ic" | jq -r '.metadata.name')
    SPEC_PROFILE=$(echo "$ic" | jq -r '.spec.tlsSecurityProfile.type // "Intermediate (Default)"')
    STATUS_PROFILE=$(echo "$ic" | jq -r '.status.tlsProfile.type // "Unknown"')

    echo -e "  Controller Name: ${BOLD}$IC_NAME${RESET}"
    if [ "$SPEC_PROFILE" != "$STATUS_PROFILE" ] && [ "$STATUS_PROFILE" != "Unknown" ]; then
         echo -e "  Configured (Spec): ${YELLOW}$SPEC_PROFILE${RESET}"
         echo -e "  Active (Status):   ${RED}$STATUS_PROFILE (Mismatch! Update might be pending)${RESET}"
    else
         echo -e "  Profile (Spec & Status): ${GREEN}$SPEC_PROFILE${RESET}"
    fi

    ROUTER_POD=$(oc get pods -n openshift-ingress -l ingresscontroller.operator.openshift.io/deployment-ingresscontroller="$IC_NAME" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    if [ ! -z "$ROUTER_POD" ]; then
        HAPROXY_CONF=$(oc exec "$ROUTER_POD" -n openshift-ingress -- cat /var/lib/haproxy/conf/haproxy.config 2>/dev/null)
        if [ ! -z "$HAPROXY_CONF" ]; then
            EFFECTIVE_TLS_OPTS=$(echo "$HAPROXY_CONF" | grep "ssl-default-bind-options" | head -n 1 | sed 's/global//' | xargs)
            echo -e "  TLS Options (HAProxy): ${YELLOW}$EFFECTIVE_TLS_OPTS${RESET}"
            
            if [[ "$EFFECTIVE_TLS_OPTS" == *"ssl-min-ver TLSv1.3"* ]]; then
                 echo "    (Legacy Ciphers hidden - MinVersion is TLS 1.3)"
                 echo "    (TLS 1.3 Suites):"
                 echo "$HAPROXY_CONF" | grep "ssl-default-bind-ciphersuites" | head -n 1 | awk '{print $2}' | tr ':' '\n' | sed 's/^/      - /'
            else
                 echo "    (TLS 1.2 & Legacy Ciphers):"
                 echo "$HAPROXY_CONF" | grep "ssl-default-bind-ciphers " | head -n 1 | awk '{print $2}' | tr ':' '\n' | sed 's/^/      - /'
            fi
        fi
    fi
    echo "  -------------------------------------------------"
done

# ===================================================================================
# [3] SERVICE MESH (ISTIO) GATEWAYS
# ===================================================================================
echo -e "\n${BOLD}[3] Component: Service Mesh (Istio) Gateways${RESET}"

# 1. Locate the Service Mesh Control Plane (Namespace detection)
SERVICE_MESH_NS=$(oc get servicemeshcontrolplane -A -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null)

if [ ! -z "$SERVICE_MESH_NS" ]; then
    # --- OSSM Control Plane Found ---
    printf "  Status: %bService Mesh Control Plane found (Namespace: %s)%b\n" "$GREEN" "$SERVICE_MESH_NS" "$RESET"
    
    # 2. Check if active gateways exist
    NUM_GATEWAYS=$(oc get gateway -n "$SERVICE_MESH_NS" --no-headers 2>/dev/null | wc -l)
    
    if [ "$NUM_GATEWAYS" -eq 0 ]; then
        # Scenario: Service Mesh installed, but empty (no apps)
        echo -e "  Result: ${YELLOW}No active gateways defined.${RESET}"
        echo "          (Service Mesh is running, but no application ingress points are configured.)"
    else
        # Scenario: Gateways found -> Audit Status Quo
        echo -e "  Result: ${BOLD}$NUM_GATEWAYS Gateway(s) found.${RESET}"
        
        # Attempt to identify physical Route host for live testing
        INGRESS_ROUTE_HOST=$(oc get route -n "$SERVICE_MESH_NS" -l istio=ingressgateway -o jsonpath='{.items[0].spec.host}' 2>/dev/null)

        oc get gateway -n "$SERVICE_MESH_NS" -o json | jq -c '.items[]' | while read -r gw; do
            GW_NAME=$(echo "$gw" | jq -r '.metadata.name')
            GW_MODES=$(echo "$gw" | jq -r '.spec.servers[] | "\(.tls.mode // "NONE")"' | sort | uniq | tr '\n' ' ')
            GW_HOSTS=$(echo "$gw" | jq -r '.spec.servers[] | .hosts[]')

            echo -e "  - Gateway: ${BOLD}$GW_NAME${RESET}"
            printf "    TLS Configuration (Spec): %b%s%b\n" "$BLUE" "$GW_MODES" "$RESET"
            
            # Iterate through hosts for Status Quo Check
            for host in $GW_HOSTS; do
                if [[ "$host" == "*" ]] && [ ! -z "$INGRESS_ROUTE_HOST" ]; then
                    target_host="$INGRESS_ROUTE_HOST"
                    display_host="* (via $INGRESS_ROUTE_HOST)"
                else
                    target_host="$host"
                    display_host="$host"
                fi
                
                echo "    Host: $display_host"
                
                # If Route is resolvable, perform active TLS handshake check
                # 'timeout' ensures script does not hang on connection issues
                if [ ! -z "$INGRESS_ROUTE_HOST" ] && [[ "$GW_MODES" == *"SIMPLE"* || "$GW_MODES" == *"MUTUAL"* ]]; then
                     # Check TLS 1.2
                     if timeout 2 openssl s_client -connect "$INGRESS_ROUTE_HOST:443" -servername "$target_host" -tls1_2 < /dev/null >/dev/null 2>&1; then
                        echo -e "      -> Live Check: ${GREEN}TLS 1.2 accepted${RESET}"
                     fi
                     # Check TLS 1.0 (Info only, no failure)
                     if timeout 2 openssl s_client -connect "$INGRESS_ROUTE_HOST:443" -servername "$target_host" -tls1 < /dev/null >/dev/null 2>&1; then
                        echo -e "      -> Live Check: ${YELLOW}TLS 1.0 accepted (Legacy Info)${RESET}"
                     fi
                fi
            done
            echo ""
        done
    fi

elif [ "$(oc get gateway -A --no-headers 2>/dev/null | wc -l)" -gt 0 ]; then
    # Fallback: Gateways present, but no Control Plane CR found (e.g., manual/upstream Istio)
    echo -e "  ${YELLOW}Note: Istio Gateways found, but no Red Hat ServiceMeshControlPlane resource detected.${RESET}"
    echo "  Please check 'Gateway' objects manually."
else
    # Nothing found
    echo -e "  Result: Service Mesh not installed or inactive."
fi

# ===================================================================================
# [4] KUBELET
# ===================================================================================
echo -e "\n${BOLD}[4] Component: Kubelet (Node Pools)${RESET}"
KC_DUMP=$(oc get kubeletconfig -o json 2>/dev/null)

oc get mcp -o json | jq -c '.items[]' | while read mcp; do
    MCP_NAME=$(echo "$mcp" | jq -r '.metadata.name')
    echo -e "  Pool: ${BOLD}$MCP_NAME${RESET}"
    
    MATCHING_KC=$(echo "$KC_DUMP" | jq -r --arg pool "$MCP_NAME" '.items[] | select(.spec.machineConfigPoolSelector.matchLabels["pools.operator.machineconfiguration.openshift.io/" + $pool] != null) | {name: .metadata.name, profile: .spec.kubeletConfig.tlsSecurityProfile.type, custom: .spec.kubeletConfig.tlsSecurityProfile.custom}')
    
    if [ ! -z "$MATCHING_KC" ]; then
        KC_NAME=$(echo "$MATCHING_KC" | jq -r '.name')
        KC_PROFILE=$(echo "$MATCHING_KC" | jq -r '.profile')
        echo -e "    Status: ${YELLOW}Custom KubeletConfig Applied${RESET}"
        echo -e "    Config Object: $KC_NAME"
        echo -e "    Profile: ${GREEN}$KC_PROFILE${RESET}"
        if [ "$KC_PROFILE" == "Custom" ]; then
             echo "    Details: Custom Ciphers defined in object."
        fi
    else
        MC_OVERRIDES=$(oc get machineconfig -o json | jq -r '.items[] | select(.spec.config.ignition.config.tlsSecurityProfile != null) | .metadata.name')
        if [ ! -z "$MC_OVERRIDES" ]; then
             echo -e "    Status: ${RED}Direct MachineConfig Overrides Detected globally ($MC_OVERRIDES)${RESET}"
        else
             echo -e "    Status: ${GREEN}Intermediate (Default - Inherited)${RESET}"
        fi
    fi
    echo ""
done

# ===================================================================================
# [5] REFERENCE SECTION
# ===================================================================================
echo -e "\n-----------------------------------------------------------------------------------"
echo -e "${BOLD}[5] Reference: Standard Profile Definitions (Cluster Version Defaults)${RESET}"
echo "Definitions fetched dynamically via 'oc explain' for your current OCP version."

for type in "Intermediate" "Modern" "Old"; do
    key=$(echo "$type" | awk '{print tolower($0)}')
    echo -e "\n  ${BOLD}Profile: ${BLUE}$type${RESET}"
    
    ver=$(get_explain_tls_version "$key")
    ciphers=$(get_explain_ciphers "$key")
    
    if [ -z "$ver" ]; then ver="Unknown/Doc missing"; fi
    echo "    Minimum TLS Version: $ver"
    echo "    Defined Ciphers:"
    if [ -z "$ciphers" ]; then
        echo "      (No explicit ciphers listed in docs - usually means Standard Go Library defaults)"
    else
        echo "$ciphers" | sed 's/^/      - /'
    fi
done

# ===================================================================================
# [6] CERTIFICATES
# ===================================================================================
echo -e "\n-----------------------------------------------------------------------------------"
echo -e "${BOLD}[6] Certificate Expiration Audit${RESET}"
printf "%-12s %-30s %-40s %-30s\n" "EXPIRY-ISO" "NAMESPACE" "SECRET NAME" "STATUS"
echo "------------------------------------------------------------------------------------------------------------------"
TEMP_CERT_FILE=$(mktemp)
NAMESPACES="openshift-ingress openshift-config openshift-kube-apiserver openshift-apiserver openshift-etcd openshift-authentication openshift-ingress-operator openshift-monitoring"

for ns in $NAMESPACES; do
    oc get secrets -n "$ns" --field-selector type=kubernetes.io/tls -o json | jq -r --arg ns "$ns" '.items[] | "\(.metadata.name)"' | while read name; do
        cert_data=$(oc get secret -n "$ns" "$name" -o jsonpath='{.data.tls\.crt}' 2>/dev/null | base64 -d 2>/dev/null)
        if [ ! -z "$cert_data" ]; then
            enddate=$(echo "$cert_data" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
            if date -d "$enddate" +%Y-%m-%d >/dev/null 2>&1; then iso_date=$(date -d "$enddate" +%Y-%m-%d); else iso_date=$(date -j -f "%b %d %T %Y %Z" "$enddate" "+%Y-%m-%d" 2>/dev/null); fi
            if [ ! -z "$iso_date" ]; then
                current_ts=$(date +%s)
                if date -d "$iso_date" +%s >/dev/null 2>&1; then cert_ts=$(date -d "$iso_date" +%s); else cert_ts=$(date -j -f "%Y-%m-%d" "$iso_date" +%s 2>/dev/null); fi
                if [ ! -z "$cert_ts" ]; then
                    days_left=$(( ($cert_ts - $current_ts) / 86400 ))
                    status="${GREEN}OK ($days_left days)${RESET}"
                    if [ $days_left -lt 30 ]; then status="${YELLOW}EXPIRING ($days_left days)${RESET}"; fi
                    if [ $days_left -lt 0 ]; then status="${RED}EXPIRED${RESET}"; fi
                    echo "$iso_date|$ns|$name|$status" >> "$TEMP_CERT_FILE"
                fi
            fi
        fi
    done
done
sort "$TEMP_CERT_FILE" | while IFS='|' read iso ns name status; do printf "%-12s %-30s %-40s %-30s\n" "$iso" "$ns" "$name" "$status"; done
TOTAL_CERTS=$(wc -l < "$TEMP_CERT_FILE")
echo "------------------------------------------------------------------------------------------------------------------"
echo -e "Total Certificates Found: ${BOLD}$TOTAL_CERTS${RESET}"
rm "$TEMP_CERT_FILE"
echo -e "\n${BOLD}Audit Complete.${RESET}"
