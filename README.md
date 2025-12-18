# OpenShift Dynamic TLS & Risk Audit

![Platform](https://img.shields.io/badge/Platform-OpenShift%204.x-red)
![Language](https://img.shields.io/badge/Language-Bash-blue)
![License](https://img.shields.io/badge/License-MIT-green)

**`ocp-tls-audit.sh`** is a robust auditing tool designed to reveal the **actual** TLS security posture and runtime configuration of Red Hat OpenShift Container Platform (OCP) clusters.

Unlike standard compliance tools that often only check the *desired state* (CRDs), this tool performs a **Risk Analysis** by verifying the **active runtime configuration** (Live ConfigMaps, HAProxy Runtime, Istio Handshakes) and rating them against cluster standards.

## 🚀 Key Features

* **Dual Audit Modes:**
    * **Infrastructure Audit (Default):** Deep dive into Control Plane, API, Ingress, and System Certs.
    * **User Workload Scan (`-u`):** Rapidly scans user namespaces for expiring application certificates, filtering out system noise.

* **Dynamic Risk Analysis:**
    * Identifies the **Highest Supported** protocol (Modernity Check).
    * Probes for the **Weakest Allowed** protocol (Risk Check) to find the "weakest link".
    * Rates findings as `[Modern]`, `[Intermediate]`, or `[Old/Legacy]`.

* **Source of Truth Reference:**
    * Dynamically fetches the official cipher definitions from the cluster's own API (`oc explain`).
    * **Standard Alignment:** Strictly follows the **[Mozilla Server-Side TLS Guidelines](https://wiki.mozilla.org/Security/Server_Side_TLS)** (Red Hat Standard).

* **Component Deep-Dive:**
    * **API Server:** Validates active Ciphers and TLS versions against the profile.
    * **Ingress Controller:** Dumps internal **HAProxy** config to verify runtime settings.
    * **Service Mesh:** Performs active handshakes against Istio Gateways (Hybrid Audit).
    * **Kubelet:** Detects insecure `KubeletConfig` overrides on Node Pools.

## 📋 Prerequisites

* **Bash** shell (Linux/macOS/WSL)
* **`oc`** CLI (logged into the target cluster)
* **`jq`** (for JSON parsing)
* **`openssl`** (for certificate checks)
* **`timeout`** (coreutils)

## 🛠️ Usage

1. Make the script executable:

        chmod +x ocp-tls-audit.sh

2. **Mode A: Infrastructure Audit (Standard)**
   Checks the security posture of the OpenShift Cluster itself (API, Ingress, Nodes).

        ./ocp-tls-audit.sh

3. **Mode B: User Workload Scan**
   Scans only user-defined namespaces for expiring TLS secrets (ignoring `openshift-*`, `kube-*`, etc.).

        ./ocp-tls-audit.sh -u
        # OR
        ./ocp-tls-audit.sh --user-certs

### Sample Output (Infrastructure Audit)

    Starting OpenShift TLS Audit (Dynamic Security & Config Audit)...
    Scan Scope: Infrastructure Audit (Deep Dive)
    Cluster: https://api.example.com:6443
    Version: 4.19.21
    Date:    Thu Dec 18 20:45:00 CET 2025
    -----------------------------------------------------------------------------------

    [1] Component: API Server
      Configured Profile: Intermediate (Default)
      Minimum TLS Version: VersionTLS12
      Active Ciphers:
        - ECDHE-ECDSA-AES128-GCM-SHA256 [Intermediate]
        - TLS_AES_256_GCM_SHA384 [Modern]
        ...

    [2] Component: Ingress Controller (Router)
      Controller: default (Profile: Intermediate (Default))
        Runtime Config: ssl-default-bind-options ssl-min-ver TLSv1.2
        Active Ciphers (Runtime):
          - TLS_AES_128_GCM_SHA256 [Modern]
          ...

    ... (Service Mesh & Kubelet Checks) ...

    [6] Certificate Expiration Audit (Infrastructure Only)
    Tip: Use -u to scan user workload certificates only.
    EXPIRY        NAMESPACE/NAME                                      STATUS                        
    ----------------------------------------------------------------------------------------------------
    2026-01-11    openshift-kube-apiserver/aggregator-client          EXPIRING (23 d)
    2028-12-10    openshift-etcd/etcd-client                          OK (1087 d)
    ...

## 🔗 Remediation & Configuration

If the audit reveals "Old" or insecure profiles, you can modify the TLS Security Profiles for the Ingress Controller, API Server, or Kubelet.

* **Official Red Hat Documentation:**
    [Configuring TLS security profiles (OpenShift 4.20)](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/security_and_compliance/tls-security-profiles)

## 👨‍💻 Authors

* **Chris Tawfik** (ctawfik@redhat.com) | **toughIQ** (toughiq@gmail.com)
* *With support from **Gemini AI***

## 📄 License

This project is open source and available under the [MIT License](LICENSE).
