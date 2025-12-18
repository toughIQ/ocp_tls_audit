# OpenShift Dynamic TLS & Risk Audit

![Platform](https://img.shields.io/badge/Platform-OpenShift%204.x-red)
![Language](https://img.shields.io/badge/Language-Bash-blue)
![License](https://img.shields.io/badge/License-MIT-green)

**`ocp-tls-audit.sh`** is a robust auditing tool designed to reveal the **actual** TLS security posture and runtime configuration of Red Hat OpenShift Container Platform (OCP) clusters.

Unlike standard compliance tools that often only check the *desired state* (CRDs), this tool performs a **Risk Analysis** by verifying the **active runtime configuration** (Live ConfigMaps, HAProxy Runtime, Istio Handshakes) and rating them against cluster standards.

## 🚀 Key Features

* **Dynamic Risk Analysis (Ceiling & Floor):**
    * Identifies the **Highest Supported** protocol (Modernity Check).
    * Probes for the **Weakest Allowed** protocol (Risk Check) to find the "weakest link".
    * Rates findings as `[Modern]`, `[Intermediate]`, or `[Old/Legacy]`.

* **Source of Truth Reference:**
    * Dynamically fetches the official cipher definitions for `Old`, `Intermediate`, and `Modern` from the cluster's own API documentation (`oc explain`).
    * **Standard Alignment:** These profiles strictly follow the **[Mozilla Server-Side TLS Guidelines](https://wiki.mozilla.org/Security/Server_Side_TLS)**, which serve as the upstream standard for Red Hat OpenShift.

* **API Server Deep-Dive:**
    * Detects if a configuration rollout is pending.
    * Lists the *exact* active Cipher Suites and validates them against the active profile.
    * Handles **Custom Profiles** intelligently by rating individual ciphers.

* **Ingress Controller (Router) Inspection:**
    * Dumps the internal **HAProxy** configuration from running pods.
    * Verifies if TLS 1.3 is enforced on the network layer.
    * Lists all active runtime ciphers.

* **Service Mesh (Istio) Hybrid Audit:**
    * **Auto-Discovery:** Finds Control Planes and Gateways automatically.
    * **Hybrid Mode:** Checks Configuration (Spec) AND performs active TLS Handshakes against Routes or LoadBalancer IPs.
    * **Fallback:** Gracefully handles internal gateways without external routes.

* **Pool-Aware Kubelet Check:**
    * Scans MachineConfigPools (`master`, `worker`, `custom`).
    * Detects overriding `KubeletConfig` objects and color-codes risky configurations (e.g., "Old" profile on workers).

* **Certificate Expiration Monitor:**
    * Scans critical OpenShift namespaces (`openshift-ingress`, `kube-apiserver`, `etcd`, etc.).
    * Provides a traffic-light status: **OK** (Green), **WARNING** (<90 days, Yellow), **EXPIRING** (<30 days, Red).

## 📋 Prerequisites

* **Bash** shell (Linux/macOS/WSL)
* **`oc`** CLI (logged into the target cluster with `cluster-admin` privileges)
* **`jq`** (for JSON parsing)
* **`openssl`** (for certificate date parsing and active handshakes)
* **`timeout`** (usually part of coreutils, used for network probes)

## 🛠️ Usage

1. Clone this repository or download the script.

2. Make the script executable:

        chmod +x ocp-tls-audit.sh

3. Run the audit:

        ./ocp-tls-audit.sh

### Sample Output

    Starting OpenShift TLS Audit (Dynamic Security & Config Audit)...
    Cluster: https://api.example.com:6443
    Version: 4.18.30
    Date:    Thu Dec 18 15:45:00 CET 2025
    -----------------------------------------------------------------------------------

    [1] Component: API Server
      Configured Profile: Custom
      Minimum TLS Version: VersionTLS12
      Active Ciphers:
        - ECDHE-ECDSA-AES128-GCM-SHA256 [Intermediate]
        - ECDHE-RSA-AES128-GCM-SHA256 [Intermediate]
        ...

    [2] Component: Ingress Controller (Router)
      Controller: default (Profile: Modern)
        Runtime Config: ssl-default-bind-options ssl-min-ver TLSv1.3
        Active Ciphers (Runtime):
          - TLS_AES_128_GCM_SHA256 [Modern]
          - TLS_AES_256_GCM_SHA384 [Modern]
          ...

    [3] Component: Service Mesh (Istio) - Hybrid Audit
      Status: Control Plane found in namespace 'istio-system'
      Gateway: public-gateway (Mode: SIMPLE)
        Active Check Target: api.example.com
          -> Highest Supported: TLSv1.3 using TLS_AES_256_GCM_SHA384 [Modern]
          -> Weakest Allowed:   TLSv1.2 using ECDHE-RSA-AES128-GCM-SHA256 [Intermediate]

    [4] Component: Kubelet (Node Pools)
      Pool: master -> Profile: Intermediate (Default/Inherited)
      Pool: worker -> Profile: Old (KubeletConfig Override)

    ... (Reference Section & Certificate Audit follows) ...

## 🔗 Remediation & Configuration

If the audit reveals "Old" or insecure profiles, you can modify the TLS Security Profiles for the Ingress Controller, API Server, or Kubelet.

* **Official Red Hat Documentation:**
    [Configuring TLS security profiles (OpenShift 4.20)](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/security_and_compliance/tls-security-profiles)

## 📚 Use Cases

* **Compliance Audits:** Supports data collection for **DORA**, **PCI-DSS**, and **BSI IT-Grundschutz** audits by proving active cipher suites and TLS versions.
* **Security Hardening:** Identifies "weak links" (e.g., a Gateway allowing TLS 1.0) before they can be exploited.
* **Configuration Verification:** Validates that "Custom" profiles are correctly applied and active on the network layer.

## 👨‍💻 Authors

* **Chris Tawfik** (ctawfik@redhat.com) | **toughIQ** (toughiq@gmail.com)
* *With support from **Gemini AI***

## 📄 License

This project is open source and available under the [MIT License](LICENSE).
