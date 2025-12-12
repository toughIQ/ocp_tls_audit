# OpenShift Dynamic TLS & Certificate Audit

![Platform](https://img.shields.io/badge/Platform-OpenShift%204.x-red)
![Language](https://img.shields.io/badge/Language-Bash-blue)
![License](https://img.shields.io/badge/License-MIT-green)

**`ocp-tls-audit.sh`** is a comprehensive, robust bash script designed to audit the **actual** TLS security posture of a Red Hat OpenShift Container Platform (OCP) cluster.

Unlike standard compliance tools that often only check the *desired state* (CRDs), this tool verifies the **active runtime configuration** (Live ConfigMaps, HAProxy settings, Node configs) to ensure that security profiles like `Modern`, `Intermediate`, or `Custom` are successfully applied and active.

## 🚀 Key Features

* **API Server Deep-Dive:**
    * Checks configured TLS Profile vs. Active ConfigMap.
    * Detects if a configuration rollout is pending.
    * Lists the *exact* active Cipher Suites (critical for verifying hardened "Custom" profiles).
* **Ingress Controller (Router) Verification:**
    * Compares `spec` (Configuration) against `status` (Operator acknowledgment).
    * Inspects running HAProxy pods to verify if TLS 1.3 is enforced (detects "Modern" profile application).
    * Filters output to show relevant TLS options and active ciphers.
* **Pool-Aware Kubelet Check:**
    * Intelligently scans MachineConfigPools (e.g., `master` vs. `worker` vs. `gpu`).
    * Detects if specific Node Pools have overriding `KubeletConfig` applied (e.g., generic Intermediate on Masters, but Legacy on Workers).
* **Certificate Expiry Monitor:**
    * Scans critical OpenShift namespaces (`openshift-ingress`, `kube-apiserver`, `etcd`, `monitoring`, etc.).
    * Reports expiration dates and status (OK/EXPIRING/EXPIRED) for all TLS secrets.
* **Dynamic Reference:**
    * Fetches the official cipher definitions for `Old`, `Intermediate`, and `Modern` from the cluster's own API documentation (`oc explain`) to serve as a baseline comparison.

## 📋 Prerequisites

* **Bash** shell (Linux/macOS/WSL)
* **`oc`** CLI (logged into the target cluster with `cluster-admin` privileges)
* **`jq`** (for JSON parsing)
* **`openssl`** (for certificate date parsing)

## 🛠️ Usage

1.  Clone this repository or download the script.
2.  Make the script executable:
    ```bash
    chmod +x ocp-tls-audit.sh
    ```
3.  Run the audit:
    ```bash
    ./ocp-tls-audit.sh
    ```

### Sample Output

```text
Starting OpenShift TLS Audit...
Cluster: [https://api.example.com:6443](https://api.example.com:6443)
Date: Fri Dec 12 16:30:00 CET 2025
-----------------------------------------------------------------------------------

[1] Component: API Server
  Configured Profile: Custom
  Minimum TLS Version: VersionTLS12
  Active Ciphers:
    - ECDHE-ECDSA-AES128-GCM-SHA256
    - ECDHE-RSA-AES128-GCM-SHA256
    - ECDHE-ECDSA-AES256-GCM-SHA384
    - ECDHE-RSA-AES256-GCM-SHA384

[2] Component: Ingress Controller
  Controller Name: default
  Profile (Spec & Status): Modern
  TLS Options (HAProxy): ssl-min-ver TLSv1.3
    (TLS 1.3 Suites):
      - TLS_AES_128_GCM_SHA256
      - TLS_AES_256_GCM_SHA384
      - TLS_CHACHA20_POLY1305_SHA256

[3] Component: Kubelet (Node Pools)
  Pool: master
    Status: Intermediate (Default - Inherited)
  Pool: worker
    Status: Custom KubeletConfig Applied
    Config Object: set-legacy-worker
    Profile: Old
...

## 📚 Background & References

OpenShift allows configuring TLS Security Profiles to balance between security and compatibility. This script helps verify these settings against industry standards.

* **Red Hat Documentation:** [Configuring TLS Security Profiles in OpenShift](https://docs.openshift.com/container-platform/4.17/security/tls-security-profiles.html)
    * *Explains the CRD based configuration for APIServer, Ingress, and Kubelet.*
* **Mozilla Security Guidelines:** [Server Side TLS](https://wiki.mozilla.org/Security/Server_Side_TLS)
    * *The upstream source for the definitions of "Old", "Intermediate", and "Modern" profiles used by OpenShift.*

## 👨‍💻 Authors

* **Chris Tawfik** (ctawfik@redhat.com) | **toughIQ** (toughiq@gmail.com)
* *With support from **Gemini AI***

## 📄 License

This project is open source and available under the [MIT License](LICENSE).
