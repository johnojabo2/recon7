# RECON7 — Autonomous Attack Surface Intelligence Platform

```text
  ██████╗ ███████╗██████╗ ██████╗ ███╗   ██╗███████╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚════██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ██╔╝
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║   ██╔╝ 
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║   ██║  
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝  

  DEFENSE-GRADE ATTACK SURFACE INTELLIGENCE & OSINT AGGREGATION PLATFORM
             AN OJABO ORGANIZATION OPEN SOURCE PROJECT
```

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://docker.com)
[![Security](https://img.shields.io/badge/Security-Audited-emerald.svg)](#-defense-grade-security--cryptography)

---

## 🛡️ Executive Overview

**Recon7** is an enterprise-grade, modular, self-hosted multi-tenant attack surface intelligence and reconnaissance platform built under the **Ojabo Organization**.

Designed for red teams, cybersecurity operations centers (SOC), enterprise defenders, educational institutions, and healthcare providers, Recon7 transforms raw internet telemetry into actionable threat intelligence. Given an authorized target domain, Recon7 resolves corporate organization boundaries, maps subdomains and origin IPs, sweeps active ports, fingerprints software technology stacks, correlates vulnerabilities against the official **CISA Known Exploited Vulnerabilities (KEV)** catalog and NVD databases, infers corporate personnel email syntax via OSINT, and synthesizes tactical attack surface reports using an AI intelligence engine.

---

## ⚡ Core Feature Matrix

| Feature Domain | System Capability |
| :--- | :--- |
| **Multi-Tenant IAM & RBAC** | Fine-grained role-based access control (`system_admin`, `tenant_admin`, `auditor`). Features anti-lockout protection, sole administrator demotion block, and a first-launch root setup wizard. |
| **Scope Authorization Gate** | Every scan request is intercepted and validated against strict authorization policies before any network packets or OSINT queries are dispatched. |
| **10-Stage Pipeline DAG** | Resilient step-checkpointed Directed Acyclic Graph (DAG) pipeline. Interrupted scans resume automatically from the last completed stage. |
| **CVE & CISA KEV Correlation** | Live real-time synchronization with the official CISA KEV feed and NVD CVE database with CVSS v3.1 scoring. |
| **Graph Topology Engine** | Interactive Cytoscape-powered multi-lens evidence graph mapping relationships between domains, subdomains, IPs, ports, technologies, CVEs, and personnel. |
| **Cryptographic Hardening** | PBKDF2 password hashing, constant-time dummy verification eliminating user enumeration timing side-channels, thread-safe brute-force rate limiting, and JWT `alg: HS256` header validation. |
| **Zero-Trust Triage Engine** | 100% local, deterministic threat triage, CVSS scoring, and attack vector synthesis ensuring zero data leakage to third-party cloud APIs. |
| **Vector PDF & Report Export** | 1-Click vector PDF export for both Executive Assessment reports (Document Mode) and Raw Telemetry Streams. |

---

## 📐 10-Stage Reconnaissance Pipeline Flow

```text
                     [ POST /api/scan ]
                            │
                            ▼
        ┌──────────────────────────────────────┐
        │ [0] Policy & Scope Authorization Gate│
        └──────────────────┬───────────────────┘
                           │
    ┌──────────────────────┼──────────────────────┐
    │                      │                      │
    ▼                      ▼                      ▼
┌──────────────┐   ┌──────────────┐   ┌──────────────────┐
│[1] Company   │   │[2] Subdomain │   │[8] People OSINT  │
│    Resolve   │   │    Enum      │   │    & Email Syn   │
└──────┬───────┘   └──────┬───────┘   └────────┬─────────┘
       │                  │                    │
       └──────────┬───────┘                    │
                  ▼                            │
      ┌──────────────────────┐                 │
      │[3] IP Resolution     │                 │
      │    & CDN Detection   │                 │
      └──────────┬───────────┘                 │
                 │                             │
    ┌────────────┴────────────┐                │
    ▼                         ▼                │
┌──────────────┐   ┌──────────────────┐        │
│[4] Concurrent│   │[5] Tech Stack    │        │
│    Port Sweep│   │    Fingerprint   │        │
└──────┬───────┘   └────────┬─────────┘        │
       │                    │                  │
       └──────────┬─────────┘                  │
                  ▼                            │
      ┌──────────────────────┐                 │
      │[6] Nuclei & App Vuln │                 │
      │    Probe Matching    │                 │
      └──────────┬───────────┘                 │
                 │                             │
                 ▼                             │
      ┌──────────────────────┐                 │
      │[7] CVE & CISA KEV    │                 │
      │    Catalog Lookup    │                 │
      └──────────┬───────────┘                 │
                 │                             │
                 └──────────┬──────────────────┘
                            ▼
                ┌──────────────────────┐
                │[9] AI Attack Triage  │
                │    & Vector Analysis │
                └──────────┬───────────┘
                           │
                           ▼
                ┌──────────────────────┐
                │[10] Report Writer    │
                │     & PDF Compiler   │
                └──────────────────────┘
```

---

## 🔒 Defense-Grade Security & Cryptography

Recon7 enforces a zero-trust security posture across all network and API surfaces:

1. **Anti-Lockout Safeguards:** Backend API routes strictly reject administrator self-demotion and block deactivation or deletion of the last remaining active System Administrator.
2. **Timing Side-Channel Protection:** Authentication routes execute constant-time dummy hash verifications when users are not found, preventing user enumeration timing attacks.
3. **JWT Security Hardening:** Requires explicit header verification (`alg == "HS256"` and `typ == "JWT"`) to eliminate JWT algorithm confusion attacks (`"alg": "none"`).
4. **Sliding-Window Rate Limiting:** Thread-safe memory limiter blocks brute-force and credential stuffing attacks on authentication endpoints.
5. **Input & Hashing Bounds:** Password inputs are truncated safely at 128 characters prior to hashing to prevent CPU DoS hashing exhaustion attacks.

---

## 🚀 Quick Start Guide

### Prerequisites
* **Python 3.10+**
* **Node.js 20+** (for building React Vite Frontend)
* **PostgreSQL 16** (or built-in zero-dependency SQLite for local testing)

---

### 1. Installation & Environment Setup

```bash
# Clone the repository
git clone https://github.com/johnojabo2/recon7.git
cd Recon7

# Create and activate Python virtual environment
python -m venv venv
# On Linux/macOS:
source venv/bin/activate
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1

# Install required Python dependencies
pip install -r requirements.txt
```

---

### 2. Configure Environment Variables

Create or update your `.env` file in the root workspace directory:

```env
APP_NAME=R7 - Reconnaissance Platform
ENVIRONMENT=development
DEBUG=True

# SQLite Database (Zero-Dependency Local Dev)
DATABASE_URL=sqlite:///./recon7.db

# PostgreSQL (Production Option)
# DATABASE_URL=postgresql://postgres:reconpassword123@127.0.0.1:5432/recon7

# Development Scope Bypass
ALLOW_ALL_SCOPES_DEV=True

# Zero-Trust Local Threat Triage Configuration
AI_ENABLED=True
ALLOW_ALL_SCOPES_DEV=True
```

---

### 3. Launch Backend Server & Async Pipeline Worker

In Terminal 1 (API Server):
```bash
python main.py
```
*The FastAPI server starts on `http://127.0.0.1:8080`. API Documentation (Swagger) is live at `http://127.0.0.1:8080/docs`.*

In Terminal 2 (Pipeline Worker):
```bash
python worker.py
```

---

### 4. Launch Frontend Web Console

In Terminal 3:
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173` in your browser. On first launch, the **Root Setup Wizard** will guide you to create your initial Master Administrator account.

---

## 🐳 Interactive Deployment Wizard (Docker & Local Network)

Recon7 includes an interactive deployment wizard that prompts for your network parameters, configures frontend build arguments (`VITE_API_URL`), generates `.env` credentials, and launches all containerized services automatically.

### On Linux / macOS / WSL:
```bash
chmod +x install.sh
./install.sh
```

### On Windows PowerShell:
```powershell
.\install.ps1
```

> 💡 **Why Build Arguments Are Crucial for Remote & LAN Access:**  
> Single Page Applications (React Vite) execute inside the client's browser. When deploying across a LAN, VPN, or public IP, client browsers cannot resolve internal container names (e.g. `http://r7-api:8000`). The interactive installer configures `VITE_API_URL` to `/api` (relative Nginx proxy) or your public API endpoint so the web console connects seamlessly across any network.

### Manual Docker Compose Deployment:
```bash
# Build and launch all containerized services in detached mode
docker compose up -d --build
```

### Services Containerized:
* `r7-postgres`: PostgreSQL 16 Alpine database container with volume persistence.
* `r7-api`: FastAPI REST backend server listening on port `8000`.
* `r7-worker`: Python async reconnaissance pipeline DAG worker.
* `r7-frontend`: Multi-stage Nginx Alpine container serving the React single-page application on ports `80` and `5173`.

---

## 📡 REST API Quick Walkthrough

### 1. Initialize Master Root Administrator (First Launch)
```bash
curl -X POST http://127.0.0.1:8080/api/setup/initialize \
  -H "Content-Type: application/json" \
  -d '{
    "full_name": "John A. Ojabo",
    "email": "admin@ojabo.org",
    "password": "SecurePassword123!",
    "organization_name": "Ojabo Security Foundation"
  }'
```

### 2. Authenticate & Obtain Bearer Token
```bash
curl -X POST http://127.0.0.1:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@ojabo.org",
    "password": "SecurePassword123!"
  }'
```

### 3. Dispatch Autonomous Reconnaissance Scan
```bash
curl -X POST http://127.0.0.1:8080/api/scan \
  -H "Authorization: Bearer <YOUR_JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "target.com",
    "scan_profile": "deep"
  }'
```

### 4. Retrieve Findings & AI Assessment Report
```bash
curl -X GET http://127.0.0.1:8080/api/scan/<SCAN_JOB_ID>/report \
  -H "Authorization: Bearer <YOUR_JWT_TOKEN>"
```

---

## 🧪 Automated Testing & Security Verification

Recon7 includes a comprehensive test suite covering core security boundaries, authentication timing, rate limiting, anti-lockout safeguards, and CPE/EPSS lookup engines.

```bash
# Run all automated test suites
pytest -v
```

---

## 📄 License & Attribution

Recon7 is open-source software released under the **[Apache License 2.0](LICENSE)**.

```text
Copyright 2026 Ojabo Organization

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

<p center>
  Developed with excellence by the <strong>Ojabo Organization</strong> • Built to empower defenders worldwide.
</p>
