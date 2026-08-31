# Recon7: Autonomous Attack Surface Management & Red Team Triage Platform

> **DEFCON 3 // CLASSIFIED SECURITY PLATFORM**
> Recon7 is an enterprise-grade, distributed Attack Surface Management (ASM) and autonomous OSINT platform designed for red team operators, SOC analysts, and security architects.

---

## 📑 Table of Contents

1. [System Architecture & Core Philosophy](#-system-architecture--core-philosophy)
2. [The 10-Step Autonomous Recon Pipeline](#-the-10-step-autonomous-recon-pipeline)
3. [Deployment & Infrastructure Setup](#-deployment--infrastructure-setup)
   - [Docker Compose (Single-Node Stack)](#1-docker-compose-production-stack)
   - [Kubernetes Manifest (`deploy.yaml`)](#2-kubernetes-cluster-deployment-deployyaml)
   - [Enterprise Helm Chart](#3-enterprise-helm-chart-deployhelmrecon7)
   - [Bare-Metal Local Development](#4-bare-metal-local-development)
4. [AI Gateway & Multi-Model Routing (LiteLLM)](#-ai-gateway--multi-model-routing-litellm)
5. [Threat Intelligence & OSINT Connectors](#-threat-intelligence--osint-connectors)
   - [Censys Search & Platform v3 (PAT)](#censys-search--platform-v3)
   - [GitHub Personal Access Token (5,000 req/hr)](#github-personal-access-tokens)
   - [Search Engines & Google Dorks](#search-engines--google-dorks)
6. [Multi-Tenant Scope Governance & Legal Gates](#-multi-tenant-scope-governance--legal-gates)
7. [RESTful OpenAPI Reference & Examples](#-restful-openapi-reference)

---

## 🏗️ System Architecture & Core Philosophy

Recon7 decouples discovery into four independent architectural tiers:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           RECON7 CLOUD ECOSYSTEM                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   [ Client Browser ] ──► [ React 18 / Tailwind SPA (Port 80/4000) ]         │
│                                    │                                        │
│                                    ▼ HTTP / Bearer Auth                     │
│               [ FastAPI Gateway Engine (Uvicorn - Port 8080) ]              │
│                     │                               │                       │
│                     ▼                               ▼                       │
│         [ PostgreSQL 16 / WAL ]         [ LiteLLM AI Gateway Layer ]        │
│          (Entities, Findings,            • Anthropic Claude Sonnet 4.5      │
│           Evidence & Auth)               • OpenAI GPT-4o / Gemini 2.0       │
│                     ▲                    • Local Ollama / Llama 3.3         │
│                     │                                                       │
│                     └───────────────┐                                       │
│                                     │ Task Polling & Persistence            │
│                 [ Asynchronous DAG Worker Engine (worker.py) ]              │
│                     ├─► Stage 01: Company & ASN Resolution                  │
│                     ├─► Stage 02: Subdomain Enumeration (crt.sh / Censys)   │
│                     ├─► Stage 03: Direct Origin IP Extraction (CDN Bypass)  │
│                     ├─► Stage 04: Port & Service Sweeps (Masscan / Nmap)    │
│                     ├─► Stage 05: Tech Stack & Header Fingerprinting        │
│                     ├─► Stage 06: Nuclei Vulnerability Pattern Matching     │
│                     ├─► Stage 07: CVE Correlation & NVD Scoring             │
│                     ├─► Stage 08: Human People OSINT & Email Deliverability │
│                     ├─► Stage 09: AI Triage & Attack Chain Synthesis        │
│                     └─► Stage 10: Executive Engagement Report Generation    │
└─────────────────────────────────────────────────────────────────────────────┘
```

1. **Frontend (Presentation Tier):** React 18 SPA with path-based routing (`react-router-dom`), HTML5 Canvas graph visualizers, and DEFCON operational styling.
2. **FastAPI Gateway (Application Tier):** Asynchronous REST API managing tenant authentication, scope attestation gates, and job queues.
3. **Database & Knowledge Ledger (Storage Tier):** Relational schema supporting PostgreSQL 16 and SQLite WAL with multi-source evidence confidence scoring.
4. **Autonomous Worker (Execution Tier):** Non-linear DAG worker orchestrating concurrent security binaries (Masscan, Nmap, Subfinder, Nuclei) and passive OSINT feeds.

---

## ⚡ The 10-Step Autonomous Recon Pipeline

Every scan executes as an asynchronous Directed Acyclic Graph (DAG):

| Stage | Subsystem | Target Operations | Primary Sensors |
| :--- | :--- | :--- | :--- |
| **01** | `recon.company_resolve` | RDAP / WHOIS registrar query, BGP ASN extraction, DMARC/DKIM email hygiene | `rdap.org`, `dnspython` |
| **02** | `recon.subdomains` | Certificate Transparency log stream, Passive DNS, Censys Certificate SANs | `crt.sh`, `certspotter`, `censys` |
| **03** | `recon.origin_extractor` | SPF netblock parsing, MX IP resolution, Cloudflare/Akamai direct origin bypass | `recon.origin_extractor`, `censys_hosts` |
| **04** | `recon.ports` | Fast prioritized non-CDN SYN port sweeper and Nmap service banner extractor | `masscan`, `nmap` |
| **05** | `recon.fingerprint` | HTTP response headers, meta generators, cookies, framework signatures | `httpx`, `recon.fingerprint` |
| **06** | `vuln.nuclei_match` | Misconfigured panels, exposed `.env` / `.git`, open Actuators and Swagger UIs | `nuclei`, `vuln.nuclei_match` |
| **07** | `vuln.cve_lookup` | NIST NVD correlation, OWASP Top 10 mapping, CVSS scoring | `vuln.cve_lookup` |
| **08** | `people.aggregate` | Employee OSINT, LinkedIn scraping, email syntax inference (`{first}.{last}`), zero-bounce SMTP verify | `people.site_crawler`, `people.verifier` |
| **09** | `ai.triage` | LiteLLM multi-model reasoning, attack path correlation, critical severity filtering | `ai.gateway`, `ai.triage` |
| **10** | `ai.report_writer` | Executive markdown audit report compilation and database persistence | `ai.report_writer` |

---

## 🚀 Deployment & Infrastructure Setup

### 1. Docker Compose (Production Stack)

Deploy the complete multi-container stack in 3 commands:

```bash
# 1. Clone the repository
git clone https://github.com/your-org/recon7.git
cd recon7

# 2. Configure credentials
cp .env.example .env

# 3. Build & Launch in Background
docker compose up -d --build
```

#### Production `docker-compose.yml`

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:16-alpine
    container_name: r7-postgres
    restart: unless-stopped
    environment:
      POSTGRES_DB: recon7
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: reconpassword123
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d recon7"]
      interval: 5s
      timeout: 5s
      retries: 5

  api:
    build: .
    container_name: r7-api
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      DATABASE_URL: postgresql://postgres:reconpassword123@postgres:5432/recon7
      LITELLM_MODEL: claude-sonnet-4-5-20250929
      ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY:-}
      JWT_SECRET: ${JWT_SECRET:-super-secret-key-change-me}
    ports:
      - "8080:8080"
    command: uvicorn main:app --host 0.0.0.0 --port 8080

  worker:
    build: .
    container_name: r7-worker
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      DATABASE_URL: postgresql://postgres:reconpassword123@postgres:5432/recon7
      LITELLM_MODEL: claude-sonnet-4-5-20250929
      ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY:-}
    command: python worker.py

  frontend:
    build: ./frontend
    container_name: r7-frontend
    restart: unless-stopped
    ports:
      - "80:80"
    depends_on:
      - api

volumes:
  postgres_data:
```

---

### 2. Kubernetes Cluster Deployment (`deploy.yaml`)

Recon7 provides a production-grade Kubernetes manifest located at `deploy/kubernetes/deploy.yaml`.

```bash
# 1. Apply namespace, ConfigMaps, Secrets, PVCs, and Deployments
kubectl apply -f deploy/kubernetes/deploy.yaml

# 2. Check rollout status across pods
kubectl get pods -n recon7 -w

# 3. View Ingress routing
kubectl get ingress -n recon7
```

---

### 3. Enterprise Helm Chart (`deploy/helm/recon7`)

```bash
# Install / Upgrade via Helm
helm upgrade --install recon7 ./deploy/helm/recon7 \
  --namespace recon7 \
  --create-namespace \
  --set secrets.anthropicApiKey="sk-ant-api03-..." \
  --set secrets.githubToken="ghp_..." \
  --set global.domain="recon7.yourdomain.com"
```

---

### 4. Bare-Metal Local Development

```bash
# 1. Python Environment Setup
python -m venv venv
# Linux/macOS: source venv/bin/activate
# Windows: .\venv\Scripts\activate
pip install -r requirements.txt

# 2. Start FastAPI Backend
python main.py

# 3. In a second terminal, start Async DAG Worker
python worker.py

# 4. In a third terminal, start Vite Dev Server
cd frontend
npm install
npm run dev
# Running on http://127.0.0.1:4000/
```

---

## 🤖 AI Gateway & Multi-Model Routing (LiteLLM)

Recon7 uses LiteLLM to dynamically route prompts to any foundation model:

| Provider | Model Identifier | Required API Key |
| :--- | :--- | :--- |
| **Anthropic** | `claude-sonnet-4-5-20250929` | `ANTHROPIC_API_KEY` |
| **Anthropic** | `anthropic/claude-3-7-sonnet-20250219` | `ANTHROPIC_API_KEY` |
| **OpenAI** | `openai/gpt-4o` | `OPENAI_API_KEY` |
| **Google** | `gemini/gemini-2.0-flash` | `GEMINI_API_KEY` |
| **DeepSeek** | `deepseek/deepseek-chat` | `DEEPSEEK_API_KEY` |
| **Local Ollama** | `ollama/llama3.3` | **Zero API Keys** (`http://localhost:11434`) |

---

## 🔍 Threat Intelligence & OSINT Connectors

### Censys Search & Platform v3

Recon7 supports both legacy v2 Basic Auth and modern **Censys Platform v3 Personal Access Tokens (PAT)**:
* **PAT Format:** `censys_LnV6Uhvu_...` $\rightarrow$ Automatically authenticated via `Authorization: Bearer <token>`.
* **v2 Format:** `API ID` + `API Secret` $\rightarrow$ Authenticated via HTTP Basic Auth.
* **Optional Organization ID:** Passes `X-Organization-ID` for multi-seat enterprise licenses.

### GitHub Personal Access Tokens

Supplying a GitHub PAT (`GITHUB_TOKEN`):
* Elevates GitHub Search API rate limits from **60 requests/hr** to **5,000 requests/hr**.
* Harvests commit author emails, organization members, and exposed tokens in repositories.

---

## 🛡️ Multi-Tenant Scope Governance & Legal Gates

Recon7 prevents illegal or accidental out-of-scope scanning via a mandatory authorization gate:

1. **Pre-Flight Scope Verification:** The API validates that the requested domain is registered in the `authorized_scopes` database table before creating a scan job.
2. **Attestation Record:** Requires security officers to record the authorization basis (`engagement_letter`, `bug_bounty`, `internal_pentest`) and the authorizing lead's email.
3. **Target Clamping:** Subdomain discovery engines discard any hostname not strictly under the authorized root domain.

---

## 📡 RESTful OpenAPI Reference

### Trigger a Scan
```bash
curl -X POST http://localhost:8080/scan \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "target.com",
    "scan_profile": "standard",
    "org_name": "Target Corporation"
  }'
```

### Retrieve Scan Status & Findings
```bash
curl -X GET http://localhost:8080/scan/d51b47d0-9497-4caf-963b-340f28cff35c \
  -H "Authorization: Bearer <JWT_TOKEN>"
```

### Register Authorized Scope
```bash
curl -X POST http://localhost:8080/scopes \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "target.com",
    "authorization_type": "engagement_letter",
    "authorized_by": "security-officer@target.com"
  }'
```

---
*Recon7 is maintained for authorized security assessments only. Always ensure valid written authorization before scanning target infrastructure.*
