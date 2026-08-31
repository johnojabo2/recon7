import React, { useState } from 'react';
import {
  BookOpen,
  Terminal,
  Server,
  Layers,
  Cpu,
  ShieldCheck,
  KeyRound,
  FileCode,
  Copy,
  Check,
  ChevronRight,
  Search,
  ExternalLink,
  Shield,
  Zap,
  Globe,
  Database,
  Lock,
  Activity,
  Workflow,
  Sparkles,
  Container,
  Boxes,
} from 'lucide-react';

export default function DocsView() {
  const [activeSection, setActiveSection] = useState('quickstart');
  const [activeDeployTab, setActiveDeployTab] = useState('docker');
  const [copiedSnippet, setCopiedSnippet] = useState(null);
  const [searchFilter, setSearchFilter] = useState('');

  const handleCopy = (code, key) => {
    navigator.clipboard.writeText(code);
    setCopiedSnippet(key);
    setTimeout(() => setCopiedSnippet(null), 2000);
  };

  const navSections = [
    { id: 'overview', title: 'Platform Overview & Architecture', icon: Layers },
    { id: 'quickstart', title: 'Installation & Deployment', icon: Container },
    { id: 'pipeline', title: '10-Step Recon DAG Pipeline', icon: Workflow },
    { id: 'ai-gateway', title: 'Zero-Trust Local Triage Engine', icon: Shield },
    { id: 'connectors', title: 'OSINT & Threat Intel Connectors', icon: KeyRound },
    { id: 'governance', title: 'Scope Enforcement & Legal Gates', icon: ShieldCheck },
    { id: 'api-ref', title: 'OpenAPI REST Reference', icon: FileCode },
  ];

  const filteredSections = navSections.filter((s) =>
    s.title.toLowerCase().includes(searchFilter.toLowerCase())
  );

  return (
    <div className="flex flex-col lg:flex-row gap-8 font-sans pb-16">
      {/* Left Sticky Docs Navigation */}
      <aside className="w-full lg:w-72 shrink-0 space-y-4">
        <div className="p-4 rounded-xl bg-panel border border-border-dim space-y-3">
          <div className="flex items-center gap-2.5 text-cyan-signal font-mono text-xs font-bold uppercase tracking-wider">
            <BookOpen className="w-4 h-4" />
            <span>Documentation Hub</span>
          </div>

          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-text-dim" />
            <input
              type="text"
              placeholder="Filter topics..."
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 rounded-md bg-void border border-border-dim focus:border-cyan-signal text-xs font-mono text-text-primary placeholder:text-text-dim/50 focus:outline-none transition-all"
            />
          </div>
        </div>

        <nav className="p-2 rounded-xl bg-panel border border-border-dim space-y-1 font-mono text-xs">
          {filteredSections.map((sec) => {
            const Icon = sec.icon;
            const isActive = activeSection === sec.id;
            return (
              <button
                key={sec.id}
                onClick={() => setActiveSection(sec.id)}
                className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-left transition-all ${
                  isActive
                    ? 'bg-void text-cyan-signal border border-cyan-signal/40 font-bold shadow-glow-cyan-sm'
                    : 'text-text-dim hover:text-text-primary hover:bg-void/50 border border-transparent'
                }`}
              >
                <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-cyan-signal' : 'text-text-dim'}`} />
                <span className="truncate">{sec.title}</span>
                {isActive && <ChevronRight className="w-3.5 h-3.5 ml-auto text-cyan-signal shrink-0" />}
              </button>
            );
          })}
        </nav>

        {/* Community & GitHub Links */}
        <div className="p-4 rounded-xl bg-void/70 border border-border-dim space-y-2 text-[11px] font-mono text-text-dim">
          <div className="text-text-primary font-bold flex items-center gap-1.5 text-xs text-emerald-400">
            <Zap className="w-3.5 h-3.5" />
            <span>Open Source Standard</span>
          </div>
          <p className="leading-relaxed">
            Recon7 is built for red teams, SOC operators, and security architects requiring strict cryptographic scope authorization.
          </p>
        </div>
      </aside>

      {/* Main Documentation Content Area */}
      <main className="flex-1 space-y-8 min-w-0">
        {/* ========================================================================= */}
        {/* SECTION: OVERVIEW */}
        {/* ========================================================================= */}
        {activeSection === 'overview' && (
          <div className="space-y-6 animate-fade-in">
            <div>
              <div className="text-xs font-mono text-cyan-signal uppercase tracking-wider font-bold">
                Platform Architecture
              </div>
              <h1 className="text-2xl lg:text-3xl font-display font-bold text-text-primary mt-1">
                Recon7 Autonomous Intelligence Engine
              </h1>
              <p className="text-sm text-text-dim mt-2 font-mono leading-relaxed">
                Recon7 is a distributed, cloud-native Attack Surface Management (ASM) and autonomous OSINT platform designed for red team operations and enterprise external perimeter auditing.
              </p>
            </div>

            {/* Architecture Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-4 rounded-xl bg-panel border border-border-dim space-y-2">
                <div className="w-8 h-8 rounded-lg bg-void border border-cyan-signal/40 flex items-center justify-center text-cyan-signal">
                  <Workflow className="w-4 h-4" />
                </div>
                <h3 className="font-bold text-sm text-text-primary font-mono">10-Step DAG Pipeline</h3>
                <p className="text-xs text-text-dim font-mono leading-relaxed">
                  Asynchronous Directed Acyclic Graph orchestrating CT logs, passive DNS, port probing, deep web spiders, and Nuclei.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-panel border border-border-dim space-y-2">
                <div className="w-8 h-8 rounded-lg bg-void border border-emerald-400/40 flex items-center justify-center text-emerald-400">
                  <Cpu className="w-4 h-4" />
                </div>
                <h3 className="font-bold text-sm text-text-primary font-mono">LiteLLM AI Gateway</h3>
                <p className="text-xs text-text-dim font-mono leading-relaxed">
                  Multi-vendor LLM routing (Claude 3.7/4.5, GPT-4o, Gemini 2.0, DeepSeek, Ollama) generating automated triage and attack paths.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-panel border border-border-dim space-y-2">
                <div className="w-8 h-8 rounded-lg bg-void border border-magenta-alert/40 flex items-center justify-center text-magenta-alert">
                  <Lock className="w-4 h-4" />
                </div>
                <h3 className="font-bold text-sm text-text-primary font-mono">Scope Authorization Gate</h3>
                <p className="text-xs text-text-dim font-mono leading-relaxed">
                  Strict legal attestation layer preventing out-of-scope scanning via cryptographically signed scope tokens.
                </p>
              </div>
            </div>

            {/* Topology Flowchart */}
            <div className="p-5 rounded-xl bg-void border border-border-dim space-y-3 font-mono text-xs">
              <div className="text-text-primary font-bold flex items-center gap-2">
                <Boxes className="w-4 h-4 text-cyan-signal" />
                <span>Distributed System Topology</span>
              </div>
              <pre className="p-4 rounded-lg bg-panel-elevated text-cyan-bright border border-border-dim overflow-x-auto text-[11px] leading-relaxed">
{`┌─────────────────────────────────────────────────────────────────────────────┐
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
└─────────────────────────────────────────────────────────────────────────────┘`}
              </pre>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* SECTION: INSTALLATION & DEPLOYMENT */}
        {/* ========================================================================= */}
        {activeSection === 'quickstart' && (
          <div className="space-y-6 animate-fade-in">
            <div>
              <div className="text-xs font-mono text-cyan-signal uppercase tracking-wider font-bold">
                Installation & Infrastructure
              </div>
              <h1 className="text-2xl lg:text-3xl font-display font-bold text-text-primary mt-1">
                Deploying Recon7
              </h1>
              <p className="text-sm text-text-dim mt-2 font-mono leading-relaxed">
                Choose your target deployment environment below for copy-paste deployment manifests, container specs, and production setups.
              </p>
            </div>

            {/* Deployment Method Tabs */}
            <div className="flex items-center gap-2 border-b border-border-dim pb-3 overflow-x-auto">
              {[
                { id: 'docker', label: '🐳 Docker Compose', desc: 'Single-node full stack' },
                { id: 'k8s', label: '☸️ Kubernetes deploy.yaml', desc: 'Production K8s manifest' },
                { id: 'helm', label: '⛵ Helm Chart', desc: 'Cloud-native chart' },
                { id: 'local', label: '💻 Local / Bare-Metal', desc: 'Native Python & Vite' },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveDeployTab(tab.id)}
                  className={`px-4 py-2 rounded-lg text-xs font-mono transition-all shrink-0 ${
                    activeDeployTab === tab.id
                      ? 'bg-cyan-signal text-void font-bold shadow-glow-cyan-sm'
                      : 'bg-panel text-text-dim hover:text-text-primary hover:bg-panel-elevated border border-border-dim'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* 1. DOCKER COMPOSE TAB */}
            {activeDeployTab === 'docker' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-mono font-bold text-text-primary flex items-center gap-2">
                    <Container className="w-4 h-4 text-cyan-signal" />
                    <span>docker-compose.yml (Production Stack)</span>
                  </h3>
                  <button
                    onClick={() =>
                      handleCopy(
                        `version: '3.8'

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
      ANTHROPIC_API_KEY: \${ANTHROPIC_API_KEY:-}
      JWT_SECRET: \${JWT_SECRET:-super-secret-key-change-me}
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
      ANTHROPIC_API_KEY: \${ANTHROPIC_API_KEY:-}
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
  postgres_data:`,
                        'docker-compose'
                      )
                    }
                    className="flex items-center gap-1.5 px-3 py-1 rounded bg-panel hover:bg-void border border-border-dim text-[11px] font-mono text-cyan-signal"
                  >
                    {copiedSnippet === 'docker-compose' ? <Check className="w-3.5 h-3.5 text-success-green" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedSnippet === 'docker-compose' ? 'COPIED' : 'COPY MANIFEST'}</span>
                  </button>
                </div>

                <pre className="p-4 rounded-xl bg-void border border-border-dim text-xs font-mono text-text-primary overflow-x-auto">
{`# 1. Clone the repository
git clone https://github.com/johnojabo2/recon7.git
cd Recon7

# 2. Configure environment credentials
cp .env.example .env
# Add your GITHUB_TOKEN, GOOGLE_SEARCH_API_KEY, etc.

# 3. Build and launch with Docker Compose
docker compose up -d --build

# 4. View logs and operational status
docker compose logs -f worker`}
                </pre>
              </div>
            )}

            {/* 2. KUBERNETES DEPLOY.YAML TAB */}
            {activeDeployTab === 'k8s' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-mono font-bold text-text-primary flex items-center gap-2">
                    <Server className="w-4 h-4 text-cyan-signal" />
                    <span>Kubernetes Cluster Deployment (deploy/kubernetes/deploy.yaml)</span>
                  </h3>
                  <button
                    onClick={() =>
                      handleCopy(`kubectl apply -f deploy/kubernetes/deploy.yaml`, 'k8s-apply')
                    }
                    className="flex items-center gap-1.5 px-3 py-1 rounded bg-panel hover:bg-void border border-border-dim text-[11px] font-mono text-cyan-signal"
                  >
                    {copiedSnippet === 'k8s-apply' ? <Check className="w-3.5 h-3.5 text-success-green" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedSnippet === 'k8s-apply' ? 'COPIED' : 'COPY COMMAND'}</span>
                  </button>
                </div>

                <div className="p-4 rounded-xl bg-void border border-border-dim space-y-3 font-mono text-xs">
                  <p className="text-text-dim">
                    The complete unified manifest creates a dedicated namespace (<code className="text-cyan-signal">recon7</code>), persistent volume claims for PostgreSQL, multi-replica API deployments, scalable distributed workers, and TLS Ingress routing.
                  </p>
                  <pre className="p-3 rounded-lg bg-panel-elevated text-cyan-bright border border-border-dim overflow-x-auto text-[11px]">
{`# Deploy full Recon7 stack into your Kubernetes cluster
kubectl apply -f deploy/kubernetes/deploy.yaml

# Check rollouts & running pods
kubectl get pods -n recon7 -w

# Check Ingress routing
kubectl get ingress -n recon7`}
                  </pre>
                </div>
              </div>
            )}

            {/* 3. HELM CHART TAB */}
            {activeDeployTab === 'helm' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-mono font-bold text-text-primary flex items-center gap-2">
                    <Boxes className="w-4 h-4 text-cyan-signal" />
                    <span>Enterprise Helm Chart (deploy/helm/recon7)</span>
                  </h3>
                  <button
                    onClick={() =>
                      handleCopy(
                        `helm upgrade --install recon7 ./deploy/helm/recon7 --namespace recon7 --create-namespace --set global.domain=recon7.yourdomain.com`,
                        'helm-install'
                      )
                    }
                    className="flex items-center gap-1.5 px-3 py-1 rounded bg-panel hover:bg-void border border-border-dim text-[11px] font-mono text-cyan-signal"
                  >
                    {copiedSnippet === 'helm-install' ? <Check className="w-3.5 h-3.5 text-success-green" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedSnippet === 'helm-install' ? 'COPIED' : 'COPY COMMAND'}</span>
                  </button>
                </div>

                <pre className="p-4 rounded-xl bg-void border border-border-dim text-xs font-mono text-text-primary overflow-x-auto">
{`# 1. Customize your values.yaml file
cat deploy/helm/recon7/values.yaml

# 2. Install / Upgrade via Helm
helm upgrade --install recon7 ./deploy/helm/recon7 \\
  --namespace recon7 \\
  --create-namespace \\
  --set secrets.anthropicApiKey="sk-ant-api..." \\
  --set secrets.githubToken="ghp_..." \\
  --set global.domain="recon7.yourorg.com"`}
                </pre>
              </div>
            )}

            {/* 4. LOCAL / BARE-METAL TAB */}
            {activeDeployTab === 'local' && (
              <div className="space-y-4">
                <h3 className="text-sm font-mono font-bold text-text-primary flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-cyan-signal" />
                  <span>Native Local Setup (Windows / macOS / Linux)</span>
                </h3>
                <pre className="p-4 rounded-xl bg-void border border-border-dim text-xs font-mono text-text-primary overflow-x-auto">
{`# 1. Install System Security Tools (Optional but Recommended)
# Ubuntu/Debian: sudo apt install nmap masscan -y
# Windows: winget install Insecure.Nmap

# 2. Set up Python 3.11+ Virtual Environment
python -m venv venv
# Linux/macOS: source venv/bin/activate
# Windows: .\\venv\\Scripts\\activate
pip install -r requirements.txt

# 3. Launch Backend API Gateway
python main.py

# 4. In a second terminal, launch Async DAG Worker
python worker.py

# 5. In a third terminal, launch Vite Frontend
cd frontend
npm install
npm run dev`}
                </pre>
              </div>
            )}
          </div>
        )}

        {/* ========================================================================= */}
        {/* SECTION: 10-STEP PIPELINE */}
        {/* ========================================================================= */}
        {activeSection === 'pipeline' && (
          <div className="space-y-6 animate-fade-in">
            <div>
              <div className="text-xs font-mono text-cyan-signal uppercase tracking-wider font-bold">
                Reconnaissance Engine
              </div>
              <h1 className="text-2xl lg:text-3xl font-display font-bold text-text-primary mt-1">
                10-Stage Asynchronous DAG Pipeline
              </h1>
              <p className="text-sm text-text-dim mt-2 font-mono leading-relaxed">
                Recon7 executes a non-linear, multi-threaded DAG pipeline where independent branches run in parallel to maximize throughput and minimize network latency.
              </p>
            </div>

            <div className="space-y-3 font-mono text-xs">
              {[
                {
                  step: 'Stage 01',
                  name: 'Company & ASN Resolution',
                  desc: 'Queries RDAP, WHOIS, and autonomous system registries to extract registered organization names, IP blocks, and BGP networks.',
                  sensor: 'recon.company_resolve',
                },
                {
                  step: 'Stage 02',
                  name: 'Subdomain Discovery & CT Log Streaming',
                  desc: 'Unions crt.sh, Certspotter, HackerTarget, Censys Certificate SAN records, and Subfinder to enumerate full domain attack surface.',
                  sensor: 'recon.subdomains',
                },
                {
                  step: 'Stage 03',
                  name: 'Direct Origin IP Extraction (CDN Bypass)',
                  desc: 'Inspects SPF TXT netblocks, mail server MX addresses, and global SSL host fingerprints to discover bare-metal IP addresses hidden behind Cloudflare and Akamai WAFs.',
                  sensor: 'recon.origin_extractor',
                },
                {
                  step: 'Stage 04',
                  name: 'Concurrent Port & Service Sweeps',
                  desc: 'Executes non-CDN prioritized SYN sweeps and Nmap service banner extraction across ports (21, 22, 80, 443, 8080, 8443, 5432, 6379, etc.).',
                  sensor: 'recon.ports',
                },
                {
                  step: 'Stage 05',
                  name: 'Web Tech & Header Fingerprinting',
                  desc: 'Deep probes HTTP response headers, meta generators, cookies, and favicon hashes to identify underlying frameworks (Next.js, Django, Laravel, WordPress, Jenkins, etc.).',
                  sensor: 'recon.fingerprint',
                },
                {
                  step: 'Stage 06',
                  name: 'Nuclei Vulnerability Pattern Matching',
                  desc: 'Executes community vulnerability templates for exposed configs (.env, .git), open Swagger/Actuator endpoints, and misconfigured panel logins.',
                  sensor: 'vuln.nuclei_match',
                },
                {
                  step: 'Stage 07',
                  name: 'CVE Correlation & NVD Scoring',
                  desc: 'Cross-references identified software versions against NIST NVD and OWASP Top 10 to establish exact CVSS severity scores.',
                  sensor: 'vuln.cve_lookup',
                },
                {
                  step: 'Stage 08',
                  name: 'People OSINT & Email Deliverability',
                  desc: 'Scrapes team directories, LinkedIn profile indexes, Wayback Machine archives, and GitHub commit authors. Automatically infers corporate email syntax ({first}.{last}@target.com) and performs zero-bounce SMTP deliverability verification.',
                  sensor: 'people.aggregate',
                },
                {
                  step: 'Stage 09',
                  name: 'Deterministic Threat Triage & Attack Path Synthesis',
                  desc: 'Evaluates asset graph relationships locally to identify critical exploit chains, credential exposure risks, and defensive remediation priorities without sending data to third-party cloud APIs.',
                  sensor: 'ai.triage',
                },
                {
                  step: 'Stage 10',
                  name: 'Executive Engagement Report Generation',
                  desc: 'Compiles an executive-grade Markdown audit document complete with executive summaries, CVSS scoreboards, attack surface graphs, and tactical remediation roadmaps.',
                  sensor: 'ai.report_writer',
                },
              ].map((st, i) => (
                <div key={i} className="p-4 rounded-xl bg-panel border border-border-dim space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] text-cyan-signal font-bold tracking-wider">{st.step}</span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-void border border-border-dim text-text-dim">
                      {st.sensor}
                    </span>
                  </div>
                  <h4 className="text-sm font-bold text-text-primary">{st.name}</h4>
                  <p className="text-text-dim text-[11px] leading-relaxed">{st.desc}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* SECTION: ZERO-TRUST LOCAL TRIAGE ENGINE */}
        {/* ========================================================================= */}
        {activeSection === 'ai-gateway' && (
          <div className="space-y-6 animate-fade-in">
            <div>
              <div className="text-xs font-mono text-cyan-signal uppercase tracking-wider font-bold">
                Zero-Trust Security & Privacy
              </div>
              <h1 className="text-2xl lg:text-3xl font-display font-bold text-text-primary mt-1">
                Zero-Trust Local Triage Engine
              </h1>
              <p className="text-sm text-text-dim mt-2 font-mono leading-relaxed">
                Recon7 is architected with a strict zero-trust data privacy mandate. All reconnaissance analysis, threat correlation, and executive report generation execute 100% locally within your infrastructure.
              </p>
            </div>

            <div className="p-5 rounded-xl bg-panel border border-border-dim space-y-4 font-mono text-xs">
              <div className="text-emerald-400 font-bold flex items-center gap-2 text-sm">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                <span>Enterprise Data Leakage Safeguards</span>
              </div>
              <div className="space-y-2 text-text-dim text-xs leading-relaxed">
                <p>
                  To protect enterprise infrastructure telemetry, IP addresses, subdomains, and corporate personnel profiles, Recon7 strictly avoids transmitting scan findings to external cloud LLM providers (e.g. Anthropic Claude, OpenAI).
                </p>
                <p>
                  All vulnerability prioritization, attack path synthesis, and CVSS score calculations are performed via deterministic local algorithms and local model runtimes (such as Ollama on <code className="text-cyan-signal">:11434</code>), guaranteeing zero telemetry leakage.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* SECTION: CONNECTORS & OSINT */}
        {/* ========================================================================= */}
        {activeSection === 'connectors' && (
          <div className="space-y-6 animate-fade-in">
            <div>
              <div className="text-xs font-mono text-cyan-signal uppercase tracking-wider font-bold">
                Threat Intelligence & OSINT
              </div>
              <h1 className="text-2xl lg:text-3xl font-display font-bold text-text-primary mt-1">
                OSINT Connectors & API Keys
              </h1>
              <p className="text-sm text-text-dim mt-2 font-mono leading-relaxed">
                Connect external intelligence feeds to enrich the knowledge graph with verified enterprise data.
              </p>
            </div>

            <div className="space-y-4 font-mono text-xs">
              <div className="p-4 rounded-xl bg-panel border border-border-dim space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-text-primary text-sm flex items-center gap-2">
                    <Globe className="w-4 h-4 text-cyan-signal" />
                    <span>Censys Search & Platform (v2 / v3 PAT)</span>
                  </span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-void border border-border-dim text-cyan-signal font-bold">
                    v2 & v3 PAT Ready
                  </span>
                </div>
                <p className="text-text-dim leading-relaxed">
                  Ingests internet-wide IPv4 scans, SAN certificates, and bare-metal servers hosting target SSL certs. Supports both v2 API ID/Secret and v3 Personal Access Tokens (Bearer PAT) with optional Organization ID headers.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-panel border border-border-dim space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-text-primary text-sm flex items-center gap-2">
                    <Activity className="w-4 h-4 text-cyan-signal" />
                    <span>GitHub Personal Access Token</span>
                  </span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-void border border-border-dim text-emerald-400 font-bold">
                    5,000 Req/Hr Quota
                  </span>
                </div>
                <p className="text-text-dim leading-relaxed">
                  Automatically raises GitHub public API rate limits from 60 to 5,000 requests/hr for harvesting repository members, commit author emails, and leaked secrets.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-panel border border-border-dim space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-text-primary text-sm flex items-center gap-2">
                    <Search className="w-4 h-4 text-cyan-signal" />
                    <span>Search Engine Connectors (SerpAPI & Google CSE)</span>
                  </span>
                </div>
                <p className="text-text-dim leading-relaxed">
                  Used for Google dorking, discovering indexed subdomains, and extracting public PDF/DOCX metadata. Automatically caches query results for 7 days to preserve search quotas.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* SECTION: SCOPE ENFORCEMENT */}
        {/* ========================================================================= */}
        {activeSection === 'governance' && (
          <div className="space-y-6 animate-fade-in">
            <div>
              <div className="text-xs font-mono text-cyan-signal uppercase tracking-wider font-bold">
                Governance & Compliance
              </div>
              <h1 className="text-2xl lg:text-3xl font-display font-bold text-text-primary mt-1">
                Cryptographic Scope Authorization Gate
              </h1>
              <p className="text-sm text-text-dim mt-2 font-mono leading-relaxed">
                Recon7 prevents accidental, unauthorized, or rogue network scanning by enforcing strict multi-tenant scope attestation.
              </p>
            </div>

            <div className="p-5 rounded-xl bg-panel border border-border-dim space-y-3 font-mono text-xs">
              <div className="text-text-primary font-bold flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span>Scope Authorization Rules</span>
              </div>
              <ul className="space-y-2 text-text-dim list-disc pl-5 leading-relaxed">
                <li>
                  <strong className="text-text-primary">Pre-Flight Scope Verification:</strong> Before any scan is queued in the database, the API checks the <code className="text-cyan-signal">authorized_scopes</code> table for an active, unexpired scope record.
                </li>
                <li>
                  <strong className="text-text-primary">Attestation Logging:</strong> Every registered scope stores the authorization type (e.g. Engagement Letter, Bug Bounty Agreement, Internal Ownership) and the authorizing security officer's email.
                </li>
                <li>
                  <strong className="text-text-primary">Domain Boundary Clamping:</strong> Subdomain and origin discovery engines discard any hostname not matching the canonical root domain or authorized CIDR.
                </li>
              </ul>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* SECTION: OPENAPI REST REFERENCE */}
        {/* ========================================================================= */}
        {activeSection === 'api-ref' && (
          <div className="space-y-6 animate-fade-in">
            <div>
              <div className="text-xs font-mono text-cyan-signal uppercase tracking-wider font-bold">
                Developer API
              </div>
              <h1 className="text-2xl lg:text-3xl font-display font-bold text-text-primary mt-1">
                RESTful OpenAPI Reference
              </h1>
              <p className="text-sm text-text-dim mt-2 font-mono leading-relaxed">
                Interact with the Recon7 API programmatically using standard HTTP JSON endpoints.
              </p>
            </div>

            <div className="space-y-4 font-mono text-xs">
              {/* Endpoint 1 */}
              <div className="p-4 rounded-xl bg-panel border border-border-dim space-y-2">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded bg-cyan-signal/20 border border-cyan-signal/40 text-cyan-signal font-bold text-[10px]">
                    POST
                  </span>
                  <code className="text-text-primary font-bold">/scan</code>
                </div>
                <p className="text-text-dim text-[11px]">
                  Trigger an asynchronous reconnaissance scan against an authorized target domain.
                </p>
                <pre className="p-3 rounded-lg bg-void text-cyan-bright border border-border-dim text-[11px]">
{`curl -X POST http://localhost:8080/scan \\
  -H "Authorization: Bearer <JWT_TOKEN>" \\
  -H "Content-Type: application/json" \\
  -d '{"domain": "target.com", "scan_profile": "standard", "org_name": "Target Corp"}'`}
                </pre>
              </div>

              {/* Endpoint 2 */}
              <div className="p-4 rounded-xl bg-panel border border-border-dim space-y-2">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded bg-emerald-400/20 border border-emerald-400/40 text-emerald-400 font-bold text-[10px]">
                    GET
                  </span>
                  <code className="text-text-primary font-bold">/scan/{'{job_id}'}</code>
                </div>
                <p className="text-text-dim text-[11px]">
                  Retrieve real-time scan status, completed stages, and metrics.
                </p>
                <pre className="p-3 rounded-lg bg-void text-cyan-bright border border-border-dim text-[11px]">
{`curl -X GET http://localhost:8080/scan/d51b47d0-9497-4caf-963b-340f28cff35c \\
  -H "Authorization: Bearer <JWT_TOKEN>"`}
                </pre>
              </div>

              {/* Endpoint 3 */}
              <div className="p-4 rounded-xl bg-panel border border-border-dim space-y-2">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded bg-cyan-signal/20 border border-cyan-signal/40 text-cyan-signal font-bold text-[10px]">
                    POST
                  </span>
                  <code className="text-text-primary font-bold">/scopes</code>
                </div>
                <p className="text-text-dim text-[11px]">
                  Register an authorized domain scope with formal legal attestation.
                </p>
                <pre className="p-3 rounded-lg bg-void text-cyan-bright border border-border-dim text-[11px]">
{`curl -X POST http://localhost:8080/scopes \\
  -H "Authorization: Bearer <JWT_TOKEN>" \\
  -H "Content-Type: application/json" \\
  -d '{"domain": "target.com", "authorization_type": "engagement_letter", "authorized_by": "lead@target.com"}'`}
                </pre>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
