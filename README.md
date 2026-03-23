# 🛡️ Web Security Exposure Analyzer

A professional-grade, multi-phase security scanning engine designed to identify technology stacks, discover vulnerabilities, and perform behavioral analysis on web applications.

![System Overview](https://img.shields.io/badge/Scan_Phases-1_through_7-blue?style=for-the-badge)
![Tech Stack](https://img.shields.io/badge/Stack-Node.js_|_React_|_Redis-green?style=for-the-badge)

---

## 🏗️ System Architecture

```mermaid
graph TD
    Client[React Frontend] -->|REST API| API[Express Backend]
    API -->|Jobs| Redis[(Redis / BullMQ)]
    Redis -->|Fetch| Worker[Background Worker]
    Worker -->|Execute| Engine[Scan Engine]
    
    subgraph Scanning Pipeline
        Engine -->|Tech| TechScanner[Technology Scanner]
        Engine -->|Infra| DNS_SSL[DNS & SSL Scanners]
        Engine -->|Vuln| VulnScanner[Vulnerability Scanner]
        Engine -->|WAF| WAFScanner[WAF Detection & Evasion]
        Engine -->|Crawling| DeepCrawl[Isolated Puppeteer Crawler]
        Engine -->|AI| AIService[AI Analysis - Gemini/OpenAI]
        Engine -->|Behavior| BehaviorScanner[Behavioral Detection]
    end
    
    Worker -->|Update Status| Redis
    API -->|Poll Status| Redis
    API -->|Live Scan Results| Client
```

---

## 🚀 The 7 Phases of Security Scanning

The analyzer operates through an evolutionary sequence of phases, moving from basic discovery to advanced behavioral intelligence. Below is the internal flow of the Engine during a Deep Scan.

### **Phase 1-4: The Discovery & Infrastructure Pipeline**

```mermaid
graph TD
    Start((Begin Scan)) --> P1
    
    subgraph Phase_1_2 [Phase 1 & 2: Infrastructure]
        P1[Axios Initial GET] --> P1_A{Check Res}
        P1_A --> P1_B[Fetch DNS/SSL]
        P1_A --> P1_C[Parse Static Headers]
    end

    subgraph Phase_15_3 [Phase 1.5 & 3: WAF & Tech]
        P1_C --> WAF[WAFDetection]
        WAF -->|Identify Strategy| TechScan[Technology Fingerprinting]
        TechScan -->|Scripts| Ext[Cookie & Script Extract]
    end

    subgraph Phase_4 [Phase 4: Core Vulnerability Scanners]
        TechScan --> Vuln[Vulnerability Scanner]
        Ext --> Header[Header Scanner]
        Ext --> SSRF[SSRF & Endpoints]
        Ext --> Secrets[Secret Leaks & Admin]
    end

    Vuln --> Sync1((Wait For Discovery))
    Header --> Sync1
    SSRF --> Sync1
    Secrets --> Sync1
```

### **Phase 5-7: The Advanced Recon & Intelligence Pipeline**

```mermaid
graph TD
    Sync1((Post-Discovery)) --> P5
    
    subgraph Phase_5 [Phase 5: Authorization & Heuristics]
        P5[Endpoint Extraction] --> Auth[Auth Bypass Tester]
        Auth --> RateLimit[Rate Limit Scanner]
        RateLimit --> DNS_Intel[Subdomain Intel]
    end

    subgraph Phase_6 [Phase 6: OSINT & Infrastructure Pivot]
        DNS_Intel --> SubTake[Takeover Engine]
        DNS_Intel --> Wayback[Wayback Archiver]
        DNS_Intel --> ASN[ASN & Cloud Pivot]
        ASN --> CDN[CDN Bypass Tests]
        Wayback --> JS[JS Config Analyzer]
        Wayback --> GitHub[GitHub Leaks]
    end

    subgraph Phase_7 [Phase 7: Behavioral Engine]
        DNS_Intel --> B1[Baseline Tester]
        B1 --> B2[Payload Mutation]
        B2 --> B3[Anomaly Observer]
        B3 --> B4[Differential Grapher]
    end

    SubTake --> Agg((Data Aggregation))
    JS --> Agg
    B4 --> Agg
    Agg --> Graph[Attack Graph Synthesis]
    Graph --> AI[AI Expert Verification]
    AI --> Final((Send JSON to UI))
```

---

## 📈 Cross-Service Event Flow

```mermaid
sequenceDiagram
    participant User
    participant Frontend
    participant Backend
    participant Queue
    participant Worker
    participant Engine
    
    User->>Frontend: Submit target URL
    Frontend->>Backend: POST /api/scan
    Backend->>Queue: Push scan job
    Backend-->>Frontend: Return Job ID
    Queue->>Worker: Distribute job
    Worker->>Engine: engine.run(target, job)
    
    rect rgb(240, 240, 240)
        Note right of Engine: Live SSE Heartbeats
        Engine-->>Worker: Update Progress (15%)
        Worker-->>Queue: Process Event
        Queue-->>Frontend: WebSocket / Axios Poll
        
        Engine-->>Engine: Phase 1-7 Exhaustive Scan
        
        Engine-->>Worker: Update Progress (80%)
    end
    
    Engine->>Engine: Run Attack Chain Analyzer
    Worker->>Queue: Job Completed (Returns JSON)
    Frontend->>Backend: Poll /api/scan/:id
    Backend->>Queue: Get job results
    Backend-->>Frontend: Send detailed JSON report
    Frontend->>User: Display stunning UI visualization
```

---

## 🛠️ Tech Stack

- **Frontend**: React 18, Vite, Lucide Icons, Framer Motion.
- **Backend**: Node.js, Express.
- **Queue System**: BullMQ / Redis.
- **Scanning Core**: Puppeteer, Axios, Cheerio.
- **Security Logic**: Custom rule engines and behavioral heuristics.
- **AI Integration**: Google Gemini / OpenAI GPT-4.

---

## ⚙️ Installation & Setup

### Prerequisites
- Node.js (v18+)
- Redis Server

### 1. Clone & Install
```bash
git clone https://github.com/akshatatcodes/web_scanner.git
cd web_scanner

# Install Backend
cd backend
npm install

# Install Frontend
cd ../frontend
npm install
```

### 2. Configure Environment
Create a `.env` file in the `backend/` directory:
```env
PORT=5000
REDIS_URL=redis://localhost:6379
GEMINI_API_KEY=your_key_here
OPENAI_API_KEY=your_key_here
```

### 3. Run the Application
```bash
# Terminal 1: Backend
cd backend
node server.js

# Terminal 2: Worker
cd backend
node worker.js

# Terminal 3: Frontend
cd frontend
npm run dev
```

---

## 🛡️ License
Distributed under the MIT License. See `LICENSE` for more information.

---

<p align="center">
  Developed by <b>Akshat Jain</b>
</p>
