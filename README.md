# 🔐 CertAI — Security Certification Copilot

> From GitHub repo to full security certification package in 60 seconds.

GoDaddy teams wait **30–134 days** on average for security certification. CertAI eliminates the prep work: give it an internal GitHub repo, get the complete package — risk category, architecture diagram, threat model, 29 questionnaire answers, and an IRP draft — streamed live to your browser.

**Built for the GoDaddy "Compress the Cycle" Hackathon — March 2026.**

---

## What it produces

- **Risk Category** (CAT 0–3) with reasoning from your code
- **Architecture Diagram** — auto-generated Mermaid SVG
- **Threat Model** — component-level threats with `file:line` code citations
- **Security Questionnaire** — all 29 GoDaddy CRR questions answered
- **Incident Response Plan** — draft tailored to your repo
- **One-click publish** to Confluence + Jira ticket creation

---

## Running locally

### Prerequisites

- Node.js 22+
- Access to GoDaddy VPN (required for GoCode proxy + internal GitHub)
- A [GoCode API key](https://godaddy-corp.atlassian.net/wiki/spaces/BI/pages/3843663280)
- A GitHub Enterprise PAT from `github.secureserver.net`
  - Settings → Developer settings → Personal access tokens
  - Scope: `Contents: Read-only`
- An Atlassian personal API token from [id.atlassian.com](https://id.atlassian.com/manage-profile/security/api-tokens)

### 1. Clone and install

```bash
git clone https://github.com/skilaru-godaddy/certai.git
cd certai
npm install
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env` and fill in:

```bash
# Required
GOCODE_API_KEY=your_gocode_api_key
GITHUB_PAT=your_github_pat

# Required for Confluence + Jira publish
ATLASSIAN_EMAIL=you@godaddy.com
ATLASSIAN_API_TOKEN=your_atlassian_api_token
```

### 3. Start

```bash
npm run dev
```

- **Web app** → http://localhost:5173
- **API server** → http://localhost:3001

Paste any `https://github.secureserver.net/org/repo` URL and click **Analyze**.

Optional inputs:
- **Branch** (defaults to `main` if blank)
- **Feature/module context** (free text to focus the review, e.g. "recently added billing webhook module")

---

## Slack slash command (optional)

### Setup

1. Go to [api.slack.com/apps](https://api.slack.com/apps) → Create New App → From scratch
2. **Slash Commands** → Create New Command:
   - Command: `/certai`
   - Request URL: `https://<ngrok-url>/slack/events` *(fill in after step 4)*
   - Usage hint: `https://github.secureserver.net/org/repo`
3. **OAuth & Permissions** → Bot Token Scopes: `chat:write`, `im:write`, `commands`
4. Install to workspace → copy **Bot User OAuth Token** (`xoxb-...`)
5. **Basic Information** → copy **Signing Secret**
6. Add to `.env`:
   ```bash
   SLACK_BOT_TOKEN=xoxb-...
   SLACK_SIGNING_SECRET=...
   ```

### Run with Slack

```bash
# Terminal 1 — app
npm run dev

# Terminal 2 — ngrok tunnel for Slack webhook
ngrok http 3002
```

Paste the ngrok URL + `/slack/events` into the Slack app's slash command Request URL.

Then in any Slack channel:

```
/certai https://github.secureserver.net/org/repo
```

The bot acknowledges immediately, DMs you when done with a **View Full Report** button.

---

## Tech stack

| Layer | Technology |
|-------|-----------|
| AI | `claude-sonnet-4-6` via **GoCode proxy** (GoDaddy internal LiteLLM) |
| AI SDK | `@anthropic-ai/sdk` — extended thinking, streaming, tool use |
| Backend | Fastify v5 + TypeScript, SSE streaming |
| Frontend | Vite + React 19 + Tailwind CSS v4 |
| Diagrams | Mermaid.js v11 — live SVG render |
| GitHub | `@octokit/rest` v21 → `github.secureserver.net` |
| Slack | `@slack/bolt` v4 |
| Publish | Atlassian REST API v2 (Confluence + Jira) |

---

## Project structure

```
certai/
├── packages/
│   ├── server/src/
│   │   ├── index.ts                # Fastify app
│   │   ├── routes/
│   │   │   ├── analyze.ts          # POST /analyze, GET /stream/:jobId, GET /job/:jobId
│   │   │   ├── publish.ts          # POST /publish → Confluence + Jira
│   │   │   └── slack.ts            # /certai slash command
│   │   └── lib/
│   │       ├── github.ts           # Repo fetching + file prioritization
│   │       ├── claude.ts           # GoCode proxy client + prompt builder
│   │       ├── analyzer.ts         # Job store + analysis pipeline
│   │       └── atlassian.ts        # Confluence page + Jira ticket creation
│   └── web/src/
│       ├── App.tsx                 # Main layout + deep link (?jobId=)
│       └── components/
│           ├── AnalysisStream.tsx  # Live phase progress + thinking preview
│           ├── MermaidDiagram.tsx  # Architecture SVG renderer
│           ├── ThreatTable.tsx     # Threat model cards
│           ├── Questionnaire.tsx   # 29-item accordion
│           └── ResultView.tsx      # Tabbed results + publish panel
└── .env.example                    # All required env vars documented
```

---

## How it works

```
Developer → pastes repo URL
         → CertAI fetches file tree from github.secureserver.net
         → prioritizes 14 security-relevant files (README, Dockerfile, CDK stacks, auth, routes, deps...)
         → streams to Claude Sonnet 4.6 via GoCode proxy (extended thinking enabled)
         → Claude reasons through risk category, threats, questionnaire, IRP
         → results stream live to browser as they generate
         → one click → Confluence page created, Jira ticket linked
```

All Claude calls route through GoDaddy's GoCode proxy — no data leaves GoDaddy's network.
