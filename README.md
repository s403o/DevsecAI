# 🛡️ DevSecAI

**Autonomous multi-agent GitHub PR reviewer & security auditing platform.**

[![Live Demo](https://img.shields.io/badge/Live_Demo-devsecai--nikhil.onrender.com-brightgreen.svg?logo=render)](https://devsecai-nikhil.onrender.com)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg?logo=typescript)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20.x-green.svg?logo=node.js)](https://nodejs.org/)
[![Vitest](https://img.shields.io/badge/Vitest-3.x-yellow.svg?logo=vitest)](https://vitest.dev/)
[![Hono](https://img.shields.io/badge/Hono-4.x-e36002.svg?logo=hono)](https://hono.dev/)
[![SARIF v2.1.0](https://img.shields.io/badge/SARIF-2.1.0-purple.svg)](https://sarifweb.azurewebsites.net/)
[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

DevSecAI ingests a GitHub pull request diff, splits it into scope-aware code blocks, and runs
specialised agents over each block to find security and performance defects. The findings are
deduplicated and risk-scored by an arbiter agent, then returned as review comments, synthesized
regression tests, ready-to-apply git patches, and a SARIF report for GitHub Code Scanning.

🌐 **Live demo:** [devsecai-nikhil.onrender.com](https://devsecai-nikhil.onrender.com)

---

## Table of contents

- [How it works](#how-it-works)
- [Features](#features)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [API reference](#api-reference)
- [GitHub webhook setup](#github-webhook-setup)
- [Project layout](#project-layout)
- [Testing](#testing)
- [Deployment](#deployment)
- [Current limitations](#current-limitations)
- [Contributing](#contributing)
- [License](#license)

---

## How it works

```text
                  GitHub webhook  ──▶  POST /api/webhooks/github
                                        (HMAC SHA-256 verified)
                                                 │
                                                 ▼
                                       Hono API gateway
                                                 │
                                                 ▼
                              Diff parser + scope-boundary chunker
                          (hunks enriched with enclosing function/class)
                                                 │
                        ┌────────────────────────┴────────────────────────┐
                        ▼                                                 ▼
              🛡️ Security agent                                ⚡ Performance agent
              OWASP / CWE patterns                             N+1 query loops
              SQLi · XSS · RCE                                  unawaited async
              hardcoded secrets                                 resource waste
                        │                                                 │
                        └────────────────────────┬────────────────────────┘
                                                 ▼
                                  🧪 Test generator agent
                                (synthesizes Vitest suites)
                                                 │
                                                 ▼
                                    ⚖️ Arbiter agent
                        dedupe · risk score 0-100 · confidence filter
                                                 │
         ┌───────────────────┬───────────────────┼───────────────────┬───────────────────┐
         ▼                   ▼                   ▼                   ▼                   ▼
   🔧 Auto-remediation   💾 SARIF 2.1.0    🕸️ Blast radius    📋 Policy engine    ⚡ Model arena
   unified git patches   Code Scanning     dependency graph   custom rulesets     benchmark view
```

The pipeline is orchestrated in [`src/orchestrator/pipeline.ts`](src/orchestrator/pipeline.ts).
Security and performance agents run in parallel; the test generator and arbiter run afterwards
because they consume the merged findings.

---

## Features

| Feature | Description | Source |
| --- | --- | --- |
| **Multi-agent review** | Security and performance agents analyse each diff chunk in parallel, then an arbiter deduplicates findings and computes a 0–100 risk score. | [`src/agents/`](src/agents/) |
| **Scope-aware chunking** | Diff hunks are expanded to their enclosing function, class, or route handler so agents see usable context instead of bare `+`/`-` lines. | [`src/parser/ast-chunker.ts`](src/parser/ast-chunker.ts) |
| **Auto-remediation patches** | Each finding with a suggested fix becomes a unified `diff --git` patch on a `devsecai/auto-fix-*` branch name. | [`src/remediation/patch-engine.ts`](src/remediation/patch-engine.ts) |
| **SARIF v2.1.0 export** | Findings export to OASIS SARIF for the GitHub Advanced Security → Code Scanning tab. | [`src/security/sarif-exporter.ts`](src/security/sarif-exporter.ts) |
| **Blast-radius graph** | Maps how a vulnerable block propagates to API endpoints, database entities, and auth middleware. | [`src/graph/blast-radius.ts`](src/graph/blast-radius.ts) |
| **Policy engine** | Toggleable custom rules (e.g. *mandatory Zod validation*, *strict JWT expiry*) injected into agent prompts. | [`src/policy/policy-engine.ts`](src/policy/policy-engine.ts) |
| **Model arena** | Side-by-side comparison view of detection recall, latency, tokens, and cost per model. *(See [limitations](#current-limitations).)* | [`src/ai/model-arena.ts`](src/ai/model-arena.ts) |
| **Interactive dashboard** | Single-page UI served at `/` — paste a diff, run a review, browse every feature tab. | [`src/server.ts`](src/server.ts) |

---

## Quick start

**Requirements:** Node.js 20 or newer.

```bash
git clone https://github.com/<your-org>/DevsecAI.git
cd DevsecAI
npm install
```

Run the test suite:

```bash
npm test
```

Start the dashboard and API:

```bash
npm run dev      # watch mode via tsx
# or
npm run build && npm start
```

Open <http://localhost:3000> and paste a diff, or use a bundled sample:

```bash
npm run review:demo      # single review over examples/sample-pr.diff
npm run demo:features    # exercises every feature module
```

To call the API directly, see the [API reference](#api-reference).

### npm scripts

| Script | Purpose |
| --- | --- |
| `npm run dev` | Start the server in watch mode (`tsx watch`). |
| `npm run build` | Type-check and emit JavaScript to `dist/`. |
| `npm start` | Run the compiled server from `dist/`. |
| `npm test` | Run the Vitest suite once. |
| `npm run review:demo` | Review the bundled sample PR diff and print the result. |
| `npm run demo:features` | Run every enterprise feature module end to end. |

---

## Configuration

All configuration is environment-based and validated with Zod at startup
([`src/config/env.ts`](src/config/env.ts)). Copy the table below into a `.env` file — it is
git-ignored.

| Variable | Default | Description |
| --- | --- | --- |
| `PORT` | `3000` | HTTP listen port. |
| `NODE_ENV` | `development` | `development`, `production`, or `test`. |
| `GITHUB_WEBHOOK_SECRET` | dev fallback | HMAC secret for webhook verification. **Required in production** — the server refuses to boot with the shared dev fallback. |
| `GITHUB_TOKEN` | — | Token used to fetch PR diffs and submit reviews. |
| `GEMINI_API_KEY` | — | Enables the Gemini provider. |
| `OPENAI_API_KEY` | — | Enables the OpenAI provider. |
| `GROQ_API_KEY` | — | Enables the Groq provider. |
| `ANTHROPIC_API_KEY` | — | Accepted by config; no request path wired yet (see [limitations](#current-limitations)). |
| `DEFAULT_LLM_PROVIDER` | auto-detected | `gemini`, `openai`, `anthropic`, `groq`, `dynamic`, or `mock`. Auto-detected from whichever API key is present. |
| `AI_MODEL_NAME` | provider-dependent | Model id, e.g. `gemini-1.5-flash` or `gpt-4o-mini`. |
| `DATABASE_URL` | local postgres | Connection string for repo memory. |
| `MIN_CONFIDENCE_THRESHOLD` | `0.70` | Findings below this confidence are dropped by the arbiter. |
| `MAX_DIFF_LINES` | `5000` | Diffs larger than this are truncated before chunking. |

**No API key is required to try the project.** With no key configured, the provider falls back to
`dynamic` — a local deterministic engine in [`src/ai/llm-provider.ts`](src/ai/llm-provider.ts) that
detects SQLi, hardcoded secrets, `eval`, XSS, N+1 loops, and unawaited `forEach` with regex rules.
It is what the test suite and the live demo run on.

---

## API reference

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/` | Interactive dashboard. |
| `GET` | `/health` | Liveness probe with version, capabilities, and active LLM provider. |
| `POST` | `/api/review` | Review a diff. Body: `{ diff, repoName?, prId?, prTitle?, prAuthor? }`. `diff` is required. |
| `POST` | `/api/export/sarif` | Convert a review result to SARIF v2.1.0. Body: `{ reviewResult }`. |
| `GET` | `/api/policies` | List all policy rules. |
| `POST` | `/api/policies` | Create a policy rule. |
| `POST` | `/api/policies/toggle` | Enable/disable a rule. Body: `{ id }`. |
| `POST` | `/api/benchmark` | Run the model arena comparison. Body: `{ diff }`. |
| `POST` | `/api/webhooks/github` | GitHub webhook ingestion. Requires a valid `x-hub-signature-256`. |

Example:

```bash
curl -X POST http://localhost:3000/api/review \
  -H 'Content-Type: application/json' \
  -d '{
    "diff": "diff --git a/src/db.ts b/src/db.ts\n@@ -1 +1,2 @@\n+const q = `SELECT * FROM users WHERE id = ${req.params.id}`;\n",
    "repoName": "acme/api",
    "prTitle": "Add user lookup"
  }'
```

Returns findings, generated tests, patches, a risk score, and an `APPROVE` / `REQUEST_CHANGES`
decision.

---

## GitHub webhook setup

1. Set `GITHUB_WEBHOOK_SECRET` and `GITHUB_TOKEN` in your environment.
2. In your repository: **Settings → Webhooks → Add webhook**.
3. Payload URL: `https://<your-host>/api/webhooks/github`
4. Content type: `application/json`
5. Secret: the same value as `GITHUB_WEBHOOK_SECRET`.
6. Events: **Pull requests** only.

Every request is HMAC SHA-256 verified with `crypto.timingSafeEqual` before any processing
([`src/github/webhook-handler.ts`](src/github/webhook-handler.ts)). Unsigned or mis-signed
requests get `401`. Only `opened`, `synchronize`, and `reopened` actions trigger a review; the
review itself runs asynchronously so GitHub receives an immediate `200`.

---

## Project layout

```text
src/
  agents/         security, performance, test-generator, and arbiter agents
  ai/             LLM provider abstraction + model arena benchmark
  config/         Zod-validated environment configuration
  db/             schema and repo memory
  github/         webhook signature verification and Octokit client
  graph/          blast-radius dependency analysis
  observability/  tracing helpers
  orchestrator/   review pipeline that sequences the agents
  parser/         diff parser and scope-boundary chunker
  policy/         custom ruleset engine
  remediation/    unified-diff patch generation
  security/       SARIF v2.1.0 exporter
  types/          shared TypeScript types
  server.ts       Hono routes + dashboard UI
tests/            Vitest suites
examples/         runnable demos and a sample PR diff
```

---

## Testing

```bash
npm test                       # full suite
npx vitest run tests/webhook.test.ts   # a single file
npx vitest                     # watch mode
npx tsc --noEmit               # type-check only
```

The suite covers the review pipeline, each enterprise feature module, and webhook signature
verification. It needs no API keys or database — the deterministic provider backs every test.

---

## Deployment

**Docker:**

```bash
docker build -t devsecai .
docker run -p 3000:3000 -e GITHUB_WEBHOOK_SECRET=<secret> -e NODE_ENV=production devsecai
```

**Render:** [`render.yaml`](render.yaml) defines the service. Add `GITHUB_WEBHOOK_SECRET` and
`GITHUB_TOKEN` as environment variables in the dashboard — the server intentionally refuses to
start in production without a real webhook secret.

---

## Current limitations

Stated plainly so the behaviour matches the docs:

- **Chunking is heuristic, not a real AST parse.** The chunker uses brace/indentation and regex
  scope detection rather than a language grammar. It handles common TypeScript and JavaScript
  shapes well and degrades on unusual formatting.
- **The model arena returns fixed sample data.** `runBenchmark()` returns a static comparison
  table for the UI; it does not currently dispatch live requests to each provider.
- **`ANTHROPIC_API_KEY` is not wired.** Config accepts it, but `LLMProvider` implements Gemini,
  OpenAI, and Groq request paths only. Setting only this key falls through to the deterministic
  engine.
- **Provider failures fall back silently.** If a live provider call throws, the pipeline drops to
  the deterministic engine without surfacing the error.
- **Repo memory is not persisted.** `DATABASE_URL` is validated but the review pipeline does not
  yet write findings to Postgres.

---

## Contributing

1. Fork and branch: `git checkout -b feat/my-change`
2. Keep `npm test` and `npx tsc --noEmit` green.
3. Add a test alongside any behaviour change — see [`tests/`](tests/) for the style.
4. Open a pull request describing what broke and why the change fixes it.

---

## License

[MIT](LICENSE) © Dappili Nikhileshwar Reddy
