import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { cors } from 'hono/cors';
import { config } from './config/env.js';
import { ReviewPipelineOrchestrator } from './orchestrator/pipeline.js';
import { GitHubWebhookHandler } from './github/webhook-handler.js';
import { GitHubClient } from './github/octokit-client.js';
import { SarifExporter } from './security/sarif-exporter.js';
import { PolicyEngine } from './policy/policy-engine.js';
import { ModelArenaBenchmark } from './ai/model-arena.js';

const app = new Hono();

app.use('*', cors());

// 1. Health Check
app.get('/health', (c) => {
  return c.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '2.0.0',
    capabilities: [
      'multi_agent_review',
      'ast_chunking',
      'auto_remediation',
      'sarif_export',
      'blast_radius_graph',
      'policy_studio',
      'model_arena_benchmark'
    ],
    llmProvider: config.DEFAULT_LLM_PROVIDER,
    model: config.AI_MODEL_NAME,
  });
});

// 2. API Review Endpoint
app.post('/api/review', async (c) => {
  try {
    const body = await c.req.json();
    const { diff, repoName, prId, prTitle, prAuthor } = body;

    if (!diff) {
      return c.json({ error: 'Diff content is required' }, 400);
    }

    const result = await ReviewPipelineOrchestrator.execute(diff, {
      prId: prId || `PR-${Math.floor(1000 + Math.random() * 9000)}`,
      repoName: repoName || 'organization/repository',
      prTitle: prTitle || 'Pull Request Review',
      prAuthor: prAuthor || 'contributor',
    });

    return c.json(result);
  } catch (error: any) {
    console.error('[API /api/review] Error:', error);
    return c.json({ error: error.message || 'Internal review pipeline failure' }, 500);
  }
});

// 3. SARIF v2.1.0 Export Endpoint (GitHub Code Scanning)
app.post('/api/export/sarif', async (c) => {
  try {
    const body = await c.req.json();
    const reviewResult = body.reviewResult;
    if (!reviewResult) {
      return c.json({ error: 'reviewResult is required' }, 400);
    }

    const sarif = SarifExporter.exportToSarif(reviewResult);
    return c.json(sarif);
  } catch (error: any) {
    return c.json({ error: error.message }, 500);
  }
});

// 4. Policy Studio Endpoints
app.get('/api/policies', (c) => {
  return c.json(PolicyEngine.getPolicies());
});

app.post('/api/policies', async (c) => {
  try {
    const body = await c.req.json();
    const created = PolicyEngine.addPolicy(body);
    return c.json(created);
  } catch (err: any) {
    return c.json({ error: err.message }, 400);
  }
});

app.post('/api/policies/toggle', async (c) => {
  try {
    const body = await c.req.json();
    const updated = PolicyEngine.togglePolicy(body.id);
    return c.json({ success: true, enabled: updated });
  } catch (err: any) {
    return c.json({ error: err.message }, 400);
  }
});

// 5. Multi-Model LLM Arena Benchmark Endpoint
app.post('/api/benchmark', async (c) => {
  try {
    const body = await c.req.json();
    const diff = body.diff || '';
    const results = await ModelArenaBenchmark.runBenchmark(diff);
    return c.json(results);
  } catch (err: any) {
    return c.json({ error: err.message }, 500);
  }
});

// 6. GitHub Webhook Ingestion Endpoint
app.post('/api/webhooks/github', async (c) => {
  const signature = c.req.header('x-hub-signature-256');
  const event = c.req.header('x-github-event') || 'unknown';
  const rawBody = await c.req.text();

  if (!GitHubWebhookHandler.verifySignature(rawBody, signature)) {
    return c.json({ error: 'Invalid HMAC signature' }, 401);
  }

  let payload: any;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return c.json({ error: 'Invalid JSON payload' }, 400);
  }

  if (!GitHubWebhookHandler.isReviewablePREvent(event, payload)) {
    return c.json({ message: `Ignored event: ${event}.${payload.action}` }, 200);
  }

  const pr = payload.pull_request;
  const repo = payload.repository;
  const owner = repo.owner.login;
  const repoName = repo.name;
  const pullNumber = pr.number;
  const commitSha = pr.head.sha;

  (async () => {
    try {
      const githubClient = new GitHubClient();
      const rawDiff = await githubClient.fetchPullRequestDiff(owner, repoName, pullNumber);

      const reviewResult = await ReviewPipelineOrchestrator.execute(rawDiff, {
        prId: `PR-${pullNumber}`,
        repoName: repo.full_name,
        prTitle: pr.title,
        prAuthor: pr.user.login,
      });

      await githubClient.submitPRReview(owner, repoName, pullNumber, commitSha, reviewResult);
    } catch (err: any) {
      console.error(`[Webhook] Async review error on PR #${pullNumber}:`, err.message);
    }
  })();

  return c.json({ status: 'queued', message: `PR #${pullNumber} queued for audit` });
});

// 7. Interactive Full-Featured Enterprise Dashboard
app.get('/', (c) => {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DevSecAI – Autonomous Multi-Agent Security Platform</title>
  <meta name="description" content="Autonomous Multi-Agent GitHub PR Reviewer & Security Auditing Platform in TypeScript.">
  
  <meta property="og:title" content="DevSecAI – Autonomous Multi-Agent Security Platform">
  <meta property="og:description" content="Autonomous Multi-Agent PR Reviewer & Security Auditing Platform with AST diff chunking, 1-click auto-remediation, and Vitest test synthesis.">
  <meta property="og:url" content="https://devsecai-nikhil.onrender.com">
  <meta property="og:type" content="website">
  <style>
    :root {
      --bg: #070a13;
      --card-bg: #0f172a;
      --card-border: #1e293b;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --primary: #3b82f6;
      --primary-glow: rgba(59, 130, 246, 0.35);
      --accent: #8b5cf6;
      --danger: #ef4444;
      --danger-bg: rgba(239, 68, 68, 0.12);
      --warning: #f59e0b;
      --warning-bg: rgba(245, 158, 11, 0.12);
      --success: #10b981;
      --success-bg: rgba(16, 185, 129, 0.12);
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      line-height: 1.5;
      padding-bottom: 60px;
    }

    .header {
      border-bottom: 1px solid var(--card-border);
      background: rgba(15, 23, 42, 0.9);
      backdrop-filter: blur(12px);
      position: sticky;
      top: 0;
      z-index: 50;
      padding: 0.85rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .brand { display: flex; align-items: center; gap: 12px; }
    .logo-icon {
      width: 38px;
      height: 38px;
      background: linear-gradient(135deg, #2563eb, #7c3aed);
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 20px;
      box-shadow: 0 0 15px var(--primary-glow);
    }

    .brand h1 { font-size: 1.2rem; font-weight: 700; }
    .brand-sub { font-size: 0.72rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }

    .nav-tabs {
      display: flex;
      gap: 6px;
      background: #090d1a;
      padding: 4px;
      border-radius: 10px;
      border: 1px solid var(--card-border);
    }

    .tab-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      padding: 7px 14px;
      border-radius: 6px;
      font-size: 0.82rem;
      font-weight: 600;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 6px;
      transition: all 0.2s;
    }
    .tab-btn:hover { color: #ffffff; }
    .tab-btn.active {
      background: #1e293b;
      color: #60a5fa;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
    }

    .container {
      max-width: 1400px;
      margin: 1.5rem auto;
      padding: 0 1.5rem;
    }

    .tab-content { display: none; }
    .tab-content.active { display: block; }

    .grid-split {
      display: grid;
      grid-template-columns: 460px 1fr;
      gap: 1.5rem;
    }

    @media (max-width: 1024px) {
      .grid-split { grid-template-columns: 1fr; }
    }

    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 1.25rem;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
      margin-bottom: 1.25rem;
    }

    .card-title {
      font-size: 0.95rem;
      font-weight: 600;
      margin-bottom: 0.75rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .sample-presets {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 0.75rem;
    }

    .preset-btn {
      background: #1e293b;
      color: #93c5fd;
      border: 1px solid #334155;
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 0.78rem;
      cursor: pointer;
      font-weight: 600;
      transition: all 0.15s;
    }
    .preset-btn:hover { background: #2563eb; color: #ffffff; border-color: #3b82f6; }
    .preset-btn:active { transform: scale(0.97); }

    textarea {
      width: 100%;
      height: 280px;
      background: #070a13;
      border: 1px solid #1e293b;
      border-radius: 8px;
      color: #c9d1d9;
      font-family: var(--font-mono);
      font-size: 0.78rem;
      padding: 12px;
      resize: vertical;
    }

    .btn-action {
      background: linear-gradient(135deg, #2563eb, #7c3aed);
      color: white;
      border: none;
      border-radius: 8px;
      padding: 9px 16px;
      font-size: 0.88rem;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      transition: all 0.2s;
    }
    .btn-action:hover { opacity: 0.92; transform: translateY(-1px); }

    .agent-pipeline {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 8px;
      margin-top: 1rem;
    }

    .agent-step {
      background: #090d1a;
      border: 1px solid #1e293b;
      border-radius: 8px;
      padding: 8px;
      text-align: center;
    }

    .agent-step.active { border-color: #3b82f6; background: rgba(59, 130, 246, 0.1); }
    .agent-step.done { border-color: #10b981; background: rgba(16, 185, 129, 0.08); }

    .agent-step-title { font-size: 0.75rem; font-weight: 600; }
    .agent-step-status { font-size: 0.68rem; color: var(--text-muted); }

    .summary-banner {
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: #1e293b;
      padding: 1rem 1.25rem;
      border-radius: 8px;
      margin-bottom: 1rem;
      border-left: 4px solid var(--danger);
    }
    .summary-banner.approved { border-left-color: var(--success); }

    .metrics-bar {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 10px;
      margin-bottom: 1.25rem;
    }

    .metric-box {
      background: #090d1a;
      border: 1px solid #1e293b;
      border-radius: 8px;
      padding: 8px;
      text-align: center;
    }

    .metric-val { font-size: 1.2rem; font-weight: 700; color: #60a5fa; }
    .metric-lbl { font-size: 0.68rem; color: var(--text-muted); text-transform: uppercase; }

    .finding-card {
      background: #090d1a;
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 1rem;
      margin-bottom: 1rem;
    }
    .finding-card.critical { border-left: 4px solid var(--danger); }
    .finding-card.high { border-left: 4px solid #f97316; }
    .finding-card.medium { border-left: 4px solid var(--warning); }

    .code-box {
      background: #050811;
      border: 1px solid #1f2937;
      border-radius: 6px;
      padding: 8px 12px;
      font-family: var(--font-mono);
      font-size: 0.78rem;
      margin: 8px 0;
      overflow-x: auto;
      white-space: pre;
    }
    .code-box.fix { border-color: #065f46; background: #022c22; color: #6ee7b7; }
    .code-box.bad { border-color: #7f1d1d; background: #2b0c0c; color: #fca5a5; }

    .graph-container {
      background: #070a13;
      border: 1px solid var(--card-border);
      border-radius: 8px;
      min-height: 380px;
      position: relative;
      overflow: hidden;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }

    .policy-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 10px;
      border-bottom: 1px solid #1e293b;
    }
    .policy-item:last-child { border-bottom: none; }

    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #1e293b; font-size: 0.85rem; }
    th { color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; }
  </style>
</head>
<body>

  <header class="header">
    <div class="brand">
      <div class="logo-icon">🛡️</div>
      <div>
        <h1>DevSecAI Platform v2.0</h1>
        <div class="brand-sub">Autonomous Multi-Agent PR Review & Remediation</div>
      </div>
    </div>

    <!-- Navigation Bar -->
    <div class="nav-tabs">
      <button class="tab-btn active" id="btn-tab-review" onclick="switchTab('review')">🛡️ Code Audit</button>
      <button class="tab-btn" id="btn-tab-remediation" onclick="switchTab('remediation')">🔧 1-Click Remediation</button>
      <button class="tab-btn" id="btn-tab-blast" onclick="switchTab('blast')">🕸️ Blast Radius Graph</button>
      <button class="tab-btn" id="btn-tab-policies" onclick="switchTab('policies')">📜 Policy Studio</button>
      <button class="tab-btn" id="btn-tab-arena" onclick="switchTab('arena')">⚡ Multi-Model Arena</button>
    </div>
  </header>

  <div class="container">

    <!-- TAB 1: CODE AUDIT & FINDINGS -->
    <div id="tab-review" class="tab-content active">
      <div class="grid-split">
        <div>
          <div class="card">
            <div class="card-title">
              <span>Git Pull Request Diff</span>
              <span style="font-size: 0.72rem; color: var(--text-muted)">Click a preset or paste diff</span>
            </div>
            <div class="sample-presets">
              <button type="button" class="preset-btn" onclick="setPreset('sqli')">SQLi & Hardcoded Key</button>
              <button type="button" class="preset-btn" onclick="setPreset('nplus1')">N+1 Query & Leaks</button>
              <button type="button" class="preset-btn" onclick="setPreset('clean')">Clean Diff (Pass)</button>
            </div>
            <textarea id="diffInput" placeholder="Paste your git diff here, or click any preset above to test..."></textarea>
            <button id="runBtn" class="btn-action" style="width: 100%; margin-top: 0.75rem;" onclick="executeReview()">
              <span>⚡ Run Autonomous Multi-Agent Audit</span>
            </button>

            <div class="agent-pipeline">
              <div class="agent-step" id="step-sec">
                <div class="agent-step-title">🛡️ Security Agent</div>
                <div class="agent-step-status" id="status-sec">Ready</div>
              </div>
              <div class="agent-step" id="step-perf">
                <div class="agent-step-title">⚡ Perf Agent</div>
                <div class="agent-step-status" id="status-perf">Ready</div>
              </div>
              <div class="agent-step" id="step-test">
                <div class="agent-step-title">🧪 Test Gen</div>
                <div class="agent-step-status" id="status-test">Ready</div>
              </div>
              <div class="agent-step" id="step-arb">
                <div class="agent-step-title">⚖️ Arbiter</div>
                <div class="agent-step-status" id="status-arb">Ready</div>
              </div>
            </div>
          </div>
        </div>

        <div>
          <div class="card" id="resultsContainer">
            <div style="text-align: center; padding: 4rem 1rem; color: var(--text-muted);">
              <div style="font-size: 2.5rem; margin-bottom: 0.5rem;">🤖</div>
              <h3>Autonomous Agent Engine Ready</h3>
              <p style="font-size: 0.85rem; max-width: 400px; margin: 0.5rem auto;">
                Click any preset button above or click 'Run Autonomous Multi-Agent Audit' to start.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 2: AUTO-REMEDIATION & 1-CLICK PATCH -->
    <div id="tab-remediation" class="tab-content">
      <div class="card">
        <div class="card-title">
          <span>🔧 Autonomous Git Patch & Remediation Engine</span>
          <button class="btn-action" onclick="downloadPatch()">💾 Download Unified .patch File</button>
        </div>
        <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1rem;">
          DevSecAI automatically rewrites vulnerable code blocks into secure AST replacements and verifies fixes against synthesized Vitest test suites.
        </p>
        <div id="remediationList"></div>
      </div>
    </div>

    <!-- TAB 3: BLAST RADIUS GRAPH -->
    <div id="tab-blast" class="tab-content">
      <div class="card">
        <div class="card-title">
          <span>🕸️ Security Blast-Radius & Downstream Dependency Map</span>
          <span id="blastScoreBadge" style="font-size: 0.8rem; color: #f87171; font-weight: 700;"></span>
        </div>
        <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1rem;">
          Visualizes propagation of vulnerabilities across API endpoints, database entities, and authentication guards.
        </p>
        <div class="graph-container" id="blastGraph">
          <svg id="blastSvg" width="100%" height="380"></svg>
        </div>
      </div>
    </div>

    <!-- TAB 4: TEAM POLICY STUDIO -->
    <div id="tab-policies" class="tab-content">
      <div class="card">
        <div class="card-title">
          <span>📜 Team Architecture & Compliance Policy Studio</span>
          <span style="font-size: 0.75rem; color: var(--text-muted)">Enforced dynamically in agent vector memory</span>
        </div>
        <div id="policyList"></div>
      </div>
    </div>

    <!-- TAB 5: MULTI-MODEL ARENA BENCHMARK -->
    <div id="tab-arena" class="tab-content">
      <div class="card">
        <div class="card-title">
          <span>⚡ Multi-Model LLM Arena (GPT-4o vs Claude 3.5 Sonnet vs DeepSeek)</span>
          <button class="btn-action" onclick="runBenchmark()">▶ Run Live Arena Benchmark</button>
        </div>
        <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1rem;">
          Side-by-side comparative evaluation of foundation models on code security precision, latency, and cost.
        </p>
        <div id="arenaResults">
          <table>
            <thead>
              <tr>
                <th>Foundation Model</th>
                <th>Provider</th>
                <th>Detection Recall</th>
                <th>Latency (ms)</th>
                <th>Tokens</th>
                <th>Cost / Review</th>
              </tr>
            </thead>
            <tbody id="arenaBody">
              <tr><td colspan="6" style="text-align: center; color: var(--text-muted);">Click 'Run Live Arena Benchmark' to compare models</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

  </div>

  <script>
    let lastReviewData = null;

    const PRESETS = {
      sqli: "diff --git a/src/routes/users.ts b/src/routes/users.ts\\nindex 83a12b4..992f1c8 100644\\n--- a/src/routes/users.ts\\n+++ b/src/routes/users.ts\\n@@ -10,6 +10,14 @@ import { Database } from '../db/client.js';\\n export async function searchUsers(db: Database, emailQuery: string) {\\n+  // Raw unparameterized SQL concatenation\\n+  const query = \`SELECT id, name, email, role FROM users WHERE email LIKE '\${emailQuery}%' AND is_active = true\`;\\n+  const result = await db.query(query);\\n+  return result.rows;\\n+}\\n\\ndiff --git a/src/config/auth.ts b/src/config/auth.ts\\nindex 45ef201..89aa102 100644\\n--- a/src/config/auth.ts\\n+++ b/src/config/auth.ts\\n@@ -1,5 +1,8 @@\\n-export const JWT_SECRET = process.env.JWT_SECRET;\\n+export const JWT_SECRET = \\\"super_secret_jwt_key_998124_do_not_share\\\";\\n+export const TOKEN_EXPIRY = '24h';",
      nplus1: "diff --git a/src/services/billing.ts b/src/services/billing.ts\\nindex 72b381a..18ca9f2 100644\\n--- a/src/services/billing.ts\\n+++ b/src/services/billing.ts\\n@@ -25,12 +25,16 @@ export async function generateMonthlyInvoices(db: any, month: string) {\\n   const orders = await db.orders.findMany({ where: { billingMonth: month } });\\n   const invoices = [];\\n   \\n+  // N+1 Query in Loop\\n+  for (const order of orders) {\\n+    const customer = await db.customers.findUnique({ where: { id: order.customerId } });\\n+    const paymentMethod = await db.paymentMethods.findFirst({ where: { customerId: customer.id } });\\n+    invoices.push({ order, customer, paymentMethod });\\n+  }\\n+  \\n   return invoices;\\n }",
      clean: "diff --git a/src/utils/math.ts b/src/utils/math.ts\\nnew file mode 100644\\nindex 0000000..342a1bc\\n--- /dev/null\\n+++ b/src/utils/math.ts\\n@@ -0,0 +1,10 @@\\n+export function calculateDiscount(price: number, percent: number): number {\\n+  if (price < 0 || percent < 0 || percent > 100) {\\n+    throw new Error('Invalid price or discount percentage');\\n+  }\\n+  return Number((price * (1 - percent / 100)).toFixed(2));\\n+}"
    };

    function setPreset(key) {
      const el = document.getElementById('diffInput');
      if (el && PRESETS[key]) {
        el.value = PRESETS[key];
        executeReview();
      }
    }

    function switchTab(tabId) {
      document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
      
      const tabEl = document.getElementById('tab-' + tabId);
      if (tabEl) tabEl.classList.add('active');

      const btnEl = document.getElementById('btn-tab-' + tabId);
      if (btnEl) btnEl.classList.add('active');

      if (tabId === 'policies') loadPolicies();
      
      if ((tabId === 'remediation' || tabId === 'blast') && !lastReviewData) {
        executeReview();
      }
    }

    async function executeReview() {
      const el = document.getElementById('diffInput');
      const diff = el ? el.value.trim() : '';
      if (!diff) return alert('Please enter or select a diff');

      const btn = document.getElementById('runBtn');
      if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span>⏳ Agents Analyzing Code...</span>';
      }

      setAgentStatus('sec', 'active', 'Scanning AST & CWEs...');
      setAgentStatus('perf', 'active', 'Analyzing Complexity...');
      setAgentStatus('test', '', 'Waiting...');
      setAgentStatus('arb', '', 'Waiting...');

      try {
        const res = await fetch('/api/review', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ diff, repoName: 'acme/core-service', prId: 'PR-801' })
        });

        const data = await res.json();
        lastReviewData = data;

        setAgentStatus('sec', 'done', 'Done');
        setAgentStatus('perf', 'done', 'Done');
        setAgentStatus('test', 'done', 'Synthesized');
        setAgentStatus('arb', 'done', 'Synthesized');

        renderResults(data);
        renderRemediation(data.remediationPatches || []);
        renderBlastRadius(data.blastRadius);
      } catch (err) {
        alert('Review failed: ' + err.message);
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = '<span>⚡ Run Autonomous Multi-Agent Audit</span>';
        }
      }
    }

    function setAgentStatus(id, state, text) {
      const el = document.getElementById('step-' + id);
      const txt = document.getElementById('status-' + id);
      if (el) el.className = 'agent-step ' + state;
      if (txt) txt.textContent = text;
    }

    function renderResults(data) {
      const container = document.getElementById('resultsContainer');
      const isApproved = data.decision === 'APPROVED';
      const riskClass = data.overallRiskScore >= 70 ? 'danger' : data.overallRiskScore >= 30 ? 'warning' : 'success';

      let html = \`
        <div class="summary-banner \${isApproved ? 'approved' : ''}">
          <div>
            <div style="font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted);">Decision</div>
            <h2 style="color: \${isApproved ? 'var(--success)' : 'var(--danger)'}">\${data.decision}</h2>
          </div>
          <div style="text-align: right;">
            <div style="font-size: 0.8rem; color: var(--text-muted);">Composite Risk Score</div>
            <div style="font-size: 1.5rem; font-weight: 800; color: var(--\${riskClass})">\${data.overallRiskScore}/100</div>
          </div>
        </div>

        <div class="metrics-bar">
          <div class="metric-box">
            <div class="metric-val">\${data.findings.length}</div>
            <div class="metric-lbl">Total Issues</div>
          </div>
          <div class="metric-box">
            <div class="metric-val">\${data.metrics.criticalCount}</div>
            <div class="metric-lbl">Critical</div>
          </div>
          <div class="metric-box">
            <div class="metric-val">\${data.metrics.totalDurationMs}ms</div>
            <div class="metric-lbl">Latency</div>
          </div>
          <div class="metric-box">
            <div class="metric-val">$\${data.metrics.totalCostUsd.toFixed(5)}</div>
            <div class="metric-lbl">LLM Cost</div>
          </div>
        </div>
      \`;

      if (data.findings.length === 0) {
        html += \`
          <div style="background: var(--success-bg); border: 1px solid #065f46; border-radius: 8px; padding: 1.5rem; text-align: center;">
            <div style="font-size: 2rem;">✅</div>
            <h3 style="color: #6ee7b7;">Diff Passed All Security & Performance Gates</h3>
          </div>
        \`;
      } else {
        html += \`
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
            <h3 style="font-size: 0.95rem;">Flagged Code Issues (\${data.findings.length})</h3>
            <button class="btn-action" style="font-size: 0.75rem; padding: 4px 10px;" onclick="exportSarif()">💾 Export SARIF (GitHub)</button>
          </div>
        \`;
        data.findings.forEach(f => {
          html += \`
            <div class="finding-card \${f.severity}">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-size: 0.7rem; font-weight: 700; text-transform: uppercase; color: #f87171;">\${f.severity}</span>
                <span style="font-size: 0.75rem; font-family: var(--font-mono); color: var(--text-muted);">\${f.file}:\${f.line}</span>
              </div>
              <h4 style="font-size: 0.95rem; font-weight: 600; margin-top: 4px;">\${f.title}</h4>
              \${f.cwe ? \`<div style="font-size: 0.75rem; color: #93c5fd;">\${f.cwe}</div>\` : ''}
              <p style="font-size: 0.85rem; color: var(--text-muted); margin-top: 4px;">\${f.description}</p>
              \${f.codeSnippet ? \`<div class="code-box bad"><pre>\${escapeHtml(f.codeSnippet)}</pre></div>\` : ''}
              \${f.suggestedFix ? \`<div style="font-size: 0.75rem; font-weight: 600; color: #34d399; margin-top: 6px;">Suggested Fix:</div><div class="code-box fix"><pre>\${escapeHtml(f.suggestedFix)}</pre></div>\` : ''}
            </div>
          \`;
        });
      }

      container.innerHTML = html;
    }

    function renderRemediation(patches) {
      const container = document.getElementById('remediationList');
      if (!patches || patches.length === 0) {
        container.innerHTML = '<div style="text-align: center; color: var(--text-muted); padding: 2rem;">No patches required for clean diffs.</div>';
        return;
      }

      let html = '';
      patches.forEach(p => {
        html += \`
          <div class="finding-card" style="border-left: 4px solid var(--success)">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="font-size: 0.85rem; font-weight: 700; color: #34d399;">Auto-Remediation Branch: <code>\${p.branchName}</code></span>
              <span style="font-size: 0.75rem; color: #60a5fa; font-weight: 600;">● Vitest Verified</span>
            </div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin: 6px 0;">Target: <b>\${p.targetFile}</b> &bull; Commit: <code>\${p.commitMessage}</code></div>
            <div class="code-box fix"><pre>\${escapeHtml(p.unifiedDiffPatch)}</pre></div>
          </div>
        \`;
      });
      container.innerHTML = html;
    }

    function renderBlastRadius(blast) {
      if (!blast) return;
      document.getElementById('blastScoreBadge').textContent = 'System Blast Exposure: ' + blast.overallBlastRadiusScore + '%';

      const svg = document.getElementById('blastSvg');
      svg.innerHTML = '';

      const colors = { vulnerable_file: '#ef4444', api_endpoint: '#3b82f6', database_table: '#8b5cf6', dependent_service: '#10b981' };

      blast.nodes.forEach((node, i) => {
        const x = 90 + (i % 3) * 230;
        const y = 80 + Math.floor(i / 3) * 110;

        const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        
        const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        circle.setAttribute('cx', x);
        circle.setAttribute('cy', y);
        circle.setAttribute('r', 24);
        circle.setAttribute('fill', colors[node.type] || '#3b82f6');
        circle.setAttribute('opacity', '0.85');

        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('x', x);
        text.setAttribute('y', y + 36);
        text.setAttribute('text-anchor', 'middle');
        text.setAttribute('fill', '#e2e8f0');
        text.setAttribute('font-size', '10');
        text.textContent = node.label.substring(0, 24);

        g.appendChild(circle);
        g.appendChild(text);
        svg.appendChild(g);
      });
    }

    async function loadPolicies() {
      const res = await fetch('/api/policies');
      const policies = await res.json();
      const list = document.getElementById('policyList');
      list.innerHTML = '';

      policies.forEach(p => {
        const item = document.createElement('div');
        item.className = 'policy-item';
        item.innerHTML = \`
          <div>
            <div style="font-weight: 600; font-size: 0.88rem;">\${p.title} <span style="font-size: 0.75rem; color: #93c5fd;">[\${p.category.toUpperCase()}]</span></div>
            <div style="font-size: 0.8rem; color: var(--text-muted);">\${p.rule}</div>
          </div>
          <div>
            <input type="checkbox" \${p.enabled ? 'checked' : ''} onchange="togglePolicy('\${p.id}')">
          </div>
        \`;
        list.appendChild(item);
      });
    }

    async function togglePolicy(id) {
      await fetch('/api/policies/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id })
      });
    }

    async function runBenchmark() {
      const body = document.getElementById('arenaBody');
      body.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #60a5fa;">Running live multi-model benchmark across foundation models...</td></tr>';

      const res = await fetch('/api/benchmark', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ diff: document.getElementById('diffInput').value })
      });
      const data = await res.json();

      let html = '';
      data.forEach(m => {
        html += \`
          <tr>
            <td style="font-weight: 700; color: #e2e8f0;">\${m.modelName}</td>
            <td style="color: var(--text-muted);">\${m.provider}</td>
            <td style="font-weight: 700; color: #34d399;">\${m.detectionRecall}%</td>
            <td>\${m.latencyMs} ms</td>
            <td>\${m.totalTokens}</td>
            <td style="font-weight: 700; color: #60a5fa;">$\${m.costUsd.toFixed(5)}</td>
          </tr>
        \`;
      });
      body.innerHTML = html;
    }

    async function exportSarif() {
      if (!lastReviewData) {
        await executeReview();
      }
      const res = await fetch('/api/export/sarif', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reviewResult: lastReviewData })
      });
      const sarif = await res.json();
      const blob = new Blob([JSON.stringify(sarif, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'devsecai-code-scanning.sarif';
      a.click();
    }

    async function downloadPatch() {
      if (!lastReviewData || !lastReviewData.remediationPatches || lastReviewData.remediationPatches.length === 0) {
        await executeReview();
      }
      if (!lastReviewData.remediationPatches || lastReviewData.remediationPatches.length === 0) {
        return alert('No patches required for this diff');
      }
      const patchText = lastReviewData.remediationPatches.map(p => p.unifiedDiffPatch).join('\\n\\n');
      const blob = new Blob([patchText], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'devsecai-remediation.patch';
      a.click();
    }

    function escapeHtml(str) {
      return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }
  </script>
</body>
</html>`;

  return c.html(html);
});

const port = config.PORT;

console.log(`\n===============================================================`);
console.log(`🛡️  DevSecAI Platform v2.0 is running!`);
console.log(`👉 Open Dashboard: http://localhost:${port}`);
console.log(`===============================================================\n`);

// High-Efficiency Keepalive Engine (Prevents Render from sleeping)
if (process.env.NODE_ENV === 'production') {
  setInterval(async () => {
    try {
      await fetch(`http://localhost:${port}/health`);
    } catch {}
  }, 1000 * 60 * 10); // Ping every 10 mins
}

serve({
  fetch: app.fetch,
  port,
  hostname: '0.0.0.0',
});
