import { z } from 'zod';
import { LLMProvider } from '../ai/llm-provider.js';
import { ParsedDiff, ReviewFinding, AgentExecutionMetrics, RepositoryGuideline } from '../types/index.js';
import { ASTContextChunker } from '../parser/ast-chunker.js';

const perfFindingSchema = z.object({
  id: z.string(),
  file: z.string(),
  line: z.number(),
  endLine: z.number().optional(),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  category: z.enum(['performance', 'concurrency', 'bug_risk']),
  title: z.string(),
  description: z.string(),
  cwe: z.string().optional(),
  codeSnippet: z.string(),
  suggestedFix: z.string(),
  confidence: z.number().min(0).max(1),
});

const performanceResponseSchema = z.object({
  findings: z.array(perfFindingSchema),
});

export class PerformanceAgent {
  public static async analyze(
    parsedDiff: ParsedDiff,
    guidelines: RepositoryGuideline[] = []
  ): Promise<{ findings: ReviewFinding[]; metrics: AgentExecutionMetrics }> {
    const startTime = Date.now();

    const contextualBlocks = parsedDiff.files.flatMap(file => 
      ASTContextChunker.extractContextualBlocks(file)
    );

    const promptPayload = {
      files: parsedDiff.files.map(f => ({
        path: f.newPath,
        additions: f.additions,
        deletions: f.deletions,
        rawDiff: f.rawDiff,
      })),
      contextualBlocks,
      guidelines: guidelines.filter(g => g.category === 'performance'),
    };

    const systemPrompt = `You are the DevSecAI Performance & Concurrency Engineering Specialist.
Your objective: Audit code diffs for N+1 database queries, unhandled async promises, memory leaks, unindexed query filters, race conditions, and blocking operations.

CRITICAL INSTRUCTIONS:
1. Detect real performance and concurrency anti-patterns in newly added code (+ lines).
2. Report with file, line number, severity ('high' | 'medium' | 'low'), exact code snippet, and optimized replacement fix.
3. Return strict JSON matching: { "findings": [...] }`;

    const userPrompt = `Audit this Pull Request diff for performance, scaling, and concurrency flaws:
\`\`\`json
${JSON.stringify(promptPayload, null, 2)}
\`\`\``;

    const response = await LLMProvider.generateCompletion({
      systemPrompt,
      userPrompt,
      responseFormat: 'json',
      temperature: 0.1,
    });

    let findings: ReviewFinding[] = [];
    try {
      const parsed = performanceResponseSchema.parse(JSON.parse(response.content));
      findings = parsed.findings.map(f => ({
        ...f,
        agentSource: 'performance_agent' as const,
      }));
    } catch (e) {
      console.warn('[PerformanceAgent] Fallback JSON parse recovery:', e);
      try {
        const rawObj = JSON.parse(response.content);
        if (Array.isArray(rawObj.findings)) {
          findings = rawObj.findings.map((f: any) => ({
            id: f.id || `perf-${Math.random().toString(36).substring(2, 8)}`,
            file: f.file || 'unknown',
            line: Number(f.line) || 1,
            severity: f.severity || 'medium',
            category: (f.category === 'concurrency' ? 'concurrency' : 'performance') as 'performance' | 'concurrency',
            title: f.title || 'Performance Warning',
            description: f.description || '',
            cwe: f.cwe,
            codeSnippet: f.codeSnippet || '',
            suggestedFix: f.suggestedFix || '',
            confidence: Number(f.confidence) || 0.85,
            agentSource: 'performance_agent' as const,
          }));
        }
      } catch {
        findings = [];
      }
    }

    const durationMs = Date.now() - startTime;
    const totalCostUsd = (response.promptTokens * 0.00000015) + (response.completionTokens * 0.0000006);

    const metrics: AgentExecutionMetrics = {
      agentRole: 'performance_agent',
      durationMs,
      promptTokens: response.promptTokens,
      completionTokens: response.completionTokens,
      totalCostUsd,
      findingsCount: findings.length,
    };

    return { findings, metrics };
  }
}