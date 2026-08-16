import { RepositoryGuideline } from '../types/index.js';

export class RepoMemoryStore {
  private static defaultGuidelines: RepositoryGuideline[] = [
    {
      id: 'rule-sec-01',
      category: 'security',
      title: 'Parameterized SQL Queries',
      rule: 'All SQL database queries must use parameterized placeholders (, ?) or typed ORM builders. Never concatenate user input into raw SQL strings.',
      severity: 'critical',
      enabled: true,
      exampleBad: "db.query(\SELECT * FROM users WHERE id = '\'\)",
      exampleGood: 'db.query("SELECT * FROM users WHERE id = ", [userId])',
    },
    {
      id: 'rule-sec-02',
      category: 'security',
      title: 'No Hardcoded Secrets',
      rule: 'Never commit secrets, API keys, private tokens, or credentials into source code. Always use environment variables validated with Zod.',
      severity: 'critical',
      enabled: true,
      exampleBad: 'const STRIPE_SECRET = "sk_live_99812489124";',
      exampleGood: 'const STRIPE_SECRET = config.STRIPE_SECRET;',
    },
    {
      id: 'rule-perf-01',
      category: 'performance',
      title: 'No N+1 Database Loops',
      rule: 'Avoid N+1 queries. Never execute single database lookups inside loops or Array.map. Batch load with WHERE id IN (...) or dataloader.',
      severity: 'high',
      enabled: true,
      exampleBad: 'for (const user of users) { await db.order.find({ userId: user.id }); }',
      exampleGood: 'const orders = await db.order.findMany({ where: { userId: { in: userIds } } });',
    },
    {
      id: 'rule-perf-02',
      category: 'performance',
      title: 'Safe Async in Loops',
      rule: 'Never use async callbacks directly inside Array.prototype.forEach. Use Promise.all with Array.prototype.map for concurrency.',
      severity: 'medium',
      enabled: true,
      exampleBad: 'items.forEach(async (item) => { await process(item); });',
      exampleGood: 'await Promise.all(items.map(item => process(item)));',
    },
  ];

  public static async getApplicableGuidelines(_repoName?: string): Promise<RepositoryGuideline[]> {
    return this.defaultGuidelines;
  }
}