import { z } from 'zod';
import dotenv from 'dotenv';

dotenv.config();

/** Shared fallback secret. Fine for local demos, refused in production. */
const DEV_WEBHOOK_SECRET = 'devsec-test-secret-key-12345';

const envSchema = z.object({
  PORT: z.coerce.number().default(3000),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  GITHUB_WEBHOOK_SECRET: z.string().default(DEV_WEBHOOK_SECRET),
  GITHUB_TOKEN: z.string().optional(),
  GEMINI_API_KEY: z.string().optional(),
  OPENAI_API_KEY: z.string().optional(),
  ANTHROPIC_API_KEY: z.string().optional(),
  GROQ_API_KEY: z.string().optional(),
  DEFAULT_LLM_PROVIDER: z.enum(['gemini', 'openai', 'anthropic', 'groq', 'dynamic', 'mock']).default('dynamic'),
  AI_MODEL_NAME: z.string().default('gemini-1.5-flash'),
  DATABASE_URL: z.string().default('postgresql://postgres:postgres@localhost:5432/devsecai'),
  MIN_CONFIDENCE_THRESHOLD: z.coerce.number().min(0).max(1).default(0.70),
  MAX_DIFF_LINES: z.coerce.number().default(5000),
});

export type EnvConfig = z.infer<typeof envSchema>;

const detectedProvider = 
  process.env.GEMINI_API_KEY ? 'gemini' :
  process.env.OPENAI_API_KEY ? 'openai' :
  process.env.GROQ_API_KEY ? 'groq' :
  process.env.ANTHROPIC_API_KEY ? 'anthropic' :
  'dynamic';

export const config: EnvConfig = envSchema.parse({
  PORT: process.env.PORT,
  NODE_ENV: process.env.NODE_ENV,
  GITHUB_WEBHOOK_SECRET: process.env.GITHUB_WEBHOOK_SECRET,
  GITHUB_TOKEN: process.env.GITHUB_TOKEN,
  GEMINI_API_KEY: process.env.GEMINI_API_KEY,
  OPENAI_API_KEY: process.env.OPENAI_API_KEY,
  ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY,
  GROQ_API_KEY: process.env.GROQ_API_KEY,
  DEFAULT_LLM_PROVIDER: process.env.DEFAULT_LLM_PROVIDER || detectedProvider,
  AI_MODEL_NAME: process.env.AI_MODEL_NAME || (detectedProvider === 'gemini' ? 'gemini-1.5-flash' : 'gpt-4o-mini'),
  DATABASE_URL: process.env.DATABASE_URL,
  MIN_CONFIDENCE_THRESHOLD: process.env.MIN_CONFIDENCE_THRESHOLD,
  MAX_DIFF_LINES: process.env.MAX_DIFF_LINES,
});

if (config.NODE_ENV === 'production' && config.GITHUB_WEBHOOK_SECRET === DEV_WEBHOOK_SECRET) {
  throw new Error('GITHUB_WEBHOOK_SECRET must be set in production; the shared dev secret is public.');
}