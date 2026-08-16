import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { GitHubWebhookHandler } from '../src/github/webhook-handler.js';
import { config } from '../src/config/env.js';

describe('GitHub Webhook Signature Verification', () => {
  const body = JSON.stringify({ action: 'opened', number: 42 });

  const sign = (payload: string, secret: string) =>
    `sha256=${crypto.createHmac('sha256', secret).update(payload).digest('hex')}`;

  it('should accept a payload signed with the configured secret', () => {
    const signature = sign(body, config.GITHUB_WEBHOOK_SECRET);
    expect(GitHubWebhookHandler.verifySignature(body, signature)).toBe(true);
  });

  it('should reject a payload signed with the wrong secret', () => {
    const signature = sign(body, 'attacker-secret');
    expect(GitHubWebhookHandler.verifySignature(body, signature)).toBe(false);
  });

  it('should reject a tampered payload', () => {
    const signature = sign(body, config.GITHUB_WEBHOOK_SECRET);
    expect(GitHubWebhookHandler.verifySignature('{"action":"closed"}', signature)).toBe(false);
  });

  it('should reject a request with no signature header', () => {
    expect(GitHubWebhookHandler.verifySignature(body)).toBe(false);
  });

  it('should reject a signature that is not sha256-prefixed', () => {
    expect(GitHubWebhookHandler.verifySignature(body, 'sha1=deadbeef')).toBe(false);
  });
});
