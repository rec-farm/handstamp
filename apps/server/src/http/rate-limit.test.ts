import { describe, expect, it } from 'vitest';
import { rateLimits } from './rate-limit.ts';

describe('rateLimits (S7)', () => {
  it('uses the production limits by default', () => {
    expect(rateLimits()).toMatchObject({
      token: { max: 120 },
      authorization: { max: 60 },
      interaction: { max: 30 },
    });
  });

  it('scales every limit together', () => {
    expect(rateLimits(50).interaction.max).toBe(1500);
    expect(rateLimits(0.5).token.max).toBe(60);
  });
});
