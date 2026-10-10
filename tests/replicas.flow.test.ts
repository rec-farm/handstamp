import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startTestServer } from './harness.ts';

// Two processes on one database, as two replicas behind a load balancer would be (PLAN R5).

let server: Awaited<ReturnType<typeof startTestServer>>;
let replica: string;

beforeAll(async () => {
  server = await startTestServer('replicas');
  replica = await server.replica();
});
afterAll(async () => {
  await server?.close();
});

describe('more than one replica', () => {
  it('keeps the setup code another process printed moments ago', async () => {
    const setupCodes = () =>
      server.sql<{ id: string }>(
        "SELECT id FROM enrollment_tokens WHERE purpose = 'setup' AND consumed_at IS NULL",
      );
    const [printed] = await setupCodes();
    await server.replica(); // boots while that code is seconds old
    expect(await setupCodes()).toEqual([printed]);
  });

  it('counts rate limits against one budget, whichever replica answers', async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 20; i++) {
      for (const origin of [server.issuer, replica])
        statuses.push((await fetch(`${origin}/interaction/nope/details`)).status);
    }
    // 30 a minute per IP and route: each process alone saw only 20.
    expect(statuses.filter((s) => s === 429)).toHaveLength(10);
    expect(statuses.slice(0, 30)).not.toContain(429);
  });
});
