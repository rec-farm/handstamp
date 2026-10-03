// Every rate limit in one place (S7). `scale` multiplies them all: 1 in production; the
// conformance stack raises it because the whole suite runs from a single IP.
export function rateLimits(scale = 1) {
  const per = (max: number) => ({ max: Math.ceil(max * scale), timeWindow: '1 minute' });
  return {
    token: per(120),
    authorization: per(60),
    interaction: per(30),
    // Guessing a 100-bit setup code is hopeless anyway; this keeps the logs quiet.
    setup: { max: Math.ceil(5 * scale), timeWindow: '15 minutes' },
  };
}

export type RateLimits = ReturnType<typeof rateLimits>;
