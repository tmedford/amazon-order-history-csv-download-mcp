/**
 * Tests for the sign-in guard: check -> re-import Chrome cookies -> retry -> typed failure.
 */

import { AuthGuard, AuthGuardDeps, SignInCheck, looksEmpty } from "../../../src/core/auth-guard";

function deps(checks: SignInCheck[], clock = { t: 0 }) {
  const calls = { check: 0, reimport: 0, sleeps: [] as number[] };
  const d: AuthGuardDeps = {
    check: async () => checks[Math.min(calls.check++, checks.length - 1)],
    reimport: async () => {
      calls.reimport++;
      return 5;
    },
    sleep: async (ms) => {
      calls.sleeps.push(ms);
      clock.t += ms;
    },
    now: () => clock.t,
  };
  return { d, calls, clock };
}

const IN: SignInCheck = { authenticated: true };
const OUT: SignInCheck = { authenticated: false, message: "Not logged in" };
const REAUTH: SignInCheck = { authenticated: false, reauthRequired: true };
const opts = { ttlMs: 1000, backoffMs: [1, 3, 10] };

describe("AuthGuard", () => {
  test("signed in: no re-import", async () => {
    const { d, calls } = deps([IN]);
    const r = await new AuthGuard(d, opts).ensure();
    expect(r).toEqual({ ok: true, repaired: false, attempts: 0 });
    expect(calls.reimport).toBe(0);
  });

  test("expired session repaired by the first re-import", async () => {
    const { d, calls } = deps([OUT, IN]);
    const r = await new AuthGuard(d, opts).ensure();
    expect(r).toEqual({ ok: true, repaired: true, attempts: 1 });
    expect(calls.reimport).toBe(1);
  });

  test("repaired on a later retry, with backoff between tries", async () => {
    const { d, calls } = deps([OUT, OUT, IN]);
    const r = await new AuthGuard(d, opts).ensure();
    expect(r.ok).toBe(true);
    expect(calls.sleeps).toEqual([1, 3]);
  });

  test("gives up after the backoff list with NOT_SIGNED_IN - never a silent success", async () => {
    const { d, calls } = deps([OUT]);
    const r = await new AuthGuard(d, opts).ensure();
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("NOT_SIGNED_IN");
    expect(calls.reimport).toBe(3);
  });

  test("password/passkey demand: one re-import, then REAUTH_REQUIRED", async () => {
    const { d, calls } = deps([REAUTH]);
    const r = await new AuthGuard(d, opts).ensure();
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("REAUTH_REQUIRED");
    expect(calls.reimport).toBe(1);
  });

  test("a sign-in page that only LOOKS like a password demand is fixed by the re-import", async () => {
    const { d } = deps([REAUTH, IN]);
    const r = await new AuthGuard(d, opts).ensure();
    expect(r).toEqual({ ok: true, repaired: true, attempts: 1 });
  });

  test("a success is trusted for ttlMs, then re-checked; invalidate() forces a check", async () => {
    const { d, calls, clock } = deps([IN]);
    const g = new AuthGuard(d, opts);
    await g.ensure();
    await g.ensure();
    expect(calls.check).toBe(1);
    clock.t += 1001;
    await g.ensure();
    expect(calls.check).toBe(2);
    g.invalidate();
    await g.ensure();
    expect(calls.check).toBe(3);
  });

  test("concurrent ensure() calls share one check", async () => {
    const { d, calls } = deps([OUT, IN]);
    const g = new AuthGuard(d, opts);
    const [a, b] = await Promise.all([g.ensure(), g.ensure()]);
    expect(a).toEqual(b);
    expect(calls.check).toBe(2); // one OUT + one IN, not four
    expect(calls.reimport).toBe(1);
  });

  test("a failed re-import does not crash the loop", async () => {
    const { d } = deps([OUT, IN]);
    d.reimport = async () => {
      throw new Error("keychain denied");
    };
    const r = await new AuthGuard(d, opts).ensure();
    expect(r.ok).toBe(true);
  });
});

describe("looksEmpty", () => {
  test("zero counts are empty", () => {
    expect(looksEmpty({ status: "success", transactionCount: 0, transactions: [] })).toBe(true);
    expect(looksEmpty({ status: "success", orders: [] })).toBe(true);
  });
  test("results, errors and non-list payloads are not", () => {
    expect(looksEmpty({ status: "success", transactionCount: 3 })).toBe(false);
    expect(looksEmpty({ status: "error", transactionCount: 0 })).toBe(false);
    expect(looksEmpty({ status: "success", order: { id: "x" } })).toBe(false);
    // order details with include_transactions=false: empty transactions is not an empty list
    expect(looksEmpty({ status: "success", order: { id: "x" }, transactions: [] })).toBe(false);
    expect(looksEmpty(null)).toBe(false);
  });
});
