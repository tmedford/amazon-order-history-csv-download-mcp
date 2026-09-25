/**
 * Sign-in guard: make sure the browser is signed in to Amazon before a tool runs, and
 * repair it from Chrome's cookies when it is not.
 *
 * Why this exists (2026-09-25): the connector imported Chrome's cookies only once, and
 * only when its own profile had no sign-in cookie. When Amazon expired that sign-in, the
 * stale cookie was still "present", import never ran again, and every tool returned
 * status "success" with 0 results while signed out - indistinguishable from "no orders".
 *
 * The guard:
 *   1. checks sign-in (cached for ttlMs after a success, so a batch of calls does not
 *      reload the page every time);
 *   2. when signed out, re-imports Chrome's cookies and checks again, with backoff;
 *   3. stops early (after one re-import) when Amazon demands a fresh password/passkey
 *      (the cvf page, or a password-only prompt) - no cookie can satisfy that;
 *   4. otherwise returns a typed failure the caller turns into a real error.
 *
 * Browser access is injected, so the retry logic is unit-tested without Playwright.
 */

export interface SignInCheck {
  authenticated: boolean;
  /** Amazon wants the password/passkey again - cookies cannot fix this. */
  reauthRequired?: boolean;
  message?: string;
}

export interface AuthGuardDeps {
  /** Load an authenticated Amazon page fresh and report what it shows. */
  check(): Promise<SignInCheck>;
  /** Copy Chrome's amazon.com cookies into the browser; returns how many. */
  reimport(): Promise<number>;
  sleep(ms: number): Promise<void>;
  now(): number;
}

export interface AuthGuardOptions {
  /** How long a successful check is trusted. */
  ttlMs: number;
  /** Wait before each re-check after a re-import; its length is the retry count. */
  backoffMs: number[];
}

export type EnsureResult =
  | { ok: true; repaired: boolean; attempts: number }
  | {
      ok: false;
      code: "NOT_SIGNED_IN" | "REAUTH_REQUIRED";
      message: string;
      attempts: number;
    };

export const DEFAULT_AUTH_GUARD_OPTIONS: AuthGuardOptions = {
  ttlMs: 5 * 60_000,
  backoffMs: [1_000, 3_000, 10_000],
};

export class AuthGuard {
  private trustedUntil = 0;
  /** One check at a time: concurrent callers share it (they would race on the one page). */
  private inFlight: Promise<EnsureResult> | null = null;

  constructor(
    private readonly deps: AuthGuardDeps,
    private readonly opts: AuthGuardOptions = DEFAULT_AUTH_GUARD_OPTIONS,
  ) {}

  /** Forget the cached success - call when a result looks like a signed-out page. */
  invalidate(): void {
    this.trustedUntil = 0;
  }

  ensure(): Promise<EnsureResult> {
    if (this.deps.now() < this.trustedUntil) {
      return Promise.resolve({ ok: true, repaired: false, attempts: 0 });
    }
    if (!this.inFlight) {
      this.inFlight = this.run().finally(() => {
        this.inFlight = null;
      });
    }
    return this.inFlight;
  }

  private async run(): Promise<EnsureResult> {
    let status = await this.deps.check();
    let attempts = 0;
    // Always try at least ONE re-import, even when the page looks like a password demand:
    // Amazon puts max_auth_age=0 on every order-history sign-in redirect, so the page alone
    // cannot tell "expired session" from "wants your password" (2026-09-25, live test).
    while (
      !status.authenticated &&
      attempts < this.opts.backoffMs.length &&
      !(status.reauthRequired && attempts >= 1)
    ) {
      const imported = await this.deps.reimport().catch(() => 0);
      console.error(`[auth] signed out - re-imported ${imported} Chrome cookies (attempt ${attempts + 1})`);
      await this.deps.sleep(this.opts.backoffMs[attempts]);
      attempts++;
      status = await this.deps.check();
    }
    if (status.authenticated) {
      this.trustedUntil = this.deps.now() + this.opts.ttlMs;
      return { ok: true, repaired: attempts > 0, attempts };
    }
    if (status.reauthRequired) {
      return {
        ok: false,
        code: "REAUTH_REQUIRED",
        attempts,
        message:
          "Amazon is asking for your password or passkey again - cookies cannot satisfy that. " +
          "Run once with AMAZON_ORDERS_HEADFUL=1 and confirm it in the visible window.",
      };
    }
    return {
      ok: false,
      code: "NOT_SIGNED_IN",
      attempts,
      message:
        `Not signed in to Amazon after ${attempts} cookie re-import(s). ` +
        "Open amazon.com in Chrome and sign in (the connector copies Chrome's session), " +
        "or run once with AMAZON_ORDERS_HEADFUL=1 and sign in in the visible window.",
    };
  }
}

/** Keys a list tool reports its size under. */
const COUNT_KEYS = ["transactionCount", "orderCount", "totalOrders", "rowCount"];

/**
 * True when a tool's JSON payload says it found nothing. A signed-out page yields exactly
 * this, so an empty result is re-verified before it is returned as "success".
 */
export function looksEmpty(payload: unknown): boolean {
  if (!payload || typeof payload !== "object") return false;
  const p = payload as Record<string, unknown>;
  if (p.status !== "success") return false;
  // a single-order payload is never "an empty list" - its transactions array is empty
  // whenever include_transactions is false (the default)
  if ("order" in p) return false;
  for (const k of COUNT_KEYS) {
    if (typeof p[k] === "number") return p[k] === 0;
  }
  for (const k of ["orders", "transactions"]) {
    if (Array.isArray(p[k])) return (p[k] as unknown[]).length === 0;
  }
  return false;
}
