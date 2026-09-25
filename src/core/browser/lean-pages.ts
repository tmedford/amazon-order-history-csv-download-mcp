/**
 * Lean worker pages: fetch only the HTML document, and run several at once.
 *
 * Why (2026-09-25): every tool loaded full Amazon pages one at a time - images, fonts,
 * tracking scripts and all - then waited on them. Amazon has no JSON API behind order
 * history, order details, invoices or the payments page (checked in the network log:
 * each is server-rendered HTML, and payments paginates with a plain form POST), but the
 * data is all in that HTML. Measured in a signed-in Chrome: 10 order-detail pages took
 * ~13s one after another and 1.4s in parallel; a payments page took ~0.8s as a bare POST.
 *
 * So worker pages abort every sub-resource except stylesheets (kept so visibility
 * checks mean what they did before) and pages are processed with bounded concurrency.
 * The extractors are unchanged: they still read a real Playwright page.
 */

import type { BrowserContext, Page, Request } from "playwright";

/** Resource types a lean page never loads. */
const BLOCKED_TYPES = new Set([
  "image",
  "media",
  "font",
  "script",
  "texttrack",
  "eventsource",
  "websocket",
  "manifest",
  "other",
]);

/**
 * Pages that build their content in JavaScript. Scripts stay on for these; everything
 * else Amazon renders on the server.
 */
const NEEDS_SCRIPTS = [
  /\/progress-tracker\//,
  /\/gp\/your-account\/ship-track/,
];

export function shouldBlock(
  req: Pick<Request, "resourceType" | "url" | "frame">,
): boolean {
  const type = req.resourceType();
  if (!BLOCKED_TYPES.has(type)) return false;
  if (type === "script") {
    let pageUrl = "";
    try {
      pageUrl = req.frame().url();
    } catch {
      // service-worker or detached-frame request: no page to ask
    }
    if (NEEDS_SCRIPTS.some((re) => re.test(pageUrl))) return false;
  }
  return true;
}

/** Open a page in `context` that loads documents and stylesheets only. */
export async function openLeanPage(context: BrowserContext): Promise<Page> {
  const page = await context.newPage();
  await page.route("**/*", (route) =>
    shouldBlock(route.request()) ? route.abort() : route.continue(),
  );
  return page;
}

/** Worker pages to run at once. AMAZON_ORDERS_CONCURRENCY overrides; clamped to 1..8. */
export function concurrency(): number {
  const n = Number(process.env.AMAZON_ORDERS_CONCURRENCY);
  return Number.isFinite(n) && n >= 1 ? Math.min(Math.floor(n), 8) : 4;
}

type Work<T, R> = (page: Page, item: T, index: number) => Promise<R>;

/** Drain `items` on each of `pages`; a task that throws yields its error in place. */
async function drain<T, R>(
  pages: Page[],
  items: T[],
  work: Work<T, R>,
): Promise<Array<R | Error>> {
  const results: Array<R | Error> = new Array(items.length);
  let next = 0;
  await Promise.all(
    pages.map(async (page) => {
      while (next < items.length) {
        const i = next++;
        try {
          results[i] = await work(page, items[i], i);
        } catch (e) {
          results[i] = e instanceof Error ? e : new Error(String(e));
        }
      }
    }),
  );
  return results;
}

/** Run `work` over `items` one at a time on an existing page (concurrency 1). */
export function mapOnPage<T, R>(
  page: Page,
  items: T[],
  work: Work<T, R>,
): Promise<Array<R | Error>> {
  return drain([page], items, work);
}

/**
 * Run `work` over `items` on up to `size` lean pages, opened here and closed after.
 * Results keep input order; one bad order never stops the rest.
 */
export async function mapWithPages<T, R>(
  context: BrowserContext,
  items: T[],
  work: Work<T, R>,
  size = concurrency(),
): Promise<Array<R | Error>> {
  if (items.length === 0) return [];
  const pages: Page[] = [];
  try {
    const workers = Math.max(1, Math.min(size, items.length));
    for (let w = 0; w < workers; w++) pages.push(await openLeanPage(context));
    return await drain(pages, items, work);
  } finally {
    await Promise.all(pages.map((p) => p.close().catch(() => {})));
  }
}
