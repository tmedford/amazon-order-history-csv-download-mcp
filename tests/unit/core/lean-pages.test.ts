/**
 * Tests for lean worker pages: what gets blocked, and the bounded-concurrency runner.
 */

import type { BrowserContext, Page } from "playwright";
import {
  concurrency,
  mapOnPage,
  mapWithPages,
  shouldBlock,
} from "../../../src/core/browser/lean-pages";
import { toCSV, toCSVWithColumns } from "../../../src/core/utils/csv";
import {
  GIFT_CARD_CSV_COLUMNS,
  TRANSACTION_CSV_COLUMNS,
} from "../../../src/tools/csv-columns";

function req(
  type: string,
  pageUrl = "https://www.amazon.com/gp/your-account/order-details?orderID=1",
) {
  return {
    resourceType: () => type,
    url: () => "https://m.media-amazon.com/x",
    frame: () => ({ url: () => pageUrl }),
  } as never;
}

describe("shouldBlock", () => {
  test("loads documents, stylesheets and data calls", () => {
    for (const t of ["document", "stylesheet", "xhr", "fetch"]) {
      expect(shouldBlock(req(t))).toBe(false);
    }
  });
  test("drops images, fonts, media and scripts", () => {
    for (const t of ["image", "font", "media", "script"]) {
      expect(shouldBlock(req(t))).toBe(true);
    }
  });
  test("keeps scripts on the client-rendered tracking page", () => {
    expect(
      shouldBlock(
        req(
          "script",
          "https://www.amazon.com/progress-tracker/package?orderId=1",
        ),
      ),
    ).toBe(false);
  });
});

function fakeContext() {
  const opened: Array<{ closed: boolean }> = [];
  const context = {
    newPage: async () => {
      const p = {
        closed: false,
        route: async () => {},
        close: async () => {
          p.closed = true;
        },
      };
      opened.push(p);
      return p as unknown as Page;
    },
  } as unknown as BrowserContext;
  return { context, opened };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("mapWithPages", () => {
  test("keeps input order, runs in parallel, closes every page", async () => {
    const { context, opened } = fakeContext();
    let live = 0;
    let peak = 0;
    const out = await mapWithPages(
      context,
      [30, 5, 20, 1, 10],
      async (_p, ms, i) => {
        peak = Math.max(peak, ++live);
        await sleep(ms);
        live--;
        return i * 10;
      },
      3,
    );
    expect(out).toEqual([0, 10, 20, 30, 40]);
    expect(peak).toBe(3);
    expect(opened).toHaveLength(3);
    expect(opened.every((p) => p.closed)).toBe(true);
  });

  test("one failing order yields its error in place; the rest complete", async () => {
    const { context } = fakeContext();
    const out = await mapWithPages(
      context,
      ["a", "bad", "c"],
      async (_p, x) => {
        if (x === "bad") throw new Error("boom");
        return x.toUpperCase();
      },
      2,
    );
    expect(out[0]).toBe("A");
    expect(out[1]).toBeInstanceOf(Error);
    expect(out[2]).toBe("C");
  });

  test("never opens more pages than there are orders", async () => {
    const { context, opened } = fakeContext();
    await mapWithPages(context, [1], async () => 1, 4);
    expect(opened).toHaveLength(1);
  });

  test("mapOnPage runs one at a time on the given page", async () => {
    const page = {} as Page;
    const seen: Page[] = [];
    let live = 0;
    let peak = 0;
    await mapOnPage(page, [3, 1, 2], async (p, ms) => {
      seen.push(p);
      peak = Math.max(peak, ++live);
      await sleep(ms);
      live--;
    });
    expect(peak).toBe(1);
    expect(seen.every((p) => p === page)).toBe(true);
  });
});

describe("concurrency", () => {
  const saved = process.env.AMAZON_ORDERS_CONCURRENCY;
  afterEach(() => {
    if (saved === undefined) delete process.env.AMAZON_ORDERS_CONCURRENCY;
    else process.env.AMAZON_ORDERS_CONCURRENCY = saved;
  });
  test("defaults to 4, honours the env var, clamps to 1..8", () => {
    delete process.env.AMAZON_ORDERS_CONCURRENCY;
    expect(concurrency()).toBe(4);
    process.env.AMAZON_ORDERS_CONCURRENCY = "2";
    expect(concurrency()).toBe(2);
    process.env.AMAZON_ORDERS_CONCURRENCY = "50";
    expect(concurrency()).toBe(8);
    process.env.AMAZON_ORDERS_CONCURRENCY = "zero";
    expect(concurrency()).toBe(4);
  });
});

describe("CSV output", () => {
  test("toCSV with no rows and no columns returns an empty string", () => {
    expect(toCSV([])).toBe("");
  });

  test("an empty export still has its header row", () => {
    const csv = toCSVWithColumns([], TRANSACTION_CSV_COLUMNS);
    expect(csv.replace("﻿", "").split("\n")[0]).toContain("Order");
  });

  test("a $0.00 gift card balance is written, not blanked", () => {
    const usd = (amount: number) => ({
      amount,
      currency: "USD",
      currencySymbol: "$",
      formatted: `$${amount.toFixed(2)}`,
    });
    const csv = toCSVWithColumns(
      [
        {
          date: new Date("2026-08-05T04:00:00Z"),
          description: "Gift Card applied",
          amount: usd(-32.34),
          closingBalance: usd(0),
          type: "applied",
        } as never,
      ],
      GIFT_CARD_CSV_COLUMNS,
    );
    expect(csv).toContain(",$0.00,");
  });
});
