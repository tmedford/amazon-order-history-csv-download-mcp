#!/usr/bin/env node

/**
 * Amazon Order History CSV Download MCP Server
 *
 * MCP server for extracting Amazon order history and exporting to CSV.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
  ProgressNotification,
} from "@modelcontextprotocol/sdk/types.js";
import { chromium, Browser, BrowserContext, Page } from "playwright";
import { readFileSync, statSync, unlinkSync, writeFileSync } from "fs";
import { isAbsolute, join } from "path";
import { homedir } from "os";
import packageMetadata from "../package.json";
import { importAmazonCookiesFromChrome } from "./core/cookie-import";
import { AuthGuard, looksEmpty } from "./core/auth-guard";

import { AmazonPlugin } from "./amazon/adapter";
import { getRegionByCode, getRegionCodes } from "./amazon/regions";
import {
  fetchOrders,
  exportOrdersCSV,
  exportItemsCSV,
  exportShipmentsCSV,
  exportTransactionsCSV,
  exportGiftCardTransactionsCSV,
  getOutputPath,
  estimateExtractionTime,
  GiftCardTransactionCSVData,
  downloadAmazonInvoice,
  isValidAmazonOrderId,
} from "./tools";
import { extractTransactionsFromPage } from "./amazon/extractors/transactions-page";
import {
  extractGiftCardData,
  GiftCardData,
} from "./amazon/extractors/gift-card";

// Initialize the Amazon plugin
const amazonPlugin = new AmazonPlugin();

// Browser context instance (lazy initialized)
let browserContext: BrowserContext | null = null;
let page: Page | null = null;

// Browser data directory for session persistence.
// Env var AMAZON_ORDERS_BROWSER_DATA_DIR overrides — required for multi-tenant
// deployments (e.g. separate Personal vs Business Amazon accounts running as
// two instances of this MCP, each with its own persistent Chromium profile).
const BROWSER_DATA_DIR =
  process.env.AMAZON_ORDERS_BROWSER_DATA_DIR ??
  join(homedir(), ".amazon-order-history-mcp", "browser-data");

/**
 * Get or create browser context instance.
 */
// Headless by default now that cookie import handles the common login case -
// a headed browser sitting open for the life of the server was pure idle
// memory once auth stopped requiring a visible window every time. Amazon
// still occasionally forces a fresh password/passkey confirmation
// (openid.pape.max_auth_age=0 on order-history pages) that a headless
// browser has nowhere to render - when that happens, set
// AMAZON_ORDERS_HEADFUL=1 for one run to get a visible window back.
const HEADLESS = process.env.AMAZON_ORDERS_HEADFUL !== "1";

// ONE BROWSER, MANY SERVERS. Every Claude Code session/window that has this MCP
// configured spawns its own copy of this server, and they all share one Chromium
// profile directory - which Chromium locks. Four servers meant one owned the browser
// and the rest failed or hung, so a tool call worked or not depending on which server
// answered. Now the first server launches the browser with a local debugging port and
// every other server attaches to it over CDP. If the owner exits the browser goes with
// it, the attached servers see "disconnected", and the next call elects a new owner.
// The endpoint is NOT a predictable port: the owner launches with --remote-debugging-port=0
// and Chromium writes the port and a per-run browser id into <profile>/DevToolsActivePort.
// Attaching reads that file, so a server only ever attaches to the browser THIS profile
// launched - never to whatever else listens on a guessable port, which would have been
// handed decrypted Amazon cookies (PR #1 review).
const DEVTOOLS_PORT_FILE = join(BROWSER_DATA_DIR, "DevToolsActivePort");
// how long a lock owner may go without a browser answering before its lock is stale
const LOCK_GRACE_MS = 15_000;

function profileEndpoint(): string | null {
  try {
    const [port, path] = readFileSync(DEVTOOLS_PORT_FILE, "utf8").split("\n");
    if (!/^\d+$/.test(port?.trim() ?? "") || !path?.startsWith("/devtools/browser/")) return null;
    return `ws://127.0.0.1:${port.trim()}${path.trim()}`;
  } catch {
    return null;
  }
}

// Set only when this server ATTACHED to someone else's browser. Shutdown must then
// disconnect, never close - closing would kill the browser under the other servers.
let attachedBrowser: Browser | null = null;

// Headless Chromium does NOT enforce one-browser-per-profile: two servers launching at
// once both "succeeded", ran two browsers on one profile directory, and only one could
// bind the debugging port. So election is done here, with an O_EXCL lockfile holding the
// owner's pid. A lock whose pid is dead is stale and is taken over.
const LOCK_FILE = `${BROWSER_DATA_DIR}.owner.lock`;
let holdsLock = false;

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    // EPERM: the process exists but belongs to another user - alive, not stale
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

function lockOwner(): { pid: number; ageMs: number } | null {
  try {
    const pid = parseInt(readFileSync(LOCK_FILE, "utf8"), 10);
    return { pid, ageMs: Date.now() - statSync(LOCK_FILE).mtimeMs };
  } catch {
    return null;
  }
}

function tryAcquireLock(): boolean {
  try {
    writeFileSync(LOCK_FILE, String(process.pid), { flag: "wx" });
    holdsLock = true;
    return true;
  } catch {
    let owner = NaN;
    try {
      owner = parseInt(readFileSync(LOCK_FILE, "utf8"), 10);
    } catch {
      return false; // vanished between the two calls - next loop retries
    }
    // Stale if the owner died - OR if its pid is alive but no browser has answered for
    // longer than the grace period. After a crash or reboot the old pid is often reused by
    // an unrelated process, and a pid check alone would then block every server forever.
    const ageMs = (() => {
      try {
        return Date.now() - statSync(LOCK_FILE).mtimeMs;
      } catch {
        return 0;
      }
    })();
    if (!pidAlive(owner) || (ageMs > LOCK_GRACE_MS && !profileEndpoint())) {
      try {
        unlinkSync(LOCK_FILE);
      } catch {
        /* someone else already cleaned it */
      }
    }
    return false;
  }
}

function releaseLock(): void {
  if (!holdsLock) return;
  holdsLock = false;
  try {
    if (parseInt(readFileSync(LOCK_FILE, "utf8"), 10) === process.pid) {
      unlinkSync(LOCK_FILE);
    }
  } catch {
    /* already gone */
  }
}
process.on("exit", releaseLock);

function dropBrowser(context: BrowserContext): void {
  if (browserContext === context) {
    browserContext = null;
    page = null;
    attachedBrowser = null;
    releaseLock();
  }
}

async function openBrowserContext(): Promise<BrowserContext> {
  const deadline = Date.now() + 60_000;
  let lastError: unknown;
  while (Date.now() < deadline) {
    // attach only to the browser this profile's live lock owner launched
    const owner = lockOwner();
    const endpoint = owner && owner.pid !== process.pid && pidAlive(owner.pid) ? profileEndpoint() : null;
    if (endpoint) {
      try {
        const browser = await chromium.connectOverCDP(endpoint, { timeout: 2000 });
        const context = browser.contexts()[0];
        if (context) {
          attachedBrowser = browser;
          browser.on("disconnected", () => dropBrowser(context));
          console.error(`[browser] Attached to the shared browser (owner pid ${owner!.pid})`);
          await importSessionFromChrome(context);
          return context;
        }
        await browser.close();
      } catch (e) {
        lastError = e; // stale DevToolsActivePort or the owner is still starting
      }
    }
    if (tryAcquireLock()) {
      try {
        const context = await chromium.launchPersistentContext(BROWSER_DATA_DIR, {
          headless: HEADLESS,
          viewport: { width: 1280, height: 800 },
          userAgent:
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
          args: [
            "--remote-debugging-port=0",
            "--remote-debugging-address=127.0.0.1",
          ],
        });
        attachedBrowser = null;
        context.on("close", () => dropBrowser(context));
        console.error(`[browser] Launched the shared browser (endpoint in ${DEVTOOLS_PORT_FILE})`);
        await importSessionFromChrome(context);
        return context;
      } catch (e) {
        lastError = e;
        releaseLock();
      }
    }
    // an owner is launching (or just died) - give it a moment, then try to attach
    if (!lastError) {
      const o = lockOwner();
      lastError = o ? `lock held by pid ${o.pid} for ${Math.round(o.ageMs / 1000)}s with no browser answering` : "no owner";
    }
    await new Promise((r) => setTimeout(r, 400));
  }
  throw new Error(`could not open or attach to the browser: ${String(lastError)}`);
}

async function importSessionFromChrome(context: BrowserContext): Promise<number> {
  // EVERY TIME THE CONNECTOR OPENS, copy Chrome's amazon.com cookies in - owner or
  // attached. This used to run only for the owner, and only when the profile had no
  // at-main/sess-at-main cookie at all. But the profile persists on disk, so once its
  // OWN sign-in expired the stale cookie was still "present", import was skipped
  // forever, and every call returned status "success" with 0 results while logged out
  // (seen 2026-09-25). Chrome is where the user actually stays signed in, so its
  // cookies are the fresher source; addCookies() overwrites same-name cookies.
  try {
    const imported = importAmazonCookiesFromChrome();
    if (imported.length > 0) {
      await context.addCookies(imported);
      console.error(`[browser] Imported ${imported.length} amazon.com cookies from Chrome.`);
      return imported.length;
    } else {
      console.error("[browser] Chrome had no importable amazon.com cookies - manual login needed.");
    }
  } catch (e) {
    // Best-effort: failure just means the caller falls back to manual login.
    console.error(
      `[browser] Cookie import skipped: ${e instanceof Error ? e.message : "unknown error"}`
    );
  }
  return 0;
}

// One open at a time: two concurrent calls used to both run openBrowserContext(), one
// launching and one attaching, leaving a lock owner that thought it was attached.
let opening: Promise<BrowserContext> | null = null;

async function getBrowserContext(): Promise<BrowserContext> {
  if (browserContext) return browserContext;
  if (!opening) {
    opening = openBrowserContext()
      .then((ctx) => {
        browserContext = ctx;
        return ctx;
      })
      .finally(() => {
        opening = null;
      });
  }
  return opening;
}

/**
 * Get or create page instance.
 */
async function getPage(): Promise<Page> {
  try {
    const context = await getBrowserContext();
    if (!page || page.isClosed()) {
      page = await context.newPage();
    }
    return page;
  } catch (e) {
    // Stale context (browser died without firing 'close') - relaunch once
    console.error(`[browser] Relaunching after error: ${e}`);
    browserContext = null;
    page = null;
    const context = await getBrowserContext();
    page = await context.newPage();
    return page;
  }
}

/**
 * Validate region parameter and return error response if invalid.
 */
function validateRegion(
  region: string | undefined,
  args: Record<string, unknown> | undefined,
): { content: Array<{ type: string; text: string }>; isError: true } | null {
  if (!region) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              error: "region parameter is required",
              validRegions: getRegionCodes(),
              receivedArgs: args,
            },
            null,
            2,
          ),
        },
      ],
      isError: true,
    };
  }

  if (!getRegionCodes().includes(region)) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              error: `Invalid region: "${region}"`,
              validRegions: getRegionCodes(),
              receivedArgs: args,
            },
            null,
            2,
          ),
        },
      ],
      isError: true,
    };
  }

  return null; // Valid region
}

// Define MCP tools
const tools: Tool[] = [
  {
    name: "get_amazon_orders",
    description:
      "Fetch Amazon order history for a specified date range or year. Returns order summaries including: order ID, date, total amount, status, item count, shipping address (7 lines), payment method, and Subscribe & Save frequency. Optionally includes detailed item data (ASIN, name, price, quantity, seller, condition) and shipment tracking. Use for browsing order history or building reports.",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: `Amazon region code. Supported: ${getRegionCodes().join(", ")}`,
          enum: getRegionCodes(),
        },
        year: {
          type: "number",
          description:
            "Year to fetch orders from (e.g., 2024). If omitted, uses current year.",
        },
        start_date: {
          type: "string",
          description:
            "Start date in ISO format (YYYY-MM-DD). Overrides year if provided.",
        },
        end_date: {
          type: "string",
          description:
            "End date in ISO format (YYYY-MM-DD). Overrides year if provided.",
        },
        include_items: {
          type: "boolean",
          description:
            "Extract item details (ASIN, name, price, quantity, seller, condition) from each order's invoice page. Adds ~2s per order.",
          default: false,
        },
        include_shipments: {
          type: "boolean",
          description:
            "Extract shipment info (delivery status, tracking link) from each order's detail page. Adds ~2s per order. Note: tracking link URL is captured but not the carrier tracking number - use fetch_tracking_numbers for that.",
          default: false,
        },
        fetch_tracking_numbers: {
          type: "boolean",
          description:
            "Extract actual carrier tracking numbers (e.g., AZ218181365JE) by visiting each shipment's 'Track package' page. Adds ~2s per shipment. Only works when include_shipments is true.",
          default: false,
        },
        max_orders: {
          type: "number",
          description:
            "Maximum number of orders to fetch. Use to limit results for large accounts or avoid timeouts.",
        },
      },
      required: ["region"],
    },
  },
  {
    name: "get_amazon_order_details",
    description:
      "Get comprehensive details for a specific Amazon order by order ID. Returns full order data including: items (ASIN, name, price, quantity, seller, condition), financial breakdown (subtotal, shipping, tax, VAT, promotions, total), shipping address, payment methods, and optionally shipment tracking and transaction history.",
    inputSchema: {
      type: "object",
      properties: {
        order_id: {
          type: "string",
          description:
            "Amazon order ID in format XXX-XXXXXXX-XXXXXXX (e.g., 123-4567890-1234567)",
        },
        region: {
          type: "string",
          description: "Amazon region code where the order was placed",
          enum: getRegionCodes(),
        },
        include_shipments: {
          type: "boolean",
          description:
            "Extract shipment info from order detail page (default: true)",
          default: true,
        },
        fetch_tracking_numbers: {
          type: "boolean",
          description:
            "Extract actual carrier tracking number (e.g., AZ218181365JE) by visiting the 'Track package' page. Adds ~2s per shipment.",
          default: false,
        },
        include_transactions: {
          type: "boolean",
          description: "Include payment transaction details (default: false)",
          default: false,
        },
      },
      required: ["order_id", "region"],
    },
  },
  {
    name: "download_amazon_invoice",
    description:
      "Download a verified Amazon order invoice as an A4 PDF. The requested order ID must match invoice-specific content before a PDF is saved.",
    inputSchema: {
      type: "object",
      properties: {
        order_id: {
          type: "string",
          description:
            "Amazon order ID in format XXX-XXXXXXX-XXXXXXX (e.g., 123-4567890-1234567)",
        },
        region: {
          type: "string",
          description: "Amazon region code where the order was placed",
          enum: getRegionCodes(),
        },
        output_path: {
          type: "string",
          description:
            "Optional absolute destination path. Defaults to ~/Downloads/amazon-{region}-invoice-{order_id}.pdf",
        },
      },
      required: ["order_id", "region"],
    },
  },
  {
    name: "export_amazon_orders_csv",
    description:
      "Export Amazon orders summary to CSV file. Fast extraction from order list page (~0.5s per 10 orders). CSV columns: Order ID, Date, Total, Status, Item Count, Address (7 lines), Subscribe & Save, Platform, Region, Order URL. Defaults to ~/Downloads with auto-generated filename. For large accounts (500+ orders), use max_orders to batch exports and avoid timeouts.",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "Amazon region code",
          enum: getRegionCodes(),
        },
        year: {
          type: "number",
          description: "Year to export (defaults to current year)",
        },
        start_date: {
          type: "string",
          description: "Start date in ISO format (YYYY-MM-DD)",
        },
        end_date: {
          type: "string",
          description: "End date in ISO format (YYYY-MM-DD)",
        },
        output_path: {
          type: "string",
          description:
            "Full path to save CSV file. Defaults to ~/Downloads/amazon-{region}-orders-{year}-{date}.csv",
        },
        max_orders: {
          type: "number",
          description:
            "Maximum number of orders to export. Recommended: 100-200 per batch for large accounts.",
        },
      },
      required: ["region"],
    },
  },
  {
    name: "export_amazon_items_csv",
    description:
      "Export detailed Amazon order items to CSV file. Visits each order's invoice page to extract item-level data (~2s/order). CSV columns: Order ID, Date, ASIN, Product Name, Condition, Quantity, Unit Price, Item Total, Seller, Subscribe & Save, Order financials (Subtotal, Shipping, Tax, VAT, Promotion, Total), Status, Address (7 lines), Payment Method, Product URL, Order URL, Region. Ideal for expense tracking, inventory analysis, or accounting exports.",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "Amazon region code",
          enum: getRegionCodes(),
        },
        year: {
          type: "number",
          description: "Year to export (defaults to current year)",
        },
        start_date: {
          type: "string",
          description: "Start date in ISO format (YYYY-MM-DD)",
        },
        end_date: {
          type: "string",
          description: "End date in ISO format (YYYY-MM-DD)",
        },
        output_path: {
          type: "string",
          description:
            "Full path to save CSV file. Defaults to ~/Downloads/amazon-{region}-items-{year}-{date}.csv",
        },
        max_orders: {
          type: "number",
          description:
            "Maximum number of orders to process. Recommended: 50-100 per batch due to ~2s/order extraction time.",
        },
      },
      required: ["region"],
    },
  },
  {
    name: "export_amazon_shipments_csv",
    description:
      "Export Amazon shipment tracking data to CSV file. Visits each order's detail page to extract tracking info (~4s/order). CSV columns: Order ID, Date, Shipment ID, Status, Delivered (Yes/No/Unknown), Tracking ID, Tracking URL, Items in Shipment, Item Names, Payment Amount, Refund. Useful for tracking deliveries and reconciling shipments.",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "Amazon region code",
          enum: getRegionCodes(),
        },
        year: {
          type: "number",
          description: "Year to export (defaults to current year)",
        },
        start_date: {
          type: "string",
          description: "Start date in ISO format (YYYY-MM-DD)",
        },
        end_date: {
          type: "string",
          description: "End date in ISO format (YYYY-MM-DD)",
        },
        output_path: {
          type: "string",
          description:
            "Full path to save CSV file. Defaults to ~/Downloads/amazon-{region}-shipments-{year}-{date}.csv",
        },
        max_orders: {
          type: "number",
          description:
            "Maximum number of orders to process. Recommended: 25-50 per batch due to ~4s/order extraction time.",
        },
        fetch_tracking_numbers: {
          type: "boolean",
          description:
            "Extract actual carrier tracking numbers (e.g., AZ218181365JE) by visiting each shipment's 'Track package' page. Adds ~2s per shipment.",
          default: false,
        },
      },
      required: ["region"],
    },
  },
  {
    name: "export_amazon_transactions_csv",
    description:
      "Export Amazon payment transactions to CSV file. Extracts transaction data from each order's detail page. CSV columns include: date, order ID, amount, payment method, card info. For faster bulk transaction export, consider get_amazon_transactions which scrapes the dedicated transactions page.",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "Amazon region code",
          enum: getRegionCodes(),
        },
        year: {
          type: "number",
          description: "Year to export (defaults to current year)",
        },
        start_date: {
          type: "string",
          description: "Start date in ISO format (YYYY-MM-DD)",
        },
        end_date: {
          type: "string",
          description: "End date in ISO format (YYYY-MM-DD)",
        },
        output_path: {
          type: "string",
          description:
            "Full path to save CSV file. Defaults to ~/Downloads/amazon-{region}-transactions-{year}-{date}.csv",
        },
        max_orders: {
          type: "number",
          description: "Maximum number of orders to process",
        },
      },
      required: ["region"],
    },
  },
  {
    name: "get_amazon_transactions",
    description:
      "Fetch all Amazon payment transactions from the dedicated transactions page. Faster than per-order extraction and supports both paginated and legacy infinite-scroll layouts. Returns: date, order IDs, amount, payment method, card info (last 4 digits), vendor. Useful for reconciling payments, tracking spending, or exporting for accounting.",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "Amazon region code",
          enum: getRegionCodes(),
        },
        start_date: {
          type: "string",
          description: "Start date filter in ISO format (YYYY-MM-DD)",
        },
        end_date: {
          type: "string",
          description: "End date filter in ISO format (YYYY-MM-DD)",
        },
        max_scrolls: {
          type: "number",
          description:
            "Maximum page or scroll advances used to load transactions. Default: 50. Increase for longer history.",
        },
      },
      required: ["region"],
    },
  },
  {
    name: "get_amazon_gift_card_balance",
    description:
      "Get current Amazon gift card balance and transaction history. Returns: current balance, last updated timestamp, and paginated transaction history (date, description, amount, closing balance, type, associated order ID, claim code, serial number). Supports fetching complete history across multiple pages.",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "Amazon region code",
          enum: getRegionCodes(),
        },
        max_pages: {
          type: "number",
          description:
            "Maximum pages of transaction history to fetch. Default: 10. Set to 0 for unlimited.",
          default: 10,
        },
        fetch_all_pages: {
          type: "boolean",
          description:
            "Automatically paginate through all available transaction history. Default: true.",
          default: true,
        },
      },
      required: ["region"],
    },
  },
  {
    name: "export_amazon_gift_cards_csv",
    description:
      "Export Amazon gift card transaction history to CSV file. CSV columns: Date, Description, Amount, Closing Balance, Type (credit/debit), Order ID, Claim Code, Serial Number, Region. Useful for tracking gift card usage and reconciling balances.",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "Amazon region code",
          enum: getRegionCodes(),
        },
        output_path: {
          type: "string",
          description:
            "Full path to save CSV file. Defaults to ~/Downloads/amazon-{region}-gift-cards-{date}.csv",
        },
        max_pages: {
          type: "number",
          description:
            "Maximum pages of transaction history to fetch. Default: 10. Set to 0 for unlimited.",
          default: 10,
        },
      },
      required: ["region"],
    },
  },
  {
    name: "get_amazon_gift_card_transactions",
    description:
      "Get Amazon gift card transaction history with full details. Returns: current balance, transaction count, and detailed transactions (date, description, amount, closing balance, transaction type, order ID, claim code, serial number). Supports pagination for complete history.",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "Amazon region code",
          enum: getRegionCodes(),
        },
        max_pages: {
          type: "number",
          description:
            "Maximum pages of transaction history to fetch. Default: 10. Set to 0 for unlimited.",
          default: 10,
        },
      },
      required: ["region"],
    },
  },
  {
    name: "check_amazon_auth_status",
    description:
      "Check if the browser session is authenticated with Amazon for a specific region. Returns authentication status (authenticated/not authenticated), current URL, and any error messages. Use this to verify login status before running other tools, or to prompt user to log in if session expired.",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "Amazon region code to check authentication for",
          enum: getRegionCodes(),
        },
      },
      required: ["region"],
    },
  },
];

// Create server instance
const server = new Server(
  {
    name: "amazon-order-history-csv-download-mcp",
    version: packageMetadata.version,
  },
  {
    capabilities: {
      tools: {},
    },
  },
);

/**
 * Send progress notification to client.
 */
async function sendProgress(
  progressToken: string | number | undefined,
  progress: number,
  total: number,
  message: string,
): Promise<void> {
  if (!progressToken) return;

  try {
    await server.notification({
      method: "notifications/progress",
      params: {
        progressToken,
        progress,
        total,
        message,
      },
    } as unknown as ProgressNotification);
  } catch (e) {
    // Progress notifications are optional, don't fail on errors
    console.error(`[progress] Failed to send: ${e}`);
  }
}

/**
 * Shared gift card data structure for export.
 */
interface GiftCardExportData {
  balance: {
    amount: number;
    currency: string;
    formatted: string;
  };
  lastUpdated: string;
  region: string;
  transactionCount: number;
  transactions: Array<{
    date: string;
    description: string;
    amount: {
      amount: number;
      currency: string;
      currencySymbol: string;
      formatted: string;
    };
    closingBalance: {
      amount: number;
      currency: string;
      currencySymbol: string;
      formatted: string;
    };
    type: string;
    orderId?: string;
    claimCode?: string;
    serialNumber?: string;
  }>;
}

/**
 * Convert GiftCardData to export format (shared by CSV and JSON exports).
 */
function formatGiftCardDataForExport(
  giftCardData: GiftCardData,
): GiftCardExportData {
  return {
    balance: {
      amount: giftCardData.balance.balance.amount,
      currency: giftCardData.balance.balance.currency,
      formatted: giftCardData.balance.balance.formatted,
    },
    lastUpdated: giftCardData.balance.lastUpdated.toISOString(),
    region: giftCardData.region,
    transactionCount: giftCardData.transactions.length,
    transactions: giftCardData.transactions.map((t) => ({
      date: t.date.toISOString(),
      description: t.description,
      amount: {
        amount: t.amount.amount,
        currency: t.amount.currency,
        currencySymbol: t.amount.currencySymbol,
        formatted: t.amount.formatted,
      },
      closingBalance: {
        amount: t.closingBalance.amount,
        currency: t.closingBalance.currency,
        currencySymbol: t.closingBalance.currencySymbol,
        formatted: t.closingBalance.formatted,
      },
      type: t.type,
      orderId: t.orderId,
      claimCode: t.claimCode,
      serialNumber: t.serialNumber,
    })),
  };
}

/**
 * Convert GiftCardData to CSV export format.
 */
function formatGiftCardDataForCSV(
  giftCardData: GiftCardData,
): GiftCardTransactionCSVData[] {
  return giftCardData.transactions.map((t) => ({
    date: t.date,
    description: t.description,
    amount: t.amount,
    closingBalance: t.closingBalance,
    type: t.type,
    orderId: t.orderId,
    claimCode: t.claimCode,
    serialNumber: t.serialNumber,
    region: giftCardData.region,
  }));
}

async function handleInvoiceDownload(
  args: Record<string, unknown> | undefined,
) {
  const regionParam = args?.region as string | undefined;
  const regionError = validateRegion(regionParam, args);
  if (regionError) return regionError;
  const region = regionParam ?? "";
  const orderId = args?.order_id as string | undefined;
  const requestedOutputPath = args?.output_path as string | undefined;

  if (!orderId || !isValidAmazonOrderId(orderId)) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            status: "error",
            params: { orderId, region, outputPath: requestedOutputPath },
            error: "order_id must use the XXX-XXXXXXX-XXXXXXX Amazon format",
          }),
        },
      ],
      isError: true,
    };
  }

  const outputPath =
    requestedOutputPath ??
    join(homedir(), "Downloads", `amazon-${region}-invoice-${orderId}.pdf`);
  if (!isAbsolute(outputPath)) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            status: "error",
            params: { orderId, region, outputPath },
            error: "output_path must be an absolute path",
          }),
        },
      ],
      isError: true,
    };
  }

  const regionConfig = getRegionByCode(region);
  if (!regionConfig) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            status: "error",
            params: { orderId, region, outputPath },
            error: `Invalid region: "${region}"`,
          }),
        },
      ],
      isError: true,
    };
  }

  const result = await downloadAmazonInvoice({
    page: await getPage(),
    orderId,
    domain: regionConfig.domain,
    outputPath,
  });
  const response = result.success
    ? {
        status: "success",
        params: { orderId, region, outputPath },
        path: result.filePath,
        bytes: result.bytes,
      }
    : {
        status: "error",
        params: { orderId, region, outputPath },
        error: result.error,
      };

  return {
    content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
    ...(result.success ? {} : { isError: true }),
  };
}

// Handle list tools request
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools };
});

// Handle tool calls
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function runTool(request: any): Promise<any> {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "get_amazon_orders": {
        const regionParam = args?.region as string | undefined;
        const regionError = validateRegion(regionParam, args);
        if (regionError) return regionError;
        const region = regionParam!; // Validated above

        // Get progress token from request meta
        const progressToken = request.params._meta?.progressToken;

        const currentPage = await getPage();
        const result = await fetchOrders(currentPage, amazonPlugin, {
          region,
          year: args?.year as number | undefined,
          startDate: args?.start_date as string | undefined,
          endDate: args?.end_date as string | undefined,
          includeItems: args?.include_items as boolean | undefined,
          includeShipments: args?.include_shipments as boolean | undefined,
          fetchTrackingNumbers: args?.fetch_tracking_numbers as
            | boolean
            | undefined,
          maxOrders: args?.max_orders as number | undefined,
          onProgress: async (message, current, total) => {
            await sendProgress(progressToken, current, total, message);
          },
        });

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: "success",
                  // Echo input parameters for debugging
                  params: {
                    region,
                    year: args?.year,
                    startDate: args?.start_date,
                    endDate: args?.end_date,
                    includeItems: args?.include_items,
                    includeShipments: args?.include_shipments,
                    fetchTrackingNumbers: args?.fetch_tracking_numbers,
                    maxOrders: args?.max_orders,
                  },
                  totalOrders: result.totalFound,
                  orders: result.orders.map((o) => ({
                    id: o.id,
                    date: o.date?.toISOString(),
                    total: o.total,
                    status: o.status?.label || "Unknown",
                    // Use itemCount from order header (extracted from list page) or fall back to items array length
                    itemCount: o.itemCount ?? o.items?.length ?? 0,
                    shipmentCount: o.shipments?.length || 0,
                    // Enhanced order header data from list page
                    subtotal: o.subtotal,
                    shipping: o.shipping,
                    tax: o.tax,
                    vat: o.vat,
                    promotion: o.promotion,
                    grandTotal: o.grandTotal,
                    // Shipping address
                    shippingAddress: o.shippingAddress,
                    // Payment method from list page
                    paymentMethod: o.paymentMethod,
                    // Recipient (simple name)
                    recipient:
                      typeof o.recipient === "object"
                        ? o.recipient
                        : { name: o.recipient },
                    // Payments from detail/invoice
                    payments: o.payments,
                    // Include items when extracted
                    items: o.items?.map((i) => ({
                      name: i.name,
                      asin: i.asin,
                      quantity: i.quantity,
                      unitPrice: i.unitPrice,
                      condition: i.condition,
                      seller: i.seller?.name,
                      subscriptionFrequency: i.subscriptionFrequency,
                    })),
                    // Include shipments when extracted
                    shipments: o.shipments?.map((s) => ({
                      shipmentId: s.shipmentId,
                      status: s.status,
                      delivered: s.delivered,
                      trackingId: s.trackingId,
                      carrier: s.carrier,
                      trackingLink: s.trackingLink,
                      itemCount: s.items?.length || 0,
                    })),
                  })),
                  itemCount: result.items.length,
                  shipmentCount: result.shipments.length,
                  errors: result.errors,
                },
                null,
                2,
              ),
            },
          ],
        };
      }

      case "get_amazon_order_details": {
        const regionParam = args?.region as string | undefined;
        const regionError = validateRegion(regionParam, args);
        if (regionError) return regionError;
        const region = regionParam!;

        const currentPage = await getPage();
        const orderId = args?.order_id as string;
        const includeShipments = args?.include_shipments as boolean | undefined;
        const fetchTrackingNumbers = args?.fetch_tracking_numbers as
          | boolean
          | undefined;
        const includeTransactions = args?.include_transactions as
          | boolean
          | undefined;

        // Use the same fetchOrders logic that works for get_amazon_orders
        const result = await fetchOrders(currentPage, amazonPlugin, {
          region,
          orderId, // This triggers single-order mode
          includeItems: true,
          includeShipments: includeShipments ?? true,
          fetchTrackingNumbers: fetchTrackingNumbers ?? false,
          includeTransactions: includeTransactions ?? false,
        });

        const order = result.orders[0];

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: result.errors.length > 0 ? "error" : "success",
                  params: {
                    orderId,
                    region,
                    includeShipments,
                    fetchTrackingNumbers,
                    includeTransactions,
                  },
                  order: order
                    ? {
                        id: order.id,
                        date: order.date?.toISOString(),
                        total: order.total,
                        shipping: order.shipping,
                        tax: order.tax,
                        recipient: order.recipient,
                        payments: order.payments,
                        itemCount: order.items?.length || 0,
                        shipmentCount: order.shipments?.length || 0,
                      }
                    : null,
                  items: result.items.map((i) => ({
                    name: i.name,
                    asin: i.asin,
                    quantity: i.quantity,
                    unitPrice: i.unitPrice,
                    condition: i.condition,
                    seller: i.seller?.name,
                    subscriptionFrequency: i.subscriptionFrequency,
                  })),
                  shipments: result.shipments.map((s) => ({
                    shipmentId: s.shipmentId,
                    status: s.status,
                    delivered: s.delivered,
                    trackingId: s.trackingId,
                    carrier: s.carrier,
                    trackingLink: s.trackingLink,
                    itemCount: s.items?.length || 0,
                  })),
                  transactions: result.transactions.map((t) => ({
                    date: t.date.toISOString(),
                    amount: t.amount,
                    vendor: t.vendor,
                    cardInfo: t.cardInfo,
                  })),
                  errors: result.errors,
                },
                null,
                2,
              ),
            },
          ],
        };
      }

      case "download_amazon_invoice": {
        return handleInvoiceDownload(args);
      }

      case "export_amazon_orders_csv": {
        const regionParam = args?.region as string | undefined;
        const regionError = validateRegion(regionParam, args);
        if (regionError) return regionError;
        const region = regionParam!;

        const currentPage = await getPage();
        const year = args?.year as number | undefined;
        const startDate = args?.start_date as string | undefined;
        const endDate = args?.end_date as string | undefined;
        const maxOrders = args?.max_orders as number | undefined;
        const outputPath = getOutputPath(
          args?.output_path as string | undefined,
          "orders",
          region,
          { year, startDate, endDate },
        );

        const fetchResult = await fetchOrders(currentPage, amazonPlugin, {
          region,
          year,
          startDate,
          endDate,
          includeItems: false,
          includeShipments: false,
          maxOrders,
        });

        // Calculate time estimate for informational purposes
        const timeEstimate = estimateExtractionTime(fetchResult.orders.length, {
          includeItems: false,
          includeShipments: false,
        });

        const exportResult = await exportOrdersCSV(
          fetchResult.orders,
          outputPath,
        );

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: exportResult.success ? "success" : "error",
                  params: {
                    region,
                    year,
                    startDate,
                    endDate,
                    maxOrders,
                    outputPath,
                  },
                  filePath: exportResult.filePath,
                  rowCount: exportResult.rowCount,
                  error: exportResult.error,
                  fetchErrors: fetchResult.errors,
                  // Include timing info for transparency
                  timing: {
                    orderCount: fetchResult.orders.length,
                    estimate: timeEstimate.formattedEstimate,
                    warnings: timeEstimate.warnings,
                    recommendations: timeEstimate.recommendations,
                  },
                },
                null,
                2,
              ),
            },
          ],
        };
      }

      case "export_amazon_items_csv": {
        const regionParam = args?.region as string | undefined;
        const regionError = validateRegion(regionParam, args);
        if (regionError) return regionError;
        const region = regionParam!;

        const currentPage = await getPage();
        const year = args?.year as number | undefined;
        const startDate = args?.start_date as string | undefined;
        const endDate = args?.end_date as string | undefined;
        const maxOrders = args?.max_orders as number | undefined;
        const outputPath = getOutputPath(
          args?.output_path as string | undefined,
          "items",
          region,
          { year, startDate, endDate },
        );

        // Pre-estimate time for items extraction (slower due to invoice/detail page visits)
        const preEstimate = estimateExtractionTime(maxOrders || 100, {
          includeItems: true,
          includeShipments: false,
          useInvoice: true,
        });

        // Warn if this might take a while
        if (preEstimate.warnings.length > 0) {
          console.error(
            `[export-items] Time estimate: ${preEstimate.formattedEstimate}`,
          );
          console.error(
            `[export-items] Warnings: ${preEstimate.warnings.join(", ")}`,
          );
        }

        const fetchResult = await fetchOrders(currentPage, amazonPlugin, {
          region,
          year,
          startDate,
          endDate,
          includeItems: true,
          includeShipments: false,
          maxOrders,
        });

        // Calculate actual time estimate based on orders found
        const timeEstimate = estimateExtractionTime(fetchResult.orders.length, {
          includeItems: true,
          includeShipments: false,
          useInvoice: true,
        });

        const exportResult = await exportItemsCSV(
          fetchResult.items,
          outputPath,
        );

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: exportResult.success ? "success" : "error",
                  params: {
                    region,
                    year,
                    startDate,
                    endDate,
                    maxOrders,
                    outputPath,
                  },
                  filePath: exportResult.filePath,
                  rowCount: exportResult.rowCount,
                  error: exportResult.error,
                  fetchErrors: fetchResult.errors,
                  timing: {
                    orderCount: fetchResult.orders.length,
                    itemCount: fetchResult.items.length,
                    estimate: timeEstimate.formattedEstimate,
                    warnings: timeEstimate.warnings,
                    recommendations: timeEstimate.recommendations,
                  },
                },
                null,
                2,
              ),
            },
          ],
        };
      }

      case "export_amazon_shipments_csv": {
        const regionParam = args?.region as string | undefined;
        const regionError = validateRegion(regionParam, args);
        if (regionError) return regionError;
        const region = regionParam!;

        const currentPage = await getPage();
        const year = args?.year as number | undefined;
        const startDate = args?.start_date as string | undefined;
        const endDate = args?.end_date as string | undefined;
        const maxOrders = args?.max_orders as number | undefined;
        const fetchTrackingNumbers = args?.fetch_tracking_numbers as
          | boolean
          | undefined;
        const outputPath = getOutputPath(
          args?.output_path as string | undefined,
          "shipments",
          region,
          { year, startDate, endDate },
        );

        const fetchResult = await fetchOrders(currentPage, amazonPlugin, {
          region,
          year,
          startDate,
          endDate,
          includeItems: false,
          includeShipments: true,
          fetchTrackingNumbers: fetchTrackingNumbers ?? false,
          maxOrders,
        });

        const timeEstimate = estimateExtractionTime(fetchResult.orders.length, {
          includeItems: false,
          includeShipments: true,
        });

        const exportResult = await exportShipmentsCSV(
          fetchResult.shipments,
          outputPath,
        );

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: exportResult.success ? "success" : "error",
                  params: {
                    region,
                    year,
                    startDate,
                    endDate,
                    maxOrders,
                    fetchTrackingNumbers,
                    outputPath,
                  },
                  filePath: exportResult.filePath,
                  rowCount: exportResult.rowCount,
                  error: exportResult.error,
                  fetchErrors: fetchResult.errors,
                  timing: {
                    orderCount: fetchResult.orders.length,
                    shipmentCount: fetchResult.shipments.length,
                    estimate: timeEstimate.formattedEstimate,
                    warnings: timeEstimate.warnings,
                    recommendations: timeEstimate.recommendations,
                  },
                },
                null,
                2,
              ),
            },
          ],
        };
      }

      case "export_amazon_transactions_csv": {
        const regionParam = args?.region as string | undefined;
        const regionError = validateRegion(regionParam, args);
        if (regionError) return regionError;
        const region = regionParam!;

        const currentPage = await getPage();
        const year = args?.year as number | undefined;
        const startDate = args?.start_date as string | undefined;
        const endDate = args?.end_date as string | undefined;
        const maxOrders = args?.max_orders as number | undefined;
        const outputPath = getOutputPath(
          args?.output_path as string | undefined,
          "transactions",
          region,
          { year, startDate, endDate },
        );

        const fetchResult = await fetchOrders(currentPage, amazonPlugin, {
          region,
          year,
          startDate,
          endDate,
          includeItems: false,
          includeShipments: false,
          includeTransactions: true,
          maxOrders,
        });

        const timeEstimate = estimateExtractionTime(fetchResult.orders.length, {
          includeItems: false,
          includeShipments: false,
        });

        const exportResult = await exportTransactionsCSV(
          fetchResult.transactions,
          outputPath,
        );

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: exportResult.success ? "success" : "error",
                  params: {
                    region,
                    year,
                    startDate,
                    endDate,
                    maxOrders,
                    outputPath,
                  },
                  filePath: exportResult.filePath,
                  rowCount: exportResult.rowCount,
                  error: exportResult.error,
                  fetchErrors: fetchResult.errors,
                  timing: {
                    orderCount: fetchResult.orders.length,
                    transactionCount: fetchResult.transactions.length,
                    estimate: timeEstimate.formattedEstimate,
                    warnings: timeEstimate.warnings,
                    recommendations: timeEstimate.recommendations,
                  },
                },
                null,
                2,
              ),
            },
          ],
        };
      }

      case "get_amazon_transactions": {
        const regionParam = args?.region as string | undefined;
        const regionError = validateRegion(regionParam, args);
        if (regionError) return regionError;
        const region = regionParam!;

        const currentPage = await getPage();
        const progressToken = request.params._meta?.progressToken;
        const startDate = args?.start_date as string | undefined;
        const endDate = args?.end_date as string | undefined;
        const maxScrolls = args?.max_scrolls as number | undefined;

        const transactions = await extractTransactionsFromPage(
          currentPage,
          region,
          {
            startDate: startDate ? new Date(startDate) : undefined,
            endDate: endDate ? new Date(endDate) : undefined,
            maxScrolls,
            onProgress: async (message, count) => {
              await sendProgress(progressToken, count, 0, message);
            },
          },
        );

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: "success",
                  params: {
                    region,
                    startDate,
                    endDate,
                    maxScrolls,
                  },
                  transactionCount: transactions.length,
                  transactions: transactions.map((t) => ({
                    date: t.date.toISOString(),
                    orderIds: t.orderIds,
                    amount: t.amount,
                    cardInfo: t.cardInfo,
                    vendor: t.vendor,
                  })),
                },
                null,
                2,
              ),
            },
          ],
        };
      }

      case "get_amazon_gift_card_balance": {
        const regionParam = args?.region as string | undefined;
        const regionError = validateRegion(regionParam, args);
        if (regionError) return regionError;
        const region = regionParam!;

        const currentPage = await getPage();
        const maxPages = (args?.max_pages as number) ?? 10;
        const fetchAllPages = (args?.fetch_all_pages as boolean) ?? true;

        const giftCardData = await extractGiftCardData(currentPage, region, {
          maxPages,
          fetchAllPages,
        });

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: "success",
                  params: {
                    region,
                    maxPages,
                    fetchAllPages,
                  },
                  balance: giftCardData.balance.balance,
                  lastUpdated: giftCardData.balance.lastUpdated.toISOString(),
                  transactionCount: giftCardData.transactions.length,
                  transactions: giftCardData.transactions.map((t) => ({
                    date: t.date.toISOString(),
                    description: t.description,
                    amount: t.amount,
                    closingBalance: t.closingBalance,
                    type: t.type,
                    orderId: t.orderId,
                    claimCode: t.claimCode,
                    serialNumber: t.serialNumber,
                  })),
                },
                null,
                2,
              ),
            },
          ],
        };
      }

      case "export_amazon_gift_cards_csv": {
        const regionParam = args?.region as string | undefined;
        const regionError = validateRegion(regionParam, args);
        if (regionError) return regionError;
        const region = regionParam!;

        const currentPage = await getPage();
        const outputPath = args?.output_path as string | undefined;
        const maxPages = (args?.max_pages as number) ?? 10;

        // Extract gift card transactions
        const giftCardData = await extractGiftCardData(currentPage, region, {
          maxPages,
          fetchAllPages: true,
        });

        // Convert to CSV format using shared helper
        const csvData = formatGiftCardDataForCSV(giftCardData);

        // Generate output path
        const today = new Date().toISOString().split("T")[0];
        const finalPath = getOutputPath(outputPath, "gift-cards", region, {
          endDate: today,
        });

        // Export to CSV
        const exportResult = await exportGiftCardTransactionsCSV(
          csvData,
          finalPath,
        );

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: exportResult.success ? "success" : "error",
                  params: {
                    region,
                    maxPages,
                  },
                  balance: giftCardData.balance.balance,
                  transactionCount: giftCardData.transactions.length,
                  filePath: exportResult.filePath,
                  rowCount: exportResult.rowCount,
                  error: exportResult.error,
                },
                null,
                2,
              ),
            },
          ],
        };
      }

      case "get_amazon_gift_card_transactions": {
        const regionParam = args?.region as string | undefined;
        const regionError = validateRegion(regionParam, args);
        if (regionError) return regionError;
        const region = regionParam!;

        const currentPage = await getPage();
        const maxPages = (args?.max_pages as number) ?? 10;

        // Extract gift card transactions
        const giftCardData = await extractGiftCardData(currentPage, region, {
          maxPages,
          fetchAllPages: true,
        });

        // Convert to export format using shared helper
        const exportData = formatGiftCardDataForExport(giftCardData);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: "success",
                  params: {
                    region,
                    maxPages,
                  },
                  ...exportData,
                },
                null,
                2,
              ),
            },
          ],
        };
      }

      case "check_amazon_auth_status": {
        const regionParam = args?.region as string | undefined;
        const regionError = validateRegion(regionParam, args);
        if (regionError) return regionError;
        const region = regionParam!;

        const currentPage = await getPage();
        const authStatus = await amazonPlugin.checkAuthStatus(
          currentPage,
          region,
        );

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: authStatus.authenticated ? "success" : "error",
                  params: {
                    region,
                  },
                  authenticated: authStatus.authenticated,
                  username: authStatus.username,
                  message: authStatus.message,
                  loginUrl: authStatus.authenticated
                    ? undefined
                    : amazonPlugin.getLoginUrl(region),
                },
                null,
                2,
              ),
            },
          ],
        };
      }

      default:
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: `Unknown tool: ${name}`,
              }),
            },
          ],
          isError: true,
        };
    }
  } catch (error) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            error: String(error),
          }),
        },
      ],
      isError: true,
    };
  }
}

// ---- sign-in guard ------------------------------------------------------------------
// Every tool call first makes sure the browser is signed in, re-importing Chrome's
// cookies and retrying when it is not (see core/auth-guard.ts for why). One guard per
// region, since each Amazon domain has its own session.
const guards = new Map<string, AuthGuard>();

// Every region's check navigates the ONE shared page, so checks take turns: each guard
// already coalesces its own callers, and this chain keeps two regions from racing goto().
let checkChain: Promise<unknown> = Promise.resolve();
function serialized<T>(fn: () => Promise<T>): Promise<T> {
  const run = checkChain.then(fn, fn);
  checkChain = run.catch(() => undefined);
  return run;
}

function guardFor(region: string): AuthGuard {
  let g = guards.get(region);
  if (!g) {
    g = new AuthGuard({
      check: () => serialized(async () => {
        const p = await getPage();
        // Always load fresh: checkAuthStatus trusts whatever Amazon page is already
        // open, which can be a stale signed-in view of a session that has since expired.
        await p
          .goto(amazonPlugin.getLoginUrl(region).replace("/ap/signin", "/gp/css/order-history"), {
            waitUntil: "domcontentloaded",
            timeout: 60000,
          })
          .catch(() => {});
        const url = p.url();
        // NOT max_auth_age=0: Amazon adds it to every order-history sign-in redirect.
        const reauthRequired =
          url.includes("/ap/cvf") ||
          ((await p.locator("#ap_password").count()) > 0 && (await p.locator("#ap_email").count()) === 0);
        const st = await amazonPlugin.checkAuthStatus(p, region);
        return { authenticated: st.authenticated && !reauthRequired, reauthRequired, message: st.message };
      }),
      reimport: async () => importSessionFromChrome(await getBrowserContext()),
      sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
      now: () => Date.now(),
    });
    guards.set(region, g);
  }
  return g;
}

function signInError(region: string, r: { code: string; message: string; attempts: number }) {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(
          { status: "error", error: r.code, message: r.message, attempts: r.attempts, region,
            loginUrl: amazonPlugin.getLoginUrl(region) },
          null,
          2,
        ),
      },
    ],
    isError: true,
  };
}

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const region = request.params.arguments?.region as string | undefined;
  const guarded = !!region && getRegionCodes().includes(region);
  if (guarded) {
    const before = await guardFor(region!).ensure();
    if (!before.ok) return signInError(region!, before);
  }
  const result = await runTool(request);
  if (!guarded || result?.isError) return result;
  // A signed-out page yields exactly an empty list. Before an empty result is returned
  // as "success", confirm the session is still alive - it can expire mid-call.
  let payload: unknown;
  try {
    payload = JSON.parse(result?.content?.[0]?.text ?? "");
  } catch {
    return result;
  }
  if (looksEmpty(payload)) {
    const g = guardFor(region!);
    g.invalidate();
    const after = await g.ensure();
    if (!after.ok) return signInError(region!, after);
    if (after.repaired) return runTool(request); // the session was fixed - try once more
  }
  return result;
});

// Cleanup on exit. The owner closes the browser; an attached server only disconnects.
async function shutdownBrowser(): Promise<void> {
  try {
    if (attachedBrowser) {
      await attachedBrowser.close();
    } else if (browserContext) {
      await browserContext.close();
    }
  } catch {
    // already gone
  }
}

process.on("SIGINT", async () => {
  await shutdownBrowser();
  process.exit(0);
});

process.on("SIGTERM", async () => {
  await shutdownBrowser();
  process.exit(0);
});

// Main entry point
async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Amazon Order History CSV Download MCP server running");
}

main().catch(console.error);
