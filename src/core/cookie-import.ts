/**
 * Copy Chrome's Cookies database and decrypt its amazon.com cookies.
 *
 * Ported from the tmedford/linkedin-mcp-server browser_import module
 * (Python), scoped down to macOS + Chrome's default profile only - this repo
 * has no Linux/Windows deployment target and no multi-browser requirement.
 *
 * Cryptographic constants are fixed by Chromium's cookie format, same as the
 * source this was ported from:
 * - salt "saltysalt"; AES-128-CBC; IV = 16 space bytes.
 * - PBKDF2-HMAC-SHA1, 1003 iterations on macOS, dklen 16.
 * - v10/v11 prefixes are 3 bytes. Store version >= 24 prepends a 32-byte
 *   SHA256(host_key) digest inside the plaintext (decrypt -> unpad -> strip-32).
 * - v20 is Chrome 127+ app-bound encryption and needs OS elevation; skipped,
 *   never attempted - the same refusal as the source, not a bypass.
 *
 * The macOS Keychain read (`security find-generic-password`) is the actual
 * consent gate: the OS may prompt the user the first time this runs. Nothing
 * here reads or stores a password - only the already-authenticated session
 * cookie.
 *
 * Decrypted cookie VALUES are never logged - only counts. If you are
 * reviewing this file for what it exposes: the macOS Keychain "Safe Storage"
 * password is Chrome's master cookie key (all sites, not just Amazon) and is
 * held in memory only for the duration of this function; the only thing
 * returned to the caller is decrypted amazon.com cookies.
 */

import { execFileSync } from "child_process";
import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

/**
 * Run a read-only query against a SQLite file via the system `sqlite3` CLI
 * (ships with macOS at /usr/bin/sqlite3 - no dependency needed) and parse
 * its `-json` output. Binary columns must be selected as `hex(col)`, since
 * JSON can't carry raw bytes - callers decode the hex themselves.
 */
function sqliteJson<T>(dbPath: string, sql: string): T[] {
  const out = execFileSync(
    "sqlite3",
    ["-readonly", "-json", dbPath, sql],
    { timeout: 10_000 }
  )
    .toString()
    .trim();
  if (!out) return []; // sqlite3 -json prints nothing for zero rows
  return JSON.parse(out) as T[];
}

const SALT = "saltysalt";
const CBC_IV = Buffer.alloc(16, " "); // 16 space bytes
const KEY_LENGTH = 16;
const MACOS_ITERATIONS = 1003;
const HOST_KEY_PREFIX_LEN = 32; // SHA256(host_key) prepended for store version >= 24
const HOST_KEY_PREFIX_MIN_VERSION = 24;
const TARGET_DOMAIN = "amazon.com";

export interface ImportedCookie {
  name: string;
  value: string; // decrypted plaintext - caller must never log this
  domain: string;
  path: string;
  expires: number; // unix seconds; -1 for a session cookie (Playwright sentinel)
  secure: boolean;
  httpOnly: boolean;
  sameSite: "Strict" | "Lax" | "None";
}

export class V20EncryptedError extends Error {}
export class KeystoreUnavailableError extends Error {}

const SAMESITE_MAP: Record<number, "Strict" | "Lax" | "None"> = {
  [-1]: "Lax",
  0: "None",
  1: "Lax",
  2: "Strict",
};

function chromeCookiesDbPath(): string {
  return path.join(
    os.homedir(),
    "Library",
    "Application Support",
    "Google",
    "Chrome",
    "Default",
    "Cookies"
  );
}

function macosSafeStoragePassword(
  account = "Chrome",
  service = "Chrome Safe Storage"
): Buffer {
  const attempts: string[][] = [
    ["find-generic-password", "-a", account, "-w"],
    ["find-generic-password", "-a", account, "-s", service, "-w"],
  ];
  let lastError: unknown;
  for (const args of attempts) {
    try {
      const out = execFileSync("security", args, { timeout: 10_000 });
      return Buffer.from(out.toString().replace(/\n$/, ""), "utf8");
    } catch (e) {
      lastError = e instanceof Error ? e.message : "unknown error";
    }
  }
  throw new KeystoreUnavailableError(
    `macOS keychain has no Safe Storage key for account ${JSON.stringify(
      account
    )} (the browser may not have created it yet). Last attempt failed: ${String(
      lastError
    )}`
  );
}

function deriveCbcKey(password: Buffer, iterations = MACOS_ITERATIONS): Buffer {
  return crypto.pbkdf2Sync(password, SALT, iterations, KEY_LENGTH, "sha1");
}

function copyLockedDb(dbPath: string): { tempDir: string; dbCopy: string } {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "amazon-cookie-import-"));
  try {
    fs.chmodSync(tempDir, 0o700);
    const dbCopy = path.join(tempDir, "Cookies");
    fs.copyFileSync(dbPath, dbCopy);
    fs.chmodSync(dbCopy, 0o600);
    for (const suffix of ["-wal", "-shm"]) {
      const sidecar = dbPath + suffix;
      if (fs.existsSync(sidecar)) {
        const sidecarCopy = dbCopy + suffix;
        fs.copyFileSync(sidecar, sidecarCopy);
        fs.chmodSync(sidecarCopy, 0o600);
      }
    }
    return { tempDir, dbCopy };
  } catch (e) {
    fs.rmSync(tempDir, { recursive: true, force: true });
    throw e;
  }
}

function decryptCbc(blob: Buffer, key: Buffer, storeVersion: number): string {
  const ciphertext = blob.subarray(3);
  const decipher = crypto.createDecipheriv("aes-128-cbc", key, CBC_IV);
  let plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  if (storeVersion >= HOST_KEY_PREFIX_MIN_VERSION) {
    plaintext = plaintext.subarray(HOST_KEY_PREFIX_LEN);
  }
  return plaintext.toString("utf8");
}

function verifyHostKeyPrefix(blob: Buffer, key: Buffer, hostKey: string): boolean {
  try {
    const ciphertext = blob.subarray(3);
    const decipher = crypto.createDecipheriv("aes-128-cbc", key, CBC_IV);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const expected = crypto.createHash("sha256").update(hostKey, "utf8").digest();
    return plaintext.subarray(0, HOST_KEY_PREFIX_LEN).equals(expected);
  } catch {
    return false;
  }
}

function decryptValue(
  blob: Buffer | null,
  plaintextValue: string | null,
  cbcKey: Buffer,
  storeVersion: number
): string {
  if (plaintextValue) return plaintextValue;
  if (!blob || blob.length === 0) return "";
  const prefix = blob.subarray(0, 3).toString("latin1");
  if (prefix === "v20") {
    throw new V20EncryptedError(
      "Cookie uses Chrome 127+ app-bound encryption (v20); decryption requires OS elevation and is not supported."
    );
  }
  if (prefix === "v10" || prefix === "v11") {
    return decryptCbc(blob, cbcKey, storeVersion);
  }
  throw new V20EncryptedError("Cookie uses an unsupported encryption prefix");
}

function expiresToUnix(expiresUtc: number): number {
  if (!expiresUtc) return -1;
  const WINDOWS_EPOCH_OFFSET_SECONDS = 11_644_473_600;
  return expiresUtc / 1_000_000 - WINDOWS_EPOCH_OFFSET_SECONDS;
}

/**
 * Import amazon.com cookies from the local Chrome's default profile.
 * Returns [] (not a throw) when Chrome isn't installed, has no cookies DB,
 * or the keychain is unavailable - the caller falls back to manual login.
 */
export function importAmazonCookiesFromChrome(): ImportedCookie[] {
  const dbPath = chromeCookiesDbPath();
  if (!fs.existsSync(dbPath)) {
    return [];
  }

  let cbcKey: Buffer;
  try {
    const password = macosSafeStoragePassword();
    cbcKey = deriveCbcKey(password);
  } catch (e) {
    console.error(
      `[cookie-import] Keychain read failed, skipping import: ${e instanceof Error ? e.message : String(e)}`
    );
    return [];
  }

  let tempDir: string;
  let dbCopy: string;
  try {
    ({ tempDir, dbCopy } = copyLockedDb(dbPath));
  } catch (e) {
    console.error(
      `[cookie-import] Failed to copy Chrome's Cookies db, skipping import: ${e instanceof Error ? e.message : String(e)}`
    );
    return [];
  }

  const cookies: ImportedCookie[] = [];
  let skippedAppBound = 0;
  let skippedWrongKey = 0;
  try {
    let storeVersion = 0;
    try {
      const metaRows = sqliteJson<{ value: string }>(
        dbCopy,
        "SELECT value FROM meta WHERE key = 'version'"
      );
      storeVersion = metaRows[0]?.value ? parseInt(metaRows[0].value, 10) : 0;
    } catch {
      storeVersion = 0;
    }

    const columns = sqliteJson<{ name: string }>(
      dbCopy,
      "PRAGMA table_info(cookies)"
    );
    const names = new Set(columns.map((c) => c.name));
    const secureCol = names.has("is_secure") ? "is_secure" : "secure";
    const httpOnlyCol = names.has("is_httponly") ? "is_httponly" : "httponly";

    // encrypted_value is BLOB - hex-encode it for JSON transport, decode below.
    // Filter to TARGET_DOMAIN in SQL, not after fetching: pulling every cookie
    // from every site blew past execFileSync's default 1MB stdout buffer
    // ("ENOBUFS") on a normal Chrome profile, and it needlessly moved other
    // sites' encrypted cookie values through this pipeline for no reason.
    const rows = sqliteJson<{
      host_key: string | null;
      name: string;
      encrypted_value_hex: string | null;
      value: string | null;
      path: string | null;
      expires_utc: number | null;
      secure_col: number;
      httponly_col: number;
      samesite: number;
    }>(
      dbCopy,
      `SELECT host_key, name, hex(encrypted_value) AS encrypted_value_hex, value, path, expires_utc, ` +
        `${secureCol} AS secure_col, ${httpOnlyCol} AS httponly_col, samesite ` +
        `FROM cookies WHERE host_key LIKE '%${TARGET_DOMAIN}%'`
    );

    for (const row of rows) {
      const hostKey = row.host_key || "";
      if (!hostKey.includes(TARGET_DOMAIN)) continue;

      const blob = row.encrypted_value_hex
        ? Buffer.from(row.encrypted_value_hex, "hex")
        : null;
      const plaintextValue = row.value;

      if (
        !plaintextValue &&
        blob &&
        blob.length >= 3 &&
        (blob.subarray(0, 3).toString("latin1") === "v10" ||
          blob.subarray(0, 3).toString("latin1") === "v11") &&
        storeVersion >= HOST_KEY_PREFIX_MIN_VERSION &&
        !verifyHostKeyPrefix(blob, cbcKey, hostKey)
      ) {
        skippedWrongKey++;
        continue;
      }

      let value: string;
      try {
        value = decryptValue(blob, plaintextValue, cbcKey, storeVersion);
      } catch (e) {
        if (e instanceof V20EncryptedError) {
          skippedAppBound++;
        } else {
          skippedWrongKey++;
        }
        continue;
      }

      cookies.push({
        name: row.name,
        value,
        domain: hostKey,
        path: row.path || "/",
        expires: expiresToUnix(row.expires_utc || 0),
        secure: Boolean(row.secure_col),
        httpOnly: Boolean(row.httponly_col),
        sameSite: SAMESITE_MAP[row.samesite] ?? "Lax",
      });
    }
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }

  console.error(
    `[cookie-import] Extracted ${cookies.length} amazon.com cookies from Chrome ` +
      `(skipped ${skippedAppBound} app-bound, ${skippedWrongKey} wrong-key)`
  );
  return cookies;
}
