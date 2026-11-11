/**
 * Login cookie for the dashboard: after a request with the right WORKER_API_KEY,
 * muse-monitor keeps the authenticated state in a cookie for 7 days from that
 * login. The cookie never holds the key: its value is "<expiry unix s>.<hex
 * HMAC-SHA256(WORKER_API_KEY, 'muse-monitor-auth.<expiry>')>". Changing
 * WORKER_API_KEY invalidates every cookie. No other secret is involved.
 */
export const AUTH_COOKIE = "mm_auth";
export const AUTH_COOKIE_MAX_AGE_S = 7 * 24 * 60 * 60;

const ATTRS = "Path=/; HttpOnly; Secure; SameSite=Strict";

async function hmacHex(key: string, message: string): Promise<string> {
  const k = await crypto.subtle.importKey("raw", new TextEncoder().encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(message));
  return [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function sameString(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Set-Cookie value for a login at nowS (unix seconds). */
export async function makeAuthCookie(key: string, nowS: number): Promise<string> {
  const exp = nowS + AUTH_COOKIE_MAX_AGE_S;
  return `${AUTH_COOKIE}=${exp}.${await hmacHex(key, `muse-monitor-auth.${exp}`)}; ${ATTRS}; Max-Age=${AUTH_COOKIE_MAX_AGE_S}`;
}

export function clearAuthCookie(): string {
  return `${AUTH_COOKIE}=; ${ATTRS}; Max-Age=0`;
}

/** Whether the Cookie header carries a login cookie that is unexpired and signed with key. */
export async function authCookieValid(cookieHeader: string | null, key: string, nowS: number): Promise<boolean> {
  if (!cookieHeader || !key) return false;
  const pair = cookieHeader.split(";").map((p) => p.trim()).find((p) => p.startsWith(`${AUTH_COOKIE}=`));
  const value = pair?.slice(AUTH_COOKIE.length + 1) ?? "";
  const match = /^(\d{1,12})\.([0-9a-f]{64})$/.exec(value);
  if (!match) return false;
  const exp = Number(match[1]);
  // expired, or further ahead than any cookie this Worker issues
  if (exp <= nowS || exp > nowS + AUTH_COOKIE_MAX_AGE_S) return false;
  return sameString(await hmacHex(key, `muse-monitor-auth.${exp}`), match[2]);
}
