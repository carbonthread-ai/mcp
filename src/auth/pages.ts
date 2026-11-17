import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import { SCOPE_LABELS, SCOPE_READ, SCOPE_WRITE } from "../policy.js";

const esc = (s: unknown) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

const STYLE = `
:root { --bg:#f6f4ef; --card:#fff; --ink:#1c1b19; --muted:#6b675f; --line:#e4e0d6; --accent:#1c1b19; --danger:#a1301f; --soft:#f1eee6; }
@media (prefers-color-scheme: dark) { :root { --bg:#151412; --card:#1e1d1a; --ink:#f1eee6; --muted:#a19c91; --line:#34312b; --accent:#f1eee6; --danger:#ef8a78; --soft:#262420; } }
* { box-sizing: border-box; }
body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px 16px;
  background:var(--bg); color:var(--ink); font:15px/1.5 "Helvetica Neue", "Inter Tight", Helvetica, Arial, sans-serif; }
main { width:100%; max-width:420px; background:var(--card); border:1px solid var(--line); border-radius:14px; padding:28px; }
.brand { font-family:"Geist Mono", ui-monospace, monospace; font-size:11px; letter-spacing:.12em; text-transform:uppercase; color:var(--muted); }
h1 { font-family:"Instrument Serif", Georgia, serif; font-weight:400; font-size:30px; line-height:1.15; margin:10px 0 6px; }
p { margin:0 0 14px; color:var(--muted); }
.who { background:var(--soft); border-radius:10px; padding:10px 12px; font-size:13px; margin:0 0 18px; color:var(--muted); word-break:break-all; }
.who b { color:var(--ink); }
label { display:block; font-size:13px; font-weight:500; margin:0 0 6px; }
input[type=email], input[type=password] { width:100%; padding:11px 12px; border:1px solid var(--line); border-radius:9px; background:transparent; color:var(--ink); font:inherit; margin:0 0 14px; }
input:focus { outline:2px solid var(--accent); outline-offset:1px; }
fieldset { border:1px solid var(--line); border-radius:10px; padding:12px; margin:4px 0 18px; }
legend { font-size:12px; color:var(--muted); padding:0 4px; }
.scope { display:flex; gap:10px; align-items:flex-start; font-size:13px; margin:6px 0; color:var(--ink); }
.scope input { margin-top:3px; }
.never { font-size:12px; color:var(--muted); margin:8px 0 0; }
.error { color:var(--danger); background:color-mix(in srgb, var(--danger) 10%, transparent); border-radius:9px; padding:9px 12px; font-size:13px; margin:0 0 14px; }
.row { display:flex; gap:10px; }
button { flex:1; padding:12px; border-radius:9px; font:600 12px "DM Sans", "Helvetica Neue", sans-serif; letter-spacing:.08em; text-transform:uppercase; cursor:pointer; border:1px solid var(--accent); }
button.primary { background:var(--accent); color:var(--card); }
button.secondary { background:transparent; color:var(--ink); border-color:var(--line); }
`;

export interface SignInView {
  pendingId: string;
  csrf: string;
  client: OAuthClientInformationFull;
  redirectUri: string;
  scopes: string[];
  email?: string;
  error?: string;
}

export function renderSignIn(v: SignInView): string {
  const appName = v.client.client_name?.trim() || "An AI app";
  const host = (() => {
    try { const u = new URL(v.redirectUri); return u.host || u.protocol; } catch { return v.redirectUri; }
  })();
  const wantsWrite = v.scopes.includes(SCOPE_WRITE);
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connect ThreadOS</title><meta name="robots" content="noindex"><style>${STYLE}</style></head>
<body><main>
  <div class="brand">ThreadOS</div>
  <h1>Connect ${esc(appName)} to ThreadOS</h1>
  <p>Sign in with your ThreadOS account. ${esc(appName)} will act as you, with your role and only the clients you can already see.</p>
  <div class="who">Sends you back to <b>${esc(host)}</b></div>
  ${v.error ? `<div class="error" role="alert">${esc(v.error)}</div>` : ""}
  <form method="post" action="/oauth/sign-in" autocomplete="on">
    <input type="hidden" name="pending" value="${esc(v.pendingId)}">
    <input type="hidden" name="csrf" value="${esc(v.csrf)}">
    <label for="email">Email</label>
    <input id="email" name="email" type="email" required autocomplete="username" value="${esc(v.email)}" ${v.email ? "" : "autofocus"}>
    <label for="password">Password</label>
    <input id="password" name="password" type="password" required autocomplete="current-password" ${v.email ? "autofocus" : ""}>
    <fieldset><legend>${esc(appName)} may</legend>
      <label class="scope"><input type="checkbox" checked disabled> <span>${esc(SCOPE_LABELS[SCOPE_READ])}</span></label>
      ${wantsWrite ? `<label class="scope"><input type="checkbox" name="write" value="1" checked> <span>${esc(SCOPE_LABELS[SCOPE_WRITE])}</span></label>` : ""}
      <p class="never">It can never approve, send to a client, schedule, publish or delete. Those stay in ThreadOS.</p>
    </fieldset>
    <div class="row">
      <button class="secondary" type="submit" name="decision" value="deny" formnovalidate>Cancel</button>
      <button class="primary" type="submit" name="decision" value="allow">Sign in and allow</button>
    </div>
  </form>
</main></body></html>`;
}

export function renderMessage(title: string, message: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>ThreadOS</title><style>${STYLE}</style></head><body><main><div class="brand">ThreadOS</div><h1>${esc(title)}</h1><p>${esc(message)}</p></main></body></html>`;
}

/** CSP for the sign-in page. form-action also governs the redirect after the form posts, so it allows the app's origin. */
export function signInCsp(redirectUri: string): string {
  let target = "";
  try {
    const u = new URL(redirectUri);
    target = u.protocol === "http:" || u.protocol === "https:" ? u.origin : u.protocol;
  } catch {
    // Unparseable URIs never get this far (registration and /authorize validate them)
  }
  return `default-src 'none'; style-src 'unsafe-inline'; form-action 'self' ${target}; frame-ancestors 'none'; base-uri 'none'`;
}
