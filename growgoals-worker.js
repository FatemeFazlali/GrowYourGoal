// GrowGoals sync worker — deploy on Cloudflare Workers (free tier is enough).
//
// Set these as SECRETS (Settings -> Variables -> Add variable -> Encrypt):
//   GITHUB_TOKEN   a fine-grained GitHub personal access token, scoped to ONLY
//                  this one repo, with Contents: Read and write, nothing else.
//   SESSION_SECRET any long random string (used to sign login sessions).
//
// Set these as plain variables (or edit the defaults below):
//   GITHUB_OWNER   your GitHub username
//   GITHUB_REPO    the repo name that will hold the data file
//   GITHUB_BRANCH  defaults to "main"
//   GITHUB_PATH    defaults to "growgoals-data.json" (created automatically)
//   ALLOWED_ORIGIN the origin of your GitHub Pages site, e.g. "https://yourname.github.io"
//                  (use "*" while testing, then lock it down)

const enc = new TextEncoder();

function cors(env, resp) {
  const h = new Headers(resp.headers);
  h.set("Access-Control-Allow-Origin", env.ALLOWED_ORIGIN || "*");
  h.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  h.set("Access-Control-Allow-Headers", "Content-Type,Authorization");
  return new Response(resp.body, { status: resp.status, headers: h });
}
function json(env, obj, status = 200) {
  return cors(env, new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json" } }));
}

async function ghGet(env) {
  const owner = env.GITHUB_OWNER, repo = env.GITHUB_REPO, branch = env.GITHUB_BRANCH || "main", path = env.GITHUB_PATH || "growgoals-data.json";
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${encodeURIComponent(branch)}`,
    { headers: { Authorization: `token ${env.GITHUB_TOKEN}`, Accept: "application/vnd.github+json", "User-Agent": "growgoals-worker" } }
  );
  if (res.status === 404) return { data: { users: {} }, sha: null };
  if (!res.ok) throw new Error("github get " + res.status);
  const j = await res.json();
  const bytes = Uint8Array.from(atob(j.content.replace(/\n/g, "")), c => c.charCodeAt(0));
  let data;
  try { data = JSON.parse(new TextDecoder().decode(bytes)); } catch (e) { data = { users: {} }; }
  data.users = data.users || {};
  return { data, sha: j.sha };
}

async function ghPut(env, data, sha, message) {
  const owner = env.GITHUB_OWNER, repo = env.GITHUB_REPO, branch = env.GITHUB_BRANCH || "main", path = env.GITHUB_PATH || "growgoals-data.json";
  const bytes = enc.encode(JSON.stringify(data));
  let bin = ""; bytes.forEach(b => bin += String.fromCharCode(b));
  const body = { message: message || "update", content: btoa(bin), branch };
  if (sha) body.sha = sha;
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`,
    { method: "PUT", headers: { Authorization: `token ${env.GITHUB_TOKEN}`, Accept: "application/vnd.github+json", "Content-Type": "application/json", "User-Agent": "growgoals-worker" }, body: JSON.stringify(body) }
  );
  if (res.status === 409) { const g = await ghGet(env); return ghPut(env, data, g.sha, message); } // retry once on conflict
  if (!res.ok) throw new Error("github put " + res.status);
  return (await res.json()).content.sha;
}

// --- password hashing (PBKDF2, kept modest so it fits Workers' free CPU budget) ---
async function pbkdf2(pw, saltB64, iterations = 20000) {
  const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, key, 256);
  let bin = ""; new Uint8Array(bits).forEach(b => bin += String.fromCharCode(b));
  return btoa(bin);
}
function randB64(n = 16) {
  const a = crypto.getRandomValues(new Uint8Array(n));
  let bin = ""; a.forEach(b => bin += String.fromCharCode(b));
  return btoa(bin);
}

// --- signed session tokens (no server-side session storage needed) ---
async function sign(env, payload) {
  const key = await crypto.subtle.importKey("raw", enc.encode(env.SESSION_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(payload));
  let bin = ""; new Uint8Array(sig).forEach(b => bin += String.fromCharCode(b));
  return btoa(bin).replace(/=+$/, "");
}
async function makeToken(env, username) {
  const payload = JSON.stringify({ u: username, exp: Date.now() + 1000 * 60 * 60 * 24 * 90 }); // 90 days
  const b64 = btoa(payload);
  return b64 + "." + await sign(env, b64);
}
async function verifyToken(env, token) {
  if (!token) return null;
  const [b64, sig] = token.split(".");
  if (!b64 || !sig) return null;
  if (await sign(env, b64) !== sig) return null;
  try {
    const payload = JSON.parse(atob(b64));
    if (payload.exp < Date.now()) return null;
    return payload.u;
  } catch (e) { return null; }
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return cors(env, new Response(null, { status: 204 }));
    const url = new URL(request.url);
    try {
      if (url.pathname === "/signup" && request.method === "POST") {
        const { u, p } = await request.json();
        if (!u || u.length < 3) return json(env, { error: "Username needs 3+ characters" }, 400);
        if (!p || p.length < 6) return json(env, { error: "Password needs 6+ characters" }, 400);
        const g = await ghGet(env);
        if (g.data.users[u]) return json(env, { error: "Username already taken" }, 400);
        const salt = randB64(16), h = await pbkdf2(p, salt);
        g.data.users[u] = { salt, hash: h, state: null };
        await ghPut(env, g.data, g.sha, "Add user " + u);
        return json(env, { token: await makeToken(env, u) });
      }

      if (url.pathname === "/login" && request.method === "POST") {
        const { u, p } = await request.json();
        const g = await ghGet(env);
        const rec = g.data.users[u];
        if (!rec) return json(env, { error: "Wrong username or password" }, 401);
        if (await pbkdf2(p, rec.salt) !== rec.hash) return json(env, { error: "Wrong username or password" }, 401);
        return json(env, { token: await makeToken(env, u) });
      }

      if (url.pathname === "/state" && request.method === "GET") {
        const user = await verifyToken(env, (request.headers.get("Authorization") || "").replace("Bearer ", ""));
        if (!user) return json(env, { error: "Not signed in" }, 401);
        const g = await ghGet(env);
        return json(env, { state: (g.data.users[user] || {}).state || null });
      }

      if (url.pathname === "/state" && request.method === "POST") {
        const user = await verifyToken(env, (request.headers.get("Authorization") || "").replace("Bearer ", ""));
        if (!user) return json(env, { error: "Not signed in" }, 401);
        const { state } = await request.json();
        const g = await ghGet(env);
        if (!g.data.users[user]) return json(env, { error: "Unknown user" }, 404);
        g.data.users[user].state = state;
        await ghPut(env, g.data, g.sha, "Update " + user);
        return json(env, { ok: true });
      }

      return json(env, { error: "Not found" }, 404);
    } catch (e) {
      return json(env, { error: e.message || "Server error" }, 500);
    }
  }
};
