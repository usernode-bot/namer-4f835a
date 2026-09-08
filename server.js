const express = require('express');
const path = require('path');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const IS_STAGING = process.env.USERNODE_ENV === 'staging';

// The platform signs user-identity tokens with an RSA private key it never
// shares. Containers get only the PUBLIC half, so this app can verify who a
// user is but cannot mint an identity — and neither can any other app.
const JWT_PUBLIC_KEY = (process.env.USERNODE_JWT_PUBLIC_KEY || '')
  .replace(/\\n/g, '\n');

// Tokens are minted for one app: the audience is this app's numeric id, so a
// token issued for a different app is rejected below rather than accepted as
// a valid user.
const APP_AUDIENCE = process.env.USERNODE_APP_ID
  ? 'usernode:app:' + process.env.USERNODE_APP_ID
  : null;

// Paths that stay open without authentication. Add a path here (and add it
// with `app.get`/`app.post` below) if you deliberately want it public.
// Everything else requires a valid platform-issued JWT.
const PUBLIC_API_PATHS = new Set(['/health']);

let shuttingDown = false;

const ADJECTIVES = [
  'silly', 'grumpy', 'electric', 'sneaky', 'fluffy', 'brave', 'tiny', 'mighty',
  'sleepy', 'jolly', 'spicy', 'quiet', 'wild', 'clever', 'cosmic', 'salty',
  'breezy', 'gentle', 'fierce', 'lucky', 'rusty', 'shiny', 'dizzy', 'plucky',
  'chunky', 'nimble', 'cranky', 'sunny', 'frosty', 'giddy', 'zany', 'bold',
  'curious', 'dapper', 'feisty', 'jumpy',
];

const NOUNS = [
  'panda', 'waffle', 'sloth', 'badger', 'comet', 'pickle', 'otter', 'walrus',
  'biscuit', 'falcon', 'noodle', 'penguin', 'cactus', 'gremlin', 'yeti',
  'toaster', 'raccoon', 'potato', 'dragon', 'muffin', 'koala', 'hedgehog',
  'wombat', 'pretzel', 'narwhal', 'llama', 'goblin', 'pigeon', 'burrito',
  'moose', 'ferret', 'nugget', 'unicorn', 'squid', 'gazelle',
];

function capitalize(word) {
  return word.charAt(0).toUpperCase() + word.slice(1);
}

function generateName() {
  const adjective = ADJECTIVES[Math.floor(Math.random() * ADJECTIVES.length)];
  const noun = NOUNS[Math.floor(Math.random() * NOUNS.length)];
  return { adjective, noun, name: `${capitalize(adjective)} ${capitalize(noun)}` };
}

app.use(express.json());

// Verify platform-issued JWT if one was passed, then enforce auth on
// anything not explicitly marked public. The iframe adds `?token=…`
// on load; the frontend script forwards the token via `x-usernode-token`
// on subsequent fetches.
app.use((req, res, next) => {
  const token = req.query.token || req.headers['x-usernode-token'];
  if (token && JWT_PUBLIC_KEY && APP_AUDIENCE) {
    try {
      // Pin the algorithm, issuer and audience. Without `algorithms` a
      // caller could hand us an HS256 token signed with the public PEM
      // (which every app knows) and forge any user.
      const claims = jwt.verify(token, JWT_PUBLIC_KEY, {
        algorithms: ['RS256'],
        issuer: 'usernode',
        audience: APP_AUDIENCE,
      });
      // `pur` names what the token is for. Only user-identity tokens
      // authenticate a person here.
      if (claims && claims.pur === 'iframe') req.user = claims;
    } catch {}
  }

  // Static assets (CSS/JS/images) are always served; the API and the HTML
  // shell are gated so direct hits to the staging/prod subdomain don't
  // leak app data to the public internet.
  if (req.method !== 'GET' || req.path.startsWith('/api/')) {
    if (PUBLIC_API_PATHS.has(req.path)) return next();
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
});

app.get('/health', (_req, res) => {
  if (shuttingDown) return res.status(503).json({ status: 'shutting-down' });
  res.json({ status: 'ok' });
});

// The template ships no favicon file; index.html carries an inline SVG
// icon instead. Answer 204 here so anything that still probes
// /favicon.ico (older browsers, direct visits) doesn't fall through to
// the auth-gated catch-all and surface a 401 in the console on every
// fresh load.
app.get('/favicon.ico', (_req, res) => res.status(204).end());

// Generate a new random adjective+noun name for the signed-in user.
app.post('/api/generate', async (req, res) => {
  try {
    const { adjective, noun, name } = generateName();
    const { rows } = await pool.query(`
      INSERT INTO generated_names (user_id, username, adjective, noun, name)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING id, name, shared, created_at
    `, [req.user.id, req.user.username, adjective, noun, name]);
    res.json({ name: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// The signed-in user's own list of generated names, newest first.
app.get('/api/names', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT id, name, shared, created_at
      FROM generated_names
      WHERE user_id = $1
      ORDER BY created_at DESC
    `, [req.user.id]);
    res.json({ names: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Share one of the signed-in user's own names to the public feed.
app.post('/api/names/:id/share', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      UPDATE generated_names
      SET shared = TRUE, shared_at = COALESCE(shared_at, NOW())
      WHERE id = $1 AND user_id = $2
      RETURNING id, name, shared, created_at
    `, [req.params.id, req.user.id]);
    if (!rows.length) return res.status(404).json({ error: 'Name not found' });
    res.json({ name: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Public feed of every name any user has shared, newest first.
app.get('/api/feed', async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT name, username, shared_at
      FROM generated_names
      WHERE shared
      ORDER BY shared_at DESC
      LIMIT 50
    `);
    res.json({ feed: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.use(express.static(path.join(__dirname, 'public')));

// HTML shell: serve the app if authenticated. Unauthenticated top-level
// visits (share links pasted into a browser — Sec-Fetch-Dest: document)
// are sent to the platform's chromeless view of this app, where the shell
// embeds it with a real token so the link just works. Every other
// tokenless case (iframe loads with an expired token, old browsers
// without Sec-Fetch-*) gets the "open in Usernode" landing page instead
// of a redirect, so the platform shell is never loaded INSIDE its own
// app iframe and stray visits still don't reveal the app.
app.get('*', (req, res) => {
  if (!req.user) {
    // Deep-link pass-through (platform #743): carry the visited
    // path+query into the chromeless view so share links land on the
    // shared screen, not Home. The clean platform route stores `path`
    // as one encoded query value so an inner ?, &, or = survives. The
    // shell decodes and validates it as relative-only before use. The
    // character test keeps the
    // value attribute-safe for the landing anchor below — anything
    // unusual falls back to the bare link.
    const deepPath = /^\/[A-Za-z0-9\-._~!$&()*+,;=:@\/%?]*$/.test(req.originalUrl)
      ? '?path=' + encodeURIComponent(req.originalUrl) : '';
    if (req.get('sec-fetch-dest') === 'document') {
      return res.redirect(302, 'https://social-vibecoding.beta.usernodelabs.org/app/namer-4f835a/full' + deepPath);
    }
    return res.status(401).send(`<!doctype html><meta charset=utf-8><title>Open in Usernode</title>
<body style="font-family:system-ui;background:#09090b;color:#e4e4e7;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">
  <div style="max-width:24rem;padding:2rem;text-align:center">
    <h1 style="font-size:1.25rem;margin:0 0 0.5rem">Open this app inside Usernode</h1>
    <p style="color:#a1a1aa;font-size:0.9rem;margin:0 0 1.25rem">This page is served via the platform; direct visits aren't authenticated.</p>
    <a href="https://social-vibecoding.beta.usernodelabs.org/app/namer-4f835a/full${deepPath}" style="display:inline-block;padding:0.5rem 1rem;background:#7c3aed;color:white;border-radius:0.5rem;text-decoration:none;font-size:0.9rem">Open in Usernode</a>
  </div>
</body>`);
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

async function seedStagingData() {
  const demoRows = [
    { userId: -101, username: 'staging-demo-luna', adjective: 'sneaky', noun: 'waffle', minutesAgo: 5 },
    { userId: -102, username: 'staging-demo-max', adjective: 'cosmic', noun: 'otter', minutesAgo: 20 },
    { userId: -103, username: 'staging-demo-ren', adjective: 'grumpy', noun: 'pretzel', minutesAgo: 45 },
    { userId: -104, username: 'staging-demo-luna', adjective: 'electric', noun: 'panda', minutesAgo: 90 },
    { userId: -105, username: 'staging-demo-max', adjective: 'fluffy', noun: 'dragon', minutesAgo: 150 },
  ];
  for (const row of demoRows) {
    const name = `Staging demo: ${capitalize(row.adjective)} ${capitalize(row.noun)}`;
    await pool.query(`
      INSERT INTO generated_names (user_id, username, adjective, noun, name, shared, shared_at, created_at)
      SELECT $1::integer, $2::varchar, $3::varchar, $4::varchar, $5::text, TRUE,
             NOW() - ($6::text || ' minutes')::interval, NOW() - ($6::text || ' minutes')::interval
      WHERE NOT EXISTS (
        SELECT 1 FROM generated_names WHERE username = $2::varchar AND name = $5::text
      )
    `, [row.userId, row.username, row.adjective, row.noun, name, row.minutesAgo]);
  }
}

async function start() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS generated_names (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      username VARCHAR(255) NOT NULL,
      adjective VARCHAR(50) NOT NULL,
      noun VARCHAR(50) NOT NULL,
      name TEXT NOT NULL,
      shared BOOLEAN NOT NULL DEFAULT FALSE,
      shared_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS generated_names_user_idx ON generated_names (user_id, created_at DESC)
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS generated_names_shared_idx ON generated_names (shared, shared_at DESC)
  `);

  if (IS_STAGING) {
    await seedStagingData();
  }

  const server = app.listen(port, () => console.log(`Listening on :${port}`));

  const DRAIN_MS = 3000;
  async function shutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`[shutdown] ${signal} received, draining`);
    server.close(() => {});
    server.closeIdleConnections?.();
    const t = setTimeout(() => server.closeAllConnections?.(), DRAIN_MS);
    t.unref?.();
    try {
      await pool.end();
    } catch (e) {
      console.error('[shutdown] pool.end failed', e.message);
    }
    process.exit(0);
  }
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

start().catch(err => { console.error(err); process.exit(1); });
