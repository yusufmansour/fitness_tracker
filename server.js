const express = require('express');
const path = require('path');
const app = express();
// test-log endpoint moved below after middleware so body is parsed
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs').promises;
const dbFile = path.join(__dirname, 'db.json');
let db = { users: [], entries: [], events: [] };
// In-memory sync state per user (non-persistent)
const syncState = new Map(); // userId -> { etag, lastModified, lastIds:Set<string>, backoffMin:number, lastAttempt:number, lastSuccess:number, userId:number }

async function loadDb() {
  try {
    const txt = await fs.readFile(dbFile, 'utf8');
    db = JSON.parse(txt || '{}');
    db.users = db.users || [];
    db.entries = db.entries || [];
    db.events = db.events || []; // initialize events array
  } catch (e) {
    db = { users: [], entries: [], events: [] };
    await saveDb();
  }
}

async function saveDb() {
  await fs.writeFile(dbFile, JSON.stringify(db, null, 2));
}

async function initDb() {
  await loadDb();
}

initDb();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({ secret: process.env.SESSION_SECRET || 'dev-secret', resave: false, saveUninitialized: false }));

// --- Simple test endpoint for logging ---
app.post('/test-log', (req, res) => {
  console.log('Test-log endpoint hit', req.body);
  res.json({ ok: true });
});

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}
// Theme helper to detect light/dark from cookie or session
function getTheme(req){
  try {
    const cookie = req.headers.cookie || '';
    const m = cookie.match(/(?:^|;\s*)theme=(dark|light)/);
    return (m && m[1]) || (req.session && req.session.theme) || 'light';
  } catch { return 'light'; }
}

// Onboarding middleware
function ensureOnboarded(req,res,next){
  if(!req.session || !req.session.userId) return res.redirect('/login');
  const user = db.users.find(u=>u.id===req.session.userId);
  if(user && !user.onboarded && !req.path.startsWith('/onboarding')) return res.redirect('/onboarding');
  next();
}

// --- Onboarding explicit routes ---
app.get('/onboarding', requireAuth, async (req,res)=>{
  await loadDb();
  const user = db.users.find(u=>u.id===req.session.userId);
  if(!user) return res.redirect('/login');
  if(user.onboarded) return res.redirect('/dashboard');
  // Determine step order: display -> goal -> colors -> id -> connect
  let step;
  if(!user.displayConfirmed) step='display';
  else if(!user.goalMeters) step='goal';
  else if(!user.shellConfirmed) step='colors';
  else if(!user.logbookUserId) step='id';
  else if(!user.logbookToken) step='connect';
  else step='done';
  if(step==='done'){ user.onboarded=true; await saveDb(); return res.redirect('/dashboard'); }
  const stepOrder = ['display','goal','colors','id','connect'];
  const stepIndex = stepOrder.indexOf(step)+1;
  const stepTotal = stepOrder.length;
  let initPrimary=null, initSecondary=null, initOar=null;
  if(step==='colors'){
    // Keep existing colors; if truly blank use black defaults
    if(!(user.shellPrimary||'').trim()) user.shellPrimary = '#000000';
    if(!(user.shellSecondary||'').trim()) user.shellSecondary = '#000000';
    if(!(user.oarColor||'').trim()) user.oarColor = '#000000';
    initPrimary = user.shellPrimary;
    initSecondary = user.shellSecondary;
    initOar = user.oarColor;
    await saveDb();
  }
  // Force dark theme during onboarding session
  req.session.theme='dark';
  const tokenError = req.session.onboardingTokenError || null; req.session.onboardingTokenError = null;
  res.render('onboarding',{ user, step, initPrimary, initSecondary, initOar, stepIndex, stepTotal, tokenError, onboardingMode:true });
});
app.post('/onboarding/display', requireAuth, async (req,res)=>{
  await loadDb();
  const user = db.users.find(u=>u.id===req.session.userId);
  if(!user) return res.redirect('/login');
  const name=(req.body.displayName||'').trim().slice(0,40);
  if(name) user.displayName=name;
  user.displayConfirmed=true;
  await saveDb();
  res.redirect('/onboarding');
});
app.post('/onboarding/goal', requireAuth, async (req,res)=>{
  await loadDb();
  const user = db.users.find(u=>u.id===req.session.userId);
  if(!user) return res.redirect('/login');
  const raw = req.body.goalMeters;
  const val = parseInt(raw,10);
  if(!isNaN(val) && val>0) user.goalMeters = val;
  await saveDb();
  res.redirect('/onboarding');
});
app.post('/onboarding/colors', requireAuth, async (req,res)=>{
  await loadDb();
  const user = db.users.find(u=>u.id===req.session.userId);
  if(!user) return res.redirect('/login');
  user.shellPrimary=req.body.shellPrimary||user.shellPrimary||'#2E7BCB';
  user.shellSecondary=req.body.shellSecondary||user.shellSecondary||'#FFD447';
  user.oarColor=req.body.oarColor||user.oarColor||'#FF4F4F';
  user.shellConfirmed = true;
  await saveDb();
  res.redirect('/onboarding');
});
// Save Concept2 numeric user id (onboarding step)
app.post('/onboarding/id', requireAuth, async (req,res)=>{
  await loadDb();
  const user = db.users.find(u=>u.id===req.session.userId);
  if(!user) return res.redirect('/login');
  const idRaw = (req.body.logbookUserId || '').toString().trim();
  if(idRaw){ const parsed = idRaw.match(/^\d+$/) ? Number(idRaw) : idRaw; user.logbookUserId = parsed; }
  await saveDb();
  res.redirect('/onboarding');
});
app.post('/onboarding/token', requireAuth, async (req,res)=>{
  await loadDb();
  const user = db.users.find(u=>u.id===req.session.userId);
  if(!user) return res.redirect('/login');
  const raw=(req.body.logbookToken||'').trim();
  const idRaw = (req.body.logbookUserId || '').toString().trim();
  // If the form submitted a raw token, validate and set it. Otherwise insist that user.logbookToken already exists (from OAuth).
  if(raw){
    if(!/^[-A-Za-z0-9]{8,120}$/.test(raw)){
      req.session.onboardingTokenError='Invalid token format (8-120 alphanumeric).';
      return res.redirect('/onboarding');
    }
    user.logbookToken = raw;
  }
  // Accept and persist an optional Concept2 numeric user id for webhook mapping
  if(idRaw){
    const parsed = idRaw.match(/^\d+$/) ? Number(idRaw) : idRaw;
    user.logbookUserId = parsed;
  }
  // Allow finishing onboarding even if no Concept2 token is present.
  user.onboarded = true;
  // Clear any previous token error state
  if(req.session) req.session.onboardingTokenError = null;
  await saveDb();
  res.redirect('/dashboard');
});
app.post('/onboarding/reset', requireAuth, async (req,res)=>{
  await loadDb();
  const user = db.users.find(u=>u.id===req.session.userId);
  if(user){
    user.onboarded = false;
    // Clear fields & confirmation flags so all steps re-run
    user.displayName = '';
    user.displayConfirmed = false;
    user.goalMeters = 0;
    user.shellPrimary = '';
    user.shellSecondary = '';
    user.oarColor = '';
    user.shellConfirmed = false;
    // Keep token but do not mark onboarded; if token exists user will still pass through token step unless skipped
    await saveDb();
  }
  res.redirect('/onboarding');
});

// Global onboarding redirect (placed after routes so /onboarding exists)
app.use(async (req,res,next)=>{ try {
  if(req.session && req.session.userId){
    await loadDb();
    const user=db.users.find(u=>u.id===req.session.userId);
    // Exempt OAuth callback (and debug) paths so provider redirects aren't intercepted
    const exemptPaths = ['/onboarding','/logout','/entry/new','/auth/concept2/callback','/auth/concept2/callback-debug','/auth/concept2','/webhook'];
    if(user && !user.onboarded && !exemptPaths.some(p=> req.path.startsWith(p))){
      return res.redirect('/onboarding');
    }
  }
  next();
} catch(e){ next(); } });

app.get('/', async (req, res) => {
  await loadDb();
  // If an OAuth provider redirected to the site root with code/error, forward to the callback handler
  try{
    if(req.query && (req.query.code || req.query.error)){
      const qs = new URLSearchParams(req.query).toString();
      return res.redirect('/auth/concept2/callback' + (qs ? ('?' + qs) : ''));
    }
  } catch(e){ /* ignore */ }
  let user = null;
  if (req.session.userId){
    user = db.users.find(u=>u.id===req.session.userId);
    attachLevelInfo(user);
  }
  res.render('index', { user });
});

app.get('/register', (req, res) => res.render('register'));
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  await loadDb();
  if (db.users.find(u => u.email === email)) return res.render('register', { error: 'Email already exists' });
  const hashed = await bcrypt.hash(password, 10);
  const id = Date.now().toString();
  const displayName = email.split('@')[0];
  db.users.push({ id, email, password: hashed, displayName, displayConfirmed:false, shellConfirmed:false, shellPrimary:'#000000', shellSecondary:'#000000', oarColor:'#000000', onboarded:false });
  await saveDb();
  req.session.userId = id;
  req.session.email = email;
  // Landing page after register -> dashboard (onboarding middleware may redirect)
  res.redirect('/dashboard');
});

app.get('/login', (req, res) => res.render('login'));
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  await loadDb();
  const user = db.users.find(u => u.email === email);
  if (!user) return res.render('login', { error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.render('login', { error: 'Invalid credentials' });
  req.session.userId = user.id;
  req.session.email = user.email;
  // Landing page after login -> dashboard
  res.redirect('/dashboard');
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// --- Concept2 OAuth callback ---
function getBaseUrl(req){
  // Prefer explicit PUBLIC_BASE_URL when set (recommended).
  if(process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL;
  // When behind proxies (ngrok) the original protocol may be in X-Forwarded-Proto.
  const forwarded = (req.get && (req.get('x-forwarded-proto') || req.get('X-Forwarded-Proto'))) || req.headers && (req.headers['x-forwarded-proto'] || req.headers['X-Forwarded-Proto']);
  const proto = forwarded ? String(forwarded).split(',')[0].trim() : (req.protocol || 'http');
  return proto + '://' + req.get('host');
}
// Helper to build Concept2 redirect URIs; can be overridden via env vars
function buildConcept2Redirect(req, opts={debug:false}){
  const base = getBaseUrl(req);
  // Default to site root for non-debug redirect to match common provider registrations
  const defaultPath = opts.debug ? (process.env.CONCEPT2_REDIRECT_DEBUG_PATH || '/auth/concept2/callback-debug') : (process.env.CONCEPT2_REDIRECT_PATH || '/');
  if(!defaultPath || defaultPath === '/' ) return base;
  if(defaultPath.startsWith('/')) return base + defaultPath;
  return base + '/' + defaultPath;
}
// Initiate Concept2 OAuth flow (redirects user to Concept2 authorization page)
app.get('/auth/concept2', requireAuth, (req,res)=>{
  const clientId = process.env.CONCEPT2_CLIENT_ID;
  if(!clientId) return res.status(500).send('OAuth client not configured');
  const redirectUri = buildConcept2Redirect(req, { debug:false });
  // anti-forgery state
  const state = Math.random().toString(36).slice(2);
  req.session.concept2State = state;
  const authBase = process.env.LOGBOOK_OAUTH_AUTHORIZE_URL || 'https://log.concept2.com/oauth/authorize';
  // Build auth URL with parameter order preferred by Concept2: client_id, scope, response_type, redirect_uri, state
  const scopeStr = 'user:read,results:read';
  const orderedParams = `client_id=${encodeURIComponent(clientId)}&scope=${encodeURIComponent(scopeStr)}&response_type=code&redirect_uri=${encodeURIComponent(redirectUri)}${state?('&state='+encodeURIComponent(state)) : ''}`;
  const authUrl = authBase + '?' + orderedParams;
  // Helpful debug logging so redirect URI mismatches or config problems are obvious in server logs
  try { console.log('Initiating Concept2 OAuth', { clientId: clientId || '[missing]', redirectUri, state, authUrl, host: req.get && req.get('host'), publicBase: process.env.PUBLIC_BASE_URL || null }); } catch(e){}
  return res.redirect(authUrl);
});

// Temporary debug route: fetch the Concept2 authorize URL server-side and return a short snippet
// Use this to capture provider-side error pages or messages without following browser redirects.
app.get('/debug/concept2/auth-check', async (req,res)=>{
  try {
    const clientId = process.env.CONCEPT2_CLIENT_ID;
    if(!clientId) return res.status(500).send('OAuth client not configured (CONCEPT2_CLIENT_ID missing)');
    const redirectUri = buildConcept2Redirect(req, { debug:false });
    const authBase = process.env.LOGBOOK_OAUTH_AUTHORIZE_URL || 'https://log.concept2.com/oauth/authorize';
    // Build auth URL using the same preferred ordering
    const scopeStr = 'user:read,results:read';
    const authUrl = authBase + '?client_id=' + encodeURIComponent(clientId) + '&scope=' + encodeURIComponent(scopeStr) + '&response_type=code&redirect_uri=' + encodeURIComponent(redirectUri) + '&state=debug-state';
    const r = await fetch(authUrl, { redirect: 'follow' });
    const status = r.status;
    const ct = r.headers.get('content-type') || '';
    const text = await r.text();
    const snippet = text ? text.substring(0, 5000) : '';
    console.log('Auth-check fetched', { authUrl, status, contentType: ct, length: text.length });
    return res.set('Content-Type','application/json').send(JSON.stringify({ ok:true, status, contentType: ct, snippet }, null, 2));
  } catch(e){ console.error('Auth-check error', e); return res.status(500).json({ ok:false, error: String(e) }); }
});
// Helper: show the exact redirect URIs and auth URLs the server will use
app.get('/debug/concept2/auth-urls', (req,res)=>{
  try {
    const clientId = process.env.CONCEPT2_CLIENT_ID || null;
    const authBase = process.env.LOGBOOK_OAUTH_AUTHORIZE_URL || 'https://log.concept2.com/oauth/authorize';
    const redirect = buildConcept2Redirect(req, { debug:false });
    const redirectDebug = buildConcept2Redirect(req, { debug:true });
      const p1 = new URLSearchParams({ response_type: 'code', client_id: clientId || '', redirect_uri: redirect, state: 'debug-state' });
    // Use the same explicit scopes as the real auth flow
    p1.append('scope','user:read,results:read');
      const p2 = new URLSearchParams({ response_type: 'code', client_id: clientId || '', redirect_uri: redirectDebug, state: 'debug-state' });
      p2.append('scope','user:read,results:read');
      // Only reveal the real clientId to an authenticated session (client_id is not secret, but avoid leaking to anonymous callers)
      const clientIdValue = (req.session && req.session.userId) ? (clientId || '[missing]') : (clientId ? '[set]' : '[missing]');
      return res.json({ ok:true, clientId: clientIdValue, redirect, redirectDebug, authUrl: authBase + '?' + p1.toString(), authUrlDebug: authBase + '?' + p2.toString() });
  } catch(e){ console.error('Auth-urls error', e); return res.status(500).json({ ok:false, error:String(e) }); }
});
// Expose last OAuth callback details to an authenticated developer session
app.get('/debug/concept2/last-callback', requireAuth, (req,res)=>{
  try{
    return res.json({ ok:true, lastOAuthCallback });
  }catch(e){ console.error('last-callback error', e); return res.status(500).json({ ok:false, error:String(e) }); }
});
  // Authenticated fetch of the authorize URL with redirects disabled to inspect provider response
  app.get('/debug/concept2/fetch-auth', requireAuth, async (req,res)=>{
    try {
      const clientId = process.env.CONCEPT2_CLIENT_ID;
      if(!clientId) return res.status(500).json({ ok:false, error:'CONCEPT2_CLIENT_ID missing' });
      const authBase = process.env.LOGBOOK_OAUTH_AUTHORIZE_URL || 'https://log.concept2.com/oauth/authorize';
      const redirect = buildConcept2Redirect(req, { debug:false });
      const scopeStr = 'user:read,results:read';
      const authUrl = authBase + '?client_id=' + encodeURIComponent(clientId) + '&scope=' + encodeURIComponent(scopeStr) + '&response_type=code&redirect_uri=' + encodeURIComponent(redirect) + '&state=debug-fetch';
      console.log('Fetch-auth: requesting', authUrl);
      const r = await fetch(authUrl, { redirect: 'manual' });
      const status = r.status;
      const location = r.headers.get('location') || r.headers.get('Location') || null;
      const ct = r.headers.get('content-type') || '';
      const text = await r.text();
      const snippet = text ? text.substring(0,5000) : '';
      console.log('Fetch-auth result', { status, location, contentType: ct, length: snippet.length });
      return res.json({ ok:true, status, location, contentType: ct, snippet });
    } catch(e){ console.error('fetch-auth error', e); return res.status(500).json({ ok:false, error:String(e) }); }
  });
// Unauthenticated debug callback to capture provider redirect query for troubleshooting.
// Use this temporarily if the provider returns an error and session state may be lost.
app.get('/auth/concept2/callback-debug', async (req,res)=>{
  try {
    console.log('Concept2 callback-debug hit', { query: req.query, headers: { host: req.get('host'), referer: req.get('referer') } });
    return res.set('Content-Type','application/json').send(JSON.stringify({ ok:true, query: req.query, headers: { host: req.get('host') } }, null, 2));
  } catch(e){ console.error('callback-debug error', e); return res.status(500).send('Error'); }
});

app.get('/auth/concept2/callback', requireAuth, async (req,res)=>{
  try {
    // Capture callback details for debugging even when it fails (do not leak secrets)
    try{
      lastOAuthCallback = {
        ts: new Date().toISOString(),
        query: req.query || {},
        headers: { host: req.get('host'), referer: req.get('referer'), forwarded_proto: req.get('x-forwarded-proto') || req.get('X-Forwarded-Proto') },
        session: { userId: req.session?.userId || null, concept2State: req.session?.concept2State || null }
      };
    }catch(e){ /* ignore capture errors */ }
    // If the provider returned an error (user denied, invalid request, etc.), log and surface it
    if(req.query.error){
      console.error('Concept2 returned error on authorization', { error: req.query.error, error_description: req.query.error_description, query: req.query });
      return res.status(400).send('Authorization error from provider: ' + String(req.query.error));
    }
    const code = req.query.code;
    if(!code){
      console.error('OAuth callback missing code', { query: req.query, headers: { host: req.get('host'), referer: req.get('referer'), forwarded_proto: req.get('x-forwarded-proto') || req.get('X-Forwarded-Proto') } });
      return res.status(400).send('Missing code');
    }
    // Validate state to protect against CSRF
    const returnedState = req.query.state;
    if(req.session && req.session.concept2State){
      if(returnedState !== req.session.concept2State){
        console.error('OAuth state mismatch', { expected: req.session.concept2State, returned: returnedState });
        return res.status(400).send('Invalid OAuth state (possible CSRF or mismatched redirect URI)');
      }
    } else if(returnedState){
      // No state stored but provider returned one — log for debugging
      console.warn('No OAuth state in session but provider returned state', { returnedState });
    }
    const clientId = process.env.CONCEPT2_CLIENT_ID;
    const clientSecret = process.env.CONCEPT2_CLIENT_SECRET;
    if(!clientId || !clientSecret){ return res.status(500).send('OAuth not configured'); }
    const redirect = buildConcept2Redirect(req, { debug:false });
    const redirectDebug = buildConcept2Redirect(req, { debug:true });
    const scopeStr = 'user:read,results:read';
    const p1str = authBase + '?client_id=' + encodeURIComponent(clientId || '') + '&scope=' + encodeURIComponent(scopeStr) + '&response_type=code&redirect_uri=' + encodeURIComponent(redirect) + '&state=debug-state';
    const p2str = authBase + '?client_id=' + encodeURIComponent(clientId || '') + '&scope=' + encodeURIComponent(scopeStr) + '&response_type=code&redirect_uri=' + encodeURIComponent(redirectDebug) + '&state=debug-state';
    // Only reveal the real clientId to an authenticated session (client_id is not secret, but avoid leaking to anonymous callers)
    const clientIdValue = (req.session && req.session.userId) ? (clientId || '[missing]') : (clientId ? '[set]' : '[missing]');
    return res.json({ ok:true, clientId: clientIdValue, redirect, redirectDebug, authUrl: p1str, authUrlDebug: p2str });
    async function doTokenExchange(attempts = 3){
      let lastErr = null;
      for(let attempt=1; attempt<=attempts; attempt++){
        try{
          const tRes = await fetch(tokenUrl, { method:'POST', headers:{ 'Content-Type':'application/x-www-form-urlencoded', 'Accept':'application/json' }, body });
          const tText = await tRes.text();
          let tJson = null; try{ tJson = tText? JSON.parse(tText): null; } catch(e){ /* keep tJson null if not JSON */ }
          // log response headers + small body snippet to help debugging
          const hdrs = {};
          try{ for(const [k,v] of tRes.headers.entries()) hdrs[k]=v; } catch(_){}
          console.log('Token exchange attempt', { attempt, status: tRes.status, statusText: tRes.statusText, headers: hdrs, bodySnippet: (tText||'').substring(0,2000) });
          // Success if we have an access token
          if(tRes.ok && tJson && tJson.access_token){ return { ok:true, json:tJson }; }
          // Non-JSON or missing access_token: treat 5xx as transient and retry, but 4xx likely permanent
          lastErr = { status: tRes.status, statusText: tRes.statusText, response: tText, parsed: tJson };
          const isServerError = tRes.status >= 500 && tRes.status < 600;
          if(isServerError && attempt < attempts){ const wait = 500 * attempt; console.warn('Transient token-exchange server error, retrying after', wait, 'ms'); await new Promise(r=>setTimeout(r, wait)); continue; }
          // otherwise stop retrying
          return { ok:false, error:lastErr };
        } catch(e){
          lastErr = { error: String(e) };
          console.error('Token exchange network/error on attempt', attempt, e);
          if(attempt < attempts){ const wait = 500 * attempt; await new Promise(r=>setTimeout(r, wait)); continue; }
          return { ok:false, error:lastErr };
        }
      }
      return { ok:false, error:lastErr };
    }

    const exchange = await doTokenExchange(3);
    if(!exchange.ok || !exchange.json?.access_token){
      // Enhanced error logging for debugging (include request details and last response/error)
      console.error('Token exchange failed', {
        request: { url: tokenUrl, body: Object.fromEntries(body), headers: { 'Content-Type':'application/x-www-form-urlencoded', 'Accept':'application/json' }, redirect_uri: redirectUri },
        last: exchange.error
      });
      return res.status(502).send('Token exchange failed');
    }
    const tJson = exchange.json;
    await loadDb();
    const user = db.users.find(u=>u.id===req.session.userId);
    if(!user) return res.redirect('/login');
    user.logbookToken = tJson.access_token;
    // Fetch profile to capture Concept2 user_id for webhook mapping
    try {
      const profRes = await fetch((process.env.LOGBOOK_API_BASE || 'https://log.concept2.com') + '/api/users/me.json', { headers:{ 'Authorization':'Bearer '+user.logbookToken, 'Accept':'application/json' } });
      if(profRes.ok){ const pTxt = await profRes.text(); const pJson = pTxt? JSON.parse(pTxt): null; const c2id = pJson?.id || pJson?.user_id || pJson?.userId; if(c2id) user.logbookUserId = c2id; }
    } catch(e) { console.error('Profile fetch error after token exchange', e); }
    await saveDb();
    // If the user is in onboarding, send them back there so the connected state updates immediately.
    try{
      const u = db.users.find(u=>u.id===req.session.userId);
      if(u && !u.onboarded) return res.redirect('/onboarding');
    }catch(e){}
    return res.redirect('/settings?tab=token');
  } catch(e){
    console.error('OAuth callback error', e);
    return res.status(500).send('OAuth error');
  }
});

app.get('/dashboard', requireAuth, async (req, res) => {
  await loadDb();
  const user = db.users.find(u=>u.id===req.session.userId);
  if(!user) return res.redirect('/login');
  attachLevelInfo(user);
  const totals = computeTotals();
  user.totalMeters = totals[user.id] || 0;
  res.render('dashboard', { user });
});
// SETTINGS routes (ensure registered)
app.get('/settings', requireAuth, async (req, res) => {
  await loadDb();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user) return res.redirect('/login');
  attachLevelInfo(user);
  const activeTab = req.query.tab || 'profile';
  res.render('settings', { user, saved: false, error: null, activeTab });
});
app.post('/settings', requireAuth, async (req, res) => {
  const { displayName, logbookToken, shellPrimary, shellSecondary, oarColor } = req.body;
  await loadDb();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user) return res.redirect('/login');
  if (!displayName || !displayName.trim()) return res.render('settings', { user, saved:false, error:'Display name required' });
  user.displayName = displayName.trim();
  user.logbookToken = (logbookToken || '').trim();
  const isHex = v => /^#[0-9a-fA-F]{6}$/.test(v || '');
  if (isHex(shellPrimary)) user.shellPrimary = shellPrimary;
  if (isHex(shellSecondary)) user.shellSecondary = shellSecondary;
  if (isHex(oarColor)) user.oarColor = oarColor;
  await saveDb();
  attachLevelInfo(user);
  res.render('settings', { user, saved:true, error:null });
});
// Profile settings update
app.post('/settings/profile', requireAuth, async (req, res) => {
  const { displayName } = req.body;
  await loadDb();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user) return res.redirect('/login');
  if (!displayName || !displayName.trim()) return res.render('settings', { user, saved:false, error:'Display name required' });
  user.displayName = displayName.trim();
  await saveDb();
  attachLevelInfo(user);
  res.render('settings', { user, saved:true, error:null });
});
// Token settings update
app.post('/settings/token', requireAuth, async (req, res) => {
  try {
    await loadDb();
    const user = db.users.find(u => u.id === req.session.userId);
    if (!user) return res.redirect('/login');
    const raw = (req.body.logbookToken || '').trim();
    const idRaw = (req.body.logbookUserId || '').toString().trim();
    // Basic validation: alphanumeric length 20-80 (adjust as needed)
    if(raw && !/^[-A-Za-z0-9]{8,120}$/.test(raw)) {
      return res.render('settings', { user, saved:false, error:'Invalid token format', activeTab:'token' });
    }
    user.logbookToken = raw;
    // Accept and save an optional numeric Concept2 user id for webhook mapping
    if(idRaw){
      // keep numeric value when possible
      const parsed = idRaw.match(/^\d+$/) ? Number(idRaw) : idRaw;
      user.logbookUserId = parsed;
    }
    await saveDb();
    attachLevelInfo(user);
    return res.render('settings', { user, saved:true, error:null, activeTab:'token' });
  } catch(err){
    console.error('POST /settings/token error', err);
    try { await loadDb(); const user = db.users.find(u => u.id === req.session.userId); return res.render('settings', { user, saved:false, error:'Server error saving token', activeTab:'token' }); } catch(e2){ return res.status(500).send('Server error'); }
  }
});
// Shell customization update
app.post('/settings/shell', requireAuth, async (req, res) => {
  const { shellPrimary, shellSecondary, oarColor } = req.body;
  await loadDb();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user) return res.redirect('/login');
  const isHex = v => /^#[0-9a-fA-F]{6}$/.test(v || '');
  if (isHex(shellPrimary)) user.shellPrimary = shellPrimary;
  if (isHex(shellSecondary)) user.shellSecondary = shellSecondary;
  if (isHex(oarColor)) user.oarColor = oarColor;
  await saveDb();
  attachLevelInfo(user);
  res.render('settings', { user, saved:true, error:null });
});
// REPLACE Concept2 fetch logic with documented endpoints (.json)
async function fetchLogbookWorkouts(token) {
  if(!token) return { profile:null, workouts:[], attempts:[], errors:[], rawProfile:null };
  const base = (process.env.LOGBOOK_API_BASE || 'https://log.concept2.com') + '/api';
  const attempts = []; const errors = [];
  const headers = { 'Accept':'application/json', 'User-Agent':'ActivityTracker/1.0', 'Authorization':'Bearer ' + token };
  async function get(url){
    try {
      const res = await fetch(url, { headers });
      const status = res.status;
      const text = await res.text();
      let json = null; try { json = text? JSON.parse(text): null; } catch{}
      attempts.push({ url, status, jsonKeys: json? Object.keys(json).slice(0,12): [], textSample: text.slice(0,120) });
      if(!res.ok) { errors.push({ url, status }); return { json:null, text }; }
      return { json, text };
    } catch(e){ errors.push({ url, error:e.message }); return { json:null, text:null }; }
  }
  // Profile variants
  const profileUrls = ['/users/me.json','/users/me','/me.json','/me'];
  let profile = null; let rawProfile = null; let userId = null;
  for(const p of profileUrls){ const { json, text } = await get(base + p); if(json){ profile = json; rawProfile = text; userId = json.id || json.user_id || json.userId || json.uid || null; break; } }
  // If still no userId try keys
  if(!userId && profile){ for(const k of ['user','account','data']){ const v = profile[k]; if(v && typeof v==='object'){ userId = v.id || v.user_id || v.userId; if(userId) break; } } }
  const workouts = []; const seen = new Set();
  if(userId){
    const candidateEndpoints = [
      `/users/${userId}/results?limit=100`,
      `/users/${userId}/results.json?limit=100`,
      `/users/${userId}/results?type=RowErg&limit=100`,
      `/users/${userId}/workouts?limit=100`,
      `/users/${userId}/workouts.json?limit=100`,
      `/users/${userId}/results?format=json&limit=100`,
      `/users/${userId}/workouts?format=json&limit=100`
    ];
    for(const ep of candidateEndpoints){
      const { json } = await get(base + ep);
      if(!json) continue;
      const arr = Array.isArray(json)? json : Array.isArray(json.data)? json.data : Array.isArray(json.results)? json.results : Array.isArray(json.workouts)? json.workouts : [];
      for(const w of arr){
        const remoteId = w.id || w.workoutId || w.logId || w.resultId;
        const meters = w.distance || w.meters || w.meter || w.total_distance || w.workDistance || 0;
        const dateRaw = w.date || w.workoutDate || w.created_at || w.datetime || w.timestamp || w.startTime || new Date().toISOString();
        const date = dateRaw.substring(0,10);
        if(remoteId && meters && !seen.has(remoteId)){ workouts.push({ remoteId:String(remoteId), date, meters:Number(meters) }); seen.add(remoteId); }
      }
      if(workouts.length) break; // stop once we have data
    }
  }
  return { profile, rawProfile, workouts, attempts, errors };
}
// Helper: compute totals & ranking
// Cutoff date: ignore any workouts dated before this (YYYY-MM-DD). Inclusive from this date forward.
const WORKOUT_CUTOFF_DATE = '2025-11-27';
function entryIsAllowedByCutoff(e){ try{ if(!e || !e.date) return true; const d = String(e.date).substring(0,10); return d >= WORKOUT_CUTOFF_DATE; }catch(e){ return true; } }

// Revised computeTotals that ignores entries before cutoff
function computeTotals(){ const totals={}; for(const e of db.entries){ if(!entryIsAllowedByCutoff(e)) continue; const v=Number(e.value); if(!isNaN(v)) totals[e.userId]=(totals[e.userId]||0)+v; } return totals; }
function computeRanking(totals){ return Object.entries(totals).map(([userId,total])=>({userId,total})).sort((a,b)=> b.total - a.total).map(r=>r.userId); }
// Alerts endpoint: level-up, goal milestones (25,50,75,100%), rank-up
app.get('/api/alerts', requireAuth, async (req,res)=>{
  try {
    await loadDb();
    const user=db.users.find(u=>u.id===req.session.userId);
    if(!user) return res.json({ ok:false, alerts:[] });
    attachLevelInfo(user);
    const totals=computeTotals();
    const ranking=computeRanking(totals);
    const rank=ranking.indexOf(user.id)+1; // 1-based
    const xpLevel=user.levelInfo.level;
    // Goal progress
    let goalPct=0; const goal=Number(user.goalMeters||0); if(goal>0){ const totalMeters=totals[user.id]||0; goalPct=totalMeters/goal; }
    const alerts=[];
    // Determine previous values: prefer session (fast), fall back to persisted user fields so alerts don't re-fire each login
    const prevLevel = (typeof req.session.prevLevel !== 'undefined') ? req.session.prevLevel : (user.lastNotifiedLevel ?? xpLevel);
    const prevRank = (typeof req.session.prevRank !== 'undefined') ? req.session.prevRank : (user.lastNotifiedRank ?? rank);
    const prevGoal = (typeof req.session.prevGoalPct !== 'undefined') ? req.session.prevGoalPct : (user.lastNotifiedGoalPct ?? 0);
    if(xpLevel>prevLevel){ alerts.push({ type:'level-up', level:xpLevel }); }
    const milestones=[0.25,0.50,0.75,1.00];
    const reached=milestones.filter(m=> goalPct>=m && prevGoal < m);
    for(const m of reached){ alerts.push({ type:'goal-milestone', milestone:m, pct:Math.round(m*100) }); }
    if(rank>0 && prevRank>0 && rank < prevRank){ alerts.push({ type:'rank-up', rank }); }
    // Persist state both to session and to user record to avoid repeat alerts on new sessions/logins
    req.session.prevLevel = xpLevel;
    req.session.prevRank = rank;
    req.session.prevGoalPct = goalPct;
    // Persist on user object so next login won't see previous as zero
    try{
      user.lastNotifiedLevel = xpLevel;
      user.lastNotifiedRank = rank;
      user.lastNotifiedGoalPct = goalPct;
      await saveDb();
    }catch(e){ console.error('Failed to persist user notification state', e); }
    res.json({ ok:true, alerts });
  } catch(e){ console.error('alerts error', e); res.json({ ok:false, alerts:[] }); }
});
function recordLeaderboardEvents(prevTotals){
  const newTotals=computeTotals();
  const prevRanking=computeRanking(prevTotals);
  const newRanking=computeRanking(newTotals);
  const prevTop3=prevRanking.slice(0,3);
  const newTop3=newRanking.slice(0,3);
  const topSet=new Set([...prevTop3,...newTop3]);
  const now=new Date().toISOString();
  for(const userId of topSet){
    const prevPos=prevRanking.indexOf(userId);
    const newPos=newRanking.indexOf(userId);
    const prevRank= prevPos>-1? prevPos+1: null;
    const newRank= newPos>-1? newPos+1: null;
    if(prevRank===newRank) continue;
    const totalMeters=newTotals[userId]||0;
    if(prevRank==null && newRank!=null && newRank<=3){
      db.events.push({ id:Date.now().toString()+Math.random().toString(36).slice(2), type:'top3-enter', userId, prevRank:null, newRank, totalMeters, date:now, createdAt:now });
    } else if(prevRank!=null && prevRank<=3 && (newRank==null || newRank>3)){
      db.events.push({ id:Date.now().toString()+Math.random().toString(36).slice(2), type:'top3-exit', userId, prevRank, newRank:null, totalMeters, date:now, createdAt:now });
    } else if(prevRank!=null && newRank!=null && prevRank<=3 && newRank<=3){
      db.events.push({ id:Date.now().toString()+Math.random().toString(36).slice(2), type:'top3-change', userId, prevRank, newRank, totalMeters, date:now, createdAt:now });
    }
  }
  // Goal milestones
  for(const u of db.users){
    const goal=Number(u.goalMeters||0); if(!goal || !isFinite(goal) || goal<=0) continue;
    const prev=Number(prevTotals[u.id]||0); const curr=Number(newTotals[u.id]||0); if(curr<=prev) continue;
    const thresholds=[0.10,0.25,0.50,0.75,1.00];
    for(const pct of thresholds){
      const reachedBefore=prev>=goal*pct; const reachedNow=curr>=goal*pct;
      if(!reachedBefore && reachedNow){
        if(!db.events.some(ev=> ev.type==='goal-milestone' && ev.userId===u.id && Math.abs(ev.milestonePct-pct)<1e-6)){
          const newPos=newRanking.indexOf(u.id); const prevPos=prevRanking.indexOf(u.id);
          db.events.push({ id:Date.now().toString()+Math.random().toString(36).slice(2), type:'goal-milestone', userId:u.id, milestonePct:pct, prevRank: prevPos>-1? prevPos+1:null, newRank: newPos>-1? newPos+1:null, totalMeters:curr, date:now, createdAt:now });
        }
      }
    }
  }
}
// API: recent updates
app.get('/api/updates', requireAuth, async (req,res)=>{ await loadDb(); const limit=Math.min(Number(req.query.limit)||10,100); const offset=Math.max(Number(req.query.offset)||0,0); const sorted=[...db.events].sort((a,b)=> new Date(b.createdAt)-new Date(a.createdAt)); const slice=sorted.slice(offset,offset+limit); const enriched = slice.map(ev=>{ const u=db.users.find(x=>x.id===ev.userId); const copy={ ...ev }; if(copy.rank && copy.newRank==null) copy.newRank=copy.rank; if(copy.type==='top3-change'){ if(copy.prevRank==null || copy.prevRank===''){ const prior=sorted.find(e2=> e2.createdAt < ev.createdAt && e2.userId===ev.userId && (e2.newRank||e2.rank)); if(prior){ copy.prevRank= prior.newRank || prior.rank; } if(copy.prevRank==null) copy.prevRank='?'; } if(copy.newRank==null || copy.newRank===''){ copy.newRank='?'; } }
  return { ...copy, user:{ id:u?.id, name:u?.displayName || (u?.email? u.email.split('@')[0]:ev.userId), shellPrimary:u?.shellPrimary, shellSecondary:u?.shellSecondary, oarColor:u?.oarColor } }; }); res.json({ ok:true, total:sorted.length, items:enriched }); });
// Sync route (re-added)
app.get('/sync/logbook', requireAuth, async (req,res)=>{
  await loadDb();
  const dry = req.query.dry === '1';
  const user = db.users.find(u => u.id === req.session.userId);
  if(!user || !user.logbookToken) return res.status(400).json({ ok:false, error:'No token set' });
  const { profile, rawProfile, workouts, attempts, errors } = await fetchLogbookWorkouts(user.logbookToken);
  if(profile && !user.logbookUserId){ const uid = profile.id || profile.user_id || profile.userId; if(uid){ user.logbookUserId = uid; await saveDb(); } }
  const existingRemote = new Set(db.entries.filter(e => e.origin==='concept2' && e.remoteId).map(e=>e.remoteId));
  let added = 0;
  let xpGained=0;
  const prevTotals = computeTotals();
  if(!dry){
    for(const w of workouts){
      // Skip already-seen remote results
      if(existingRemote.has(w.remoteId)) continue;
      const d = String(w.date||'').substring(0,10);
      if(d && d < WORKOUT_CUTOFF_DATE){ continue; }
      db.entries.push({ id: Date.now().toString()+Math.random().toString(36).slice(2), userId:user.id, date:w.date, value:w.meters, origin:'concept2', remoteId:w.remoteId });
      added++; xpGained += awardBaselineXp(user, w.meters);
    }
    if(added){ recordLeaderboardEvents(prevTotals); await saveDb(); }
    user.logbookLastSync = { when:new Date().toISOString(), imported:added, scanned:workouts.length, xpGained }; await saveDb();
  }
  res.json({ ok:true, preview:dry, imported:added, candidate:workouts.length, profileFound:!!profile, profileKeys: profile? Object.keys(profile):[], attempts, errors });
});
// Fast-sync endpoint: trigger an immediate poll for current user
app.get('/api/sync/logbook/now', requireAuth, async (req,res)=>{
  try {
    await loadDb();
    const user = db.users.find(u => u.id === req.session.userId);
    if(!user || !user.logbookToken) return res.status(400).json({ ok:false, error:'No token set' });
    await pollUserConcept2(user);
    return res.json({ ok:true });
  } catch(e){ return res.status(500).json({ ok:false }); }
});
app.get('/api/debug/logbook/profile', requireAuth, async (req,res)=>{
  await loadDb();
  const user = db.users.find(u => u.id === req.session.userId);
  if(!user || !user.logbookToken) return res.status(400).json({ ok:false, error:'No token' });
  const data = await fetchLogbookWorkouts(user.logbookToken);
  res.json({ ok:true, profile:data.profile, rawProfile:data.rawProfile?.slice(0,500), attempts:data.attempts, errors:data.errors, sample:data.workouts.slice(0,3) });
});
// Small authenticated endpoint for onboarding UI to poll whether a token exists
app.get('/api/debug/logbook/has-token', requireAuth, async (req,res)=>{
  try {
    await loadDb();
    const user = db.users.find(u => u.id === req.session.userId);
    return res.json({ ok:true, hasToken: !!(user && user.logbookToken) });
  } catch(e){
    return res.status(500).json({ ok:false, error:'Server error' });
  }
});
// API to fetch entries
app.get('/api/entries', async (req, res) => {
  await loadDb();
  res.json(db.entries);
});

function registerEntryDeleteRoutes(){
  console.log('Registering entry delete routes');
  app.delete('/api/entries/:id', requireAuth, async (req, res) => {
    await loadDb();
    const id = req.params.id;
    const entry = db.entries.find(e => e.id === id);
    if (!entry) return res.status(404).json({ ok:false, error:'Not found' });
    if (entry.userId !== req.session.userId) return res.status(403).json({ ok:false, error:'Forbidden' });
    db.entries = db.entries.filter(e => e.id !== id);
    await saveDb();
    res.json({ ok:true });
  });
}
registerEntryDeleteRoutes();

app.get('/leaderboard', requireAuth, async (req, res) => {
  await loadDb();
  const currentUser = db.users.find(u=>u.id===req.session.userId) || null;
  attachLevelInfo(currentUser);
  const totals = computeTotals();
  const rows = Object.entries(totals).map(([userId,total]) => {
    const user = db.users.find(u => u.id === userId);
    const name = user?.displayName || (user?.email ? user.email.split('@')[0] : userId);
    const hue = [...userId].reduce((a,c)=>a+c.charCodeAt(0),0) % 360;
    return { userId, name, total, totalFormatted: Number(total).toLocaleString('en-US'), hue, shellPrimary: user?.shellPrimary || '#000000', shellSecondary: user?.shellSecondary || '#000000', oarColor: user?.oarColor || '#000000' };
  }).sort((a,b)=> b.total - a.total);
  const max = rows.reduce((m,r)=> r.total>m? r.total:m, 0);
  res.render('leaderboard', { rows, max, user: currentUser });
});
// Consolidated New Entry routes (moved here before 404)
app.get('/entry/new', requireAuth, async (req,res)=>{ try { await loadDb(); const user=db.users.find(u=>u.id===req.session.userId); attachLevelInfo(user); const theme=getTheme(req); return res.render('entry_new',{ user, error:null, theme }); } catch(e){ console.error('render /entry/new error',e); return res.status(500).send('Server error'); } });
app.post('/entry/new', requireAuth, async (req,res)=>{ try { await loadDb(); const user=db.users.find(u=>u.id===req.session.userId); const theme=getTheme(req); if(!user) return res.status(404).send('User not found'); const meters=parseInt(req.body.meters,10); if(isNaN(meters)||meters<=0) return res.render('entry_new',{ user, error:'Enter a positive number.', theme }); const prevTotals=computeTotals(); const entry={ id:Date.now().toString()+Math.random().toString(36).slice(2), userId:user.id, value:meters, createdAt:new Date().toISOString(), date:new Date().toISOString().substring(0,10) }; db.entries.push(entry); awardBaselineXp(user, meters); recordLeaderboardEvents(prevTotals); await saveDb(); return res.redirect('/dashboard'); } catch(e){ console.error('save /entry/new error',e); const theme=getTheme(req); return res.status(500).render('entry_new',{ user:null, error:'Server error saving entry.', theme }); } });

// Updates page
app.get('/updates', requireAuth, async (req,res)=>{ try { await loadDb(); const user=db.users.find(u=>u.id===req.session.userId); attachLevelInfo(user); return res.render('updates', { user }); } catch(e){ console.error('Render /updates error', e); return res.status(500).send('Server error'); } });


// Global user attach (after session & static) so templates always have user
app.use(async (req,res,next)=>{ try { if(req.session?.userId){ await loadDb(); const u=db.users.find(x=>x.id===req.session.userId); attachLevelInfo(u); res.locals.user = u; } } catch{} next(); });

// GAMIFICATION ADDITIONS START
// XP & Level helpers
function xpNeededForLevel(level){ if(level<=1) return 0; return 10 * (level-1) * level / 2; }
function levelData(xp){ let level=1; while(true){ const need=level*10; if(xp < xpNeededForLevel(level)+need) break; level++; } const currentStart = xpNeededForLevel(level); const nextNeed = level*10; const progress = Math.min(1, Math.max(0, (xp - currentStart)/nextNeed)); return { level, progress, currentStart, nextNeed }; }

// Challenge definitions
const CHALLENGES = [
  // Single day distance
  { id:'day_distance_3000', group:'day', meters:3000, xp:1 },
  { id:'day_distance_5000', group:'day', meters:5000, xp:2 },
  { id:'day_distance_10000', group:'day', meters:10000, xp:3 },
  { id:'day_distance_15000', group:'day', meters:15000, xp:5 },
  { id:'day_distance_20000', group:'day', meters:20000, xp:7 },
  { id:'day_distance_30000', group:'day', meters:30000, xp:10 },
  // Streak (>=1k each day)
  { id:'streak_1', group:'streak', days:1, xp:2 },
  { id:'streak_2', group:'streak', days:2, xp:4 },
  { id:'streak_3', group:'streak', days:3, xp:6 },
  { id:'streak_4', group:'streak', days:4, xp:8 },
  { id:'streak_5', group:'streak', days:5, xp:10 },
  // Total distance
  { id:'total_25000', group:'total', meters:25000, xp:6 },
  { id:'total_50000', group:'total', meters:50000, xp:15 },
  { id:'total_100000', group:'total', meters:100000, xp:30 },
  { id:'total_150000', group:'total', meters:150000, xp:40 },
  { id:'total_200000', group:'total', meters:200000, xp:70 },
  { id:'total_300000', group:'total', meters:300000, xp:100 }
];

function ensureUserGamifyFields(u){ if(!u) return; if(typeof u.xp!=='number') u.xp=0; if(typeof u.meterBank!=='number') u.meterBank=0; if(!Array.isArray(u.claimedChallenges)) u.claimedChallenges=[]; }

// Evaluate challenge statuses for user
function evaluateChallenges(user){ ensureUserGamifyFields(user); // Precompute stats
  if(!user) return [];
  const userEntries = db.entries.filter(e=> e.userId===user.id && entryIsAllowedByCutoff(e));
  // Daily distances map date->meters
  const daily = {}; for(const e of userEntries){ const d=(e.date||e.createdAt||'').substring(0,10); const m=Number(e.value)||Number(e.meters)||0; daily[d]=(daily[d]||0)+m; }
  // Longest current streak ending today (>=1k meters per day)
  const dates = Object.keys(daily).sort();
  let streak=0; let today = new Date().toISOString().substring(0,10); let cursor=today; while(true){ if(daily[cursor] && daily[cursor]>=1000){ streak++; const prev = new Date(cursor); prev.setDate(prev.getDate()-1); cursor = prev.toISOString().substring(0,10); } else break; }
  const totalMeters = userEntries.reduce((s,e)=> s + (Number(e.value)||0),0);
  // Determine single largest day distance
  const maxDay = dates.reduce((m,d)=> daily[d]>m? daily[d]:m,0);
  return CHALLENGES.map(ch=>{ let complete=false; if(ch.group==='day') complete = maxDay >= ch.meters; else if(ch.group==='streak') complete = streak >= ch.days; else if(ch.group==='total') complete = totalMeters >= ch.meters; const claimed = Array.isArray(user.claimedChallenges) ? user.claimedChallenges.includes(ch.id) : false; const claimable = complete && !claimed; return { ...ch, complete, claimed, claimable }; }); }

// Award baseline XP from meters (1 XP per 1000 m, track remainder)
function awardBaselineXp(user, meters){ ensureUserGamifyFields(user); user.meterBank += meters; let gained=0; while(user.meterBank >= 1000){ user.meterBank -= 1000; user.xp += 1; gained++; } return gained; }

// --- Inject gamification into existing flows ---
// Patch loadDb to ensure fields
const originalLoadDb = loadDb; loadDb = async function(){ await originalLoadDb(); for(const u of db.users){ ensureUserGamifyFields(u); if(typeof u.displayConfirmed==='undefined'){ u.displayConfirmed = !!u.onboarded && !!u.displayName; } if(typeof u.shellConfirmed==='undefined'){ u.shellConfirmed = !!u.onboarded && !!(u.shellPrimary && u.shellSecondary && u.oarColor); } } };

// Helper to attach level info for rendering
function attachLevelInfo(u){ if(!u) return u; ensureUserGamifyFields(u); u.levelInfo = levelData(u.xp||0); return u; }

// Route: Challenges page
app.get('/challenges', requireAuth, async (req,res)=>{ await loadDb(); const user=db.users.find(u=>u.id===req.session.userId); if(!user) return res.redirect('/login'); attachLevelInfo(user); const list=evaluateChallenges(user); const claimable=list.filter(c=>c.claimable); const incomplete=list.filter(c=>!c.complete); const claimed=list.filter(c=>c.claimed); res.render('challenges',{ user, claimable, incomplete, claimed }); });

// Claim route
app.post('/challenges/claim', requireAuth, async (req,res)=>{ try { await loadDb(); const user=db.users.find(u=>u.id===req.session.userId); if(!user) return res.status(404).json({ ok:false, error:'User not found' }); const id=(req.body.id||'').trim(); const all=evaluateChallenges(user); const target=all.find(c=> c.id===id); if(!target) return res.status(400).json({ ok:false, error:'Invalid challenge' }); if(!target.claimable) return res.status(400).json({ ok:false, error: target.claimed? 'Already claimed':'Not complete' }); user.claimedChallenges.push(target.id); ensureUserGamifyFields(user); const before=levelData(user.xp).level; user.xp += target.xp; const after=levelData(user.xp).level; await saveDb(); return res.json({ ok:true, xpAward:target.xp, levelBefore:before, levelAfter:after, xp:user.xp, progress:levelData(user.xp).progress }); } catch(e){ console.error('Claim error', e); return res.status(500).json({ ok:false, error:'Server error' }); } });

// API: challenge summary (for header dot)
app.get('/api/challenges/summary', requireAuth, async (req,res)=>{ await loadDb(); const user=db.users.find(u=>u.id===req.session.userId); const list=evaluateChallenges(user); const claimable=list.filter(c=>c.claimable).length; res.json({ ok:true, claimable }); });

// API: xp status
app.get('/api/xp', requireAuth, async (req,res)=>{ await loadDb(); const user=db.users.find(u=>u.id===req.session.userId); if(!user) return res.status(404).json({ ok:false }); const data=levelData(user.xp); res.json({ ok:true, xp:user.xp, level:data.level, progress:data.progress }); });

// Ensure displayName default applied on registration if missing '@'
// (Already done but reinforce for existing users)
for(const u of db.users){ if(!u.displayName){ u.displayName = (u.email||'user').split('@')[0]; } }

// (final 404 + error handlers moved to the end of the file)

// --- Server startup ---
// Dynamic port selection with fallback if in use
function startServer(port, maxPort){
  initDb().then(()=>{
    const server = app.listen(port, ()=>{
      console.log(`fitness_tracker server listening on http://localhost:${port}`);
    });
    server.on('error', err => {
      if(err.code === 'EADDRINUSE'){
        const next = port + 1;
        if(next <= maxPort){
          console.warn(`Port ${port} in use, retrying on ${next}...`);
          startServer(next, maxPort);
        } else {
          console.error(`All ports ${port}..${maxPort} in use. Exiting.`);
          process.exit(1);
        }
      } else {
        console.error('Server error during listen:', err);
        process.exit(1);
      }
    });
  }).catch(err=>{
    console.error('Failed to initialize DB, exiting.', err);
    process.exit(1);
  });
}
const BASE_PORT = parseInt(process.env.PORT,10) || 3000;
startServer(BASE_PORT, BASE_PORT + 10);

// ---- Lightweight Poller + SSE ----
const sseClients = new Set();
function broadcastEvent(ev){ const payload = `data: ${JSON.stringify(ev)}\n\n`; for(const res of sseClients){ try { res.write(payload); } catch{} } }
// Lightweight in-memory webhook debug buffer
const webhookDebug = [];
function pushWebhookDebug(entry){ try { webhookDebug.push({ ...entry, ts:new Date().toISOString() }); if(webhookDebug.length>50) webhookDebug.shift(); } catch{} }

// Capture the last OAuth callback details for debugging (protected endpoint)
let lastOAuthCallback = null;

app.get('/api/updates/stream', requireAuth, (req,res)=>{
  res.setHeader('Content-Type','text/event-stream');
  res.setHeader('Cache-Control','no-cache');
  res.setHeader('Connection','keep-alive');
  res.flushHeaders && res.flushHeaders();
  res.write(`data: {"ok":true}\n\n`);
  sseClients.add(res);
  req.on('close', ()=> sseClients.delete(res));
});

async function pollUserConcept2(user){
  if(!user || !user.logbookToken) return;
  const now = Date.now();
  const st = syncState.get(user.id) || { etag:null, lastModified:null, lastIds:new Set(), backoffMin:5, lastAttempt:0, lastSuccess:0 };
  if(st.lastAttempt && now - st.lastAttempt < st.backoffMin*60*1000) return;
  st.lastAttempt = now; syncState.set(user.id, st);
  try {
    // Reuse existing fetch with userId discovery, then try workouts/results endpoints with conditional headers
    const base = (process.env.LOGBOOK_API_BASE || 'https://log.concept2.com') + '/api';
    const headers = { 'Accept':'application/json', 'User-Agent':'ActivityTracker/1.0', 'Authorization':'Bearer ' + user.logbookToken };
    if(st.etag) headers['If-None-Match'] = st.etag;
    if(st.lastModified) headers['If-Modified-Since'] = st.lastModified;
    // Discover user id once
    let userId = user.logbookUserId || null;
    if(!userId){
      const res = await fetch(base + '/users/me.json', { headers });
      if(res.ok){ const txt = await res.text(); try { const js = JSON.parse(txt); userId = js.id || js.user_id || js.userId; } catch{} }
      if(userId){ user.logbookUserId = userId; await saveDb(); }
    }
    if(!userId) return;

    // Try a list of candidate endpoints for recent activities
    const endpoints = [
      `${base}/users/${userId}/workouts.json?limit=50`,
      `${base}/users/${userId}/results.json?limit=50`,
      `${base}/users/${userId}/results?format=json&limit=50`
    ];
    let etag = null, lastMod = null, arr = [], scanned = 0, status = 0;
    for(const url of endpoints){
      const res = await fetch(url, { headers });
      status = res.status;
      if(res.status === 304){ etag = res.headers.get('etag') || res.headers.get('ETag'); lastMod = res.headers.get('last-modified') || res.headers.get('Last-Modified'); break; }
      const text = await res.text(); let json=null; try{ json=text? JSON.parse(text): null; }catch{}
      const candidate = Array.isArray(json)? json : Array.isArray(json?.data)? json.data : Array.isArray(json?.workouts)? json.workouts : Array.isArray(json?.results)? json.results : [];
      scanned = candidate.length;
      etag = res.headers.get('etag') || res.headers.get('ETag');
      lastMod = res.headers.get('last-modified') || res.headers.get('Last-Modified');
      if(candidate.length){ arr = candidate; break; }
    }

    if(status === 304){ st.backoffMin = Math.min(st.backoffMin + 5, 60); return; }

    const prevTotals = computeTotals();
    let added=0; let xpGained=0;
    const existingRemote = new Set(db.entries.filter(e => e.origin==='concept2' && e.remoteId).map(e=>e.remoteId));
    for(const w of arr){
      const remoteId = String(w.id || w.workoutId || w.logId || w.resultId || '');
      const metersRaw = w.distance || w.meters || w.total_distance || w.workDistance || 0;
      const meters = typeof metersRaw === 'string' ? Number(metersRaw.replace(/[^0-9]/g,'')) : Number(metersRaw);
      const dateRaw = w.date || w.workoutDate || w.created_at || w.datetime || w.timestamp || new Date().toISOString();
      const date = String(dateRaw).substring(0,10);
      if(date && date < WORKOUT_CUTOFF_DATE) continue; // ignore old workouts
      if(!remoteId || !meters) continue;
      if(st.lastIds.has(remoteId)) continue;
      if(existingRemote.has(remoteId)) { st.lastIds.add(remoteId); continue; }
      db.entries.push({ id: Date.now().toString()+Math.random().toString(36).slice(2), userId:user.id, date, value:meters, origin:'concept2', remoteId });
      added++;
      xpGained += awardBaselineXp(user, meters);
      st.lastIds.add(remoteId);
    }
    if(added){
      recordLeaderboardEvents(prevTotals); await saveDb();
      user.logbookLastSync = { when:new Date().toISOString(), imported:added, scanned, xpGained };
      await saveDb();
      st.backoffMin = 5; st.lastSuccess = Date.now();
      broadcastEvent({ type:'workouts-imported', userId:user.id, imported:added, scanned });
    } else {
      st.backoffMin = Math.min(st.backoffMin + 5, 60);
    }
    st.etag = etag || st.etag; st.lastModified = lastMod || st.lastModified; syncState.set(user.id, st);
  } catch(e){ st.backoffMin = Math.min(st.backoffMin*2, 120); syncState.set(user.id, st); }
}

function startPoller(){
  setInterval(async ()=>{
    try { await loadDb(); for(const u of db.users){ if(u.logbookToken) await pollUserConcept2(u); } } catch{}
  }, 120000); // 2 minutes tick; backoff per-user controls actual rate
}
startPoller();

// ---- Concept2 Webhook Receiver ----
// Configure your webhook URL in the Concept2 developer portal to point to:
// POST /webhook/concept2
// Optionally set CONCEPT2_WEBHOOK_SECRET to a shared token for simple auth.
app.post('/webhook/concept2', async (req,res)=>{
  console.log('Webhook endpoint hit', { time: new Date().toISOString() });
  // TEMP DEBUG: print headers and body to help diagnose missing payloads
  try { console.log('Webhook headers:', req.headers); } catch(e){}
  try { console.log('Webhook body (parsed):', typeof req.body === 'object' ? JSON.stringify(req.body).slice(0,2000) : String(req.body)); } catch(e){}
  try {
    const secret = process.env.CONCEPT2_WEBHOOK_SECRET || null;
    const got = (req.headers['x-concept2-secret'] || req.query.secret || req.body?.secret || null);
    const authOk = !secret || got === secret;
    if(secret && !authOk){
      pushWebhookDebug({ path:'/webhook/concept2', note:'secret-mismatch', hasSecretHeader: !!req.headers['x-concept2-secret'] });
      return res.status(401).json({ ok:false, error:'unauthorized' });
    }
    // Try to normalize payloads with variants: {type, result}, {event, data}, {action, workout}
    const raw = req.body || {};
    const envelopeType = raw.type || raw.event || raw.action || null;
    const inner = raw.result || raw.data || raw.workout || raw.item || raw.payload || raw;
    const payload = inner && inner.data ? inner.data : inner;
    // Some providers include a top-level envelope `type` (e.g. 'result-added')
    // while the inner `result` object may also have its own `type` (e.g. 'rower').
    // Prefer the envelope type so we detect events like 'result-added'.
    const type = envelopeType || (payload && payload.type);
    pushWebhookDebug({ path:'/webhook/concept2', gotType:type || 'unknown', keys:Object.keys(raw||{}), auth: secret? (authOk?'ok':'mismatch'):'none' });
    await loadDb();
    if(type === 'result-added' || type === 'result-updated' || type === 'workout-added' || type === 'workout-updated'){
      const r = payload.result || payload || {};
      const userIdRemote = r.user_id || r.userId || raw.user_id || raw.userId;
      const remoteId = String(r.id || r.result_id || r.workoutId || r.logId || '');
      const metersRaw = r.distance || r.total_distance || r.meters || r.workDistance || 0;
      const meters = typeof metersRaw === 'string' ? Number(String(metersRaw).replace(/[^0-9]/g,'')) : Number(metersRaw);
      const date = String(r.date || r.workoutDate || r.datetime || r.timestamp || '').substring(0,10) || new Date().toISOString().substring(0,10);
      // Debug: print incoming Concept2 webhook info
      console.log('Concept2 Webhook Received:', {
        userIdRemote,
        remoteId,
        meters,
        date,
        rawPayload: req.body
      });
      // Ignore workouts older than cutoff
      if(date && date < WORKOUT_CUTOFF_DATE){ pushWebhookDebug({ note:'skipped-old', userIdRemote, remoteId, date }); return res.status(200).json({ ok:true, ignored:true, reason:'before-cutoff' }); }
      const user = db.users.find(u=> (u.logbookUserId && String(u.logbookUserId)===String(userIdRemote)) || (u.id===userIdRemote));
      if(!user){ pushWebhookDebug({ note:'user-not-mapped', userIdRemote, remoteId }); return res.status(200).json({ ok:true, ignored:true, reason:'user-not-mapped' }); }
      // Update or insert entry
      const existingIdx = db.entries.findIndex(e=> e.origin==='concept2' && e.remoteId===remoteId);
      if(existingIdx>-1){ db.entries[existingIdx].value = meters; db.entries[existingIdx].date = date; }
      else { db.entries.push({ id: Date.now().toString()+Math.random().toString(36).slice(2), userId:user.id, date, value:meters, origin:'concept2', remoteId }); awardBaselineXp(user, meters); }
      const prevTotals = computeTotals();
      recordLeaderboardEvents(prevTotals); await saveDb();
      user.logbookLastSync = { when:new Date().toISOString(), imported: existingIdx>-1? 0: 1, scanned: 1, xpGained: 0 }; await saveDb();
      broadcastEvent({ type:'workout-webhook', action:type, userId:user.id, remoteId, meters });
      pushWebhookDebug({ note:'processed', action:type, userId:user.id, remoteId, meters });
      return res.status(200).json({ ok:true });
    } else if(type === 'result-deleted' || type === 'workout-deleted'){
      const remoteId = String(payload.result_id || payload.resultId || payload.id || '');
      const before = db.entries.length;
      db.entries = db.entries.filter(e=> !(e.origin==='concept2' && e.remoteId===remoteId));
      await saveDb();
      broadcastEvent({ type:'workout-webhook', action:type, remoteId });
      pushWebhookDebug({ note:'deleted', action:type, remoteId });
      return res.status(200).json({ ok:true, removed: before - db.entries.length });
    } else {
      pushWebhookDebug({ note:'unknown-type', type });
      // Return 200 so provider doesn't aggressively retry unknown variants
      return res.status(200).json({ ok:true, ignored:true, reason:'unknown-type', type });
    }
  } catch(e){ console.error('webhook error', e); return res.status(500).json({ ok:false }); }
});

// Small debug endpoints to verify webhook reachability and recent events
app.get('/webhook/_health', (req,res)=> res.json({ ok:true }));
app.get('/webhook/concept2/debug', requireAuth, (req,res)=> res.json({ ok:true, events:webhookDebug.slice(-20).reverse() }));

// Final 404 & error handlers (placed after all routes)
app.use((req,res,next)=>{ if(req.path.startsWith('/api/')) return res.status(404).json({ ok:false, error:'Not found' }); res.status(404).send('Not found'); });
app.use((err,req,res,next)=>{ console.error('Error handler (final):', err); if(req.path.startsWith('/api/')) return res.status(500).json({ ok:false, error:'Server error' }); res.status(500).send('Server error'); });