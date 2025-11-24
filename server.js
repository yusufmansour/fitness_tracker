const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs').promises;

const app = express();
const dbFile = path.join(__dirname, 'db.json');
let db = { users: [], entries: [], events: [] };

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
  // Determine step order: display -> goal -> colors
  let step;
  if(!user.displayName) step='display';
  else if(!user.goalMeters) step='goal';
  else step='colors';
  let initPrimary=null, initSecondary=null, initOar=null;
  if(step==='colors'){
    const randColor = () => '#'+Math.floor(Math.random()*0xFFFFFF).toString(16).padStart(6,'0');
    if(!(user.shellPrimary||'').trim()) user.shellPrimary = randColor();
    if(!(user.shellSecondary||'').trim()) user.shellSecondary = randColor();
    if(!(user.oarColor||'').trim()) user.oarColor = randColor();
    initPrimary = user.shellPrimary;
    initSecondary = user.shellSecondary;
    initOar = user.oarColor;
    await saveDb();
  }
  res.render('onboarding',{ user, step, initPrimary, initSecondary, initOar });
});
app.post('/onboarding/display', requireAuth, async (req,res)=>{
  await loadDb();
  const user = db.users.find(u=>u.id===req.session.userId);
  if(!user) return res.redirect('/login');
  const name=(req.body.displayName||'').trim().slice(0,40);
  if(name) user.displayName=name;
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
  user.onboarded=true;
  await saveDb();
  res.redirect('/updates');
});
app.post('/onboarding/reset', requireAuth, async (req,res)=>{
  await loadDb();
  const user = db.users.find(u=>u.id===req.session.userId);
  if(user){
    user.onboarded = false;
    user.displayName = '';
    user.shellPrimary = '';
    user.shellSecondary = '';
    user.oarColor = '';
    await saveDb();
  }
  res.redirect('/onboarding');
});

// Global onboarding redirect (placed after routes so /onboarding exists)
app.use(async (req,res,next)=>{ try { if(req.session && req.session.userId){ await loadDb(); const user=db.users.find(u=>u.id===req.session.userId); if(user && !user.onboarded && !req.path.startsWith('/onboarding') && !req.path.startsWith('/logout') && !req.path.startsWith('/entry/new')) return res.redirect('/onboarding'); } next(); } catch(e){ next(); } });

app.get('/', (req, res) => {
  res.render('index', { user: req.session.userId ? { id: req.session.userId, email: req.session.email } : null });
});

app.get('/register', (req, res) => res.render('register'));
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  await loadDb();
  if (db.users.find(u => u.email === email)) return res.render('register', { error: 'Email already exists' });
  const hashed = await bcrypt.hash(password, 10);
  const id = Date.now().toString();
  const displayName = email.split('@')[0];
  db.users.push({ id, email, password: hashed, displayName, shellPrimary:'#2E7BCB', shellSecondary:'#FFD447', oarColor:'#FF4F4F', onboarded:false });
  await saveDb();
  req.session.userId = id;
  req.session.email = email;
  res.redirect('/updates');
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
  res.redirect('/updates');
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

app.get('/dashboard', requireAuth, async (req, res) => {
  await loadDb();
  const user = db.users.find(u=>u.id===req.session.userId);
  if(!user) return res.redirect('/login');
  const totalMeters = db.entries.filter(e=>e.userId===user.id).reduce((s,e)=> s + (Number(e.value)||0),0);
  res.render('dashboard', { user:{ id:user.id, email:user.email, shellSecondary:user.shellSecondary, goalMeters:user.goalMeters||0, totalMeters } });
});
// SETTINGS routes (ensure registered)
app.get('/settings', requireAuth, async (req, res) => {
  await loadDb();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user) return res.redirect('/login');
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
  res.render('settings', { user, saved:true, error:null });
});
// Token settings update
app.post('/settings/token', requireAuth, async (req, res) => {
  try {
    await loadDb();
    const user = db.users.find(u => u.id === req.session.userId);
    if (!user) return res.redirect('/login');
    const raw = (req.body.logbookToken || '').trim();
    // Basic validation: alphanumeric length 20-80 (adjust as needed)
    if(raw && !/^[-A-Za-z0-9]{8,120}$/.test(raw)) {
      return res.render('settings', { user, saved:false, error:'Invalid token format', activeTab:'token' });
    }
    user.logbookToken = raw;
    await saveDb();
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
  res.render('settings', { user, saved:true, error:null });
});
app.post('/settings/shell', requireAuth, async (req,res)=>{
  try {
    await loadDb();
    const user = db.users.find(u=>u.id===req.session.userId);
    if(user){
      user.shellPrimary = req.body.shellPrimary || user.shellPrimary || '#2E7BCB';
      user.shellSecondary = req.body.shellSecondary || user.shellSecondary || '#FFD447';
      user.oarColor = req.body.oarColor || user.oarColor || '#FF4F4F';
      await saveDb();
      return res.json({ok:true});
    }
    res.status(404).json({ok:false,error:'User not found'});
  } catch(err){
    console.error('Shell save error',err);
    res.status(500).json({ok:false,error:'Server error'});
  }
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
function computeTotals(){ const totals={}; for(const e of db.entries){ const v=Number(e.value); if(!isNaN(v)) totals[e.userId]=(totals[e.userId]||0)+v; } return totals; }
function computeRanking(totals){ return Object.entries(totals).map(([userId,total])=>({userId,total})).sort((a,b)=> b.total - a.total).map(r=>r.userId); }
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
  const existingRemote = new Set(db.entries.filter(e => e.origin==='concept2' && e.remoteId).map(e=>e.remoteId));
  let added = 0;
  const prevTotals = computeTotals();
  if(!dry){
    for(const w of workouts){ if(existingRemote.has(w.remoteId)) continue; db.entries.push({ id: Date.now().toString()+Math.random().toString(36).slice(2), userId:user.id, date:w.date, value:w.meters, origin:'concept2', remoteId:w.remoteId }); added++; }
    if(added){ recordLeaderboardEvents(prevTotals); await saveDb(); }
    user.logbookLastSync = { when:new Date().toISOString(), imported:added, scanned:workouts.length }; await saveDb();
  }
  res.json({ ok:true, preview:dry, imported:added, candidate:workouts.length, profileFound:!!profile, profileKeys: profile? Object.keys(profile):[], attempts, errors });
});
app.get('/api/debug/logbook/profile', requireAuth, async (req,res)=>{
  await loadDb();
  const user = db.users.find(u => u.id === req.session.userId);
  if(!user || !user.logbookToken) return res.status(400).json({ ok:false, error:'No token' });
  const data = await fetchLogbookWorkouts(user.logbookToken);
  res.json({ ok:true, profile:data.profile, rawProfile:data.rawProfile?.slice(0,500), attempts:data.attempts, errors:data.errors, sample:data.workouts.slice(0,3) });
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
  const totals = {};
  for (const e of db.entries) { const val = Number(e.value); if (!isNaN(val)) totals[e.userId] = (totals[e.userId] || 0) + val; }
  const rows = Object.entries(totals).map(([userId,total]) => {
    const user = db.users.find(u => u.id === userId);
    const name = user?.displayName || (user?.email ? user.email.split('@')[0] : userId);
    const hue = [...userId].reduce((a,c)=>a+c.charCodeAt(0),0) % 360;
    return { userId, name, total, totalFormatted: Number(total).toLocaleString('en-US'), hue, shellPrimary: user?.shellPrimary || '#000000', shellSecondary: user?.shellSecondary || '#000000', oarColor: user?.oarColor || '#000000' };
  }).sort((a,b)=> b.total - a.total);
  const max = rows.reduce((m,r)=> r.total>m? r.total:m, 0);
  res.render('leaderboard', { rows, max });
});
// Consolidated New Entry routes (moved here before 404)
app.get('/entry/new', requireAuth, async (req,res)=>{ try { await loadDb(); const user=db.users.find(u=>u.id===req.session.userId); const theme=getTheme(req); return res.render('entry_new',{ user, error:null, theme }); } catch(e){ console.error('render /entry/new error',e); return res.status(500).send('Server error'); } });
app.post('/entry/new', requireAuth, async (req,res)=>{ try { await loadDb(); const user=db.users.find(u=>u.id===req.session.userId); const theme=getTheme(req); if(!user) return res.status(404).send('User not found'); const meters=parseInt(req.body.meters,10); if(isNaN(meters)||meters<=0) return res.render('entry_new',{ user, error:'Enter a positive number.', theme }); const prevTotals=computeTotals(); const entry={ id:Date.now().toString()+Math.random().toString(36).slice(2), userId:user.id, value:meters, createdAt:new Date().toISOString() }; db.entries.push(entry); recordLeaderboardEvents(prevTotals); await saveDb(); return res.redirect('/dashboard'); } catch(e){ console.error('save /entry/new error',e); const theme=getTheme(req); return res.status(500).render('entry_new',{ user:null, error:'Server error saving entry.', theme }); } });

// Updates page
app.get('/updates', requireAuth, async (req,res)=>{ try { return res.render('updates', { user:{ id:req.session.userId, email:req.session.email } }); } catch(e){ console.error('Render /updates error', e); return res.status(500).send('Server error'); } });

// Fallback 404 handler
app.use((req,res,next)=>{
  if(req.path.startsWith('/api/')) return res.status(404).json({ ok:false, error:'Not found' });
  res.status(404).send('Not found');
});
// Error handler
app.use((err,req,res,next)=>{
  console.error('Error handler:', err);
  if(req.path.startsWith('/api/')) return res.status(500).json({ ok:false, error:'Server error' });
  res.status(500).send('Server error');
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}/`);
});

// Ensure body parsers loaded before form routes
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// END CLEANUP

const syncInProgress = new Set();

// Auto sync middleware (runs after session available)
app.use(async (req,res,next)=>{
  try {
    if(req.session?.userId){
      await loadDb();
      const user = db.users.find(u=>u.id===req.session.userId);
      if(user && user.logbookToken){
        const lastTs = user.logbookLastSync?.when ? Date.parse(user.logbookLastSync.when) : 0;
        const now = Date.now();
        const THRESHOLD = 30 * 60 * 1000; // 30 minutes
        if(now - lastTs > THRESHOLD && !syncInProgress.has(user.id)){
          syncInProgress.add(user.id);
          (async ()=>{
            try {
              const { workouts } = await fetchLogbookWorkouts(user.logbookToken);
              const existingRemote = new Set(db.entries.filter(e=> e.origin==='concept2' && e.remoteId).map(e=>e.remoteId));
              const prevTotals = computeTotals();
              let added=0;
              for(const w of workouts){
                if(existingRemote.has(w.remoteId)) continue;
                db.entries.push({ id: Date.now().toString()+Math.random().toString(36).slice(2), userId:user.id, date:w.date, value:w.meters, origin:'concept2', remoteId:w.remoteId });
                added++;
              }
              if(added){ recordLeaderboardEvents(prevTotals); }
              user.logbookLastSync = { when:new Date().toISOString(), imported:added, scanned:workouts.length };
              await saveDb();
              console.log(`Auto-synced ${added} workouts for user ${user.id}`);
            } catch(err){ console.error('Auto sync error', err); }
            finally { syncInProgress.delete(user.id); }
          })();
        }
      }
    }
  } catch(e){ console.error('Auto sync middleware error', e); }
  next();
});