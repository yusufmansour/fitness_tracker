#!/usr/bin/env node
const fs = require('fs').promises;
const path = require('path');

function usage(){
  console.log('Usage: node scripts/map_logbook_user.js --email user@example.com --id 2467237');
  console.log('   or: node scripts/map_logbook_user.js --userId <localUserId> --id 2467237');
  console.log('Options: --email (match local user email), --userId (local id), --id (Concept2 user id)');
  process.exit(1);
}

function getArg(name){
  const idx = process.argv.indexOf(name);
  if(idx===-1) return null;
  return process.argv[idx+1] || null;
}

(async function(){
  try{
    const email = getArg('--email');
    const userId = getArg('--userId');
    const c2id = getArg('--id');
    if(!c2id || (!email && !userId)) return usage();
    const dbFile = path.join(__dirname, '..', 'db.json');
    const txt = await fs.readFile(dbFile, 'utf8');
    const db = JSON.parse(txt || '{}');
    db.users = db.users || [];
    let user = null;
    if(email){ user = db.users.find(u => String(u.email || '').toLowerCase() === String(email).toLowerCase()); }
    else if(userId){ user = db.users.find(u => u.id === userId); }
    if(!user){ console.error('User not found. Check --email or --userId.'); process.exit(2); }
    // Set numeric id if looks numeric
    const parsed = String(c2id).match(/^\d+$/) ? Number(c2id) : c2id;
    user.logbookUserId = parsed;
    await fs.writeFile(dbFile, JSON.stringify(db, null, 2));
    console.log('Mapped Concept2 id', parsed, 'to local user', user.id, user.email || user.displayName);
    process.exit(0);
  }catch(e){ console.error('Error mapping user:', e); process.exit(3); }
})();
