// main.js placeholder - could be used for client side interactions
console.log('fitness_tracker main.js loaded');

(function(){
  // Force dark theme permanently (light theme removed)
  document.documentElement.dataset.theme='dark';

  // Year auto-fill
  const yearEl = document.getElementById('year');
  if(yearEl){ yearEl.textContent = new Date().getFullYear(); }

  // SVG icon helper (reduced repetition)
  window.renderShellIcon = function(user, scale){
    const primary = (user && user.shellPrimary) || '#000000';
    const secondary = (user && user.shellSecondary) || '#000000';
    const oar = (user && user.oarColor) || '#000000';
    const sc = scale || 0.09;
    return `<svg width="110" height="40" viewBox="0 0 300 110" preserveAspectRatio="xMidYMid meet" class="mini-shell"><g transform="translate(0,110) scale(${sc},-${sc})" stroke="none">`+
      `<path fill='${oar}' d='M1161 1018 c7 -13 37 -53 68 -90 31 -37 81 -99 111 -138 30 -39 75 -96 100 -128 25 -31 55 -71 67 -88 l21 -31 -33 -44 c-50 -65 -132 -170 -195 -247 -30 -38 -68 -85 -85 -107 -16 -21 -41 -51 -53 -67 -13 -15 -20 -28 -14 -28 12 0 482 477 482 489 0 5 -84 97 -186 203 -103 106 -207 217 -232 246 -48 54 -71 68 -51 30z'/>`+
      `<path fill='${primary}' d='M1235 640 c-38 -4 -113 -10 -165 -14 -52 -4 -162 -13 -245 -21 -253 -25 -503 -45 -563 -46 -62 0 -108 -13 -82 -22 8 -3 69 -8 135 -11 66 -4 136 -8 155 -11 19 -2 145 -13 280 -25 135 -11 262 -22 283 -25 21 -2 98 -8 172 -11 116 -6 135 -5 135 8 0 8 -11 25 -25 38 -14 13 -25 29 -25 36 0 20 39 82 55 88 8 3 15 10 15 16 0 11 -19 11 -125 0z m30 -50 c4 -6 2 -17 -4 -24 -6 -7 -8 -27 -5 -45 l7 -31 -99 5 c-55 4 -130 10 -169 15 -38 5 -106 12 -149 16 -44 4 -91 10 -105 14 -24 6 -23 7 14 13 22 4 94 12 160 18 105 10 153 14 312 26 18 2 35 -2 38 -7z'/>`+
      `<path fill='${primary}' d='M1690 642 c0 -5 14 -26 30 -47 17 -21 30 -45 30 -53 0 -8 -17 -35 -37 -60 l-37 -45 80 6 c43 4 138 12 209 17 72 6 150 12 175 15 25 2 77 7 115 10 39 3 90 8 115 11 178 17 389 34 433 34 28 0 58 4 66 9 17 11 -8 14 -309 36 -118 8 -258 20 -310 25 -52 6 -187 17 -300 25 -113 8 -217 18 -232 21 -16 3 -28 1 -28 -4z m300 -62 c373 -29 403 -43 135 -65 -38 -3 -90 -8 -115 -10 -25 -3 -86 -7 -136 -11 l-90 -5 0 50 0 51 35 0 c20 0 97 -5 171 -10z'/>`+
      `<path fill='${secondary}' d='M1265 590 c4 -6 2 -17 -4 -24 -6 -7 -8 -27 -5 -45 l7 -31 -99 5 c-55 4 -130 10 -169 15 -38 5 -106 12 -149 16 -44 4 -91 10 -105 14 -24 6 -23 7 14 13 22 4 94 12 160 18 105 10 153 14 312 26 18 2 35 -2 38 -7 z'/>`+
      `<path fill='${secondary}' d='M1990 580 c373 -29 403 -43 135 -65 -38 -3 -90 -8 -115 -10 -25 -3 -86 -7 -136 -11 l-90 -5 0 50 0 51 35 0 c20 0 97 -5 171 -10z'/>`+
    `</g></svg>`;
  };

  // Updates feed (if present on page)
  (function(){
    const list = document.getElementById('updatesList');
    if(!list) return;
    const loadEl = document.getElementById('updatesLoading');
    const moreBtn = document.getElementById('showMoreUpdates');
    let offset=0; const page=10; let total=0;
    function medal(r){ if(r===1) return '🥇'; if(r===2) return '🥈'; if(r===3) return '🥉'; return ''; }
    function rankWithMedal(r){ if(r==null || r==='?') return r==='?'? '#?' : ''; return `#${r}${medal(r)}`; }
    function desc(ev){ const name=ev.user?.name||'User'; const meters=(ev.totalMeters||0).toLocaleString('en-US'); const toRank=(ev.newRank!=null?ev.newRank: (ev.rank!=null? ev.rank: null)); const fromRank=ev.prevRank!=null? ev.prevRank: null; const to=(toRank!=null? rankWithMedal(toRank): (ev.type.startsWith('top3-')? '#?' : '')); const from=(fromRank!=null? rankWithMedal(fromRank): (ev.type==='top3-change'||ev.type==='top3-exit'? '#?' : '')); const icon = renderShellIcon(ev.user); if(ev.type==='top3-enter') return `${icon} <strong>${name}</strong> entered Top 3 at ${to} (${meters} m)`; if(ev.type==='top3-exit') return `${icon} <strong>${name}</strong> left Top 3 from ${from} (${meters} m)`; if(ev.type==='top3-change') return `${icon} <strong>${name}</strong> moved from ${from} to ${to} (${meters} m)`; if(ev.type==='goal-milestone'){ const pct=Math.round(ev.milestonePct*100); const rankDisplay = toRank && toRank<=3? ` (${rankWithMedal(toRank)})` : ''; return `${icon} <strong>${name}</strong> reached ${pct}% goal (${meters} m)${rankDisplay}`; } return `${icon} Update`; }
    function load(){ fetch('/api/updates?limit='+page+'&offset='+offset).then(r=>r.json()).then(data=>{ if(!data.ok) throw new Error('fail'); total=data.total; if(loadEl) loadEl.remove(); data.items.forEach(ev=>{ const li=document.createElement('li'); li.className='update-item'; li.style.cssText='display:flex;align-items:center;gap:.5rem;font-size:.7rem;background:var(--color-surface);padding:.35rem .5rem;border:1px solid var(--color-border);border-radius:4px;'; li.innerHTML=`<time datetime='${ev.date}' style='color:var(--color-text-light);font-size:.55rem;'>${(ev.date||'').slice(0,10)}</time> <span>${desc(ev)}</span>`; list.appendChild(li); }); offset+=data.items.length; if(moreBtn){ moreBtn.style.display= offset < total ? 'inline-flex':'none'; } }).catch(()=>{ if(loadEl){ loadEl.textContent='Failed to load updates'; } }); }
    moreBtn && moreBtn.addEventListener('click', load); load();
  })();

  // Live updates via SSE: listen for server broadcast of imports
  (function(){
    try {
      const es = new EventSource('/api/updates/stream');
      es.onmessage = function(ev){
        try { const data = JSON.parse(ev.data||'{}');
          if(data && data.type==='workouts-imported'){
            showToast(`Imported ${data.imported} new workouts`, true);
            updateChallengeDot();
            pollAlerts();
            refreshXp();
          }
          else if(data && data.type==='workout-webhook'){
            const act = data.action || 'update';
            showToast(`Workout ${act.replace('result-','')} via webhook`, true);
            updateChallengeDot(); pollAlerts(); refreshXp();
          }
        } catch{}
      };
      es.onerror = function(){ /* ignore; browser will retry */ };
    } catch{}
  })();

  // Trigger a fast sync once when user opens the page (throttled)
  (function(){
    try {
      const key='lastFastSync'; const now=Date.now(); const prev=parseInt(localStorage.getItem(key)||'0',10);
      if(!prev || (now - prev) > 5*60*1000){ // 5 minutes throttle
        fetch('/api/sync/logbook/now').then(()=>{ localStorage.setItem(key, String(now)); }).catch(()=>{});
      }
    } catch{}
  })();

  // Toast helper
  function ensureToast(){ let t=document.getElementById('globalToast'); if(!t){ t=document.createElement('div'); t.id='globalToast'; t.className='toast'; document.body.appendChild(t); } return t; }
  function showToast(msg, ok){ const t=ensureToast(); t.textContent=msg; t.dataset.state= ok? 'ok':'err'; t.classList.add('visible'); setTimeout(()=> t.classList.remove('visible'), 2200); }
  // Persistent alert queue (requires manual dismissal)
  const alertQueue=[]; let showingAlert=false;
  function pushAlert(alert){ alertQueue.push(alert); if(!showingAlert) showNextAlert(); }
  function showNextAlert(){ if(!alertQueue.length){ showingAlert=false; const ov=document.querySelector('.alert-overlay'); if(ov) ov.remove(); return; } showingAlert=true; const data=alertQueue.shift(); renderAlert(data); }
  function renderAlert(a){ let overlay=document.querySelector('.alert-overlay'); if(!overlay){ overlay=document.createElement('div'); overlay.className='alert-overlay'; document.body.appendChild(overlay); }
    overlay.innerHTML=''; const card=document.createElement('div'); card.className='alert-card '+a.type;
    const icon = a.type==='level-up'? '⬆️' : a.type==='goal-milestone'? '🎯' : a.type==='rank-up'? '🏅' : 'ℹ️';
    const title = a.type==='level-up'? 'Level Up!' : a.type==='goal-milestone'? ('Goal '+a.pct+'% Reached') : a.type==='rank-up'? 'Rank Improved' : 'Notice';
    const body = a.type==='level-up'? ('Level '+a.level+' \u2013 '+a.name) : a.type==='goal-milestone'? ('You have reached '+a.pct+'% of your goal.') : a.type==='rank-up'? ('You moved up to rank #'+a.rank+'.') : (a.message||'');
    card.innerHTML='<button class="alert-dismiss" aria-label="Dismiss alert">✕</button>'+
      '<h3><span class="alert-icon">'+icon+'</span>'+title+'</h3>'+
      '<p>'+body+'</p>'+
      '<div class="alert-actions"><button class="btn" type="button" id="alertOkBtn">Got it</button></div>';
    overlay.appendChild(card);
    function dismiss(){ card.classList.add('closing'); overlay.remove(); showingAlert=false; setTimeout(showNextAlert,150); }
    card.querySelector('.alert-dismiss').addEventListener('click', dismiss);
    card.querySelector('#alertOkBtn').addEventListener('click', dismiss);
  }

  // Deduplicate level-up notifications across sources (poll + instant)
  function maybeNotifyLevel(level){
    try{
      const last = parseInt(localStorage.getItem('notifiedLevel')||'0',10);
      if(Number.isFinite(level) && level > last){
        const tierName = levelTierName(level||1);
        pushAlert({ type:'level-up', level, name:tierName });
        localStorage.setItem('notifiedLevel', String(level));
      }
    } catch{
      // Fallback if localStorage blocked
      const tierName = levelTierName(level||1);
      pushAlert({ type:'level-up', level, name:tierName });
    }
  }

  // Settings AJAX saves
  (function(){
    const profileForm=document.querySelector('form[action="/settings/profile"]');
    const tokenForm=document.querySelector('form[action="/settings/token"]');
    const shellForm=document.getElementById('shellForm');
    function ajaxForm(form, successMsg){ if(!form) return; form.addEventListener('submit', e=>{ e.preventDefault(); const fd=new FormData(form); fetch(form.action,{ method:'POST', body:new URLSearchParams(fd) }).then(r=>r.text()).then(()=>{ showToast(successMsg,true); }).catch(()=> showToast('Save failed',false)); }); }
    ajaxForm(profileForm,'Profile saved');
    ajaxForm(tokenForm,'Token saved');
    if(shellForm){ const saveBtn=document.getElementById('saveShellBtn'); saveBtn && saveBtn.addEventListener('click', e=>{ e.preventDefault(); const fd=new FormData(shellForm); fetch(shellForm.action,{ method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ shellPrimary: fd.get('shellPrimary'), shellSecondary: fd.get('shellSecondary'), oarColor: fd.get('oarColor') }) }).then(r=> r.ok? showToast('Shell colors saved',true): showToast('Save failed',false)).catch(()=> showToast('Save failed',false)); }); }
  })();

  function updateChallengeDot(){ fetch('/api/challenges/summary').then(r=>r.json()).then(d=>{ if(!d.ok) return; const dot=document.getElementById('challenge-dot'); const link=document.getElementById('challenges-link'); if(dot){ dot.style.display = d.claimable>0? 'inline-block':'none'; } if(link){ link.classList.toggle('claimable', d.claimable>0); } }); }
  setInterval(updateChallengeDot, 20000); updateChallengeDot();
  // Alerts polling (level-up, goal milestones, rank-up)
  function pollAlerts(){ fetch('/api/alerts').then(r=>r.json()).then(d=>{ if(!d.ok) return; (d.alerts||[]).forEach(a=>{
    if(a.type==='level-up'){ maybeNotifyLevel(a.level); }
    else if(a.type==='goal-milestone'){ pushAlert({ type:'goal-milestone', pct:a.pct }); }
    else if(a.type==='rank-up'){ pushAlert({ type:'rank-up', rank:a.rank }); }
  }); }); }
  setInterval(pollAlerts, 25000); pollAlerts();

  function animateSegments(prevFilled, newFilled){ const bar=document.querySelector('.level-bar'); if(!bar) return; const segments=bar.querySelectorAll('.segment'); segments.forEach((seg,i)=>{ if(i < newFilled && i >= prevFilled){ seg.classList.add('flash'); setTimeout(()=> seg.classList.remove('flash'), 1200); } }); }
  function refreshXp(){ fetch('/api/xp').then(r=>r.json()).then(d=>{ if(!d.ok) return; const lvlNum=document.getElementById('level-number'); if(lvlNum) lvlNum.textContent = d.level; const bar=document.querySelector('.level-bar'); if(bar){ const prevProgress=parseFloat(localStorage.getItem('xpProgress')||'0'); const oldFilled=Math.floor(prevProgress*10); const newProgress=d.progress; const newFilled=Math.floor(newProgress*10); const remainder=newProgress*10 - newFilled; const prevRemainder=prevProgress*10 - oldFilled; const segments=bar.querySelectorAll('.segment'); segments.forEach((seg,i)=>{ const fillEl=seg.querySelector('.seg-fill'); if(i<newFilled){ seg.classList.add('filled'); if(fillEl) fillEl.style.width='100%'; }
      else if(i===newFilled){ seg.classList.remove('filled'); if(fillEl) fillEl.style.width=(remainder*100).toFixed(1)+'%'; }
        else { seg.classList.remove('filled'); if(fillEl) fillEl.style.width='0%'; }
      }); if(newFilled>oldFilled){ animateSegments(oldFilled, newFilled); } else if(newFilled===oldFilled && remainder>prevRemainder){ const partialSeg=segments[newFilled]; if(partialSeg){ partialSeg.classList.add('partial-flash'); setTimeout(()=> partialSeg.classList.remove('partial-flash'), 1200); } } localStorage.setItem('xpFilledCount', String(newFilled)); localStorage.setItem('xpProgress', String(newProgress)); } }); }
    // (Deprecated numeric refreshXp kept for reference; replaced below)
    function refreshXpNumeric(){ fetch('/api/xp').then(r=>r.json()).then(d=>{ if(!d.ok) return; const bar=document.querySelector('.level-bar'); if(bar){ const oldFilled=parseInt(localStorage.getItem('xpFilledCount')||'0'); const newFilled=Math.floor(d.progress*10); const segments=bar.querySelectorAll('.segment'); segments.forEach((seg,i)=>{ seg.classList.toggle('filled', i<newFilled); }); if(newFilled>oldFilled){ animateSegments(oldFilled, newFilled); } localStorage.setItem('xpFilledCount', String(newFilled)); } }); }
  function updateXpTooltip(progress){ const bar=document.querySelector('.level-bar'); if(!bar) return; const tip=bar.querySelector('.xp-tooltip'); if(tip){ tip.textContent=(progress*100).toFixed(1)+'%'; } bar.dataset.progress=progress; bar.setAttribute('title','Progress: '+(progress*100).toFixed(1)+'%'); bar.setAttribute('aria-label','Level progress '+(progress*100).toFixed(1)+'%'); }
  // Wrap original refreshXp to include tooltip update
  // Preserve old function reference if needed
  const originalRefreshXpLegacy = refreshXp;
    const BASE_LEVEL_NAMES=['beginner','novice','intermediate','experienced','competitive','champion','olympian'];
    function levelTierName(level){ const baseCount=BASE_LEVEL_NAMES.length; if(level<=baseCount) return BASE_LEVEL_NAMES[level-1]; return BASE_LEVEL_NAMES[baseCount-1] + '+'.repeat(level-baseCount); }
    const originalRefreshXp = refreshXpNumeric;
  refreshXp = function(){ fetch('/api/xp').then(r=>r.json()).then(d=>{ if(!d.ok) return; updateXpTooltip(d.progress); const nameEl=document.getElementById('level-name'); if(nameEl){ nameEl.textContent= levelTierName(d.level||1); }
    const prevLevel = parseInt(localStorage.getItem('xpLevel')||'1',10);
    if(d.level > prevLevel){ maybeNotifyLevel(d.level); }
    const bar=document.querySelector('.level-bar'); if(bar){ const prevProgress=parseFloat(localStorage.getItem('xpProgress')||'0'); const oldFilled=Math.floor(prevProgress*10); const newProgress=d.progress; const newFilled=Math.floor(newProgress*10); const remainder=newProgress*10 - newFilled; const prevRemainder=prevProgress*10 - oldFilled; const segments=bar.querySelectorAll('.segment'); segments.forEach((seg,i)=>{ const fillEl=seg.querySelector('.seg-fill'); if(i<newFilled){ seg.classList.add('filled'); if(fillEl) fillEl.style.width='100%'; } else if(i===newFilled){ seg.classList.remove('filled'); if(fillEl) fillEl.style.width=(remainder*100).toFixed(1)+'%'; } else { seg.classList.remove('filled'); if(fillEl) fillEl.style.width='0%'; } }); if(newFilled>oldFilled){ animateSegments(oldFilled,newFilled); } else if(newFilled===oldFilled && remainder>prevRemainder){ const partialSeg=segments[newFilled]; if(partialSeg){ partialSeg.classList.add('partial-flash'); setTimeout(()=> partialSeg.classList.remove('partial-flash'), 1200); } } localStorage.setItem('xpFilledCount', String(newFilled)); localStorage.setItem('xpProgress', String(newProgress)); localStorage.setItem('xpLevel', String(d.level)); } }); };

  // Initial segment flash if gained since last visit (server-rendered progress already applied)
  (function initXpBar(){ const bar=document.querySelector('.level-bar'); if(!bar) return; const progress=parseFloat(bar.dataset.progress||'0'); updateXpTooltip(progress); const dataLevel=parseInt(bar.getAttribute('data-level')||'0',10); const nameEl=document.getElementById('level-name'); if(nameEl && dataLevel){ nameEl.textContent= levelTierName(dataLevel||1); }
    const newFilled=Math.floor(progress*10); const oldFilled=parseInt(localStorage.getItem('xpFilledCount')||'0'); if(newFilled>oldFilled){ animateSegments(oldFilled, newFilled); } else { const prevProgress=parseFloat(localStorage.getItem('xpProgress')||'0'); const prevFilled=Math.floor(prevProgress*10); const prevRem=prevProgress*10 - prevFilled; const rem=progress*10 - newFilled; if(newFilled===prevFilled && rem>prevRem){ const segments=bar.querySelectorAll('.segment'); const partialSeg=segments[newFilled]; partialSeg && partialSeg.classList.add('partial-flash'); setTimeout(()=> partialSeg.classList.remove('partial-flash'), 1200); } } localStorage.setItem('xpFilledCount', String(newFilled)); localStorage.setItem('xpProgress', String(progress)); })();

  document.addEventListener('click', function(e){ const btn = e.target.closest('.claim-btn'); if(!btn) return; const id=btn.getAttribute('data-id'); btn.disabled=true; fetch('/challenges/claim',{ method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ id }) }).then(r=>r.json()).then(d=>{ if(!d.ok){ btn.disabled=false; return alert(d.error||'Error'); } const before=d.levelBefore, after=d.levelAfter; refreshXp(); const card=btn.closest('.challenge.card'); if(card){ card.remove(); } updateChallengeDot(); pollAlerts(); }).catch(()=>{ btn.disabled=false; alert('Network error'); }); });
})();
