// aitit-training-os — Cloudflare Worker backing the multi-athlete Training OS.
//
// Athlete-facing routes (require header X-Session-Token, issued by /auth/login):
//   POST /auth/login {username,password} -> {token,athleteId,displayName}
//   POST /auth/logout                    -> {ok:true}          (deletes the session row)
//   GET  /me                             -> {displayName, programs:[{id,name}]}
//   GET  /program/:id/config             -> {phases:[...], activityTypes:[...]}
//   GET  /program/:id/state              -> stored JSON blob (or null)
//   POST /program/:id/state              -> stores the request body as the JSON blob
//   GET  /program/:id/leaderboard        -> computed week/wave/program stats per linked athlete
//   POST /feedback {feedbackText}        -> files product feedback against the logged-in athlete
//
// Admin routes (no auth check — protected only by the URL being unlisted, by design):
//   GET  /admin/athletes                 POST /admin/athletes {username,password,displayName,programIds}
//   PUT  /admin/athletes/:id              {displayName}
//   PUT  /admin/athletes/:id/programs     {programIds}
//   PUT  /admin/athletes/:id/password     {password}
//   DELETE /admin/athletes/:id
//   GET  /admin/programs                 POST /admin/programs {name, activityTypeIds}
//   GET  /admin/programs/:id             DELETE /admin/programs/:id
//   POST /admin/programs/:id/phases       {name,startDate,endDate}
//   PUT  /admin/programs/:id/phases/:phaseId   {name,startDate,endDate}
//   DELETE /admin/programs/:id/phases/:phaseId
//   PUT  /admin/programs/:id/activity-types   {activityTypeIds:[...]}  (replaces linked set; never touches program_state)
//   GET  /admin/activity-types           POST /admin/activity-types {key,label,infoText}
//   PUT  /admin/activity-types/:key      {label,infoText}
//   GET  /admin/feedback                 -> all product feedback, newest first, with the author's name

const ALLOWED_ORIGIN = 'https://daviddamjakob-claude.github.io';

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin === ALLOWED_ORIGIN ? origin : ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Session-Token',
  };
}
function json(obj, status, cors) {
  return new Response(JSON.stringify(obj), { status: status || 200, headers: { ...cors, 'Content-Type': 'application/json' } });
}
async function readJson(request) {
  try { return await request.json(); } catch { return null; }
}

// ---------------- password hashing (PBKDF2, Web Crypto) ----------------
async function pbkdf2(password, saltBytes) {
  const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: saltBytes, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
  return Buffer.from(bits).toString('base64');
}
async function hashNewPassword(password) {
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  return { hash: await pbkdf2(password, saltBytes), salt: Buffer.from(saltBytes).toString('base64') };
}
async function verifyPassword(password, saltB64, hashB64) {
  return (await pbkdf2(password, Buffer.from(saltB64, 'base64'))) === hashB64;
}

// ---------------- session helpers ----------------
async function requireAthlete(request, env) {
  const token = request.headers.get('X-Session-Token');
  if (!token) return null;
  const row = await env.DB.prepare('SELECT athlete_id FROM sessions WHERE token = ?').bind(token).first();
  return row ? row.athlete_id : null;
}
async function athleteHasProgram(env, athleteId, programId) {
  const row = await env.DB.prepare('SELECT 1 FROM athlete_programs WHERE athlete_id = ? AND program_id = ?').bind(athleteId, programId).first();
  return !!row;
}

// ---------------- week/phase derivation (mirrors deriveWeeks() in index.html) ----------------
function isoDate(d) { return d.toISOString().slice(0, 10); }
function deriveWeeksWithIds(phases) {
  const weeks = [];
  let wn = 0;
  phases.forEach(p => {
    const start = new Date(p.startDate + 'T00:00:00Z');
    const end = new Date(p.endDate + 'T00:00:00Z');
    let cursor = new Date(start);
    while (cursor <= end) {
      wn++;
      const wStart = new Date(cursor);
      let wEnd = new Date(cursor); wEnd.setUTCDate(wEnd.getUTCDate() + 6);
      if (wEnd > end) wEnd = new Date(end);
      weeks.push({ id: 'w' + wn, phaseName: p.name, startISO: isoDate(wStart), endISO: isoDate(wEnd) });
      cursor.setUTCDate(cursor.getUTCDate() + 7);
    }
  });
  return weeks;
}
function weekStatusOf(w, todayISO) {
  if (todayISO > w.endISO) return 'past';
  if (todayISO < w.startISO) return 'future';
  return 'current';
}
// "1:55" -> 115 (H:MM), "0:46:54" -> 46.9 (H:MM:SS) — mirrors parseHM() in index.html
function parseHM(v) {
  if (v == null || v === '') return NaN;
  const parts = String(v).split(':').map(Number);
  if (parts.some(isNaN)) return NaN;
  if (parts.length === 2) return parts[0] * 60 + parts[1];
  if (parts.length === 3) return parts[0] * 60 + parts[1] + parts[2] / 60;
  return NaN;
}
// "Zone 2 Time" always means time logged specifically under the built-in 'zone2' activity key —
// independent of the per-workout "include in Run Progress chart" checkbox, which only controls the chart.
//
// byDiscipline is keyed by activity type and carries both done and target so the leaderboard's
// hover tooltips can break a bar down per activity. It only contains types that actually appear in
// the logged workouts or the stored targets; the frontend fills in any linked-but-unused types.
function sumWeeks(weeks, stateData) {
  let sessions = 0, target = 0, zone2Minutes = 0;
  const byDiscipline = {};
  const zone2Activities = [];
  const touch = key => (byDiscipline[key] ||= { done: 0, target: 0 });
  weeks.forEach(w => {
    const wk = stateData && stateData.weeks && stateData.weeks[w.id];
    if (!wk) return;
    const workouts = wk.workouts || [];
    sessions += workouts.length;
    workouts.forEach(x => {
      touch(x.type).done += 1;
      if (x.type === 'zone2') {
        const mins = parseHM(x.values && x.values.time);
        if (!isNaN(mins)) zone2Minutes += mins;
        zone2Activities.push({ date: (x.values && x.values.date) || null, minutes: isNaN(mins) ? null : Math.round(mins) });
      }
    });
    if (wk.targets) Object.entries(wk.targets).forEach(([key, t]) => {
      const planned = Number(t.planned) || 0;
      target += planned;
      touch(key).target += planned;
    });
  });
  zone2Activities.sort((a, b) => ((a.date || '') < (b.date || '') ? -1 : 1));
  return { sessions, target, zone2Minutes: Math.round(zone2Minutes), completionPct: target > 0 ? Math.round(sessions / target * 100) : 0, byDiscipline, zone2Activities };
}
// byWeek / byWave are the per-sub-period breakdowns behind the Current Wave and Full Program
// tooltips; both are built oldest-first so the frontend can render them in order.
function computeAthleteStats(weeks, stateData) {
  const todayISO = isoDate(new Date());
  const currentWeek = weeks.find(w => weekStatusOf(w, todayISO) === 'current');
  const nonFutureWeeks = weeks.filter(w => weekStatusOf(w, todayISO) !== 'future');
  const currentWaveName = currentWeek ? currentWeek.phaseName : null;
  const waveWeeks = currentWaveName ? nonFutureWeeks.filter(w => w.phaseName === currentWaveName) : [];
  const byWeek = waveWeeks.map(w => ({ label: 'Week ' + w.id.slice(1), byDiscipline: sumWeeks([w], stateData).byDiscipline }));
  const waveOrder = [];
  const waveGroups = {};
  nonFutureWeeks.forEach(w => {
    if (!waveGroups[w.phaseName]) { waveGroups[w.phaseName] = []; waveOrder.push(w.phaseName); }
    waveGroups[w.phaseName].push(w);
  });
  const byWave = waveOrder.map(name => ({ label: name, byDiscipline: sumWeeks(waveGroups[name], stateData).byDiscipline }));
  return {
    currentWeek: currentWeek ? sumWeeks([currentWeek], stateData) : { sessions: 0, target: 0, zone2Minutes: 0, completionPct: 0, byDiscipline: {}, zone2Activities: [] },
    currentWave: { ...sumWeeks(waveWeeks, stateData), waveName: currentWaveName, byWeek },
    program: { ...sumWeeks(nonFutureWeeks, stateData), byWave },
  };
}

// ---------------- route handlers ----------------
async function handleLogin(request, env, cors) {
  const body = await readJson(request);
  if (!body || !body.username || !body.password) return json({ error: 'username and password required' }, 400, cors);
  const athlete = await env.DB.prepare('SELECT id, password_hash, salt, display_name FROM athletes WHERE username = ?').bind(body.username).first();
  if (!athlete || !(await verifyPassword(body.password, athlete.salt, athlete.password_hash))) {
    return json({ error: 'Invalid username or password' }, 401, cors);
  }
  const token = crypto.randomUUID();
  await env.DB.prepare('INSERT INTO sessions (token, athlete_id) VALUES (?, ?)').bind(token, athlete.id).run();
  return json({ token, athleteId: athlete.id, displayName: athlete.display_name }, 200, cors);
}
async function handleLogout(request, env, cors) {
  const token = request.headers.get('X-Session-Token');
  if (token) await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
  return json({ ok: true }, 200, cors);
}
async function handleMe(request, env, cors) {
  const athleteId = await requireAthlete(request, env);
  if (!athleteId) return json({ error: 'Unauthorized' }, 401, cors);
  const athlete = await env.DB.prepare('SELECT display_name FROM athletes WHERE id = ?').bind(athleteId).first();
  const programs = await env.DB.prepare(
    'SELECT p.id, p.name FROM programs p JOIN athlete_programs ap ON ap.program_id = p.id WHERE ap.athlete_id = ? ORDER BY p.id'
  ).bind(athleteId).all();
  return json({ displayName: athlete.display_name, programs: programs.results }, 200, cors);
}
// The *Data() helpers hold the raw reads, split out from their handlers so the same query can be
// reused from another route without re-running the athlete auth/authorisation checks that wrap it.
async function programConfigData(env, programId) {
  const phases = await env.DB.prepare('SELECT id, name, start_date AS startDate, end_date AS endDate FROM phases WHERE program_id = ? ORDER BY sort_order').bind(programId).all();
  const activityTypes = await env.DB.prepare(
    'SELECT a.key, a.label, a.info_text AS infoText FROM activity_types a JOIN program_activity_types pat ON pat.activity_type_id = a.id WHERE pat.program_id = ? ORDER BY pat.sort_order'
  ).bind(programId).all();
  return { phases: phases.results, activityTypes: activityTypes.results };
}
async function handleProgramConfig(request, env, cors, programId) {
  const athleteId = await requireAthlete(request, env);
  if (!athleteId) return json({ error: 'Unauthorized' }, 401, cors);
  if (!(await athleteHasProgram(env, athleteId, programId))) return json({ error: 'Forbidden' }, 403, cors);
  return json(await programConfigData(env, programId), 200, cors);
}
async function programStateData(env, athleteId, programId) {
  const row = await env.DB.prepare('SELECT data FROM program_state WHERE athlete_id = ? AND program_id = ?').bind(athleteId, programId).first();
  return row ? row.data : 'null';
}
async function handleStateGet(request, env, cors, programId) {
  const athleteId = await requireAthlete(request, env);
  if (!athleteId) return json({ error: 'Unauthorized' }, 401, cors);
  if (!(await athleteHasProgram(env, athleteId, programId))) return json({ error: 'Forbidden' }, 403, cors);
  const data = await programStateData(env, athleteId, programId);
  return new Response(data, { headers: { ...cors, 'Content-Type': 'application/json' } });
}
async function handleStatePost(request, env, cors, programId) {
  const athleteId = await requireAthlete(request, env);
  if (!athleteId) return json({ error: 'Unauthorized' }, 401, cors);
  if (!(await athleteHasProgram(env, athleteId, programId))) return json({ error: 'Forbidden' }, 403, cors);
  const body = await request.text();
  try { JSON.parse(body); } catch { return json({ error: 'Invalid JSON' }, 400, cors); }
  await env.DB.prepare(
    'INSERT INTO program_state (athlete_id, program_id, data, updated_at) VALUES (?, ?, ?, datetime(\'now\')) ' +
    'ON CONFLICT(athlete_id, program_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at'
  ).bind(athleteId, programId, body).run();
  return json({ ok: true }, 200, cors);
}
async function programLeaderboardData(env, programId) {
  const phasesRes = await env.DB.prepare('SELECT name, start_date AS startDate, end_date AS endDate FROM phases WHERE program_id = ? ORDER BY sort_order').bind(programId).all();
  const weeks = deriveWeeksWithIds(phasesRes.results);
  const linked = await env.DB.prepare(
    'SELECT a.id, a.display_name AS displayName FROM athletes a JOIN athlete_programs ap ON ap.athlete_id = a.id WHERE ap.program_id = ? ORDER BY a.id'
  ).bind(programId).all();
  const athletes = await Promise.all(linked.results.map(async a => {
    const stateRow = await env.DB.prepare('SELECT data FROM program_state WHERE athlete_id = ? AND program_id = ?').bind(a.id, programId).first();
    const stateData = stateRow ? JSON.parse(stateRow.data) : null;
    return { athleteId: a.id, displayName: a.displayName, ...computeAthleteStats(weeks, stateData) };
  }));
  return { athletes };
}
async function handleLeaderboard(request, env, cors, programId) {
  const athleteId = await requireAthlete(request, env);
  if (!athleteId) return json({ error: 'Unauthorized' }, 401, cors);
  if (!(await athleteHasProgram(env, athleteId, programId))) return json({ error: 'Forbidden' }, 403, cors);
  return json(await programLeaderboardData(env, programId), 200, cors);
}
async function handleFeedbackPost(request, env, cors) {
  const athleteId = await requireAthlete(request, env);
  if (!athleteId) return json({ error: 'Unauthorized' }, 401, cors);
  const body = await readJson(request);
  const feedbackText = body && typeof body.feedbackText === 'string' ? body.feedbackText.trim() : '';
  if (!feedbackText) return json({ error: 'feedbackText required' }, 400, cors);
  await env.DB.prepare('INSERT INTO product_feedback (athlete_id, feedback_text) VALUES (?, ?)').bind(athleteId, feedbackText).run();
  return json({ ok: true }, 200, cors);
}

// ---------------- admin handlers (no auth, by design) ----------------
// Independent reads/writes go through Promise.all rather than a sequential await loop — every D1
// statement is its own network round trip, and serialising them was what made the admin buttons
// feel slow.
async function adminListAthletes(env, cors) {
  const [athletes, links] = await Promise.all([
    env.DB.prepare('SELECT id, username, display_name AS displayName FROM athletes ORDER BY id').all(),
    env.DB.prepare(
      'SELECT ap.athlete_id AS athleteId, p.id AS programId, p.name FROM athlete_programs ap JOIN programs p ON p.id = ap.program_id'
    ).all(),
  ]);
  const byAthlete = {};
  for (const l of links.results) (byAthlete[l.athleteId] ||= []).push({ id: l.programId, name: l.name });
  return json(athletes.results.map(a => ({ ...a, programs: byAthlete[a.id] || [] })), 200, cors);
}
async function adminCreateAthlete(request, env, cors) {
  const body = await readJson(request);
  if (!body || !body.username || !body.password || !body.displayName) return json({ error: 'username, password, displayName required' }, 400, cors);
  const { hash, salt } = await hashNewPassword(body.password);
  const result = await env.DB.prepare('INSERT INTO athletes (username, password_hash, salt, display_name) VALUES (?, ?, ?, ?)')
    .bind(body.username, hash, salt, body.displayName).run();
  const athleteId = result.meta.last_row_id;
  await Promise.all((body.programIds || []).map(programId =>
    env.DB.prepare('INSERT INTO athlete_programs (athlete_id, program_id) VALUES (?, ?)').bind(athleteId, programId).run()
  ));
  return json({ id: athleteId }, 201, cors);
}
async function adminUpdateAthletePrograms(request, env, cors, athleteId) {
  const body = await readJson(request);
  if (!body || !Array.isArray(body.programIds)) return json({ error: 'programIds array required' }, 400, cors);
  await env.DB.prepare('DELETE FROM athlete_programs WHERE athlete_id = ?').bind(athleteId).run();
  await Promise.all(body.programIds.map(programId =>
    env.DB.prepare('INSERT INTO athlete_programs (athlete_id, program_id) VALUES (?, ?)').bind(athleteId, programId).run()
  ));
  return json({ ok: true }, 200, cors);
}
async function adminUpdateAthletePassword(request, env, cors, athleteId) {
  const body = await readJson(request);
  if (!body || !body.password) return json({ error: 'password required' }, 400, cors);
  const { hash, salt } = await hashNewPassword(body.password);
  await env.DB.prepare('UPDATE athletes SET password_hash = ?, salt = ? WHERE id = ?').bind(hash, salt, athleteId).run();
  // Force re-login everywhere the password changed, since old sessions were issued under the old password.
  await env.DB.prepare('DELETE FROM sessions WHERE athlete_id = ?').bind(athleteId).run();
  return json({ ok: true }, 200, cors);
}
async function adminUpdateAthleteProfile(request, env, cors, athleteId) {
  const body = await readJson(request);
  if (!body || !body.displayName) return json({ error: 'displayName required' }, 400, cors);
  await env.DB.prepare('UPDATE athletes SET display_name = ? WHERE id = ?').bind(body.displayName, athleteId).run();
  return json({ ok: true }, 200, cors);
}
async function adminDeleteAthlete(env, cors, athleteId) {
  await env.DB.prepare('DELETE FROM sessions WHERE athlete_id = ?').bind(athleteId).run();
  await env.DB.prepare('DELETE FROM program_state WHERE athlete_id = ?').bind(athleteId).run();
  await env.DB.prepare('DELETE FROM athlete_programs WHERE athlete_id = ?').bind(athleteId).run();
  await env.DB.prepare('DELETE FROM product_feedback WHERE athlete_id = ?').bind(athleteId).run();
  await env.DB.prepare('DELETE FROM athletes WHERE id = ?').bind(athleteId).run();
  return json({ ok: true }, 200, cors);
}
async function adminListPrograms(env, cors) {
  const programs = await env.DB.prepare('SELECT id, name FROM programs ORDER BY id').all();
  return json(programs.results, 200, cors);
}
async function adminCreateProgram(request, env, cors) {
  const body = await readJson(request);
  if (!body || !body.name) return json({ error: 'name required' }, 400, cors);
  const result = await env.DB.prepare('INSERT INTO programs (name) VALUES (?)').bind(body.name).run();
  const programId = result.meta.last_row_id;
  await Promise.all((body.activityTypeIds || []).map((activityTypeId, order) =>
    env.DB.prepare('INSERT INTO program_activity_types (program_id, activity_type_id, sort_order) VALUES (?, ?, ?)').bind(programId, activityTypeId, order).run()
  ));
  return json({ id: programId }, 201, cors);
}
async function adminGetProgram(env, cors, programId) {
  const program = await env.DB.prepare('SELECT id, name FROM programs WHERE id = ?').bind(programId).first();
  if (!program) return json({ error: 'Not found' }, 404, cors);
  const phases = await env.DB.prepare('SELECT id, name, start_date AS startDate, end_date AS endDate FROM phases WHERE program_id = ? ORDER BY sort_order').bind(programId).all();
  const activityTypes = await env.DB.prepare(
    'SELECT a.id, a.key, a.label, a.info_text AS infoText FROM activity_types a JOIN program_activity_types pat ON pat.activity_type_id = a.id WHERE pat.program_id = ? ORDER BY pat.sort_order'
  ).bind(programId).all();
  return json({ ...program, phases: phases.results, activityTypes: activityTypes.results }, 200, cors);
}
async function adminCreatePhase(request, env, cors, programId) {
  const body = await readJson(request);
  if (!body || !body.name || !body.startDate || !body.endDate) return json({ error: 'name, startDate, endDate required' }, 400, cors);
  const maxOrder = await env.DB.prepare('SELECT COALESCE(MAX(sort_order), -1) AS m FROM phases WHERE program_id = ?').bind(programId).first();
  const result = await env.DB.prepare('INSERT INTO phases (program_id, name, start_date, end_date, sort_order) VALUES (?, ?, ?, ?, ?)')
    .bind(programId, body.name, body.startDate, body.endDate, maxOrder.m + 1).run();
  return json({ id: result.meta.last_row_id }, 201, cors);
}
async function adminUpdatePhase(request, env, cors, phaseId) {
  const body = await readJson(request);
  if (!body || !body.name || !body.startDate || !body.endDate) return json({ error: 'name, startDate, endDate required' }, 400, cors);
  await env.DB.prepare('UPDATE phases SET name = ?, start_date = ?, end_date = ? WHERE id = ?').bind(body.name, body.startDate, body.endDate, phaseId).run();
  return json({ ok: true }, 200, cors);
}
async function adminDeletePhase(env, cors, phaseId) {
  await env.DB.prepare('DELETE FROM phases WHERE id = ?').bind(phaseId).run();
  return json({ ok: true }, 200, cors);
}
// Deleting a program takes every athlete's logged state for it with it — the referencing rows go
// first so the final DELETE never trips a foreign key.
async function adminDeleteProgram(env, cors, programId) {
  await env.DB.prepare('DELETE FROM program_state WHERE program_id = ?').bind(programId).run();
  await env.DB.prepare('DELETE FROM program_activity_types WHERE program_id = ?').bind(programId).run();
  await env.DB.prepare('DELETE FROM phases WHERE program_id = ?').bind(programId).run();
  await env.DB.prepare('DELETE FROM athlete_programs WHERE program_id = ?').bind(programId).run();
  await env.DB.prepare('DELETE FROM programs WHERE id = ?').bind(programId).run();
  return json({ ok: true }, 200, cors);
}
// Only ever touches the program<->activity-type link table — program_state (logged workout data)
// is never read or written here, so unlinking (and re-linking later) never loses any history.
async function adminUpdateProgramActivityTypes(request, env, cors, programId) {
  const body = await readJson(request);
  if (!body || !Array.isArray(body.activityTypeIds)) return json({ error: 'activityTypeIds array required' }, 400, cors);
  await env.DB.prepare('DELETE FROM program_activity_types WHERE program_id = ?').bind(programId).run();
  await Promise.all(body.activityTypeIds.map((activityTypeId, order) =>
    env.DB.prepare('INSERT INTO program_activity_types (program_id, activity_type_id, sort_order) VALUES (?, ?, ?)').bind(programId, activityTypeId, order).run()
  ));
  return json({ ok: true }, 200, cors);
}
async function adminListActivityTypes(env, cors) {
  const rows = await env.DB.prepare('SELECT id, key, label, info_text AS infoText FROM activity_types ORDER BY id').all();
  return json(rows.results, 200, cors);
}
async function adminListFeedback(env, cors) {
  const rows = await env.DB.prepare(
    'SELECT pf.id, a.display_name AS displayName, a.username, pf.feedback_text AS feedbackText, pf.created_at AS createdAt ' +
    'FROM product_feedback pf JOIN athletes a ON a.id = pf.athlete_id ORDER BY pf.created_at DESC'
  ).all();
  return json(rows.results, 200, cors);
}
async function adminCreateActivityType(request, env, cors) {
  const body = await readJson(request);
  if (!body || !body.key || !body.label || !body.infoText) return json({ error: 'key, label, infoText required' }, 400, cors);
  if (!/^[a-zA-Z0-9_]+$/.test(body.key)) return json({ error: 'key must contain only letters, numbers and underscores' }, 400, cors);
  try {
    const result = await env.DB.prepare('INSERT INTO activity_types (key, label, info_text) VALUES (?, ?, ?)')
      .bind(body.key, body.label, body.infoText).run();
    return json({ id: result.meta.last_row_id }, 201, cors);
  } catch (err) {
    return json({ error: 'That key already exists' }, 400, cors);
  }
}
async function adminUpdateActivityType(request, env, cors, key) {
  const body = await readJson(request);
  if (!body || !body.label || !body.infoText) return json({ error: 'label, infoText required' }, 400, cors);
  await env.DB.prepare('UPDATE activity_types SET label = ?, info_text = ? WHERE key = ?')
    .bind(body.label, body.infoText, key).run();
  return json({ ok: true }, 200, cors);
}
export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const cors = corsHeaders(origin);
    if (request.method === 'OPTIONS') return new Response(null, { headers: cors });

    const url = new URL(request.url);
    const seg = url.pathname.split('/').filter(Boolean);
    const method = request.method;

    try {
      if (method === 'POST' && seg[0] === 'auth' && seg[1] === 'login') return handleLogin(request, env, cors);
      if (method === 'POST' && seg[0] === 'auth' && seg[1] === 'logout') return handleLogout(request, env, cors);
      if (method === 'GET' && seg[0] === 'me') return handleMe(request, env, cors);

      if (seg[0] === 'program' && seg[2] === 'config' && method === 'GET') return handleProgramConfig(request, env, cors, seg[1]);
      if (seg[0] === 'program' && seg[2] === 'state' && method === 'GET') return handleStateGet(request, env, cors, seg[1]);
      if (seg[0] === 'program' && seg[2] === 'state' && method === 'POST') return handleStatePost(request, env, cors, seg[1]);
      if (seg[0] === 'program' && seg[2] === 'leaderboard' && method === 'GET') return handleLeaderboard(request, env, cors, seg[1]);

      if (seg[0] === 'feedback' && !seg[1] && method === 'POST') return handleFeedbackPost(request, env, cors);

      if (seg[0] === 'admin' && seg[1] === 'athletes' && !seg[2] && method === 'GET') return adminListAthletes(env, cors);
      if (seg[0] === 'admin' && seg[1] === 'athletes' && !seg[2] && method === 'POST') return adminCreateAthlete(request, env, cors);
      if (seg[0] === 'admin' && seg[1] === 'athletes' && seg[3] === 'programs' && method === 'PUT') return adminUpdateAthletePrograms(request, env, cors, seg[2]);
      if (seg[0] === 'admin' && seg[1] === 'athletes' && seg[3] === 'password' && method === 'PUT') return adminUpdateAthletePassword(request, env, cors, seg[2]);
      if (seg[0] === 'admin' && seg[1] === 'athletes' && seg[2] && !seg[3] && method === 'PUT') return adminUpdateAthleteProfile(request, env, cors, seg[2]);
      if (seg[0] === 'admin' && seg[1] === 'athletes' && seg[2] && !seg[3] && method === 'DELETE') return adminDeleteAthlete(env, cors, seg[2]);

      if (seg[0] === 'admin' && seg[1] === 'programs' && !seg[2] && method === 'GET') return adminListPrograms(env, cors);
      if (seg[0] === 'admin' && seg[1] === 'programs' && !seg[2] && method === 'POST') return adminCreateProgram(request, env, cors);
      if (seg[0] === 'admin' && seg[1] === 'programs' && seg[2] && !seg[3] && method === 'GET') return adminGetProgram(env, cors, seg[2]);
      if (seg[0] === 'admin' && seg[1] === 'programs' && seg[2] && !seg[3] && method === 'DELETE') return adminDeleteProgram(env, cors, seg[2]);
      if (seg[0] === 'admin' && seg[1] === 'programs' && seg[3] === 'phases' && !seg[4] && method === 'POST') return adminCreatePhase(request, env, cors, seg[2]);
      if (seg[0] === 'admin' && seg[1] === 'programs' && seg[3] === 'phases' && seg[4] && method === 'PUT') return adminUpdatePhase(request, env, cors, seg[4]);
      if (seg[0] === 'admin' && seg[1] === 'programs' && seg[3] === 'phases' && seg[4] && method === 'DELETE') return adminDeletePhase(env, cors, seg[4]);
      if (seg[0] === 'admin' && seg[1] === 'programs' && seg[3] === 'activity-types' && !seg[4] && method === 'PUT') return adminUpdateProgramActivityTypes(request, env, cors, seg[2]);

      if (seg[0] === 'admin' && seg[1] === 'feedback' && method === 'GET') return adminListFeedback(env, cors);

      if (seg[0] === 'admin' && seg[1] === 'activity-types' && !seg[2] && method === 'GET') return adminListActivityTypes(env, cors);
      if (seg[0] === 'admin' && seg[1] === 'activity-types' && !seg[2] && method === 'POST') return adminCreateActivityType(request, env, cors);
      if (seg[0] === 'admin' && seg[1] === 'activity-types' && seg[2] && method === 'PUT') return adminUpdateActivityType(request, env, cors, seg[2]);

      return json({ error: 'Not found' }, 404, cors);
    } catch (err) {
      return json({ error: String(err && err.message || err) }, 500, cors);
    }
  },
};
