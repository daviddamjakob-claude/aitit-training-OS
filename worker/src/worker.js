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
//   GET  /program/:id/feed               -> every linked athlete's workouts + week wrap-ups,
//                                          each with its high-five count and comment thread
//   POST /program/:id/feed/high-five      {itemKey}       -> toggles the viewer's high five
//   POST /program/:id/feed/comments       {itemKey,body}  -> appends a comment
//   DELETE /program/:id/feed/comments/:commentId          -> deletes the viewer's own comment
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
//   POST /admin/wrapups/backfill         -> generates any missing week wrap-ups for every program
//
// Cron (see triggers.crons in wrangler.jsonc): generates the week wrap-ups every Monday at
// 18:00 Europe/Madrid.

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

// ---------------- feed ----------------
// A feed item key identifies a card across both kinds. Workout ids ('wo_...') are only unique
// within one athlete's state blob, so the owning athlete is part of the key rather than trusted
// to be globally distinct.
function workoutItemKey(athleteId, workoutId) { return 'w:' + athleteId + ':' + workoutId; }
function wrapupItemKey(athleteId, weekId) { return 'r:' + athleteId + ':' + weekId; }
// Cheap ownership check for writes: rather than rebuilding the whole feed to confirm a card
// exists, the key is parsed and the athlete it names is checked against the program, which is
// enough to stop high fives and comments being filed against another program's cards.
async function feedItemKeyBelongsToProgram(env, programId, itemKey) {
  const m = /^([wr]):(\d+):(.+)$/.exec(itemKey || '');
  if (!m) return false;
  return athleteHasProgram(env, Number(m[2]), programId);
}

// Workouts are grouped by the week column they were logged under (not by re-deriving from the
// date they carry), so the Feed's week sections line up exactly with the Training Log's.
async function programFeedData(env, programId, viewerAthleteId) {
  const [phasesRes, linked] = await Promise.all([
    env.DB.prepare('SELECT name, start_date AS startDate, end_date AS endDate FROM phases WHERE program_id = ? ORDER BY sort_order').bind(programId).all(),
    env.DB.prepare('SELECT a.id, a.display_name AS displayName FROM athletes a JOIN athlete_programs ap ON ap.athlete_id = a.id WHERE ap.program_id = ? ORDER BY a.id').bind(programId).all(),
  ]);
  const weeks = deriveWeeksWithIds(phasesRes.results);
  const weekById = {};
  weeks.forEach(w => { weekById[w.id] = w; });
  const nameById = {};
  linked.results.forEach(a => { nameById[a.id] = a.displayName; });

  const states = await Promise.all(linked.results.map(async a => {
    const row = await env.DB.prepare('SELECT data FROM program_state WHERE athlete_id = ? AND program_id = ?').bind(a.id, programId).first();
    let data = null;
    try { data = row ? JSON.parse(row.data) : null; } catch { data = null; }
    return { athlete: a, data };
  }));

  const items = [];
  states.forEach(({ athlete, data }) => {
    if (!data || !data.weeks) return;
    Object.keys(data.weeks).forEach(weekId => {
      if (!weekById[weekId]) return;
      ((data.weeks[weekId] || {}).workouts || []).forEach(x => {
        items.push({
          key: workoutItemKey(athlete.id, x.id),
          kind: 'workout',
          athleteId: athlete.id,
          displayName: athlete.displayName,
          weekId,
          date: (x.values && x.values.date) || null,
          type: x.type,
          values: x.values || {},
          review: x.review || '',
          details: x.details || '',
          photos: (x.photos || []).map(p => ({ secure_url: p.secure_url })),
        });
      });
    });
  });

  const wrapups = await env.DB.prepare(
    'SELECT athlete_id AS athleteId, week_id AS weekId, data, created_at AS createdAt FROM week_wrapups WHERE program_id = ?'
  ).bind(programId).all();
  wrapups.results.forEach(r => {
    if (!weekById[r.weekId]) return;
    let summary = null;
    try { summary = JSON.parse(r.data); } catch { return; }
    items.push({
      key: wrapupItemKey(r.athleteId, r.weekId),
      kind: 'wrapup',
      athleteId: r.athleteId,
      displayName: nameById[r.athleteId] || 'Unknown athlete',
      weekId: r.weekId,
      createdAt: r.createdAt,
      summary,
    });
  });

  // High fives and comments are read for the whole program in one query each and then attached,
  // rather than one round trip per card.
  const [hf, cm] = await Promise.all([
    env.DB.prepare('SELECT item_key AS itemKey, actor_athlete_id AS actorId FROM feed_high_fives WHERE program_id = ?').bind(programId).all(),
    env.DB.prepare(
      'SELECT c.id, c.item_key AS itemKey, c.author_athlete_id AS authorId, a.display_name AS authorName, c.body, c.created_at AS createdAt ' +
      'FROM feed_comments c JOIN athletes a ON a.id = c.author_athlete_id WHERE c.program_id = ? ORDER BY c.created_at'
    ).bind(programId).all(),
  ]);
  const hfByKey = {}, cmByKey = {};
  hf.results.forEach(r => { (hfByKey[r.itemKey] ||= []).push(r.actorId); });
  cm.results.forEach(r => { (cmByKey[r.itemKey] ||= []).push({ id: r.id, authorId: r.authorId, authorName: r.authorName, body: r.body, createdAt: r.createdAt }); });
  items.forEach(it => {
    const actors = hfByKey[it.key] || [];
    it.highFives = { count: actors.length, mine: actors.indexOf(viewerAthleteId) !== -1 };
    it.comments = cmByKey[it.key] || [];
  });

  return { viewerAthleteId, weeks, items };
}
async function handleFeed(request, env, cors, programId) {
  const athleteId = await requireAthlete(request, env);
  if (!athleteId) return json({ error: 'Unauthorized' }, 401, cors);
  if (!(await athleteHasProgram(env, athleteId, programId))) return json({ error: 'Forbidden' }, 403, cors);
  return json(await programFeedData(env, programId, athleteId), 200, cors);
}
async function handleHighFive(request, env, cors, programId) {
  const athleteId = await requireAthlete(request, env);
  if (!athleteId) return json({ error: 'Unauthorized' }, 401, cors);
  if (!(await athleteHasProgram(env, athleteId, programId))) return json({ error: 'Forbidden' }, 403, cors);
  const body = await readJson(request);
  const itemKey = body && typeof body.itemKey === 'string' ? body.itemKey : '';
  if (!(await feedItemKeyBelongsToProgram(env, programId, itemKey))) return json({ error: 'Unknown feed item' }, 400, cors);
  const existing = await env.DB.prepare('SELECT 1 FROM feed_high_fives WHERE program_id = ? AND item_key = ? AND actor_athlete_id = ?')
    .bind(programId, itemKey, athleteId).first();
  if (existing) {
    await env.DB.prepare('DELETE FROM feed_high_fives WHERE program_id = ? AND item_key = ? AND actor_athlete_id = ?')
      .bind(programId, itemKey, athleteId).run();
  } else {
    await env.DB.prepare('INSERT INTO feed_high_fives (program_id, item_key, actor_athlete_id) VALUES (?, ?, ?)')
      .bind(programId, itemKey, athleteId).run();
  }
  const row = await env.DB.prepare('SELECT COUNT(*) AS c FROM feed_high_fives WHERE program_id = ? AND item_key = ?').bind(programId, itemKey).first();
  return json({ count: row.c, mine: !existing }, 200, cors);
}
async function handleCommentPost(request, env, cors, programId) {
  const athleteId = await requireAthlete(request, env);
  if (!athleteId) return json({ error: 'Unauthorized' }, 401, cors);
  if (!(await athleteHasProgram(env, athleteId, programId))) return json({ error: 'Forbidden' }, 403, cors);
  const body = await readJson(request);
  const itemKey = body && typeof body.itemKey === 'string' ? body.itemKey : '';
  const text = body && typeof body.body === 'string' ? body.body.trim() : '';
  if (!(await feedItemKeyBelongsToProgram(env, programId, itemKey))) return json({ error: 'Unknown feed item' }, 400, cors);
  if (!text) return json({ error: 'body required' }, 400, cors);
  if (text.length > 1000) return json({ error: 'Comment is too long (1000 characters max)' }, 400, cors);
  const result = await env.DB.prepare('INSERT INTO feed_comments (program_id, item_key, author_athlete_id, body) VALUES (?, ?, ?, ?)')
    .bind(programId, itemKey, athleteId, text).run();
  const row = await env.DB.prepare(
    'SELECT c.id, c.author_athlete_id AS authorId, a.display_name AS authorName, c.body, c.created_at AS createdAt ' +
    'FROM feed_comments c JOIN athletes a ON a.id = c.author_athlete_id WHERE c.id = ?'
  ).bind(result.meta.last_row_id).first();
  return json(row, 201, cors);
}
async function handleCommentDelete(request, env, cors, programId, commentId) {
  const athleteId = await requireAthlete(request, env);
  if (!athleteId) return json({ error: 'Unauthorized' }, 401, cors);
  if (!(await athleteHasProgram(env, athleteId, programId))) return json({ error: 'Forbidden' }, 403, cors);
  // Scoped to the author so one athlete can never delete another's comment.
  const result = await env.DB.prepare('DELETE FROM feed_comments WHERE id = ? AND program_id = ? AND author_athlete_id = ?')
    .bind(commentId, programId, athleteId).run();
  if (!result.meta.changes) return json({ error: 'Not found' }, 404, cors);
  return json({ ok: true }, 200, cors);
}

// ---------------- week wrap-ups ----------------
// YYYY-MM-DD in the program's reference timezone. The wrap-up cron and the week grid both need
// to agree on what "today" is, and UTC would roll the day over an hour or two early in Barcelona.
const WRAPUP_TIMEZONE = 'Europe/Madrid';
function localISODate(d) {
  return new Intl.DateTimeFormat('en-CA', { timeZone: WRAPUP_TIMEZONE, year: 'numeric', month: '2-digit', day: '2-digit' }).format(d);
}
// A week is wrapped up once it has ended, so the Monday cron and the admin backfill are the same
// operation over a different set of already-finished weeks. Idempotent: the UNIQUE index on
// (program_id, athlete_id, week_id) means re-running only ever fills gaps.
//
// Weeks with nothing planned and nothing done are skipped — that is what an athlete's record
// looks like for the stretch of the program before they joined it, and a wall of empty 0/0
// cards is not a wrap-up.
async function generateWrapupsForProgram(env, programId, todayISO) {
  const phasesRes = await env.DB.prepare('SELECT name, start_date AS startDate, end_date AS endDate FROM phases WHERE program_id = ? ORDER BY sort_order').bind(programId).all();
  const finishedWeeks = deriveWeeksWithIds(phasesRes.results).filter(w => w.endISO < todayISO);
  if (!finishedWeeks.length) return 0;
  const [linked, existing] = await Promise.all([
    env.DB.prepare('SELECT a.id FROM athletes a JOIN athlete_programs ap ON ap.athlete_id = a.id WHERE ap.program_id = ?').bind(programId).all(),
    env.DB.prepare('SELECT athlete_id AS athleteId, week_id AS weekId FROM week_wrapups WHERE program_id = ?').bind(programId).all(),
  ]);
  const have = new Set(existing.results.map(r => r.athleteId + '|' + r.weekId));
  const states = await Promise.all(linked.results.map(async a => {
    const row = await env.DB.prepare('SELECT data FROM program_state WHERE athlete_id = ? AND program_id = ?').bind(a.id, programId).first();
    let data = null;
    try { data = row ? JSON.parse(row.data) : null; } catch { data = null; }
    return { athleteId: a.id, data };
  }));
  const inserts = [];
  states.forEach(({ athleteId, data }) => {
    finishedWeeks.forEach(w => {
      if (have.has(athleteId + '|' + w.id)) return;
      const s = sumWeeks([w], data);
      if (!s.sessions && !s.target) return;
      inserts.push(env.DB.prepare(
        'INSERT OR IGNORE INTO week_wrapups (program_id, athlete_id, week_id, week_start, week_end, phase_name, data) VALUES (?, ?, ?, ?, ?, ?, ?)'
      ).bind(programId, athleteId, w.id, w.startISO, w.endISO, w.phaseName, JSON.stringify({
        sessions: s.sessions,
        target: s.target,
        completionPct: s.completionPct,
        zone2Minutes: s.zone2Minutes,
        byDiscipline: s.byDiscipline,
      })));
    });
  });
  if (!inserts.length) return 0;
  await env.DB.batch(inserts);
  return inserts.length;
}
async function generateWrapupsForAllPrograms(env, todayISO) {
  const programs = await env.DB.prepare('SELECT id FROM programs').all();
  const counts = {};
  for (const p of programs.results) counts[p.id] = await generateWrapupsForProgram(env, p.id, todayISO);
  return counts;
}
async function adminBackfillWrapups(env, cors) {
  const counts = await generateWrapupsForAllPrograms(env, localISODate(new Date()));
  return json({ ok: true, created: counts }, 200, cors);
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

      if (seg[0] === 'program' && seg[2] === 'feed' && !seg[3] && method === 'GET') return handleFeed(request, env, cors, seg[1]);
      if (seg[0] === 'program' && seg[2] === 'feed' && seg[3] === 'high-five' && method === 'POST') return handleHighFive(request, env, cors, seg[1]);
      if (seg[0] === 'program' && seg[2] === 'feed' && seg[3] === 'comments' && !seg[4] && method === 'POST') return handleCommentPost(request, env, cors, seg[1]);
      if (seg[0] === 'program' && seg[2] === 'feed' && seg[3] === 'comments' && seg[4] && method === 'DELETE') return handleCommentDelete(request, env, cors, seg[1], seg[4]);

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
      if (seg[0] === 'admin' && seg[1] === 'wrapups' && seg[2] === 'backfill' && method === 'POST') return adminBackfillWrapups(env, cors);

      if (seg[0] === 'admin' && seg[1] === 'activity-types' && !seg[2] && method === 'GET') return adminListActivityTypes(env, cors);
      if (seg[0] === 'admin' && seg[1] === 'activity-types' && !seg[2] && method === 'POST') return adminCreateActivityType(request, env, cors);
      if (seg[0] === 'admin' && seg[1] === 'activity-types' && seg[2] && method === 'PUT') return adminUpdateActivityType(request, env, cors, seg[2]);

      return json({ error: 'Not found' }, 404, cors);
    } catch (err) {
      return json({ error: String(err && err.message || err) }, 500, cors);
    }
  },

  // Cron fires at both 16:00 and 17:00 UTC on Mondays so that exactly one of the two is 18:00 in
  // Europe/Madrid whether or not summer time is in effect; the other hour returns immediately.
  async scheduled(event, env, ctx) {
    const hour = Number(new Intl.DateTimeFormat('en-GB', { timeZone: WRAPUP_TIMEZONE, hour: 'numeric', hour12: false }).format(new Date()));
    if (hour !== 18) return;
    ctx.waitUntil(generateWrapupsForAllPrograms(env, localISODate(new Date())));
  },
};
