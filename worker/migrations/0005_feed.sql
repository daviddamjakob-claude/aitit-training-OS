-- Migration number: 0005 	 2026-08-30T09:00:00.000Z
-- The Feed tab: a shared, program-wide timeline of everyone's logged workouts, plus a weekly
-- wrap-up per athlete, with high fives and comments on both kinds of card.

-- One stored snapshot per athlete per finished week. Stored rather than computed on read so a
-- wrap-up stays a record of what the week looked like when it closed, and so it has a creation
-- time of its own to sit on. UNIQUE is what makes generation idempotent — the Monday cron and
-- the admin backfill run the same code and only ever fill gaps.
CREATE TABLE week_wrapups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  program_id INTEGER NOT NULL REFERENCES programs(id),
  athlete_id INTEGER NOT NULL REFERENCES athletes(id),
  week_id TEXT NOT NULL,
  week_start TEXT NOT NULL,
  week_end TEXT NOT NULL,
  phase_name TEXT NOT NULL,
  data TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(program_id, athlete_id, week_id)
);
CREATE INDEX idx_week_wrapups_program ON week_wrapups (program_id, week_id);

-- item_key identifies the card being reacted to across both kinds: 'w:<athleteId>:<workoutId>'
-- for a logged workout, 'r:<athleteId>:<weekId>' for a wrap-up. Workout ids are only unique
-- inside one athlete's state blob, which is why the owner is part of the key.
CREATE TABLE feed_high_fives (
  program_id INTEGER NOT NULL REFERENCES programs(id),
  item_key TEXT NOT NULL,
  actor_athlete_id INTEGER NOT NULL REFERENCES athletes(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (program_id, item_key, actor_athlete_id)
);

CREATE TABLE feed_comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  program_id INTEGER NOT NULL REFERENCES programs(id),
  item_key TEXT NOT NULL,
  author_athlete_id INTEGER NOT NULL REFERENCES athletes(id),
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_feed_comments_lookup ON feed_comments (program_id, item_key, created_at);
