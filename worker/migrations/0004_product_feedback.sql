-- Migration number: 0004 	 2026-07-28T19:56:00.000Z
-- Product feedback filed from the athlete app's feedback modal, read back in the Admin Center.
-- The table was originally created ad-hoc against the remote D1 and never recorded as a
-- migration; this file backfills it so a fresh database reproduces the deployed schema.

CREATE TABLE product_feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  athlete_id INTEGER NOT NULL REFERENCES athletes(id),
  feedback_text TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
