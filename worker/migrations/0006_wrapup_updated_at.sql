-- Migration number: 0006 	 2026-09-09T09:00:00.000Z
-- Athletes can refresh a week review the cron has posted (POST /program/:id/wrapups/:weekId)
-- from a button on that week, so a row can now change after it is created and needs a time of
-- its own for that. Existing rows count as last updated when created.
ALTER TABLE week_wrapups ADD COLUMN updated_at TEXT;
UPDATE week_wrapups SET updated_at = created_at WHERE updated_at IS NULL;
