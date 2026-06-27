
ALTER TABLE public.clients ADD COLUMN IF NOT EXISTS uses_ai_features boolean NOT NULL DEFAULT false;

UPDATE public.clients SET uses_ai_features = true WHERE has_agentic_features = true;

INSERT INTO public.checklist_items (category, checklist_key, title, severity, sort_order, what_to_look_for, is_active)
VALUES
  ('AI Service Continuity','ai_fallback_exists','A fallback exists if the primary AI provider is unavailable','high',301,'Identify the core feature(s) depending on the AI provider. Confirm there is a defined fallback behavior — cached response, simplified non-AI version, or secondary provider — rather than a hard failure.',true),
  ('AI Service Continuity','ai_model_deprecation_monitored','Model deprecation is monitored, not discovered by a broken feature','medium',302,'Check whether the model version is hardcoded. Confirm there is a process for monitoring the provider''s deprecation notices.',true),
  ('AI Service Continuity','ai_data_minimized','Data sent to the AI provider is documented and minimized','high',303,'Review every API call to the AI provider. Confirm only necessary fields are sent, not full user records by default. Confirm this is documented somewhere.',true),
  ('AI Service Continuity','ai_provider_outage_plan','There is a written plan for AI provider long-term unavailability','medium',304,'Ask whether a written contingency plan exists for the AI provider becoming unavailable for an extended period or ceasing operation. Confirm it covers what would break and what users would be told.',true),
  ('AI Service Continuity','ai_data_backed_up_independently','Core user data is backed up independently of the AI provider','critical',305,'Confirm user data and AI-generated content are persisted in the app''s own database, not solely accessible through a live call to the AI provider.',true),
  ('AI Service Continuity','ai_backup_restore_tested','Backup and restore process is tested','critical',306,'Confirm database backups are enabled. Confirm a test restore has actually been performed, not just assumed to work.',true)
ON CONFLICT (checklist_key) DO UPDATE SET
  category = EXCLUDED.category,
  title = EXCLUDED.title,
  severity = EXCLUDED.severity,
  sort_order = EXCLUDED.sort_order,
  what_to_look_for = EXCLUDED.what_to_look_for,
  is_active = true;
