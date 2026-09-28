-- Separate migration: a newly added enum value cannot be used in the same
-- transaction that adds it.
--
-- Re-label scanner-written 'na' rows whose own notes say the check did not run
-- or could not be determined. Auditor-entered N/A (auto_scanned = false) is left alone.
UPDATE public.audit_findings
SET status = 'inconclusive'
WHERE status = 'na'
  AND auto_scanned = true
  AND notes ~* '(could not|couldn''t|not checked|not tested|not probed|not verified|inconclusive|probe failed|unexpected status|cannot verify|cannot fetch|review each write policy|could NOT be determined)';
