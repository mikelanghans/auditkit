INSERT INTO public.checklist_items (category, title, severity, checklist_key, what_to_look_for, sort_order)
VALUES (
  'Infrastructure & Configuration',
  'Dependency vulnerabilities scanned',
  'high',
  'dep_vulns',
  'npm dependencies with known CVEs (especially critical or high severity) expose the app to publicly documented attacks. Check package.json against the npm advisory database and flag packages that are vulnerable or more than 2 major versions / 6 months out of date. Use the Scan Dependencies tool to auto-populate this item.',
  38
)
ON CONFLICT (checklist_key) DO UPDATE SET
  title = EXCLUDED.title,
  category = EXCLUDED.category,
  severity = EXCLUDED.severity,
  what_to_look_for = EXCLUDED.what_to_look_for;