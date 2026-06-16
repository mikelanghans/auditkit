export function SeverityBadge({ severity }: { severity: string }) {
  const label = severity.charAt(0).toUpperCase() + severity.slice(1);
  return (
    <span className="text-xs text-muted-foreground" title={`Severity: ${label}`}>
      Severity: {label}
    </span>
  );
}
