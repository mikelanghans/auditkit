import { cn } from "@/lib/utils";

const styles: Record<string, string> = {
  critical: "bg-sev-critical/15 text-sev-critical border-sev-critical/30",
  high: "bg-sev-high/15 text-sev-high border-sev-high/40",
  medium: "bg-sev-medium/20 text-[oklch(0.45_0.12_80)] border-sev-medium/50",
  low: "bg-sev-low/15 text-sev-low border-sev-low/40",
};

export function SeverityBadge({ severity }: { severity: string }) {
  const label = severity.charAt(0).toUpperCase() + severity.slice(1);
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium tracking-normal",
        styles[severity] ?? styles.medium,
      )}
      title={`Severity: ${label} — how serious this issue would be if it failed`}
    >
      <span className="text-muted-foreground font-normal">Severity:</span>
      {label}
    </span>
  );
}
