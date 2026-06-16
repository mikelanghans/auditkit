import { cn } from "@/lib/utils";

const styles: Record<string, string> = {
  critical: "bg-sev-critical/15 text-sev-critical border-sev-critical/30",
  high: "bg-sev-high/15 text-sev-high border-sev-high/40",
  medium: "bg-sev-medium/20 text-[oklch(0.45_0.12_80)] border-sev-medium/50",
  low: "bg-sev-low/15 text-sev-low border-sev-low/40",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium uppercase tracking-wide",
        styles[severity] ?? styles.medium,
      )}
    >
      {severity}
    </span>
  );
}
