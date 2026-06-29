import { CheckCircle2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { formatAgo } from "@/hooks/use-last-run";

/**
 * Tiny "Last run · 5m ago" line shown beneath a scan trigger so users can tell
 * at a glance that a scan has already been executed in this audit.
 */
export function LastRunBadge({
  ts,
  className,
  label = "Last run",
}: {
  ts: number | null | undefined;
  className?: string;
  label?: string;
}) {
  if (!ts) return null;
  const d = new Date(ts);
  const iso = d.toLocaleString();
  return (
    <span
      title={iso}
      className={cn(
        "inline-flex items-center gap-1 text-[10.5px] leading-none text-muted-foreground tabular-nums",
        className,
      )}
    >
      <CheckCircle2 className="h-3 w-3 text-status-pass" />
      {label} · {formatAgo(ts)}
    </span>
  );
}
