
function DependencyResultsPanel({ result }: { result: DepScanResult }) {
  const sevClass = (s: DepFindingSev) => {
    if (s === "critical") return "bg-status-fail/10 text-status-fail border-status-fail/40";
    if (s === "high") return "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/40";
    if (s === "medium") return "bg-status-na/10 text-status-na border-status-na/40";
    return "bg-muted text-muted-foreground border-border";
  };
  const rowClass = (s: DepFindingSev) => {
    if (s === "critical") return "bg-status-fail/5";
    if (s === "high") return "bg-amber-500/5";
    return "";
  };
  return (
    <Card className="p-4 border-l-4 border-l-amber-500/60">
      <div className="flex items-center gap-2 mb-3">
        <Package className="h-4 w-4 text-amber-600 dark:text-amber-400 shrink-0" />
        <div className="font-medium text-sm">Dependency scan — {result.repo}</div>
        <div className="ml-auto text-xs text-muted-foreground">
          {result.packagesScanned} scanned · {result.findings.length} flagged
        </div>
      </div>
      <div className="overflow-x-auto rounded-md border border-border">
        <table className="w-full text-sm">
          <thead className="bg-muted/50 text-xs uppercase tracking-wide text-muted-foreground">
            <tr>
              <th className="text-left px-3 py-2 font-medium">Package</th>
              <th className="text-left px-3 py-2 font-medium">Current</th>
              <th className="text-left px-3 py-2 font-medium">Latest</th>
              <th className="text-left px-3 py-2 font-medium">Severity</th>
              <th className="text-left px-3 py-2 font-medium">CVE / Reason</th>
            </tr>
          </thead>
          <tbody>
            {result.findings.map((f, i) => (
              <tr key={`${f.name}-${i}`} className={cn("border-t border-border", rowClass(f.severity))}>
                <td className="px-3 py-2 font-mono text-xs">{f.name}</td>
                <td className="px-3 py-2 font-mono text-xs">{f.current}</td>
                <td className="px-3 py-2 font-mono text-xs text-muted-foreground">{f.latest ?? "—"}</td>
                <td className="px-3 py-2">
                  <span className={cn("inline-flex items-center px-1.5 py-0.5 rounded border text-[10px] font-medium uppercase", sevClass(f.severity))}>
                    {f.severity}
                  </span>
                </td>
                <td className="px-3 py-2 text-xs">
                  {f.cve && (
                    <a
                      href={f.advisoryUrl ?? `https://nvd.nist.gov/vuln/detail/${f.cve}`}
                      target="_blank" rel="noreferrer"
                      className="inline-flex items-center gap-1 font-mono text-primary hover:underline"
                    >
                      {f.cve} <ExternalLink className="h-3 w-3" />
                    </a>
                  )}
                  <div className="text-muted-foreground">{f.reason}</div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

type DepFindingSev = DepScanResult["findings"][number]["severity"];
