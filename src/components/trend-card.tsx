// How the scanner-checked items moved over time (phase 4.4). One line per
// state, one axis (item count), crosshair tooltip, legend plus end labels,
// and a table view. Colors were validated for colorblind separation in
// light and dark; "unverified" is a neutral dashed line, not a third hue.
import { useMemo, useState } from "react";
import { format } from "date-fns";
import { CartesianGrid, LabelList, Line, LineChart, XAxis, YAxis } from "recharts";
import { TrendingUp } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ChartContainer, ChartLegend, ChartLegendContent, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart";
import { useReportExtras } from "@/components/report-extras";
import { trendFromHistory, type TrendPoint } from "@/lib/report-model";

const config = {
  failing: { label: "Failing", theme: { light: "#d93a2b", dark: "#e2554d" } },
  passing: { label: "Passing", theme: { light: "#2a7fb8", dark: "#3d93cc" } },
  unverified: { label: "Unverified", theme: { light: "#6b7280", dark: "#9ca3af" } },
} satisfies ChartConfig;

export function TrendCard({ auditId }: { auditId: string }) {
  const extras = useReportExtras(auditId);
  const points = useMemo(() => trendFromHistory(extras.data?.runs ?? [], extras.data?.results ?? []), [extras.data]);
  if (extras.isLoading || points.length === 0) return null;
  return <TrendChart points={points} />;
}

export function TrendChart({ points }: { points: TrendPoint[] }) {
  const [asTable, setAsTable] = useState(false);
  const data = points.map((p) => ({ ...p, when: format(new Date(p.at), "MMM d"), whenFull: format(new Date(p.at), "PP p") }));
  const last = data.length - 1;
  // End labels: keep them at least ~14px apart so close values don't collide.
  const endOffset = useMemo(() => {
    const keys = ["failing", "passing", "unverified"] as const;
    const end = data[last];
    if (!end) return {} as Record<string, number>;
    const max = Math.max(1, ...data.flatMap((d) => keys.map((k) => d[k])));
    const pxPerUnit = 150 / max; // approximate plot height
    const ys = keys.map((k) => ({ k, y: -end[k] * pxPerUnit })).sort((a, b) => a.y - b.y);
    const out: Record<string, number> = {};
    let prev = -Infinity;
    for (const { k, y } of ys) {
      const placed = Math.max(y, prev + 14);
      out[k] = placed - y;
      prev = placed;
    }
    return out;
  }, [data, last]);
  return (    <Card className="p-4 space-y-3">
      <div className="flex items-center gap-2">
        <TrendingUp className="h-4 w-4 text-primary" />
        <h2 className="text-sm font-semibold">Scanner results over time</h2>
        <span className="text-xs text-muted-foreground">Items checked by scanners, after each run</span>
        <Button variant="ghost" size="sm" className="ml-auto h-7 text-xs" onClick={() => setAsTable(!asTable)}>
          {asTable ? "Show chart" : "Show table"}
        </Button>
      </div>
      {points.length === 1 && !asTable && (
        <p className="text-xs text-muted-foreground">One run so far: the trend appears from the second run.</p>
      )}
      {asTable ? (
        <table className="w-full text-xs">
          <thead>
            <tr className="text-left text-muted-foreground"><th className="py-1">Run</th><th>When</th><th>Failing</th><th>Passing</th><th>Couldn't verify</th></tr>
          </thead>
          <tbody>
            {data.map((p) => (
              <tr key={p.runId} className="border-t border-border/50">
                <td className="py-1">{p.label}</td>
                <td>{p.whenFull}</td>
                <td className="tabular-nums">{p.failing}</td>
                <td className="tabular-nums">{p.passing}</td>
                <td className="tabular-nums">{p.unverified}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <ChartContainer config={config} className="aspect-auto h-[220px] w-full">
          <LineChart data={data} margin={{ top: 8, right: 96, bottom: 0, left: 0 }} accessibilityLayer>
            <CartesianGrid vertical={false} strokeOpacity={0.4} />
            <XAxis dataKey="when" tickLine={false} axisLine={false} tickMargin={8} minTickGap={16} />
            <YAxis allowDecimals={false} tickLine={false} axisLine={false} width={28} />
            <ChartTooltip
              cursor
              content={<ChartTooltipContent indicator="line" labelFormatter={(_, payload) => payload?.[0]?.payload?.whenFull ?? ""} />}
            />
            <ChartLegend content={<ChartLegendContent />} />
            {(["failing", "passing", "unverified"] as const).map((k) => (
              <Line
                key={k}
                dataKey={k}
                type="monotone"
                stroke={`var(--color-${k})`}
                strokeWidth={2}
                strokeDasharray={k === "unverified" ? "5 4" : undefined}
                dot={{ r: 4, strokeWidth: 2, fill: `var(--color-${k})`, stroke: "var(--color-card)" }}
                activeDot={{ r: 5, strokeWidth: 2, fill: `var(--color-${k})`, stroke: "var(--color-card)" }}
                isAnimationActive={false}
              >
                <LabelList
                  dataKey={k}
                  position="right"
                  offset={10}
                  className="fill-foreground text-[11px]"
                  formatter={(v: number) => v}
                  content={(props: any) =>
                    props.index === last ? (
                      <text x={props.x + 10} y={props.y + (endOffset[k] ?? 0)} dy={4} className="fill-muted-foreground text-[11px]">
                        {config[k].label} {props.value}
                      </text>
                    ) : null
                  }
                />
              </Line>
            ))}
          </LineChart>
        </ChartContainer>
      )}
    </Card>
  );
}
