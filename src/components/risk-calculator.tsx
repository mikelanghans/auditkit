import { useMemo, useState, useEffect } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Card } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { supabase } from "@/integrations/supabase/client";
import { toast } from "sonner";
import {
  INDUSTRY_OPTIONS,
  REVENUE_OPTIONS,
  USER_COUNT_OPTIONS,
  calculateRiskExposure,
  formatCurrency,
  formatRange,
  isCompleteRiskInput,
  AUDIT_INVESTMENT,
  type Industry,
  type RevenueRange,
  type UserCountRange,
} from "@/lib/risk-calculator";
import { ShieldAlert } from "lucide-react";

type Props = {
  clientId: string;
  industry: string | null;
  annualRevenueRange: string | null;
  userCountRange: string | null;
};

export function RiskCalculator({ clientId, industry, annualRevenueRange, userCountRange }: Props) {
  const [ind, setInd] = useState<string>(industry ?? "");
  const [rev, setRev] = useState<string>(annualRevenueRange ?? "");
  const [usr, setUsr] = useState<string>(userCountRange ?? "");
  const qc = useQueryClient();

  useEffect(() => { setInd(industry ?? ""); }, [industry]);
  useEffect(() => { setRev(annualRevenueRange ?? ""); }, [annualRevenueRange]);
  useEffect(() => { setUsr(userCountRange ?? ""); }, [userCountRange]);

  const dirty = ind !== (industry ?? "") || rev !== (annualRevenueRange ?? "") || usr !== (userCountRange ?? "");

  const save = useMutation({
    mutationFn: async () => {
      const { error } = await supabase
        .from("clients")
        .update({
          industry: ind || null,
          annual_revenue_range: rev || null,
          user_count_range: usr || null,
        } as any)
        .eq("id", clientId);
      if (error) throw error;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["client", clientId] });
      toast.success("Risk profile saved");
    },
    onError: (e: any) => toast.error(e.message),
  });

  const exposure = useMemo(() => {
    if (!isCompleteRiskInput(ind, rev, usr)) return null;
    return calculateRiskExposure(ind as Industry, rev as RevenueRange, usr as UserCountRange);
  }, [ind, rev, usr]);

  return (
    <section>
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          <ShieldAlert className="h-5 w-5 text-navy" /> Risk Calculator
        </h2>
        {dirty && (
          <Button size="sm" onClick={() => save.mutate()} disabled={save.isPending} className="bg-navy text-navy-foreground hover:bg-navy/90">
            Save
          </Button>
        )}
      </div>
      <Card className="p-4 space-y-4">
        <div className="grid gap-3 md:grid-cols-3">
          <SelectField label="Industry" value={ind} onChange={setInd} options={INDUSTRY_OPTIONS as readonly string[]} placeholder="Select industry" />
          <SelectField label="Approximate Annual Revenue" value={rev} onChange={setRev} options={REVENUE_OPTIONS as readonly string[]} placeholder="Select revenue range" />
          <SelectField label="Approximate Registered Users" value={usr} onChange={setUsr} options={USER_COUNT_OPTIONS as readonly string[]} placeholder="Select user range" />
        </div>

        {exposure && (
          <div className="rounded-lg border border-border bg-muted/30 p-4 space-y-3">
            <div className="text-xs uppercase tracking-widest text-muted-foreground">Risk Exposure</div>
            <ul className="divide-y divide-border">
              <ExposureRow
                title="Direct breach cost"
                detail={`${exposure.inputs.userMidpoint.toLocaleString()} est. records × $${exposure.inputs.costPerRecord}/record (${exposure.inputs.industry})`}
                value={formatCurrency(exposure.directBreachCost)}
              />
              <ExposureRow
                title="Revenue at risk from downtime"
                detail={`${formatCurrency(exposure.inputs.revenueMidpoint)} annual ÷ 365 × 3 days`}
                value={formatCurrency(exposure.downtimeCost)}
              />
              <ExposureRow
                title="Regulatory exposure"
                detail={
                  <ul className="mt-1 space-y-0.5">
                    {exposure.regulatory.flags.map((f) => (
                      <li key={f.name} className="text-xs">
                        <span className="font-medium text-foreground">{f.name}:</span> {f.note} · <span className="tabular-nums">{formatRange(f.low, f.high)}</span>
                      </li>
                    ))}
                  </ul>
                }
                value={formatRange(exposure.regulatory.low, exposure.regulatory.high)}
              />
              <ExposureRow
                title="Estimated customer churn cost"
                detail={`${formatCurrency(exposure.inputs.revenueMidpoint)} annual × 6% post-breach churn`}
                value={formatCurrency(exposure.churnCost)}
              />
            </ul>

            <div className="pt-3 border-t border-border flex items-baseline justify-between">
              <span className="text-sm font-semibold">Total estimated exposure</span>
              <span className="text-lg font-semibold tabular-nums text-status-fail">
                {formatRange(exposure.totalLow, exposure.totalHigh)}
              </span>
            </div>

            <div className="text-xs text-muted-foreground bg-background rounded px-3 py-2 border border-border">
              <span className="font-medium text-foreground">Audit investment:</span> ${AUDIT_INVESTMENT.toLocaleString()}
              {" | "}
              <span className="font-medium text-foreground">Estimated exposure:</span> {formatRange(exposure.totalLow, exposure.totalHigh)}
              {" | "}
              <span className="font-medium text-foreground">Protection ratio:</span> {exposure.protectionRatio.toFixed(1)}x
            </div>
          </div>
        )}

        <p className="text-[11px] text-muted-foreground leading-relaxed">
          Estimates based on IBM Cost of a Data Breach Report 2024 and Verizon DBIR 2024. Actual costs vary by breach type, jurisdiction, and response. This is not a legal or financial assessment.
        </p>
      </Card>
    </section>
  );
}

function SelectField({
  label, value, onChange, options, placeholder,
}: {
  label: string; value: string; onChange: (v: string) => void; options: readonly string[]; placeholder: string;
}) {
  return (
    <div className="space-y-1.5">
      <Label>{label}</Label>
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger><SelectValue placeholder={placeholder} /></SelectTrigger>
        <SelectContent>
          {options.map((o) => <SelectItem key={o} value={o}>{o}</SelectItem>)}
        </SelectContent>
      </Select>
    </div>
  );
}

function ExposureRow({ title, detail, value }: { title: string; detail: React.ReactNode; value: string }) {
  return (
    <li className="py-2 flex items-start justify-between gap-4">
      <div className="min-w-0">
        <div className="text-sm font-medium">{title}</div>
        <div className="text-xs text-muted-foreground">{detail}</div>
      </div>
      <div className="text-sm font-semibold tabular-nums shrink-0">{value}</div>
    </li>
  );
}
