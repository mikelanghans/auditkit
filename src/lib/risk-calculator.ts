// Risk exposure calculator for a client profile.
// Estimates are illustrative, sourced from IBM Cost of a Data Breach 2024 and Verizon DBIR 2024.

export const INDUSTRY_OPTIONS = [
  "SaaS/Tech",
  "Healthcare",
  "Finance/Fintech",
  "E-commerce/Retail",
  "Education",
  "Professional Services",
  "Other",
] as const;

export const REVENUE_OPTIONS = [
  "Under $100K",
  "$100K-$500K",
  "$500K-$1M",
  "$1M-$5M",
  "Over $5M",
] as const;

export const USER_COUNT_OPTIONS = [
  "Under 1,000",
  "1,000-10,000",
  "10,000-100,000",
  "Over 100,000",
] as const;

export type Industry = (typeof INDUSTRY_OPTIONS)[number];
export type RevenueRange = (typeof REVENUE_OPTIONS)[number];
export type UserCountRange = (typeof USER_COUNT_OPTIONS)[number];

const COST_PER_RECORD: Record<Industry, number> = {
  Healthcare: 499,
  "Finance/Fintech": 336,
  "SaaS/Tech": 212,
  "E-commerce/Retail": 175,
  Education: 165,
  "Professional Services": 165,
  Other: 165,
};

const REVENUE_MIDPOINT: Record<RevenueRange, number> = {
  "Under $100K": 50_000,
  "$100K-$500K": 300_000,
  "$500K-$1M": 750_000,
  "$1M-$5M": 3_000_000,
  "Over $5M": 10_000_000,
};

const USER_MIDPOINT: Record<UserCountRange, number> = {
  "Under 1,000": 500,
  "1,000-10,000": 5_500,
  "10,000-100,000": 55_000,
  "Over 100,000": 250_000,
};

export type RegFlag = { name: string; note: string; low: number; high: number };

export type RiskExposure = {
  directBreachCost: number;
  downtimeCost: number;
  regulatory: { flags: RegFlag[]; low: number; high: number };
  churnCost: number;
  totalLow: number;
  totalHigh: number;
  midpoint: number;
  protectionRatio: number;
  inputs: {
    industry: Industry;
    revenue: RevenueRange;
    userCount: UserCountRange;
    revenueMidpoint: number;
    userMidpoint: number;
    costPerRecord: number;
  };
};

export const AUDIT_INVESTMENT = 5000;

export function calculateRiskExposure(
  industry: Industry,
  revenue: RevenueRange,
  userCount: UserCountRange,
): RiskExposure {
  const revenueMid = REVENUE_MIDPOINT[revenue];
  const userMid = USER_MIDPOINT[userCount];
  const costPerRecord = COST_PER_RECORD[industry];

  const directBreachCost = userMid * costPerRecord;
  const downtimeCost = (revenueMid / 365) * 3;
  const churnCost = revenueMid * 0.06;

  const flags: RegFlag[] = [];
  if (industry === "Healthcare") {
    flags.push({
      name: "HIPAA",
      note: "$100–$1,000 per violation (per affected record)",
      low: userMid * 100,
      high: userMid * 1_000,
    });
  }
  if (industry === "Finance/Fintech") {
    flags.push({
      name: "SOX & GLBA",
      note: "Baseline enforcement exposure",
      low: 100_000,
      high: 1_000_000,
    });
  }
  if (userMid >= 10_000) {
    flags.push({
      name: "CCPA",
      note: "$100–$750 per user per incident",
      low: userMid * 100,
      high: userMid * 750,
    });
  }
  flags.push({
    name: "GDPR",
    note: "Up to 4% of annual revenue if EU users are in scope",
    low: 0,
    high: Math.round(revenueMid * 0.04),
  });

  const regLow = flags.reduce((s, f) => s + f.low, 0);
  const regHigh = flags.reduce((s, f) => s + f.high, 0);

  const totalLow = directBreachCost + downtimeCost + regLow + churnCost;
  const totalHigh = directBreachCost + downtimeCost + regHigh + churnCost;
  const midpoint = (totalLow + totalHigh) / 2;

  return {
    directBreachCost,
    downtimeCost,
    regulatory: { flags, low: regLow, high: regHigh },
    churnCost,
    totalLow,
    totalHigh,
    midpoint,
    protectionRatio: midpoint / AUDIT_INVESTMENT,
    inputs: {
      industry,
      revenue,
      userCount,
      revenueMidpoint: revenueMid,
      userMidpoint: userMid,
      costPerRecord,
    },
  };
}

export function formatCurrency(n: number): string {
  if (!isFinite(n)) return "$0";
  const rounded = Math.round(n);
  if (rounded >= 1_000_000) return `$${(rounded / 1_000_000).toFixed(rounded >= 10_000_000 ? 1 : 2)}M`;
  if (rounded >= 10_000) return `$${Math.round(rounded / 1000)}K`;
  return `$${rounded.toLocaleString()}`;
}

export function formatRange(low: number, high: number): string {
  if (Math.round(low) === Math.round(high)) return formatCurrency(low);
  return `${formatCurrency(low)} – ${formatCurrency(high)}`;
}

export function isCompleteRiskInput(
  industry: string | null | undefined,
  revenue: string | null | undefined,
  userCount: string | null | undefined,
): industry is Industry {
  return (
    !!industry && (INDUSTRY_OPTIONS as readonly string[]).includes(industry) &&
    !!revenue && (REVENUE_OPTIONS as readonly string[]).includes(revenue) &&
    !!userCount && (USER_COUNT_OPTIONS as readonly string[]).includes(userCount)
  );
}
