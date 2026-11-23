import { ArrowDownRight, TrendingDown } from "lucide-react";
import { pick, type Language } from "../i18n";
import type { MatrixSummary } from "../types";

interface ResidualRiskChartProps {
  lang: Language;
  summary: MatrixSummary;
}

export function ResidualRiskChart({ lang, summary }: ResidualRiskChartProps) {
  const maxAvg = Math.max(summary.maxScore, 1);
  const currentPct = Math.min(100, (summary.currentAvgScore / maxAvg) * 100);
  const residualPct = Math.min(100, (summary.residualAvgScore / maxAvg) * 100);

  return (
    <div className="rounded-xl border border-[#2C313E] bg-[#21252F] p-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-[#F25C2A]">
            {pick(lang, "Simulador What-If · Gobernanza", "What-If Simulator · Governance")}
          </p>
          <h3 className="mt-0.5 text-base font-bold text-[#F2DFC8]">
            {pick(lang, "Riesgo Actual vs. Riesgo Residual", "Current Risk vs. Residual Risk")}
          </h3>
          <p className="text-xs text-[#8C93A3]">
            {pick(
              lang,
              "Selecciona hallazgos en el plan de remediación (desde el inspector o tabla) para proyectar cuánto baja el riesgo corporativo.",
              "Select findings in the remediation plan (from the inspector or table) to project organizational risk reduction.",
            )}
          </p>
        </div>

        <div className="flex items-center gap-2 rounded-lg border border-[#F25C2A]/35 bg-[#181B22] px-3.5 py-2">
          <TrendingDown className="h-4 w-4 text-[#F25C2A]" />
          <div>
            <p className="text-[10px] uppercase tracking-wider text-[#8C93A3]">
              {pick(lang, "Reducción Estimada", "Estimated Reduction")}
            </p>
            <p className="font-mono text-lg font-bold leading-none text-[#F2DFC8]">
              -{summary.riskReductionPct.toFixed(1)}%
            </p>
          </div>
        </div>
      </div>

      <div className="mt-5 grid gap-4 md:grid-cols-2">
        <div className="rounded-lg border border-[#2D3240] bg-[#191C23] p-4">
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-[#F2DFC8]">
              {pick(lang, "Riesgo Actual", "Current Risk")}
            </span>
            <span className="font-mono text-[#F25C2A]">
              {pick(lang, "Prom.", "Avg.")} {summary.currentAvgScore.toFixed(1)}/{summary.maxScore}
            </span>
          </div>
          <div className="mt-2.5 h-2.5 w-full overflow-hidden rounded-full bg-[#262B36]">
            <div
              className="h-full rounded-full bg-[#F25C2A] transition-all duration-300"
              style={{ width: `${currentPct}%` }}
            />
          </div>
          <div className="mt-3 flex items-center justify-between text-[11px] text-[#8C93A3]">
            <span>{pick(lang, "Críticos", "Critical")}: <strong className="text-[#F2DFC8]">{summary.criticalCount}</strong></span>
            <span>{pick(lang, "Altos", "High")}: <strong className="text-[#F2DFC8]">{summary.highCount}</strong></span>
            <span>{pick(lang, "Abiertos", "Open")}: <strong className="text-[#F2DFC8]">{summary.openRiskPairs}</strong></span>
          </div>
        </div>

        <div className="rounded-lg border border-[#2D3240] bg-[#191C23] p-4">
          <div className="flex items-center justify-between text-xs">
            <span className="flex items-center gap-1.5 font-semibold text-[#F2DFC8]">
              <ArrowDownRight className="h-3.5 w-3.5 text-emerald-400" />
              {pick(lang, "Riesgo Residual (Post-Remediación)", "Residual Risk (Post-Remediation)")}
            </span>
            <span className="font-mono text-emerald-400">
              {pick(lang, "Prom.", "Avg.")} {summary.residualAvgScore.toFixed(1)}/{summary.maxScore}
            </span>
          </div>
          <div className="mt-2.5 h-2.5 w-full overflow-hidden rounded-full bg-[#262B36]">
            <div
              className="h-full rounded-full bg-emerald-500 transition-all duration-300"
              style={{ width: `${residualPct}%` }}
            />
          </div>
          <div className="mt-3 flex items-center justify-between text-[11px] text-[#8C93A3]">
            <span>{pick(lang, "Críticos", "Critical")}: <strong className="text-emerald-300">{summary.residualCriticalCount}</strong></span>
            <span>{pick(lang, "Altos", "High")}: <strong className="text-emerald-300">{summary.residualHighCount}</strong></span>
            <span>{pick(lang, "Restantes", "Remaining")}: <strong className="text-[#F2DFC8]">{summary.residualOpenPairs}</strong></span>
          </div>
        </div>
      </div>
    </div>
  );
}
