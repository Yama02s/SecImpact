import { CheckSquare, Flame, Loader2, RefreshCw, Square } from "lucide-react";
import { pick, translateSla, type Language } from "../i18n";
import type { RiskItem, RiskLevel } from "../types";

interface RiskTableProps {
  lang: Language;
  items: RiskItem[];
  selectedItemId: string | null;
  selectedCell: { impact: number; likelihood: number } | null;
  isEnriching?: boolean;
  onEnrichAll?: () => void;
  onSelectItem: (item: RiskItem) => void;
  onToggleRemediationPlan: (itemId: string) => void;
}

function levelBadge(lang: Language, level: RiskLevel) {
  const styles: Record<RiskLevel, string> = {
    critical: "bg-[#F25C2A]/20 text-[#FF7A4D] border-[#F25C2A]/50",
    high: "bg-[#D97A34]/20 text-[#F09D58] border-[#D97A34]/50",
    medium: "bg-[#C2A35B]/20 text-[#E5CA84] border-[#C2A35B]/50",
    low: "bg-[#4D8B74]/20 text-[#7BC2A6] border-[#4D8B74]/50",
  };
  const labels: Record<RiskLevel, string> = {
    critical: pick(lang, "Crítico", "Critical"),
    high: pick(lang, "Alto", "High"),
    medium: pick(lang, "Medio", "Medium"),
    low: pick(lang, "Bajo", "Low"),
  };
  return (
    <span
      className={`inline-flex items-center rounded border px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider ${styles[level]}`}
    >
      {labels[level]}
    </span>
  );
}

export function RiskTable({
  lang,
  items,
  selectedItemId,
  selectedCell,
  isEnriching,
  onEnrichAll,
  onSelectItem,
  onToggleRemediationPlan,
}: RiskTableProps) {
  const openItems = items.filter((i) => i.status === "open");
  const filtered = selectedCell
    ? openItems.filter(
        (i) =>
          i.impact === selectedCell.impact &&
          i.likelihood === selectedCell.likelihood,
      )
    : openItems;

  return (
    <div className="rounded-xl border border-[#2C313E] bg-[#21252F] p-5">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-base font-bold text-[#F2DFC8]">
            {pick(lang, "Hallazgos Priorizados & Controles GRC", "Prioritized Findings & GRC Controls")}
          </h3>
          <p className="text-xs text-[#8C93A3]">
            {selectedCell
              ? pick(
                  lang,
                  `${filtered.length} hallazgo(s) en Impacto ${selectedCell.impact} × Probabilidad ${selectedCell.likelihood}`,
                  `${filtered.length} finding(s) at Impact ${selectedCell.impact} × Likelihood ${selectedCell.likelihood}`,
                )
              : pick(
                  lang,
                  "Haz clic en una fila para calibrar su impacto o editar su control GRC.",
                  "Click a row to calibrate its impact or edit its assigned GRC control.",
                )}
          </p>
        </div>

        {onEnrichAll && openItems.length > 0 && (
          <button
            type="button"
            disabled={isEnriching}
            onClick={onEnrichAll}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[#343A49] bg-[#181B22] px-3 py-1.5 text-xs font-semibold text-[#F2DFC8] transition hover:border-[#F25C2A] disabled:opacity-55"
          >
            {isEnriching ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin text-[#F25C2A]" />
            ) : (
              <RefreshCw className="h-3.5 w-3.5 text-[#F25C2A]" />
            )}
            {isEnriching
              ? pick(lang, "Consultando NVD/EPSS/KEV...", "Querying NVD/EPSS/KEV...")
              : pick(lang, "Enriquecer CVEs (NVD / EPSS / KEV)", "Enrich CVEs (NVD / EPSS / KEV)")}
          </button>
        )}
      </div>

      {filtered.length === 0 ? (
        <div className="rounded-lg border border-dashed border-[#313644] py-8 text-center text-xs text-[#7D8596]">
          {pick(lang, "No hay hallazgos abiertos en este cuadrante.", "No open findings in this quadrant.")}
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-[#2C313E] font-mono text-[10px] uppercase tracking-wider text-[#7D8596]">
                <th className="py-2.5 pr-2 w-10">{pick(lang, "Plan", "Plan")}</th>
                <th className="py-2.5 px-2">{pick(lang, "Nivel / Score", "Level / Score")}</th>
                <th className="py-2.5 px-2">{pick(lang, "CVE & Activo", "CVE & Asset")}</th>
                <th className="py-2.5 px-2">{pick(lang, "Control GRC Sugerido", "Assigned GRC Control")}</th>
                <th className="py-2.5 pl-2 text-right">{pick(lang, "Criterio", "Basis")}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#282D39]">
              {filtered.map((item) => {
                const isSelected = selectedItemId === item.id;
                return (
                  <tr
                    key={item.id}
                    onClick={() => onSelectItem(item)}
                    className={`cursor-pointer transition ${
                      isSelected ? "bg-[#2A2F3C]" : "hover:bg-[#1C1F26]/70"
                    }`}
                  >
                    <td
                      className="py-3 pr-2 align-top"
                      onClick={(e) => {
                        e.stopPropagation();
                        onToggleRemediationPlan(item.id);
                      }}
                    >
                      <button
                        type="button"
                        className="text-[#8C93A3] hover:text-[#F25C2A]"
                      >
                        {item.inRemediationPlan ? (
                          <CheckSquare className="h-4 w-4 text-emerald-400" />
                        ) : (
                          <Square className="h-4 w-4" />
                        )}
                      </button>
                    </td>
                    <td className="py-3 px-2 align-top whitespace-nowrap">
                      <div className="flex flex-col gap-1">
                        {levelBadge(lang, item.riskLevel)}
                        <span className="font-mono text-[11px] text-[#949BAA]">
                          {item.riskScore}/{item.maxScore} · I{item.impact}×{pick(lang, "P", "L")}{item.likelihood}
                        </span>
                        <span className="text-[10px] text-[#8C93A3]">
                          SLA: {translateSla(lang, item.slaWindow)}
                        </span>
                      </div>
                    </td>
                    <td className="py-3 px-2 align-top">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-[#F2DFC8]">
                          {item.cveId}
                        </span>
                        {item.inKev && (
                          <span className="inline-flex items-center gap-0.5 rounded bg-[#F25C2A]/20 px-1.5 py-0.5 text-[10px] font-bold text-[#F25C2A]">
                            <Flame className="h-2.5 w-2.5" /> KEV
                          </span>
                        )}
                        <span className="font-mono text-[10px] text-[#7D8596]">
                          CVSS {item.cvss.toFixed(1)} · EPSS {item.epss.toFixed(0)}%
                        </span>
                      </div>
                      <p className="mt-0.5 font-medium text-[#E6E1D9]">
                        {item.title}
                      </p>
                      <p className="text-[11px] text-[#8C93A3]">
                        {item.assetName} ({item.exposure.toUpperCase()})
                      </p>
                    </td>
                    <td className="py-3 px-2 align-top text-[11px] text-[#B6BCC9] max-w-[230px]">
                      {item.grcControl}
                    </td>
                    <td className="py-3 pl-2 align-top text-right whitespace-nowrap">
                      {item.isCalibrated ? (
                        <span className="rounded bg-[#F2DFC8]/15 px-2 py-0.5 font-mono text-[10px] font-semibold text-[#F2DFC8]">
                          {pick(lang, "Calibrado", "Calibrated")}
                        </span>
                      ) : (
                        <span className="font-mono text-[10px] text-[#6E7687]">
                          {pick(lang, "Sugerido", "Suggested")}
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
