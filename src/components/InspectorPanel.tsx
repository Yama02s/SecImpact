import { Flame, RotateCcw, ShieldCheck, Sliders, X } from "lucide-react";
import { GRC_CONTROLS_CATALOG } from "../grcCatalog";
import { pick, translateSla, type Language } from "../i18n";
import type { GrcFramework, RiskItem } from "../types";

interface InspectorPanelProps {
  lang: Language;
  item: RiskItem | null;
  matrixSize: number;
  framework: GrcFramework;
  onClose: () => void;
  onCalibrate: (
    itemId: string,
    impact: number,
    likelihood: number,
    note: string,
    customGrcControl?: string,
  ) => void;
  onResetCalibration: (itemId: string) => void;
  onToggleRemediationPlan: (itemId: string) => void;
}

export function InspectorPanel({
  lang,
  item,
  matrixSize,
  framework,
  onClose,
  onCalibrate,
  onResetCalibration,
  onToggleRemediationPlan,
}: InspectorPanelProps) {
  if (!item) {
    return (
      <aside className="hidden xl:flex w-[320px] shrink-0 flex-col items-center justify-center border-l border-[#2B2F3B] bg-[#181B22] p-6 text-center">
        <Sliders className="h-7 w-7 text-[#4B5263]" />
        <p className="mt-3 text-sm font-semibold text-[#F2DFC8]">
          {pick(lang, "Inspector de Criterio", "Auditor Inspector")}
        </p>
        <p className="mt-1.5 text-xs leading-relaxed text-[#7D8596]">
          {pick(
            lang,
            "Selecciona cualquier hallazgo en la matriz o la tabla para revisar la recomendación automática, ajustar el impacto según tu criterio y ver el control GRC sugerido.",
            "Select any finding in the matrix or table to review the automatic suggestion, calibrate impact/likelihood, and pick its GRC control.",
          )}
        </p>
      </aside>
    );
  }

  const levels = Array.from({ length: matrixSize }, (_, i) => i + 1);

  return (
    <aside className="flex w-[336px] shrink-0 flex-col border-l border-[#2B2F3B] bg-[#181B22] overflow-y-auto">
      <div className="flex items-start justify-between border-b border-[#262A35] px-5 py-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs font-bold text-[#F25C2A]">
              {item.cveId}
            </span>
            {item.inKev && (
              <span className="inline-flex items-center gap-1 rounded bg-[#F25C2A]/20 px-1.5 py-0.5 text-[10px] font-bold text-[#F25C2A]">
                <Flame className="h-3 w-3" /> KEV
              </span>
            )}
          </div>
          <h3 className="mt-1 text-sm font-bold leading-snug text-[#F2DFC8]">
            {item.title}
          </h3>
          <p className="mt-0.5 text-xs text-[#8C93A3]">
            {item.assetName} · {item.assetHost}
          </p>
          <p className="mt-1 font-mono text-[10px] uppercase tracking-wider text-[#F2DFC8]/80">
            {pick(lang, "Plazo SLA sugerido", "Suggested SLA")}: {translateSla(lang, item.slaWindow)}
          </p>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="rounded p-1 text-[#7D8596] hover:bg-[#232731] hover:text-[#F2DFC8]"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="space-y-5 p-5">
        <div className="rounded-lg border border-[#2C313E] bg-[#1F232C] p-3.5">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[#8C93A3]">
              {pick(lang, "Sugerencia Automática", "Automatic Suggestion")}
            </span>
            <span className="font-mono text-xs font-semibold text-[#F2DFC8]">
              I:{item.suggestedImpact} × {pick(lang, "P", "L")}:{item.suggestedLikelihood}
            </span>
          </div>
          <p className="mt-1.5 text-[11px] leading-relaxed text-[#9AA1B0]">
            {item.suggestionReason}
          </p>
        </div>

        <div className="space-y-3.5">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[#F25C2A]">
              {pick(lang, "Criterio del Auditor", "Auditor Judgment")}
            </span>
            {item.isCalibrated && (
              <button
                type="button"
                onClick={() => onResetCalibration(item.id)}
                className="inline-flex items-center gap-1 text-[11px] text-[#8C93A3] hover:text-[#F2DFC8]"
              >
                <RotateCcw className="h-3 w-3" /> {pick(lang, "Restaurar", "Reset")}
              </button>
            )}
          </div>

          <div>
            <label className="mb-1.5 block text-xs text-[#9AA1B0]">
              {pick(lang, "Impacto al Negocio (Eje Y)", "Business Impact (Y-Axis)")}: <strong className="text-[#F2DFC8]">{item.impact}/{matrixSize}</strong>
            </label>
            <div className="grid gap-1.5" style={{ gridTemplateColumns: `repeat(${matrixSize}, minmax(0, 1fr))` }}>
              {levels.map((v) => (
                <button
                  key={`imp-${v}`}
                  type="button"
                  onClick={() => onCalibrate(item.id, v, item.likelihood, item.auditorNote)}
                  className={`rounded-md py-1.5 font-mono text-xs font-bold transition ${
                    item.impact === v
                      ? "bg-[#F25C2A] text-white"
                      : "bg-[#232731] text-[#949BAA] hover:text-[#F2DFC8]"
                  }`}
                >
                  {v}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="mb-1.5 block text-xs text-[#9AA1B0]">
              {pick(lang, "Probabilidad de Explotación (Eje X)", "Exploitation Likelihood (X-Axis)")}: <strong className="text-[#F2DFC8]">{item.likelihood}/{matrixSize}</strong>
            </label>
            <div className="grid gap-1.5" style={{ gridTemplateColumns: `repeat(${matrixSize}, minmax(0, 1fr))` }}>
              {levels.map((v) => (
                <button
                  key={`lik-${v}`}
                  type="button"
                  onClick={() => onCalibrate(item.id, item.impact, v, item.auditorNote)}
                  className={`rounded-md py-1.5 font-mono text-xs font-bold transition ${
                    item.likelihood === v
                      ? "bg-[#F25C2A] text-white"
                      : "bg-[#232731] text-[#949BAA] hover:text-[#F2DFC8]"
                  }`}
                >
                  {v}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="mb-1.5 block text-xs text-[#9AA1B0]">
              {pick(lang, "Justificación de criterio (para el informe)", "Judgment justification (for report)")}
            </label>
            <textarea
              rows={3}
              value={item.auditorNote}
              onChange={(e) =>
                onCalibrate(item.id, item.impact, item.likelihood, e.target.value)
              }
              placeholder={pick(
                lang,
                "Ej. Ajustado por segmentación de red, WAF o criticidad real del negocio...",
                "e.g. Adjusted due to network segmentation, WAF, or actual business criticality...",
              )}
              className="w-full rounded-lg border border-[#313644] bg-[#15171D] px-3 py-2 text-xs text-[#E6E1D9] placeholder-[#5F6676] focus:border-[#F25C2A] focus:outline-none"
            />
          </div>
        </div>

        <div className="rounded-lg border border-[#2C313E] bg-[#1F232C] p-3.5 space-y-2">
          <div className="flex items-center justify-between">
            <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[#8C93A3]">
              {pick(lang, "Control GRC Asignado", "Assigned GRC Control")}
            </p>
            <span className="font-mono text-[10px] text-[#F25C2A]">
              {pick(lang, "Editable", "Editable")}
            </span>
          </div>
          <select
            value={item.grcControl}
            onChange={(e) =>
              onCalibrate(
                item.id,
                item.impact,
                item.likelihood,
                item.auditorNote,
                e.target.value,
              )
            }
            className="w-full rounded-md border border-[#313644] bg-[#15171D] px-2.5 py-2 text-xs text-[#F2DFC8] focus:border-[#F25C2A] focus:outline-none"
          >
            {!GRC_CONTROLS_CATALOG[framework].includes(item.grcControl) && (
              <option value={item.grcControl}>{item.grcControl}</option>
            )}
            {GRC_CONTROLS_CATALOG[framework].map((ctrl) => (
              <option key={ctrl} value={ctrl}>
                {ctrl}
              </option>
            ))}
          </select>
        </div>

        <button
          type="button"
          onClick={() => onToggleRemediationPlan(item.id)}
          className={`flex w-full items-center justify-center gap-2 rounded-lg border px-4 py-2.5 text-xs font-semibold transition ${
            item.inRemediationPlan
              ? "border-emerald-500/50 bg-emerald-500/15 text-emerald-300"
              : "border-[#313644] bg-[#232731] text-[#F2DFC8] hover:border-[#F25C2A]"
          }`}
        >
          <ShieldCheck className="h-4 w-4" />
          {item.inRemediationPlan
            ? pick(lang, "Incluido en Plan de Remediación", "Included in Remediation Plan")
            : pick(lang, "Incluir en Simulación Residual", "Include in Residual Simulation")}
        </button>

        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[#7D8596]">
            {pick(lang, "Remediación Técnica", "Technical Remediation")}
          </p>
          <p className="mt-1 text-xs leading-relaxed text-[#B6BCC9]">
            {item.remediation || "—"}
          </p>
        </div>
      </div>
    </aside>
  );
}
