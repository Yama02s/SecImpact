import { useState } from "react";
import { Check, Flame, GripVertical } from "lucide-react";
import { pick, type Language } from "../i18n";
import type { MatrixCell, RiskItem, RiskLevel } from "../types";

interface MatrixCanvasProps {
  lang: Language;
  matrixSize: number;
  cells: MatrixCell[];
  items: RiskItem[];
  selectedItemId: string | null;
  selectedCell: { impact: number; likelihood: number } | null;
  onSelectCell: (cell: { impact: number; likelihood: number } | null) => void;
  onSelectItem: (item: RiskItem) => void;
  onDropItemOnCell: (itemId: string, impact: number, likelihood: number) => void;
}

function cellPalette(level: RiskLevel, hasItems: boolean, isDragOver: boolean): string {
  if (isDragOver) {
    return "bg-[#F25C2A]/25 border-[#F25C2A] ring-2 ring-[#F25C2A]/50";
  }
  switch (level) {
    case "critical":
      return hasItems
        ? "bg-[#F25C2A]/22 border-[#F25C2A]/70 hover:border-[#F25C2A]"
        : "bg-[#241E22] border-[#382729] hover:border-[#5C3535]";
    case "high":
      return hasItems
        ? "bg-[#D97A34]/20 border-[#D97A34]/65 hover:border-[#E88B38]"
        : "bg-[#232022] border-[#352D28] hover:border-[#544133]";
    case "medium":
      return hasItems
        ? "bg-[#C2A35B]/18 border-[#C2A35B]/55 hover:border-[#D9B45B]"
        : "bg-[#212124] border-[#313134] hover:border-[#4B4739]";
    case "low":
      return hasItems
        ? "bg-[#4D8B74]/20 border-[#4D8B74]/55 hover:border-[#5FA68C]"
        : "bg-[#1E2226] border-[#2A3136] hover:border-[#394A48]";
  }
}

export function MatrixCanvas({
  lang,
  matrixSize,
  cells,
  items,
  selectedItemId,
  selectedCell,
  onSelectCell,
  onSelectItem,
  onDropItemOnCell,
}: MatrixCanvasProps) {
  const [dragOverKey, setDragOverKey] = useState<string | null>(null);

  const impacts = Array.from({ length: matrixSize }, (_, i) => matrixSize - i);
  const likelihoods = Array.from({ length: matrixSize }, (_, i) => i + 1);
  const openItems = items.filter((i) => i.status === "open");

  const getCell = (impact: number, likelihood: number) =>
    cells.find((c) => c.impact === impact && c.likelihood === likelihood);

  return (
    <div className="rounded-xl border border-[#2C313E] bg-[#21252F] p-5">
      <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-[#F25C2A]">
            {pick(lang, "Calibración Interactiva · Drag & Drop", "Interactive Calibration · Drag & Drop")}
          </p>
          <h2 className="mt-0.5 text-lg font-bold tracking-tight text-[#F2DFC8]">
            {pick(lang, "Matriz de Impacto vs. Probabilidad", "Impact vs. Likelihood Matrix")} ({matrixSize}×{matrixSize})
          </h2>
          <p className="text-xs text-[#8C93A3]">
            {pick(
              lang,
              "Arrastra cualquier CVE entre celdas para ajustar el riesgo según tu criterio de auditoría, o haz clic en un hallazgo para abrir el inspector.",
              "Drag any CVE between cells to adjust risk using your auditor judgment, or click a finding to open the inspector.",
            )}
          </p>
        </div>

        {selectedCell && (
          <button
            type="button"
            onClick={() => onSelectCell(null)}
            className="rounded-md border border-[#F25C2A]/50 bg-[#F25C2A]/15 px-3 py-1.5 text-xs font-medium text-[#F2DFC8] transition hover:bg-[#F25C2A]/25"
          >
            {pick(lang, "Mostrar todos", "Show all")} (I{selectedCell.impact} × {pick(lang, "P", "L")}{selectedCell.likelihood})
          </button>
        )}
      </div>

      <div className="overflow-x-auto">
        <div className="min-w-[600px]">
          <div
            className="grid gap-2"
            style={{
              gridTemplateColumns: `88px repeat(${matrixSize}, minmax(0, 1fr))`,
            }}
          >
            {/* Header esquina */}
            <div className="flex items-end justify-end pr-2 pb-1 font-mono text-[10px] uppercase tracking-wider text-[#6E7687]">
              I ↑ / P →
            </div>
            {likelihoods.map((l) => (
              <div
                key={`lh-${l}`}
                className="pb-1 text-center font-mono text-[11px] font-semibold uppercase tracking-wider text-[#949BAA]"
              >
                {pick(lang, "Prob.", "Like.")} {l}
              </div>
            ))}

            {/* Filas */}
            {impacts.map((impact) => (
              <div key={`row-${impact}`} className="contents">
                <div className="flex items-center justify-end pr-2 font-mono text-[11px] font-semibold uppercase tracking-wider text-[#F2DFC8]/85">
                  Imp. {impact}
                </div>

                {likelihoods.map((likelihood) => {
                  const key = `${impact}-${likelihood}`;
                  const cell = getCell(impact, likelihood);
                  const cellItems = openItems.filter(
                    (it) => it.impact === impact && it.likelihood === likelihood,
                  );
                  const isSelected =
                    selectedCell?.impact === impact &&
                    selectedCell?.likelihood === likelihood;
                  const isDragOver = dragOverKey === key;

                  return (
                    <div
                      key={key}
                      onClick={() =>
                        onSelectCell(isSelected ? null : { impact, likelihood })
                      }
                      onDragOver={(e) => {
                        e.preventDefault();
                        if (dragOverKey !== key) setDragOverKey(key);
                      }}
                      onDragLeave={() => {
                        if (dragOverKey === key) setDragOverKey(null);
                      }}
                      onDrop={(e) => {
                        e.preventDefault();
                        setDragOverKey(null);
                        const draggedId = e.dataTransfer.getData("text/plain");
                        if (draggedId) {
                          onDropItemOnCell(draggedId, impact, likelihood);
                        }
                      }}
                      className={`min-h-[104px] cursor-pointer rounded-lg border p-2 transition-all flex flex-col justify-between ${cellPalette(
                        cell?.level ?? "low",
                        cellItems.length > 0,
                        isDragOver,
                      )} ${
                        isSelected
                          ? "ring-2 ring-[#F2DFC8]/70 ring-offset-2 ring-offset-[#1C1F26]"
                          : ""
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-[10px] text-[#949BAA]">
                          {impact * likelihood}
                        </span>
                        {cellItems.length > 0 && (
                          <span className="font-mono text-[11px] font-bold text-[#F2DFC8]">
                            {cellItems.length}
                          </span>
                        )}
                      </div>

                      <div className="mt-1.5 space-y-1">
                        {cellItems.map((it) => {
                          const active = selectedItemId === it.id;
                          return (
                            <div
                              key={it.id}
                              draggable
                              onDragStart={(e) => {
                                e.stopPropagation();
                                e.dataTransfer.setData("text/plain", it.id);
                              }}
                              onClick={(e) => {
                                e.stopPropagation();
                                onSelectItem(it);
                              }}
                              className={`group flex items-center gap-1 rounded px-1.5 py-1 text-[10px] font-medium transition cursor-grab active:cursor-grabbing ${
                                active
                                  ? "bg-[#F25C2A] text-white shadow"
                                  : "bg-[#15171D]/85 text-[#E6E1D9] hover:bg-[#15171D] border border-[#313644]"
                              }`}
                              title={`${it.cveId} — ${it.assetName} (arrastra para calibrar)`}
                            >
                              <GripVertical className="h-2.5 w-2.5 shrink-0 opacity-50" />
                              <span className="truncate font-mono">
                                {it.cveId}
                              </span>
                              {it.inKev && (
                                <Flame className="h-2.5 w-2.5 shrink-0 text-[#F25C2A] group-hover:text-white" />
                              )}
                              {it.isCalibrated && (
                                <span
                                  className="ml-auto h-1.5 w-1.5 shrink-0 rounded-full bg-[#F2DFC8]"
                                  title="Calibrado manualmente por el auditor"
                                />
                              )}
                              {it.inRemediationPlan && (
                                <Check
                                  className="h-2.5 w-2.5 shrink-0 text-emerald-400"
                                  aria-label="En plan de remediación"
                                />
                              )}
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Leyenda minimalista */}
      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-[#2C313E] pt-3 text-[11px] text-[#8C93A3]">
        <div className="flex flex-wrap items-center gap-4">
          <span className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-sm bg-[#F25C2A]" /> {pick(lang, "Crítico", "Critical")}
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-sm bg-[#D97A34]" /> {pick(lang, "Alto", "High")}
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-sm bg-[#C2A35B]" /> {pick(lang, "Medio", "Medium")}
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-sm bg-[#4D8B74]" /> {pick(lang, "Bajo", "Low")}
          </span>
        </div>
        <div className="flex items-center gap-3 text-[10px]">
          <span className="flex items-center gap-1">
            <span className="h-1.5 w-1.5 rounded-full bg-[#F2DFC8]" /> {pick(lang, "Calibrado por auditor", "Auditor calibrated")}
          </span>
          <span className="flex items-center gap-1">
            <Check className="h-3 w-3 text-emerald-400" /> {pick(lang, "En plan What-If", "In What-If plan")}
          </span>
        </div>
      </div>
    </div>
  );
}
