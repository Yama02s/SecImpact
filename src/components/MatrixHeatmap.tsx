import type { MatrixCell, RiskLevel } from "../types";

interface MatrixHeatmapProps {
  cells: MatrixCell[];
  selectedCell: { impact: number; likelihood: number } | null;
  onSelectCell: (cell: { impact: number; likelihood: number } | null) => void;
}

const IMPACT_LABELS: Record<number, string> = {
  5: "5 · Catastrófico",
  4: "4 · Mayor",
  3: "3 · Moderado",
  2: "2 · Menor",
  1: "1 · Insignificante",
};

const LIKELIHOOD_LABELS: Record<number, string> = {
  1: "1 · Muy Baja",
  2: "2 · Baja",
  3: "3 · Media",
  4: "4 · Alta",
  5: "5 · Muy Alta",
};

function cellColorClass(level: RiskLevel, hasItems: boolean): string {
  switch (level) {
    case "critical":
      return hasItems
        ? "bg-rose-600/85 hover:bg-rose-500 border-rose-400/60 text-white shadow-lg shadow-rose-950/50"
        : "bg-rose-950/40 hover:bg-rose-950/60 border-rose-900/50 text-rose-300/60";
    case "high":
      return hasItems
        ? "bg-orange-500/80 hover:bg-orange-500 border-orange-300/60 text-white shadow-lg shadow-orange-950/50"
        : "bg-orange-950/35 hover:bg-orange-950/55 border-orange-900/40 text-orange-300/60";
    case "medium":
      return hasItems
        ? "bg-amber-500/75 hover:bg-amber-500 border-amber-300/60 text-slate-950 font-semibold"
        : "bg-amber-950/30 hover:bg-amber-950/50 border-amber-900/40 text-amber-300/60";
    case "low":
      return hasItems
        ? "bg-emerald-600/75 hover:bg-emerald-500 border-emerald-400/60 text-white"
        : "bg-emerald-950/30 hover:bg-emerald-950/50 border-emerald-900/40 text-emerald-300/60";
  }
}

export function MatrixHeatmap({
  cells,
  selectedCell,
  onSelectCell,
}: MatrixHeatmapProps) {
  const impacts = [5, 4, 3, 2, 1];
  const likelihoods = [1, 2, 3, 4, 5];

  const getCell = (impact: number, likelihood: number) =>
    cells.find((c) => c.impact === impact && c.likelihood === likelihood);

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-base font-semibold text-slate-100">
            Matriz de Impacto vs. Probabilidad (5×5)
          </h2>
          <p className="text-xs text-slate-400">
            Haz clic en cualquier cuadrante para filtrar los hallazgos abiertos en esa zona.
          </p>
        </div>

        {selectedCell && (
          <button
            type="button"
            onClick={() => onSelectCell(null)}
            className="rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-1 text-xs font-medium text-cyan-300 transition hover:bg-cyan-500/20"
          >
            Limpiar filtro (I:{selectedCell.impact} × P:{selectedCell.likelihood})
          </button>
        )}
      </div>

      <div className="overflow-x-auto">
        <div className="min-w-[540px]">
          <div className="grid grid-cols-[140px_repeat(5,minmax(0,1fr))] gap-2">
            {/* Encabezado vacío superior izquierdo */}
            <div className="flex items-end justify-end pr-2 pb-1 text-[11px] font-medium uppercase tracking-wider text-slate-500">
              Impacto ↑ / Prob. →
            </div>
            {likelihoods.map((l) => (
              <div
                key={`hdr-${l}`}
                className="pb-1 text-center text-xs font-medium text-slate-400"
              >
                {LIKELIHOOD_LABELS[l]}
              </div>
            ))}

            {/* Filas del Heatmap (Impacto 5 -> 1) */}
            {impacts.map((impact) => (
              <div key={`row-${impact}`} className="contents">
                <div className="flex items-center justify-end pr-2 text-xs font-medium text-slate-300">
                  {IMPACT_LABELS[impact]}
                </div>
                {likelihoods.map((likelihood) => {
                  const cell = getCell(impact, likelihood);
                  const count = cell?.count ?? 0;
                  const score = cell?.score ?? impact * likelihood;
                  const level = cell?.level ?? "low";
                  const isSelected =
                    selectedCell?.impact === impact &&
                    selectedCell?.likelihood === likelihood;

                  return (
                    <button
                      key={`cell-${impact}-${likelihood}`}
                      type="button"
                      onClick={() =>
                        onSelectCell(
                          isSelected ? null : { impact, likelihood },
                        )
                      }
                      className={`group relative flex h-20 flex-col items-center justify-center rounded-lg border transition-all ${cellColorClass(
                        level,
                        count > 0,
                      )} ${
                        isSelected
                          ? "ring-2 ring-cyan-400 ring-offset-2 ring-offset-slate-950 scale-[1.02]"
                          : ""
                      }`}
                      title={`Impacto ${impact} × Probabilidad ${likelihood} = Score ${score}/25 (${count} hallazgos)`}
                    >
                      <span className="text-2xl font-bold leading-none">
                        {count > 0 ? count : "·"}
                      </span>
                      <span className="mt-1 text-[10px] opacity-80">
                        Score {score}
                      </span>
                    </button>
                  );
                })}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Leyenda */}
      <div className="mt-4 flex flex-wrap items-center gap-4 border-t border-slate-800/80 pt-3 text-xs text-slate-400">
        <span className="flex items-center gap-1.5">
          <span className="h-3 w-3 rounded bg-rose-600" /> Crítico (16–25)
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-3 w-3 rounded bg-orange-500" /> Alto (10–15)
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-3 w-3 rounded bg-amber-500" /> Medio (5–9)
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-3 w-3 rounded bg-emerald-600" /> Bajo (1–4)
        </span>
      </div>
    </div>
  );
}
