import { useState } from "react";
import {
  ArrowRight,
  Cloud,
  Database,
  Download,
  Flame,
  Globe,
  Monitor,
  Network,
  Server,
  Shield,
} from "lucide-react";
import { downloadPngFromSvg, downloadSvgFile } from "../exportMatrix";
import { buildZoneMapSvg } from "../exportZoneMap";
import { pick, type Language } from "../i18n";
import { sanitizeFilename } from "../security";
import type {
  Asset,
  AssetType,
  AuditProject,
  Exposure,
  MatrixReport,
  RiskLevel,
} from "../types";

interface ZoneMapPanelProps {
  lang: Language;
  audit: AuditProject;
  report: MatrixReport;
  onChangeAssetExposure: (assetId: string, exposure: Exposure) => void;
}

const ZONES: {
  key: Exposure;
  step: string;
  title: string;
  subtitle: string;
  accent: string;
  borderAccent: string;
}[] = [
  {
    key: "internet",
    step: "01",
    title: "Internet / Perímetro",
    subtitle: "Superficie expuesta directamente",
    accent: "text-[#F25C2A]",
    borderAccent: "border-t-[#F25C2A]",
  },
  {
    key: "dmz",
    step: "02",
    title: "Zona DMZ",
    subtitle: "Servicios intermedios segmentados",
    accent: "text-[#D97A34]",
    borderAccent: "border-t-[#D97A34]",
  },
  {
    key: "internal",
    step: "03",
    title: "Red Interna / Core",
    subtitle: "Active Directory, DB y red privada",
    accent: "text-emerald-400",
    borderAccent: "border-t-[#4D8B74]",
  },
];

function AssetIcon({ type }: { type: AssetType }) {
  switch (type) {
    case "webApp":
      return <Globe className="h-4 w-4 text-[#F2DFC8]" />;
    case "database":
      return <Database className="h-4 w-4 text-[#F2DFC8]" />;
    case "activeDirectory":
      return <Shield className="h-4 w-4 text-[#F25C2A]" />;
    case "network":
      return <Network className="h-4 w-4 text-[#F2DFC8]" />;
    case "cloud":
      return <Cloud className="h-4 w-4 text-[#F2DFC8]" />;
    case "workstation":
      return <Monitor className="h-4 w-4 text-[#F2DFC8]" />;
    default:
      return <Server className="h-4 w-4 text-[#F2DFC8]" />;
  }
}

function riskBorderClass(level: RiskLevel | "none"): string {
  switch (level) {
    case "critical":
      return "border-[#F25C2A]/70 bg-[#261E22]";
    case "high":
      return "border-[#D97A34]/65 bg-[#252122]";
    case "medium":
      return "border-[#C2A35B]/55 bg-[#232326]";
    case "low":
      return "border-[#4D8B74]/55 bg-[#1F2427]";
    default:
      return "border-[#2D3240] bg-[#1D212A]";
  }
}

function riskBadge(lang: Language, level: RiskLevel | "none") {
  const styles: Record<RiskLevel | "none", string> = {
    critical: "bg-[#F25C2A] text-white",
    high: "bg-[#D97A34] text-white",
    medium: "bg-[#C2A35B] text-[#15171D]",
    low: "bg-[#4D8B74] text-white",
    none: "bg-[#2B303D] text-[#8C93A3]",
  };
  const labels: Record<RiskLevel | "none", string> = {
    critical: pick(lang, "Crítico", "Critical"),
    high: pick(lang, "Alto", "High"),
    medium: pick(lang, "Medio", "Medium"),
    low: pick(lang, "Bajo", "Low"),
    none: pick(lang, "Sin CVEs", "No CVEs"),
  };
  return (
    <span
      className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-bold uppercase ${styles[level]}`}
    >
      {labels[level]}
    </span>
  );
}

export function ZoneMapPanel({
  lang,
  audit,
  report,
  onChangeAssetExposure,
}: ZoneMapPanelProps) {
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);
  const safeSlug = sanitizeFilename(audit.name, "auditoria");

  function getAssetRiskSummary(assetId: string) {
    const items = report.items.filter(
      (i) => i.status === "open" && i.assetId === assetId,
    );
    const order: Record<RiskLevel, number> = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
    };
    let maxLevel: RiskLevel | "none" = "none";
    for (const it of items) {
      if (maxLevel === "none" || order[it.riskLevel] > order[maxLevel]) {
        maxLevel = it.riskLevel;
      }
    }
    return {
      items,
      maxLevel,
      kevCount: items.filter((i) => i.inKev).length,
    };
  }

  function handleExport(theme: "light" | "dark", format: "png" | "svg") {
    const svg = buildZoneMapSvg(audit, report, theme, lang);
    const filename = `${safeSlug}-mapa-zonas-${theme}`;
    if (format === "png") {
      downloadPngFromSvg(svg, filename);
    } else {
      downloadSvgFile(svg, filename);
    }
  }

  const selectedAsset: Asset | null =
    audit.assets.find((a) => a.id === selectedAssetId) ?? null;
  const selectedSummary = selectedAsset
    ? getAssetRiskSummary(selectedAsset.id)
    : null;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-[#F25C2A]">
            {pick(lang, "Paso 03 · Superficie de Ataque & Arquitectura", "Step 03 · Attack Surface & Architecture")}
          </p>
          <h2 className="mt-1 text-2xl font-bold tracking-tight text-[#F2DFC8]">
            {pick(lang, "Mapa de Exposición por Zonas", "Zone Exposure Map")}
          </h2>
          <p className="mt-1 text-xs text-[#8C93A3]">
            {pick(
              lang,
              "Visualiza cómo se distribuyen tus activos críticos desde el perímetro hacia la red interna. Puedes reasignar la zona de cualquier activo y exportar el diagrama para tu informe.",
              "Visualize how critical assets are distributed from the perimeter to the internal network. Reassign any asset's zone and export the diagram for your report.",
            )}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => handleExport("light", "png")}
            className="inline-flex items-center gap-1.5 rounded-lg bg-[#F25C2A] px-3.5 py-2 text-xs font-semibold text-white transition hover:bg-[#ff6d3d]"
          >
            <Download className="h-3.5 w-3.5" /> {pick(lang, "PNG Claro (Word/PDF)", "Light PNG (Word/PDF)")}
          </button>
          <button
            type="button"
            onClick={() => handleExport("dark", "png")}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[#343A49] bg-[#21252F] px-3 py-2 text-xs font-medium text-[#F2DFC8] transition hover:border-[#F25C2A]"
          >
            <Download className="h-3.5 w-3.5" /> {pick(lang, "PNG Oscuro", "Dark PNG")}
          </button>
          <button
            type="button"
            onClick={() => handleExport("light", "svg")}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[#343A49] bg-[#181B22] px-3 py-2 text-xs font-medium text-[#949BAA] transition hover:text-[#F2DFC8]"
          >
            SVG
          </button>
        </div>
      </div>

      {/* Flujo visual 3 Zonas */}
      <div className="grid gap-4 lg:grid-cols-3">
        {ZONES.map((zone, idx) => {
          const assets = audit.assets.filter((a) => a.exposure === zone.key);
          const zTitle =
            zone.key === "internet"
              ? pick(lang, "Internet / Perímetro", "Internet / Perimeter")
              : zone.key === "dmz"
                ? pick(lang, "Zona DMZ", "DMZ Zone")
                : pick(lang, "Red Interna / Core", "Internal Network / Core");
          const zSub =
            zone.key === "internet"
              ? pick(lang, "Superficie expuesta directamente", "Directly exposed surface")
              : zone.key === "dmz"
                ? pick(lang, "Servicios intermedios segmentados", "Segmented intermediate services")
                : pick(lang, "Active Directory, DB y red privada", "Active Directory, DB & private network");
          return (
            <div
              key={zone.key}
              className={`relative flex flex-col rounded-xl border border-[#2C313E] border-t-[3px] ${zone.borderAccent} bg-[#181B22] p-4`}
            >
              <div className="mb-3.5 flex items-center justify-between">
                <div>
                  <div className={`font-mono text-[10px] font-bold uppercase tracking-[0.16em] ${zone.accent}`}>
                    {zone.step} · {zTitle}
                  </div>
                  <p className="text-[11px] text-[#7D8596]">{zSub}</p>
                </div>
                <span className="rounded bg-[#232731] px-2 py-0.5 font-mono text-xs font-bold text-[#F2DFC8]">
                  {assets.length}
                </span>
              </div>

              {idx < 2 && (
                <div className="pointer-events-none hidden lg:flex absolute -right-3 top-1/2 z-10 -translate-y-1/2 h-6 w-6 items-center justify-center rounded-full border border-[#343A49] bg-[#15171D] text-[#8C93A3]">
                  <ArrowRight className="h-3.5 w-3.5" />
                </div>
              )}

              {assets.length === 0 ? (
                <div className="flex flex-1 items-center justify-center rounded-lg border border-dashed border-[#2B303D] py-10 text-xs text-[#636B7C]">
                  {pick(lang, "Sin activos en esta zona", "No assets in this zone")}
                </div>
              ) : (
                <div className="space-y-2.5">
                  {assets.map((asset) => {
                    const summary = getAssetRiskSummary(asset.id);
                    const isSelected = selectedAssetId === asset.id;
                    return (
                      <div
                        key={asset.id}
                        onClick={() =>
                          setSelectedAssetId(isSelected ? null : asset.id)
                        }
                        className={`cursor-pointer rounded-lg border p-3 transition ${riskBorderClass(
                          summary.maxLevel,
                        )} ${
                          isSelected
                            ? "ring-2 ring-[#F2DFC8]/70"
                            : "hover:border-[#F2DFC8]/40"
                        }`}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex items-center gap-2 min-w-0">
                            <AssetIcon type={asset.assetType} />
                            <p className="truncate text-sm font-semibold text-[#F2DFC8]">
                              {asset.name}
                            </p>
                          </div>
                          {riskBadge(lang, summary.maxLevel)}
                        </div>

                        <p className="mt-1 truncate font-mono text-[10px] text-[#8C93A3]">
                          {asset.host}
                        </p>

                        <div className="mt-2.5 flex items-center justify-between text-[11px] text-[#949BAA]">
                          <div className="flex items-center gap-2">
                            <span>
                              Crit.{" "}
                              <strong className="text-[#F2DFC8]">
                                {asset.criticality}/5
                              </strong>
                            </span>
                            <span>· {summary.items.length} CVE(s)</span>
                            {summary.kevCount > 0 && (
                              <span className="inline-flex items-center gap-0.5 text-[#F25C2A] font-bold">
                                <Flame className="h-3 w-3" /> KEV
                              </span>
                            )}
                          </div>

                          <select
                            value={asset.exposure}
                            onClick={(e) => e.stopPropagation()}
                            onChange={(e) =>
                              onChangeAssetExposure(
                                asset.id,
                                e.target.value as Exposure,
                              )
                            }
                            className="rounded border border-[#313644] bg-[#15171D] px-1.5 py-0.5 text-[10px] text-[#E6E1D9] focus:border-[#F25C2A] focus:outline-none"
                          >
                            <option value="internet">Internet</option>
                            <option value="dmz">DMZ</option>
                            <option value="internal">{pick(lang, "Interna", "Internal")}</option>
                          </select>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Detalle del activo seleccionado */}
      {selectedAsset && selectedSummary && (
        <div className="rounded-xl border border-[#2C313E] bg-[#21252F] p-5">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#2C313E] pb-3">
            <div>
              <h3 className="text-sm font-bold text-[#F2DFC8]">
                {selectedAsset.name} — Superficie y Hallazgos
              </h3>
              <p className="font-mono text-xs text-[#8C93A3]">
                {selectedAsset.host}
              </p>
            </div>
            <span className="font-mono text-xs text-[#8C93A3]">
              Criticidad {selectedAsset.criticality}/5 · {selectedSummary.items.length} CVE(s) abiertos
            </span>
          </div>

          {selectedSummary.items.length === 0 ? (
            <p className="mt-3 text-xs text-[#8C93A3]">
              Este activo aún no tiene CVEs vinculados. Puedes asociar hallazgos en <strong className="text-[#F2DFC8]">Inventario → CVEs / Hallazgos</strong>.
            </p>
          ) : (
            <div className="mt-3 grid gap-2 sm:grid-cols-2">
              {selectedSummary.items.map((it) => (
                <div
                  key={it.id}
                  className="flex items-center justify-between rounded-lg border border-[#2D3240] bg-[#181B22] px-3 py-2 text-xs"
                >
                  <div className="min-w-0 pr-2">
                    <span className="font-mono font-bold text-[#F2DFC8]">
                      {it.cveId}
                    </span>
                    <p className="truncate text-[11px] text-[#8C93A3]">
                      {it.title}
                    </p>
                  </div>
                  <span className="shrink-0 font-mono text-[11px] font-bold text-[#F25C2A]">
                    {it.riskScore}/{it.maxScore}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
