import { useState } from "react";
import { Bug, Flame, Plus, Trash2 } from "lucide-react";
import { pick, type Language } from "../i18n";
import type { Asset, Finding } from "../types";

interface FindingsPanelProps {
  lang: Language;
  assets: Asset[];
  findings: Finding[];
  onAddFinding: (finding: Finding) => void;
  onDeleteFinding: (id: string) => void;
}

export function FindingsPanel({
  lang,
  assets,
  findings,
  onAddFinding,
  onDeleteFinding,
}: FindingsPanelProps) {
  const [cveId, setCveId] = useState("");
  const [title, setTitle] = useState("");
  const [cvss, setCvss] = useState(7.5);
  const [epss, setEpss] = useState(25.0);
  const [inKev, setInKev] = useState(false);
  const [selectedAssets, setSelectedAssets] = useState<string[]>([]);
  const [remediation, setRemediation] = useState("");

  function toggleAssetSelection(id: string) {
    setSelectedAssets((prev) =>
      prev.includes(id) ? prev.filter((a) => a !== id) : [...prev, id],
    );
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!cveId.trim() || !title.trim() || selectedAssets.length === 0) return;

    onAddFinding({
      id: `find-${Date.now()}`,
      cveId: cveId.trim().toUpperCase(),
      title: title.trim(),
      description: "",
      cvss,
      epss,
      inKev,
      status: "open",
      assetIds: selectedAssets,
      remediation:
        remediation.trim() ||
        pick(lang, "Aplicar parche oficial del fabricante.", "Apply official vendor patch."),
    });

    setCveId("");
    setTitle("");
    setRemediation("");
    setInKev(false);
    setSelectedAssets([]);
  }

  return (
    <div className="grid gap-6 lg:grid-cols-[360px_1fr]">
      <form
        onSubmit={handleSubmit}
        className="rounded-xl border border-[#2C313E] bg-[#21252F] p-5 space-y-4 h-fit"
      >
        <div className="flex items-center gap-2 text-sm font-bold text-[#F2DFC8]">
          <Plus className="h-4 w-4 text-[#F25C2A]" />
          {pick(lang, "Registrar CVE / Hallazgo", "Register CVE / Finding")}
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-xs font-medium text-[#8C93A3] mb-1">
              CVE ID *
            </label>
            <input
              value={cveId}
              onChange={(e) => setCveId(e.target.value)}
              placeholder="CVE-2025-12345"
              className="w-full rounded-lg border border-[#313644] bg-[#15171D] px-3 py-2 font-mono text-xs text-[#E6E1D9] focus:border-[#F25C2A] focus:outline-none"
              required
            />
          </div>
          <div className="flex items-end pb-1.5">
            <label className="flex cursor-pointer items-center gap-2 text-xs font-medium text-[#E6E1D9]">
              <input
                type="checkbox"
                checked={inKev}
                onChange={(e) => setInKev(e.target.checked)}
                className="h-4 w-4 accent-[#F25C2A]"
              />
              {pick(lang, "En CISA KEV", "In CISA KEV")}
            </label>
          </div>
        </div>

        <div>
          <label className="block text-xs font-medium text-[#8C93A3] mb-1">
            {pick(lang, "Título del hallazgo *", "Finding title *")}
          </label>
          <input
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder={pick(lang, "Ej. RCE en servicio web expuesto", "e.g. RCE on exposed web service")}
            className="w-full rounded-lg border border-[#313644] bg-[#15171D] px-3 py-2 text-xs text-[#E6E1D9] focus:border-[#F25C2A] focus:outline-none"
            required
          />
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-xs font-medium text-[#8C93A3] mb-1">
              CVSS (0.0 – 10.0)
            </label>
            <input
              type="number"
              step="0.1"
              min={0}
              max={10}
              value={cvss}
              onChange={(e) => setCvss(Number(e.target.value))}
              className="w-full rounded-lg border border-[#313644] bg-[#15171D] px-3 py-2 font-mono text-xs text-[#E6E1D9] focus:border-[#F25C2A] focus:outline-none"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-[#8C93A3] mb-1">
              EPSS (0 – 100%)
            </label>
            <input
              type="number"
              step="0.1"
              min={0}
              max={100}
              value={epss}
              onChange={(e) => setEpss(Number(e.target.value))}
              className="w-full rounded-lg border border-[#313644] bg-[#15171D] px-3 py-2 font-mono text-xs text-[#E6E1D9] focus:border-[#F25C2A] focus:outline-none"
            />
          </div>
        </div>

        <div>
          <label className="block text-xs font-medium text-[#8C93A3] mb-1.5">
            {pick(lang, "Activos afectados *", "Affected assets *")}
          </label>
          <div className="max-h-36 space-y-1.5 overflow-y-auto rounded-lg border border-[#313644] bg-[#15171D] p-2.5">
            {assets.map((asset) => (
              <label
                key={asset.id}
                className="flex cursor-pointer items-center gap-2 text-xs text-[#E6E1D9] hover:text-[#F2DFC8]"
              >
                <input
                  type="checkbox"
                  checked={selectedAssets.includes(asset.id)}
                  onChange={() => toggleAssetSelection(asset.id)}
                  className="accent-[#F25C2A]"
                />
                <span>{asset.name}</span>
                <span className="text-[#6E7687]">({asset.exposure})</span>
              </label>
            ))}
          </div>
        </div>

        <div>
          <label className="block text-xs font-medium text-[#8C93A3] mb-1">
            {pick(lang, "Remediación recomendada", "Recommended remediation")}
          </label>
          <textarea
            rows={2}
            value={remediation}
            onChange={(e) => setRemediation(e.target.value)}
            placeholder={pick(lang, "Ej. Actualizar paquete y segmentar puerto...", "e.g. Upgrade package and segment port...")}
            className="w-full rounded-lg border border-[#313644] bg-[#15171D] px-3 py-2 text-xs text-[#E6E1D9] focus:border-[#F25C2A] focus:outline-none"
          />
        </div>

        <button
          type="submit"
          disabled={selectedAssets.length === 0}
          className="w-full rounded-lg bg-[#F25C2A] px-4 py-2 text-xs font-semibold text-white transition hover:bg-[#ff6d3d] disabled:cursor-not-allowed disabled:opacity-40"
        >
          {pick(lang, "Agregar Hallazgo", "Add Finding")}
        </button>
      </form>

      <div className="rounded-xl border border-[#2C313E] bg-[#21252F] p-5">
        <h3 className="mb-4 flex items-center gap-2 text-sm font-bold text-[#F2DFC8]">
          <Bug className="h-4 w-4 text-[#F25C2A]" />
          {pick(lang, "CVEs Registrados", "Registered CVEs")} ({findings.length})
        </h3>
        <div className="space-y-2">
          {findings.map((finding) => (
            <div
              key={finding.id}
              className="flex items-start justify-between gap-3 rounded-lg border border-[#2B303D] bg-[#181B22] px-4 py-3"
            >
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs font-bold text-[#F2DFC8]">
                    {finding.cveId}
                  </span>
                  <span className="rounded bg-[#262B36] px-1.5 py-0.5 font-mono text-[10px] text-[#949BAA]">
                    CVSS {finding.cvss.toFixed(1)}
                  </span>
                  <span className="rounded bg-[#262B36] px-1.5 py-0.5 font-mono text-[10px] text-[#949BAA]">
                    EPSS {finding.epss.toFixed(1)}%
                  </span>
                  {finding.inKev && (
                    <span className="inline-flex items-center gap-1 rounded bg-[#F25C2A]/20 px-1.5 py-0.5 text-[10px] font-bold text-[#F25C2A]">
                      <Flame className="h-2.5 w-2.5" /> KEV
                    </span>
                  )}
                </div>
                <p className="mt-1 text-sm font-semibold text-[#E6E1D9]">{finding.title}</p>
                <p className="mt-0.5 text-xs text-[#8C93A3]">
                  {pick(
                    lang,
                    `Afecta a ${finding.assetIds.length} activo(s)`,
                    `Affects ${finding.assetIds.length} asset(s)`,
                  )}{" "}
                  · {finding.remediation}
                </p>
              </div>
              <button
                type="button"
                onClick={() => onDeleteFinding(finding.id)}
                className="rounded-md p-2 text-[#6E7687] transition hover:bg-[#F25C2A]/15 hover:text-[#F25C2A]"
                title={pick(lang, "Eliminar CVE", "Delete CVE")}
              >
                <Trash2 className="h-4 w-4" />
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
