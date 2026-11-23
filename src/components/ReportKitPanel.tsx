import { useEffect, useMemo, useState } from "react";
import { Check, Copy, Download, FileImage, FileText, Moon, Network, Sun } from "lucide-react";
import { generateMarkdownReport } from "../api";
import { buildMatrixSvg, downloadPngFromSvg, downloadSvgFile } from "../exportMatrix";
import { buildZoneMapSvg } from "../exportZoneMap";
import { pick, translateSla, type Language } from "../i18n";
import { sanitizeFilename } from "../security";
import type { AuditProject, MatrixReport } from "../types";

interface ReportKitPanelProps {
  lang: Language;
  audit: AuditProject;
  report: MatrixReport;
  onExportJson: () => void;
}

function buildEnglishMarkdown(audit: AuditProject, report: MatrixReport): string {
  const n = report.summary.matrixSize;
  const fw =
    audit.config.framework === "iso27001"
      ? "ISO/IEC 27001:2022"
      : audit.config.framework === "nistCsf"
        ? "NIST CSF 2.0"
        : audit.config.framework === "owaspTop10"
          ? "OWASP Top 10:2025"
          : "CIS Controls v8";

  const openItems = report.items.filter((i) => i.status === "open");
  const lines: string[] = [
    `# Risk Management Report — ${audit.name}`,
    "",
    `- **Organization:** ${audit.client}`,
    `- **Auditor:** ${audit.auditor}`,
    `- **Date:** ${audit.date}`,
    `- **Methodology:** ${n}×${n} Matrix · ${fw}`,
    "",
    "## 1. Current Risk vs. Residual Risk (Remediation Plan)",
    "",
    "| Metric | Current Risk | Residual Risk (Post-Remediation) |",
    "| :--- | :---: | :---: |",
    `| Open exposures | ${report.summary.openRiskPairs} | ${report.summary.residualOpenPairs} |`,
    `| Critical risks | **${report.summary.criticalCount}** | **${report.summary.residualCriticalCount}** |`,
    `| High risks | ${report.summary.highCount} | ${report.summary.residualHighCount} |`,
    `| Average score (1–${report.summary.maxScore}) | ${report.summary.currentAvgScore.toFixed(1)} | ${report.summary.residualAvgScore.toFixed(1)} |`,
    `| Estimated total risk reduction | — | **-${report.summary.riskReductionPct.toFixed(1)}%** |`,
    "",
    `## 2. Impact vs. Likelihood Matrix (${n}×${n})`,
    "",
    `| Impact \\ Likelihood | ${Array.from({ length: n }, (_, i) => `L${i + 1}`).join(" | ")} |`,
    `| :--- | ${Array.from({ length: n }, () => ":---:").join(" | ")} |`,
  ];

  for (let imp = n; imp >= 1; imp--) {
    const counts = Array.from({ length: n }, (_, i) => {
      const c = report.cells.find((x) => x.impact === imp && x.likelihood === i + 1)?.count ?? 0;
      return c > 0 ? `**${c}**` : "·";
    });
    lines.push(`| **I${imp}** | ${counts.join(" | ")} |`);
  }

  lines.push(
    "",
    "## 3. Prioritized Remediation Plan (SLA & Controls)",
    "",
    "| # | CVE | Asset | Level | SLA | Score | Control | Basis / Note |",
    "| :---: | :--- | :--- | :---: | :---: | :---: | :--- | :--- |",
  );

  openItems.forEach((item, idx) => {
    const note = item.isCalibrated
      ? item.auditorNote
        ? `Calibrated: ${item.auditorNote}`
        : "Auditor calibrated"
      : "Automatic suggestion";
    lines.push(
      `| ${idx + 1} | \`${item.cveId}\` | ${item.assetName} | **${item.riskLevel.toUpperCase()}** | ${translateSla("en", item.slaWindow)} | ${item.riskScore}/${item.maxScore} | ${item.grcControl} | ${note} |`,
    );
  });

  if (openItems.length > 0) {
    const counts = new Map<string, number>();
    openItems.forEach((i) => counts.set(i.grcControl, (counts.get(i.grcControl) ?? 0) + 1));
    const ranked = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
    lines.push(
      "",
      `## 4. Gap Concentration (${fw})`,
      "",
      "| Control / Category | Findings | % of Total |",
      "| :--- | :---: | :---: |",
    );
    ranked.forEach(([ctrl, cnt]) => {
      const pct = ((cnt / openItems.length) * 100).toFixed(1);
      lines.push(`| ${ctrl} | **${cnt}** | ${pct}% |`);
    });
  }

  return lines.join("\n");
}

export function ReportKitPanel({
  lang,
  audit,
  report,
  onExportJson,
}: ReportKitPanelProps) {
  const [previewTheme, setPreviewTheme] = useState<"light" | "dark">("light");
  const [markdown, setMarkdown] = useState("");
  const [copied, setCopied] = useState(false);

  const svgString = useMemo(
    () => buildMatrixSvg(audit, report, previewTheme, lang),
    [audit, report, previewTheme, lang],
  );
  const svgPreviewSrc = useMemo(
    () => `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svgString)}`,
    [svgString],
  );
  const zoneSvgString = useMemo(
    () => buildZoneMapSvg(audit, report, previewTheme, lang),
    [audit, report, previewTheme, lang],
  );
  const zonePreviewSrc = useMemo(
    () => `data:image/svg+xml;charset=utf-8,${encodeURIComponent(zoneSvgString)}`,
    [zoneSvgString],
  );

  const safeSlug = sanitizeFilename(audit.name, "audit");

  useEffect(() => {
    if (lang === "en") {
      setMarkdown(buildEnglishMarkdown(audit, report));
    } else {
      generateMarkdownReport(audit).then(setMarkdown);
    }
  }, [audit, report, lang]);

  async function handleCopyMd() {
    await navigator.clipboard.writeText(markdown);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function handleDownloadMd() {
    const blob = new Blob([markdown], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${safeSlug}-${lang === "en" ? "grc-report" : "informe-grc"}.md`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-6 max-w-5xl">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-[#F25C2A]">
            {pick(lang, "Paso 05 · Entregables de Documentación", "Step 05 · Report Deliverables")}
          </p>
          <h2 className="mt-1 text-2xl font-bold tracking-tight text-[#F2DFC8]">
            {pick(lang, "Report Kit listo para tu Informe Final", "Report Kit ready for your Final Report")}
          </h2>
          <p className="mt-1 text-sm text-[#8C93A3]">
            {pick(
              lang,
              "Exporta la matriz y el mapa en alta resolución (con fondo blanco para Word/PDF o fondo oscuro para presentaciones) y las tablas GRC con tus criterios.",
              "Export the matrix and zone map in high resolution (light background for Word/PDF or dark for slides) along with executive GRC tables.",
            )}
          </p>
        </div>

        <button
          type="button"
          onClick={onExportJson}
          className="inline-flex items-center gap-1.5 rounded-lg border border-[#343A49] bg-[#21252F] px-3.5 py-2 text-xs font-semibold text-[#F2DFC8] transition hover:border-[#F25C2A]"
        >
          <Download className="h-3.5 w-3.5 text-[#F25C2A]" />
          {pick(lang, "Guardar proyecto (.secimpact.json)", "Save project (.secimpact.json)")}
        </button>
      </div>

      {/* Vista previa segura de Matriz */}
      <div className="rounded-xl border border-[#2C313E] bg-[#21252F] p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <FileImage className="h-4 w-4 text-[#F25C2A]" />
            <h3 className="text-sm font-bold text-[#F2DFC8]">
              {pick(lang, "Imagen de Matriz", "Matrix Image")} ({report.summary.matrixSize}×{report.summary.matrixSize})
            </h3>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="inline-flex rounded-lg border border-[#313644] bg-[#15171D] p-0.5">
              <button
                type="button"
                onClick={() => setPreviewTheme("light")}
                className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition ${
                  previewTheme === "light"
                    ? "bg-[#F2DFC8] text-[#15171D]"
                    : "text-[#8C93A3] hover:text-[#F2DFC8]"
                }`}
              >
                <Sun className="h-3.5 w-3.5" /> {pick(lang, "Fondo Claro (Word/PDF)", "Light (Word/PDF)")}
              </button>
              <button
                type="button"
                onClick={() => setPreviewTheme("dark")}
                className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition ${
                  previewTheme === "dark"
                    ? "bg-[#F25C2A] text-white"
                    : "text-[#8C93A3] hover:text-[#F2DFC8]"
                }`}
              >
                <Moon className="h-3.5 w-3.5" /> {pick(lang, "Oscuro", "Dark")}
              </button>
            </div>

            <button
              type="button"
              onClick={() =>
                downloadPngFromSvg(svgString, `${safeSlug}-matrix-${previewTheme}`)
              }
              className="inline-flex items-center gap-1.5 rounded-lg bg-[#F25C2A] px-3.5 py-1.5 text-xs font-semibold text-white transition hover:bg-[#ff6d3d]"
            >
              <Download className="h-3.5 w-3.5" /> {pick(lang, "Descargar PNG (2x)", "Download PNG (2x)")}
            </button>
            <button
              type="button"
              onClick={() =>
                downloadSvgFile(svgString, `${safeSlug}-matrix-${previewTheme}`)
              }
              className="inline-flex items-center gap-1.5 rounded-lg border border-[#343A49] bg-[#181B22] px-3 py-1.5 text-xs font-medium text-[#F2DFC8] transition hover:border-[#F25C2A]"
            >
              SVG
            </button>
          </div>
        </div>

        <div className="flex justify-center overflow-x-auto rounded-lg border border-[#2C313E] bg-[#15171D] p-4">
          <img
            src={svgPreviewSrc}
            alt="Impact Matrix"
            className="max-w-full h-auto rounded"
          />
        </div>
      </div>

      {/* Vista previa segura del Mapa de Exposición por Zonas */}
      <div className="rounded-xl border border-[#2C313E] bg-[#21252F] p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Network className="h-4 w-4 text-[#F25C2A]" />
            <h3 className="text-sm font-bold text-[#F2DFC8]">
              {pick(lang, "Mapa de Exposición por Zonas", "Zone Exposure Map")} (
              {previewTheme === "light" ? pick(lang, "Claro", "Light") : pick(lang, "Oscuro", "Dark")})
            </h3>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() =>
                downloadPngFromSvg(zoneSvgString, `${safeSlug}-zone-map-${previewTheme}`)
              }
              className="inline-flex items-center gap-1.5 rounded-lg bg-[#F25C2A] px-3.5 py-1.5 text-xs font-semibold text-white transition hover:bg-[#ff6d3d]"
            >
              <Download className="h-3.5 w-3.5" /> {pick(lang, "Descargar PNG (2x)", "Download PNG (2x)")}
            </button>
            <button
              type="button"
              onClick={() =>
                downloadSvgFile(zoneSvgString, `${safeSlug}-zone-map-${previewTheme}`)
              }
              className="inline-flex items-center gap-1.5 rounded-lg border border-[#343A49] bg-[#181B22] px-3 py-1.5 text-xs font-medium text-[#F2DFC8] transition hover:border-[#F25C2A]"
            >
              SVG
            </button>
          </div>
        </div>

        <div className="flex justify-center overflow-x-auto rounded-lg border border-[#2C313E] bg-[#15171D] p-4">
          <img
            src={zonePreviewSrc}
            alt="Zone Exposure Map"
            className="max-w-full h-auto rounded"
          />
        </div>
      </div>

      {/* Reporte Markdown GRC */}
      <div className="rounded-xl border border-[#2C313E] bg-[#21252F] p-5 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <FileText className="h-4 w-4 text-[#F25C2A]" />
            <h3 className="text-sm font-bold text-[#F2DFC8]">
              {pick(lang, "Tablas & Resumen Ejecutivo (Markdown)", "Tables & Executive Summary (Markdown)")}
            </h3>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleCopyMd}
              className="inline-flex items-center gap-1.5 rounded-lg border border-[#343A49] bg-[#181B22] px-3 py-1.5 text-xs font-medium text-[#F2DFC8] transition hover:border-[#F25C2A]"
            >
              {copied ? (
                <>
                  <Check className="h-3.5 w-3.5 text-emerald-400" /> {pick(lang, "Copiado", "Copied")}
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5" /> {pick(lang, "Copiar Markdown", "Copy Markdown")}
                </>
              )}
            </button>
            <button
              type="button"
              onClick={handleDownloadMd}
              className="inline-flex items-center gap-1.5 rounded-lg bg-[#F2DFC8] px-3.5 py-1.5 text-xs font-semibold text-[#15171D] transition hover:bg-white"
            >
              <Download className="h-3.5 w-3.5" /> {pick(lang, "Descargar .md", "Download .md")}
            </button>
          </div>
        </div>

        <pre className="max-h-80 overflow-auto rounded-lg border border-[#2C313E] bg-[#15171D] p-4 font-mono text-xs leading-relaxed text-[#D4D8E1] whitespace-pre-wrap">
          {markdown}
        </pre>
      </div>
    </div>
  );
}
