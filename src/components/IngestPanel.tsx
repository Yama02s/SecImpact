import { useRef, useState } from "react";
import { FileCode2, Layers, Loader2, UploadCloud } from "lucide-react";
import { importNmapXml, lookupCve } from "../api";
import { pick, type Language } from "../i18n";
import type { Asset, AuditProject, Finding } from "../types";

interface IngestPanelProps {
  lang: Language;
  audit: AuditProject;
  onImportBatch: (newAssets: Asset[], newFindings: Finding[]) => void;
  onGoToMatrix: () => void;
  onGoToInventory: () => void;
}

export function IngestPanel({
  lang,
  audit,
  onImportBatch,
  onGoToMatrix,
  onGoToInventory,
}: IngestPanelProps) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [pasteText, setPasteText] = useState("");
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);

  function ensureTargetAsset(): { assetId: string; newAsset?: Asset } {
    if (audit.assets.length > 0) {
      return { assetId: audit.assets[0].id };
    }
    const autoAsset: Asset = {
      id: `asset-${Date.now()}`,
      name: "Infraestructura Auditada",
      host: "Por clasificar",
      assetType: "server",
      exposure: "internet",
      criticality: 4,
      owner: "Sin asignar",
    };
    return { assetId: autoAsset.id, newAsset: autoAsset };
  }

  function handleFile(file: File) {
    const reader = new FileReader();
    reader.onload = async () => {
      const content = String(reader.result || "");

      // 1. Nmap XML (.xml)
      if (file.name.toLowerCase().endsWith(".xml") || content.includes("<nmaprun")) {
        setIsProcessing(true);
        setStatusMsg("Procesando reporte Nmap XML...");
        try {
          const result = await importNmapXml(content);
          if (result.hostsParsed === 0) {
            setIsProcessing(false);
            setStatusMsg("No se encontraron hosts activos en el archivo Nmap XML.");
            return;
          }

          // Enriquecer CVEs detectados por scripts NSE (ej. vulners / vuln)
          const existingCves = new Set(audit.findings.map((f) => f.cveId.toUpperCase()));
          const enrichedFindings: Finding[] = [];
          const freshFindings = result.findings.filter(
            (f) => !existingCves.has(f.cveId.toUpperCase()),
          );

          for (let i = 0; i < freshFindings.length; i++) {
            const f = freshFindings[i];
            setStatusMsg(
              `Nmap: ${result.hostsParsed} host(s) · Enriqueciendo CVE (${i + 1}/${freshFindings.length}): ${f.cveId}...`,
            );
            const enriched = await lookupCve(f.cveId);
            enrichedFindings.push({
              ...f,
              title: enriched?.found ? enriched.title : f.title,
              description: enriched?.description || f.description,
              cvss: enriched?.found ? enriched.cvss : f.cvss,
              epss: enriched ? enriched.epss : f.epss,
              inKev: enriched ? enriched.inKev : f.inKev,
              cwe: enriched?.cwe || "",
            });
          }

          onImportBatch(result.assets, enrichedFindings);
          setIsProcessing(false);
          setStatusMsg(
            `Nmap importado: ${result.hostsParsed} activo(s), ${result.openPortsTotal} puerto(s) abierto(s) y ${enrichedFindings.length} CVE(s).`,
          );

          if (enrichedFindings.length > 0) {
            onGoToMatrix();
          } else {
            onGoToInventory();
          }
          return;
        } catch (err) {
          setIsProcessing(false);
          setStatusMsg(`Error importando Nmap XML: ${String(err)}`);
          return;
        }
      }

      // 2. Nuclei JSONL (.jsonl o .json por líneas)
      const { assetId, newAsset } = ensureTargetAsset();
      const lines = content.split(/\r?\n/).filter((l) => l.trim().startsWith("{"));
      if (lines.length > 0) {
        const imported: Finding[] = [];
        for (const line of lines) {
          try {
            const obj = JSON.parse(line);
            const info = obj.info ?? {};
            const sev = String(info.severity ?? "medium").toLowerCase();
            const cvss =
              sev === "critical" ? 9.5 : sev === "high" ? 7.8 : sev === "medium" ? 5.5 : 3.1;
            const cve =
              info?.classification?.["cve-id"]?.[0] ||
              obj["template-id"] ||
              `HALLAZGO-${imported.length + 1}`;
            imported.push({
              id: `nuc-${Date.now()}-${imported.length}`,
              cveId: String(cve).toUpperCase(),
              title: String(info.name || obj["template-id"] || "Hallazgo importado"),
              description: String(info.description || ""),
              cvss,
              epss: sev === "critical" ? 72 : sev === "high" ? 35 : 8,
              inKev: false,
              status: "open",
              assetIds: [assetId],
              remediation: "Revisar hallazgo y aplicar mitigación correspondiente.",
            });
          } catch {
            // ignorar línea no válida
          }
        }
        if (imported.length > 0) {
          onImportBatch(newAsset ? [newAsset] : [], imported);
          setStatusMsg(`Se importaron ${imported.length} hallazgos desde Nuclei.`);
          onGoToMatrix();
          return;
        }
      }

      setStatusMsg(
        "Formato no reconocido. Usa un reporte Nmap (.xml), Nuclei (.jsonl) o pega tus CVEs abajo.",
      );
    };
    reader.readAsText(file);
  }

  async function handlePasteCves() {
    const matches = pasteText.match(/CVE-\d{4}-\d{4,7}/gi);
    if (!matches || matches.length === 0) {
      setStatusMsg("No se detectaron códigos CVE (ej. CVE-2024-21887).");
      return;
    }
    const existingCves = new Set(audit.findings.map((f) => f.cveId.toUpperCase()));
    const unique = Array.from(new Set(matches.map((m) => m.toUpperCase()))).filter(
      (cve) => !existingCves.has(cve),
    );

    if (unique.length === 0) {
      setStatusMsg("Todos los CVEs pegados ya estaban registrados en esta auditoría.");
      return;
    }

    const { assetId, newAsset } = ensureTargetAsset();
    setIsProcessing(true);
    const newFindings: Finding[] = [];

    for (let idx = 0; idx < unique.length; idx++) {
      const cve = unique[idx];
      setStatusMsg(`Consultando NVD, EPSS y KEV (${idx + 1}/${unique.length}): ${cve}...`);
      const enriched = await lookupCve(cve);

      newFindings.push({
        id: `paste-${Date.now()}-${idx}`,
        cveId: cve,
        title: enriched?.found
          ? enriched.title
          : `Vulnerabilidad detectada (${cve})`,
        description: enriched?.description || "Cargado desde notas de auditoría.",
        cvss: enriched?.found ? enriched.cvss : 7.5,
        epss: enriched ? enriched.epss : 25.0,
        inKev: enriched ? enriched.inKev : false,
        status: "open",
        assetIds: [assetId],
        remediation: "Evaluar parche oficial y calibrar impacto según contexto.",
        cwe: enriched?.cwe || "",
      });
    }

    setIsProcessing(false);
    onImportBatch(newAsset ? [newAsset] : [], newFindings);
    setPasteText("");
    setStatusMsg(`Se agregaron y enriquecieron ${newFindings.length} CVE(s).`);
    onGoToMatrix();
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-[#F25C2A]">
          {pick(lang, "Paso 01 · Ingesta de Hallazgos", "Step 01 · Findings Ingest")}
        </p>
        <h2 className="mt-1 text-2xl font-bold tracking-tight text-[#F2DFC8]">
          {pick(lang, "Importa los resultados de tu auditoría", "Import your audit findings")}
        </h2>
        <p className="mt-1 text-sm text-[#8C93A3]">
          {pick(
            lang,
            "Arrastra reportes de Nmap o Nuclei, pega tus CVEs detectados o registra tu infraestructura manualmente.",
            "Drop Nmap or Nuclei reports, paste detected CVEs, or register your infrastructure manually.",
          )}
        </p>
      </div>

      {/* Dropzone de escáneres */}
      <div
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => {
          e.preventDefault();
          const f = e.dataTransfer.files?.[0];
          if (f && !isProcessing) handleFile(f);
        }}
        onClick={() => !isProcessing && fileRef.current?.click()}
        className="group cursor-pointer rounded-xl border-2 border-dashed border-[#343A49] bg-[#21252F]/70 p-10 text-center transition hover:border-[#F25C2A] hover:bg-[#232731]"
      >
        <input
          ref={fileRef}
          type="file"
          accept=".xml,.jsonl,.json"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) handleFile(f);
            e.target.value = "";
          }}
          className="hidden"
        />
        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full border border-[#F25C2A]/40 bg-[#F25C2A]/10 text-[#F25C2A] transition group-hover:scale-105">
          {isProcessing ? (
            <Loader2 className="h-6 w-6 animate-spin" />
          ) : (
            <UploadCloud className="h-6 w-6" />
          )}
        </div>
        <p className="mt-4 text-sm font-semibold text-[#F2DFC8]">
          {pick(
            lang,
            "Arrastra aquí el reporte de tu escáner o haz clic para seleccionarlo",
            "Drag and drop your scanner report here, or click to browse",
          )}
        </p>
        <p className="mt-1 text-xs text-[#8C93A3]">
          {pick(lang, "Compatible con", "Compatible with")}{" "}
          <code className="text-[#F2DFC8]">Nmap (.xml)</code> {pick(lang, "y", "and")}{" "}
          <code className="text-[#F2DFC8]">Nuclei (.jsonl)</code>
        </p>
        <p className="mt-2 font-mono text-[11px] text-[#6E7687]">
          Tip Nmap: <span className="text-[#949BAA]">nmap -sV --script vulners -oX scan.xml &lt;target&gt;</span>
        </p>
        <div className="mt-4 flex flex-wrap justify-center gap-2 text-[10px] font-mono uppercase tracking-wider text-[#7D8596]">
          <span className="rounded border border-[#F25C2A]/50 bg-[#181B22] px-2.5 py-1 text-[#F2DFC8]">
            Nmap XML ✓
          </span>
          <span className="rounded border border-[#313644] bg-[#181B22] px-2.5 py-1 text-[#F2DFC8]">
            Nuclei JSONL ✓
          </span>
          <span className="rounded border border-[#2B2F3B] bg-[#181B22]/50 px-2.5 py-1 opacity-60">
            {pick(lang, "Nessus / OpenVAS (Próximo)", "Nessus / OpenVAS (Soon)")}
          </span>
          <span className="rounded border border-[#2B2F3B] bg-[#181B22]/50 px-2.5 py-1 opacity-60">
            {pick(lang, "CSV / Excel (Próximo)", "CSV / Excel (Soon)")}
          </span>
        </div>
      </div>

      {statusMsg && (
        <div className="rounded-lg border border-[#F25C2A]/40 bg-[#F25C2A]/10 px-4 py-2.5 text-xs text-[#F2DFC8]">
          {statusMsg}
        </div>
      )}

      <div className="grid gap-5 md:grid-cols-2">
        <div className="rounded-xl border border-[#2C313E] bg-[#21252F] p-5 space-y-3">
          <div className="flex items-center gap-2 text-sm font-semibold text-[#F2DFC8]">
            <FileCode2 className="h-4 w-4 text-[#F25C2A]" />
            {pick(lang, "Pegado rápido de CVEs", "Quick CVE Paste")}
          </div>
          <p className="text-xs text-[#8C93A3]">
            {pick(
              lang,
              "Pega texto libre o notas de tu pentest con códigos CVE para extraerlos y enriquecerlos automáticamente.",
              "Paste raw notes or pentest logs containing CVE IDs to automatically extract and enrich them.",
            )}
          </p>
          <textarea
            rows={3}
            value={pasteText}
            onChange={(e) => setPasteText(e.target.value)}
            placeholder={pick(
              lang,
              "Ej. Encontrado CVE-2024-3094 y CVE-2023-44487 en servidor web...",
              "e.g. Found CVE-2024-3094 and CVE-2023-44487 on web server...",
            )}
            className="w-full rounded-lg border border-[#313644] bg-[#15171D] p-3 font-mono text-xs text-[#E6E1D9] placeholder-[#5F6676] focus:border-[#F25C2A] focus:outline-none"
          />
          <button
            type="button"
            disabled={isProcessing}
            onClick={handlePasteCves}
            className="inline-flex items-center gap-2 rounded-lg bg-[#F25C2A] px-4 py-2 text-xs font-semibold text-white transition hover:bg-[#ff6d3d] disabled:opacity-60"
          >
            {isProcessing && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
            {isProcessing
              ? pick(lang, "Consultando NVD / EPSS / KEV...", "Querying NVD / EPSS / KEV...")
              : pick(lang, "Detectar, enriquecer y agregar", "Detect, enrich & add")}
          </button>
        </div>

        <div className="rounded-xl border border-[#2C313E] bg-[#21252F] p-5 flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center gap-2 text-sm font-semibold text-[#F2DFC8]">
              <Layers className="h-4 w-4 text-[#F25C2A]" />
              {pick(lang, "Carga Manual de Infraestructura", "Manual Infrastructure Setup")}
            </div>
            <p className="mt-1.5 text-xs leading-relaxed text-[#8C93A3]">
              {pick(
                lang,
                "¿Prefieres definir primero los activos de tu cliente (servidores, bases de datos, VPN, Active Directory) y luego vincular cada vulnerabilidad?",
                "Prefer to define your client assets first (servers, databases, VPN, Active Directory) and then link each vulnerability?",
              )}
            </p>
          </div>
          <button
            type="button"
            onClick={onGoToInventory}
            className="w-fit rounded-lg border border-[#3B4152] bg-[#181B22] px-4 py-2 text-xs font-semibold text-[#F2DFC8] transition hover:border-[#F25C2A]"
          >
            {pick(lang, "Ir al Inventario de Activos", "Go to Asset Inventory")}
          </button>
        </div>
      </div>
    </div>
  );
}
