import { useRef, useState } from "react";
import { ArrowRight, Clock, FolderOpen, Plus, Sparkles, Trash2 } from "lucide-react";
import { pick, t, type Language } from "../i18n";
import type { AuditProject, GrcFramework } from "../types";

interface WelcomeScreenProps {
  lang: Language;
  recentAudits: AuditProject[];
  onCreateAudit: (audit: AuditProject) => void;
  onOpenAudit: (audit: AuditProject) => void;
  onDeleteRecent: (index: number) => void;
  onLoadDemo: () => void;
}

export function WelcomeScreen({
  lang,
  recentAudits,
  onCreateAudit,
  onOpenAudit,
  onDeleteRecent,
  onLoadDemo,
}: WelcomeScreenProps) {
  const [name, setName] = useState("");
  const [client, setClient] = useState("");
  const [auditor, setAuditor] = useState("");
  const [matrixSize, setMatrixSize] = useState<3 | 4 | 5>(5);
  const [framework, setFramework] = useState<GrcFramework>("cisControls");
  const fileRef = useRef<HTMLInputElement>(null);

  function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    const today = new Date().toISOString().slice(0, 10);
    onCreateAudit({
      name: name.trim(),
      client: client.trim() || "Organización",
      auditor: auditor.trim() || "Auditor",
      date: today,
      config: { matrixSize, framework },
      assets: [],
      findings: [],
      overrides: {},
      plannedRemediationIds: [],
    });
  }

  function handleOpenProjectFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const parsed = JSON.parse(String(reader.result)) as AuditProject;
        if (parsed && Array.isArray(parsed.assets) && Array.isArray(parsed.findings)) {
          onOpenAudit({
            ...parsed,
            config: parsed.config ?? { matrixSize: 5, framework: "cisControls" },
            overrides: parsed.overrides ?? {},
            plannedRemediationIds: parsed.plannedRemediationIds ?? [],
          });
        }
      } catch {
        alert("El archivo seleccionado no es un proyecto válido de SecImpact.");
      }
    };
    reader.readAsText(file);
    e.target.value = "";
  }

  return (
    <div className="flex flex-1 overflow-y-auto bg-[#1C1F26]">
      <div className="mx-auto flex w-full max-w-5xl flex-col justify-center px-8 py-12">
        {/* Cabecera editorial */}
        <div className="mb-10 flex flex-wrap items-end justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <span className="h-4 w-4 rounded-full border-[3px] border-[#F25C2A]" />
              <span className="text-xs font-bold tracking-[0.26em] text-[#8C93A3]">
                SECIMPACT WORKSPACE
              </span>
            </div>
            <h1 className="mt-3 text-4xl font-bold tracking-tight text-[#F2DFC8]">
              {t(lang, "welcomeHeading")}
            </h1>
            <p className="mt-2 max-w-xl text-sm text-[#8C93A3]">
              {t(lang, "welcomeSub")}
            </p>
          </div>

          <div className="flex items-center gap-2.5">
            <input
              ref={fileRef}
              type="file"
              accept=".json"
              onChange={handleOpenProjectFile}
              className="hidden"
            />
            <button
              type="button"
              onClick={() => fileRef.current?.click()}
              className="inline-flex items-center gap-2 rounded-lg border border-[#323746] bg-[#21252F] px-3.5 py-2 text-xs font-semibold text-[#F2DFC8] transition hover:border-[#F25C2A]"
            >
              <FolderOpen className="h-3.5 w-3.5 text-[#F25C2A]" />
              {t(lang, "openSaved")}
            </button>
            <button
              type="button"
              onClick={onLoadDemo}
              className="inline-flex items-center gap-1.5 rounded-lg border border-[#2C313E] bg-[#181B22] px-3.5 py-2 text-xs font-medium text-[#949BAA] transition hover:border-[#444B5E] hover:text-[#F2DFC8]"
            >
              <Sparkles className="h-3.5 w-3.5 text-[#F25C2A]" />
              {t(lang, "viewDemo")}
            </button>
          </div>
        </div>

        {/* Grid principal: Nueva Auditoría + Recientes */}
        <div className="grid gap-8 lg:grid-cols-[1.15fr_0.85fr]">
          {/* Formulario Nueva Auditoría */}
          <form
            onSubmit={handleCreate}
            className="rounded-xl border border-[#2C313E] bg-[#21252F] p-6 space-y-5"
          >
            <div className="flex items-center gap-2">
              <Plus className="h-4 w-4 text-[#F25C2A]" />
              <h2 className="text-sm font-bold uppercase tracking-[0.14em] text-[#F2DFC8]">
                {t(lang, "newAudit")}
              </h2>
            </div>

            <div className="space-y-4">
              <div>
                <label className="mb-1.5 block text-xs font-medium text-[#8C93A3]">
                  {t(lang, "auditName")}
                </label>
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder={pick(
                    lang,
                    "Ej. Pentest Externo e Infraestructura 2026",
                    "e.g. External & Infrastructure Pentest 2026",
                  )}
                  className="w-full rounded-lg border border-[#313644] bg-[#15171D] px-3.5 py-2.5 text-sm text-[#E6E1D9] placeholder-[#5B6272] focus:border-[#F25C2A] focus:outline-none"
                  required
                />
              </div>

              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="mb-1.5 block text-xs font-medium text-[#8C93A3]">
                    {t(lang, "clientOrg")}
                  </label>
                  <input
                    value={client}
                    onChange={(e) => setClient(e.target.value)}
                    placeholder={pick(lang, "Ej. Empresa S.A.", "e.g. Acme Corp")}
                    className="w-full rounded-lg border border-[#313644] bg-[#15171D] px-3.5 py-2.5 text-sm text-[#E6E1D9] placeholder-[#5B6272] focus:border-[#F25C2A] focus:outline-none"
                  />
                </div>
                <div>
                  <label className="mb-1.5 block text-xs font-medium text-[#8C93A3]">
                    {t(lang, "auditorTeam")}
                  </label>
                  <input
                    value={auditor}
                    onChange={(e) => setAuditor(e.target.value)}
                    placeholder={pick(lang, "Tu nombre o equipo", "Your name or team")}
                    className="w-full rounded-lg border border-[#313644] bg-[#15171D] px-3.5 py-2.5 text-sm text-[#E6E1D9] placeholder-[#5B6272] focus:border-[#F25C2A] focus:outline-none"
                  />
                </div>
              </div>

              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="mb-1.5 block text-xs font-medium text-[#8C93A3]">
                    {t(lang, "matrixScale")}
                  </label>
                  <div className="grid grid-cols-3 gap-1.5">
                    {([5, 4, 3] as const).map((size) => (
                      <button
                        key={size}
                        type="button"
                        onClick={() => setMatrixSize(size)}
                        className={`rounded-lg py-2 font-mono text-xs font-semibold transition ${
                          matrixSize === size
                            ? "bg-[#F25C2A] text-white"
                            : "border border-[#313644] bg-[#15171D] text-[#949BAA] hover:text-[#F2DFC8]"
                        }`}
                      >
                        {size}×{size}
                      </button>
                    ))}
                  </div>
                </div>

                <div>
                  <label className="mb-1.5 block text-xs font-medium text-[#8C93A3]">
                    {t(lang, "refFramework")}
                  </label>
                  <select
                    value={framework}
                    onChange={(e) => setFramework(e.target.value as GrcFramework)}
                    className="w-full rounded-lg border border-[#313644] bg-[#15171D] px-3 py-2 text-xs text-[#F2DFC8] focus:border-[#F25C2A] focus:outline-none"
                  >
                    <option value="cisControls">CIS Controls v8</option>
                    <option value="iso27001">ISO/IEC 27001:2022</option>
                    <option value="nistCsf">NIST CSF 2.0</option>
                    <option value="owaspTop10">OWASP Top 10:2025</option>
                  </select>
                </div>
              </div>
            </div>

            <button
              type="submit"
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-[#F25C2A] px-5 py-3 text-sm font-semibold text-white transition hover:bg-[#ff6d3d]"
            >
              {t(lang, "createStart")}
              <ArrowRight className="h-4 w-4" />
            </button>
          </form>

          {/* Auditorías recientes */}
          <div className="rounded-xl border border-[#2C313E] bg-[#181B22] p-6 flex flex-col">
            <div className="flex items-center gap-2 mb-4">
              <Clock className="h-4 w-4 text-[#8C93A3]" />
              <h2 className="text-sm font-bold uppercase tracking-[0.14em] text-[#F2DFC8]">
                {t(lang, "recentAudits")}
              </h2>
            </div>

            {recentAudits.length === 0 ? (
              <div className="flex flex-1 flex-col items-center justify-center rounded-lg border border-dashed border-[#2C313E] p-8 text-center">
                <p className="text-xs font-medium text-[#949BAA]">
                  {t(lang, "noRecent")}
                </p>
                <p className="mt-1 text-[11px] text-[#6E7687]">
                  {t(lang, "noRecentSub")}
                </p>
              </div>
            ) : (
              <div className="space-y-2.5 overflow-y-auto max-h-[320px]">
                {recentAudits.map((item, idx) => (
                  <div
                    key={`${item.name}-${idx}`}
                    onClick={() => onOpenAudit(item)}
                    className="group flex cursor-pointer items-center justify-between rounded-lg border border-[#282D39] bg-[#21252F] px-4 py-3 transition hover:border-[#F25C2A]"
                  >
                    <div className="min-w-0">
                      <p className="truncate text-sm font-semibold text-[#F2DFC8]">
                        {item.name}
                      </p>
                      <p className="truncate text-[11px] text-[#8C93A3]">
                        {item.client} · {item.assets.length} activos · {item.findings.length} CVEs
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        onDeleteRecent(idx);
                      }}
                      className="rounded p-1.5 text-[#636B7C] opacity-0 transition group-hover:opacity-100 hover:bg-[#F25C2A]/15 hover:text-[#F25C2A]"
                      title="Quitar de recientes"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
