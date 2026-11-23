import { useEffect, useState } from "react";
import { computeImpactMatrix, fetchSampleAudit, lookupCve } from "./api";
import { t, type AppTheme, type Language } from "./i18n";
import { sanitizeFilename } from "./security";
import { AssetsPanel } from "./components/AssetsPanel";
import { FindingsPanel } from "./components/FindingsPanel";
import { IngestPanel } from "./components/IngestPanel";
import { InspectorPanel } from "./components/InspectorPanel";
import { MatrixCanvas } from "./components/MatrixCanvas";
import { ReportKitPanel } from "./components/ReportKitPanel";
import { ResidualRiskChart } from "./components/ResidualRiskChart";
import { RiskTable } from "./components/RiskTable";
import { SettingsModal } from "./components/SettingsModal";
import { Sidebar, type WorkspaceView } from "./components/Sidebar";
import { TitleBar } from "./components/TitleBar";
import { WelcomeScreen } from "./components/WelcomeScreen";
import { ZoneMapPanel } from "./components/ZoneMapPanel";
import type { Asset, AuditConfig, AuditProject, Exposure, Finding, MatrixReport } from "./types";

const RECENT_STORAGE_KEY = "secimpact_recent_audits_v1";
const PREFS_STORAGE_KEY = "secimpact_prefs_v1";

function loadPrefs(): { lang: Language; theme: AppTheme } {
  try {
    const raw = localStorage.getItem(PREFS_STORAGE_KEY);
    if (!raw) return { lang: "es", theme: "dark" };
    const p = JSON.parse(raw);
    return {
      lang: p?.lang === "en" ? "en" : "es",
      theme: p?.theme === "light" ? "light" : "dark",
    };
  } catch {
    return { lang: "es", theme: "dark" };
  }
}

function loadRecentAudits(): AuditProject[] {
  try {
    const raw = localStorage.getItem(RECENT_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export default function App() {
  const initialPrefs = loadPrefs();
  const [lang, setLang] = useState<Language>(initialPrefs.lang);
  const [theme, setTheme] = useState<AppTheme>(initialPrefs.theme);
  const [settingsOpen, setSettingsOpen] = useState(false);

  const [recentAudits, setRecentAudits] = useState<AuditProject[]>(() =>
    loadRecentAudits(),
  );
  const [audit, setAudit] = useState<AuditProject | null>(null);
  const [report, setReport] = useState<MatrixReport | null>(null);
  const [activeView, setActiveView] = useState<WorkspaceView>("ingest");
  const [inventorySubTab, setInventorySubTab] = useState<"assets" | "findings">("assets");
  const [selectedCell, setSelectedCell] = useState<{
    impact: number;
    likelihood: number;
  } | null>(null);
  const [selectedItemId, setSelectedItemId] = useState<string | null>(null);
  const [isEnriching, setIsEnriching] = useState(false);

  // Aplicar tema claro/oscuro al documento raíz y guardar preferencias
  useEffect(() => {
    const root = document.documentElement;
    root.classList.remove("dark", "light");
    root.classList.add(theme);
    root.lang = lang;
    try {
      localStorage.setItem(PREFS_STORAGE_KEY, JSON.stringify({ lang, theme }));
    } catch {
      // ignore
    }
  }, [lang, theme]);

  // Recalcular matriz cada vez que cambia la auditoría abierta
  useEffect(() => {
    if (!audit) {
      setReport(null);
      return;
    }
    computeImpactMatrix(audit).then(setReport);

    // Guardar automáticamente en recientes
    setRecentAudits((prev) => {
      const filtered = prev.filter(
        (p) => !(p.name === audit.name && p.client === audit.client),
      );
      const updated = [audit, ...filtered].slice(0, 8);
      try {
        localStorage.setItem(RECENT_STORAGE_KEY, JSON.stringify(updated));
      } catch {
        // ignorar cuota excedida
      }
      return updated;
    });
  }, [audit]);

  function handleCreateAudit(newAudit: AuditProject) {
    setAudit(newAudit);
    setSelectedCell(null);
    setSelectedItemId(null);
    setActiveView("ingest");
  }

  function handleOpenAudit(existing: AuditProject) {
    setAudit(existing);
    setSelectedCell(null);
    setSelectedItemId(null);
    setActiveView(existing.findings.length > 0 ? "matrix" : "ingest");
  }

  function handleDeleteRecent(index: number) {
    setRecentAudits((prev) => {
      const updated = prev.filter((_, i) => i !== index);
      try {
        localStorage.setItem(RECENT_STORAGE_KEY, JSON.stringify(updated));
      } catch {
        // ignore
      }
      return updated;
    });
  }

  function handleLoadDemo() {
    fetchSampleAudit().then((demo) => {
      setAudit(demo);
      setSelectedCell(null);
      setSelectedItemId(null);
      setActiveView("matrix");
    });
  }

  function handleChangeConfig(config: AuditConfig) {
    setSelectedCell(null);
    setAudit((prev) => (prev ? { ...prev, config } : prev));
  }

  function handleCalibrate(
    itemId: string,
    impact: number,
    likelihood: number,
    note: string,
    customGrcControl?: string,
  ) {
    setAudit((prev) => {
      if (!prev) return prev;
      const existing = prev.overrides[itemId];
      return {
        ...prev,
        overrides: {
          ...prev.overrides,
          [itemId]: {
            impact,
            likelihood,
            note,
            customGrcControl:
              customGrcControl !== undefined
                ? customGrcControl
                : existing?.customGrcControl,
          },
        },
      };
    });
  }

  async function handleEnrichAllCves() {
    if (!audit || isEnriching) return;
    setIsEnriching(true);
    const updatedFindings: Finding[] = [];
    for (const f of audit.findings) {
      if (/^CVE-\d{4}-\d{4,7}$/i.test(f.cveId.trim())) {
        const res = await lookupCve(f.cveId);
        if (res && res.found) {
          updatedFindings.push({
            ...f,
            title: res.title,
            description: res.description,
            cvss: res.cvss,
            epss: res.epss,
            inKev: res.inKev || f.inKev,
            cwe: res.cwe,
          });
          continue;
        }
      }
      updatedFindings.push(f);
    }
    setAudit((prev) => (prev ? { ...prev, findings: updatedFindings } : prev));
    setIsEnriching(false);
  }

  function handleResetCalibration(itemId: string) {
    setAudit((prev) => {
      if (!prev) return prev;
      const next = { ...prev.overrides };
      delete next[itemId];
      return { ...prev, overrides: next };
    });
  }

  function handleDropItemOnCell(itemId: string, impact: number, likelihood: number) {
    const existingNote = audit?.overrides[itemId]?.note ?? "";
    handleCalibrate(itemId, impact, likelihood, existingNote);
    setSelectedItemId(itemId);
  }

  function handleToggleRemediationPlan(itemId: string) {
    setAudit((prev) => {
      if (!prev) return prev;
      const exists = prev.plannedRemediationIds.includes(itemId);
      return {
        ...prev,
        plannedRemediationIds: exists
          ? prev.plannedRemediationIds.filter((id) => id !== itemId)
          : [...prev.plannedRemediationIds, itemId],
      };
    });
  }

  function handleAddAsset(asset: Asset) {
    setAudit((prev) => (prev ? { ...prev, assets: [...prev.assets, asset] } : prev));
  }

  function handleChangeAssetExposure(assetId: string, exposure: Exposure) {
    setAudit((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        assets: prev.assets.map((a) =>
          a.id === assetId ? { ...a, exposure } : a,
        ),
      };
    });
  }

  function handleDeleteAsset(assetId: string) {
    setAudit((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        assets: prev.assets.filter((a) => a.id !== assetId),
        findings: prev.findings.map((f) => ({
          ...f,
          assetIds: f.assetIds.filter((id) => id !== assetId),
        })),
      };
    });
  }

  function handleAddFinding(finding: Finding) {
    setAudit((prev) =>
      prev ? { ...prev, findings: [...prev.findings, finding] } : prev,
    );
  }

  function handleImportBatch(newAssets: Asset[], newFindings: Finding[]) {
    setAudit((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        assets: [...prev.assets, ...newAssets],
        findings: [...prev.findings, ...newFindings],
      };
    });
  }

  function handleDeleteFinding(findingId: string) {
    setAudit((prev) =>
      prev
        ? { ...prev, findings: prev.findings.filter((f) => f.id !== findingId) }
        : prev,
    );
  }

  function handleExportJson() {
    if (!audit) return;
    const blob = new Blob([JSON.stringify(audit, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${sanitizeFilename(audit.name, "proyecto")}.secimpact.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // Pantalla de Inicio / Gestor de Auditorías
  if (!audit || !report) {
    return (
      <div className="flex h-screen w-screen flex-col overflow-hidden bg-[#1C1F26] text-[#E6E1D9]">
        <TitleBar lang={lang} onOpenSettings={() => setSettingsOpen(true)} />
        <WelcomeScreen
          lang={lang}
          recentAudits={recentAudits}
          onCreateAudit={handleCreateAudit}
          onOpenAudit={handleOpenAudit}
          onDeleteRecent={handleDeleteRecent}
          onLoadDemo={handleLoadDemo}
        />
        {settingsOpen && (
          <SettingsModal
            lang={lang}
            theme={theme}
            onChangeLang={setLang}
            onChangeTheme={setTheme}
            onClose={() => setSettingsOpen(false)}
          />
        )}
      </div>
    );
  }

  const selectedItem =
    report.items.find((i) => i.id === selectedItemId) ?? null;

  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden bg-[#1C1F26] text-[#E6E1D9]">
      {/* Barra superior personalizada */}
      <TitleBar
        lang={lang}
        projectName={audit.name}
        clientName={audit.client}
        onGoHome={() => {
          setAudit(null);
          setSelectedCell(null);
          setSelectedItemId(null);
        }}
        onOpenSettings={() => setSettingsOpen(true)}
      />

      <div className="flex min-h-0 flex-1 overflow-hidden">
        {/* Barra Lateral Izquierda */}
        <Sidebar
          lang={lang}
          activeView={activeView}
          onChangeView={setActiveView}
          config={audit.config}
          onChangeConfig={handleChangeConfig}
          openCount={report.summary.openRiskPairs}
          assetCount={audit.assets.length}
        />

        {/* Lienzo Central */}
        <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
          <header className="flex shrink-0 flex-wrap items-center justify-between gap-4 border-b border-[#2B2F3B] bg-[#191C23] px-6 py-3">
            <div className="min-w-0 flex items-center gap-2">
              <input
                value={audit.name}
                onChange={(e) =>
                  setAudit((prev) => (prev ? { ...prev, name: e.target.value } : prev))
                }
                className="bg-transparent text-sm font-bold text-[#F2DFC8] focus:outline-none focus:underline"
              />
              <span className="text-[#4B5263]">/</span>
              <input
                value={audit.client}
                onChange={(e) =>
                  setAudit((prev) => (prev ? { ...prev, client: e.target.value } : prev))
                }
                className="bg-transparent text-xs text-[#8C93A3] focus:outline-none focus:text-[#F2DFC8]"
              />
            </div>

            <div className="flex items-center gap-5 font-mono text-xs">
              <div className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-[#F25C2A]" />
                <span className="text-[#8C93A3]">{t(lang, "criticals")}</span>
                <strong className="text-[#F2DFC8]">{report.summary.criticalCount}</strong>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-[#D97A34]" />
                <span className="text-[#8C93A3]">{t(lang, "highs")}</span>
                <strong className="text-[#F2DFC8]">{report.summary.highCount}</strong>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-[#8C93A3]">{t(lang, "residual")}</span>
                <strong className="text-emerald-400">
                  -{report.summary.riskReductionPct.toFixed(0)}%
                </strong>
              </div>
            </div>
          </header>

          <main className="flex-1 overflow-y-auto p-6">
            {activeView === "ingest" && (
              <IngestPanel
                lang={lang}
                audit={audit}
                onImportBatch={handleImportBatch}
                onGoToMatrix={() => setActiveView("matrix")}
                onGoToInventory={() => setActiveView("inventory")}
              />
            )}

            {activeView === "matrix" && (
              <div className="space-y-6">
                <MatrixCanvas
                  lang={lang}
                  matrixSize={report.summary.matrixSize}
                  cells={report.cells}
                  items={report.items}
                  selectedItemId={selectedItemId}
                  selectedCell={selectedCell}
                  onSelectCell={setSelectedCell}
                  onSelectItem={(item) => setSelectedItemId(item.id)}
                  onDropItemOnCell={handleDropItemOnCell}
                />

                <ResidualRiskChart lang={lang} summary={report.summary} />

                <RiskTable
                  lang={lang}
                  items={report.items}
                  selectedItemId={selectedItemId}
                  selectedCell={selectedCell}
                  isEnriching={isEnriching}
                  onEnrichAll={handleEnrichAllCves}
                  onSelectItem={(item) => setSelectedItemId(item.id)}
                  onToggleRemediationPlan={handleToggleRemediationPlan}
                />
              </div>
            )}

            {activeView === "zonemap" && (
              <ZoneMapPanel
                lang={lang}
                audit={audit}
                report={report}
                onChangeAssetExposure={handleChangeAssetExposure}
              />
            )}

            {activeView === "inventory" && (
              <div className="space-y-5">
                <div className="flex items-center gap-2 border-b border-[#2B2F3B] pb-3">
                  <button
                    type="button"
                    onClick={() => setInventorySubTab("assets")}
                    className={`rounded-lg px-3.5 py-1.5 text-xs font-semibold transition ${
                      inventorySubTab === "assets"
                        ? "bg-[#F25C2A] text-white"
                        : "bg-[#21252F] text-[#949BAA] hover:text-[#F2DFC8]"
                    }`}
                  >
                    {t(lang, "assetsTab")} ({audit.assets.length})
                  </button>
                  <button
                    type="button"
                    onClick={() => setInventorySubTab("findings")}
                    className={`rounded-lg px-3.5 py-1.5 text-xs font-semibold transition ${
                      inventorySubTab === "findings"
                        ? "bg-[#F25C2A] text-white"
                        : "bg-[#21252F] text-[#949BAA] hover:text-[#F2DFC8]"
                    }`}
                  >
                    {t(lang, "findingsTab")} ({audit.findings.length})
                  </button>
                </div>

                {inventorySubTab === "assets" ? (
                  <AssetsPanel
                    lang={lang}
                    assets={audit.assets}
                    onAddAsset={handleAddAsset}
                    onDeleteAsset={handleDeleteAsset}
                  />
                ) : (
                  <FindingsPanel
                    lang={lang}
                    assets={audit.assets}
                    findings={audit.findings}
                    onAddFinding={handleAddFinding}
                    onDeleteFinding={handleDeleteFinding}
                  />
                )}
              </div>
            )}

            {activeView === "report" && (
              <ReportKitPanel
                lang={lang}
                audit={audit}
                report={report}
                onExportJson={handleExportJson}
              />
            )}
          </main>
        </div>

        {/* Panel Inspector Derecho */}
        {activeView === "matrix" && (
          <InspectorPanel
            lang={lang}
            item={selectedItem}
            matrixSize={report.summary.matrixSize}
            framework={audit.config.framework}
            onClose={() => setSelectedItemId(null)}
            onCalibrate={handleCalibrate}
            onResetCalibration={handleResetCalibration}
            onToggleRemediationPlan={handleToggleRemediationPlan}
          />
        )}
      </div>

      {settingsOpen && (
        <SettingsModal
          lang={lang}
          theme={theme}
          onChangeLang={setLang}
          onChangeTheme={setTheme}
          onClose={() => setSettingsOpen(false)}
        />
      )}
    </div>
  );
}
