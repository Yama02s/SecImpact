import { FileDown, Grid2x2, Layers, Network, UploadCloud } from "lucide-react";
import { t, type Language, type TranslationKey } from "../i18n";
import type { AuditConfig, GrcFramework } from "../types";

export type WorkspaceView = "ingest" | "matrix" | "zonemap" | "inventory" | "report";

interface SidebarProps {
  lang: Language;
  activeView: WorkspaceView;
  onChangeView: (view: WorkspaceView) => void;
  config: AuditConfig;
  onChangeConfig: (config: AuditConfig) => void;
  openCount: number;
  assetCount: number;
}

const NAV_ITEMS: {
  id: WorkspaceView;
  step: string;
  labelKey: TranslationKey;
  subKey: TranslationKey;
  icon: typeof Grid2x2;
}[] = [
  {
    id: "ingest",
    step: "01",
    labelKey: "stepIngest",
    subKey: "stepIngestSub",
    icon: UploadCloud,
  },
  {
    id: "matrix",
    step: "02",
    labelKey: "stepMatrix",
    subKey: "stepMatrixSub",
    icon: Grid2x2,
  },
  {
    id: "zonemap",
    step: "03",
    labelKey: "stepZoneMap",
    subKey: "stepZoneMapSub",
    icon: Network,
  },
  {
    id: "inventory",
    step: "04",
    labelKey: "stepInventory",
    subKey: "stepInventorySub",
    icon: Layers,
  },
  {
    id: "report",
    step: "05",
    labelKey: "stepReport",
    subKey: "stepReportSub",
    icon: FileDown,
  },
];

export function Sidebar({
  lang,
  activeView,
  onChangeView,
  config,
  onChangeConfig,
  openCount,
  assetCount,
}: SidebarProps) {
  return (
    <aside className="flex w-[240px] shrink-0 flex-col justify-between border-r border-[#2B2F3B] bg-[#15171D] select-none">
      <div>
        <div className="px-3 py-5">
          <p className="mb-2.5 px-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-[#6B7280]">
            {t(lang, "workflowTitle")}
          </p>
          <nav className="space-y-1">
            {NAV_ITEMS.map((item) => {
              const Icon = item.icon;
              const isActive = activeView === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => onChangeView(item.id)}
                  className={`group relative flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left transition ${
                    isActive
                      ? "bg-[#232731] text-[#F2DFC8]"
                      : "text-[#949BAA] hover:bg-[#1C1F26] hover:text-[#E6E1D9]"
                  }`}
                >
                  {isActive && (
                    <span className="absolute left-0 top-2 bottom-2 w-[3px] rounded-r bg-[#F25C2A]" />
                  )}
                  <span
                    className={`font-mono text-[10px] font-semibold ${
                      isActive ? "text-[#F25C2A]" : "text-[#636B7C]"
                    }`}
                  >
                    {item.step}
                  </span>
                  <Icon className="h-4 w-4 shrink-0 opacity-85" />
                  <div className="min-w-0 flex-1">
                    <div className="text-xs font-semibold leading-tight">
                      {t(lang, item.labelKey)}
                    </div>
                    <div className="truncate text-[10px] text-[#788091]">
                      {t(lang, item.subKey)}
                    </div>
                  </div>
                  {item.id === "matrix" && openCount > 0 && (
                    <span className="rounded bg-[#2E3340] px-1.5 py-0.5 font-mono text-[10px] text-[#F2DFC8]">
                      {openCount}
                    </span>
                  )}
                  {item.id === "inventory" && (
                    <span className="rounded bg-[#262A35] px-1.5 py-0.5 font-mono text-[10px] text-[#8C93A3]">
                      {assetCount}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        <div className="mx-3 mt-1 rounded-lg border border-[#262A35] bg-[#1A1D24] p-3.5 space-y-3.5">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[#7D8596] mb-2">
              {t(lang, "matrixScale")}
            </p>
            <div className="grid grid-cols-3 gap-1.5">
              {([5, 4, 3] as const).map((size) => (
                <button
                  key={size}
                  type="button"
                  onClick={() => onChangeConfig({ ...config, matrixSize: size })}
                  className={`rounded-md py-1.5 font-mono text-xs font-semibold transition ${
                    config.matrixSize === size
                      ? "bg-[#F25C2A] text-white"
                      : "bg-[#232731] text-[#949BAA] hover:text-[#F2DFC8]"
                  }`}
                >
                  {size}×{size}
                </button>
              ))}
            </div>
          </div>

          <div>
            <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[#7D8596] mb-1.5">
              {t(lang, "grcFramework")}
            </p>
            <select
              value={config.framework}
              onChange={(e) =>
                onChangeConfig({
                  ...config,
                  framework: e.target.value as GrcFramework,
                })
              }
              className="w-full rounded-md border border-[#313644] bg-[#232731] px-2.5 py-1.5 text-xs text-[#F2DFC8] focus:border-[#F25C2A] focus:outline-none"
            >
              <option value="cisControls">CIS Controls v8</option>
              <option value="iso27001">ISO/IEC 27001:2022</option>
              <option value="nistCsf">NIST CSF 2.0</option>
              <option value="owaspTop10">OWASP Top 10:2025</option>
            </select>
          </div>
        </div>
      </div>

      <div className="border-t border-[#262A35] px-5 py-3 text-[10px] font-mono uppercase tracking-widest text-[#5F6676]">
        SecImpact · v0.3.0
      </div>
    </aside>
  );
}
