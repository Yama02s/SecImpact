import { FolderOpen, Minus, Settings, Square, X } from "lucide-react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { isTauriRuntime } from "../api";
import { t, type Language } from "../i18n";

interface TitleBarProps {
  lang: Language;
  projectName?: string;
  clientName?: string;
  onGoHome?: () => void;
  onOpenSettings: () => void;
}

export function TitleBar({
  lang,
  projectName,
  clientName,
  onGoHome,
  onOpenSettings,
}: TitleBarProps) {
  const isTauri = isTauriRuntime();

  async function handleMinimize() {
    if (isTauri) await getCurrentWindow().minimize();
  }

  async function handleToggleMaximize() {
    if (isTauri) await getCurrentWindow().toggleMaximize();
  }

  async function handleClose() {
    if (isTauri) await getCurrentWindow().close();
  }

  return (
    <div
      data-tauri-drag-region
      className="flex h-9 shrink-0 items-center justify-between border-b border-[#242833] bg-[#111318] select-none"
    >
      {/* Izquierda: marca + Proyectos + Ajustes */}
      <div className="flex items-center gap-2.5 pl-3.5" data-tauri-drag-region>
        <div className="flex items-center gap-2" data-tauri-drag-region>
          <span className="h-2.5 w-2.5 rounded-full border-[2px] border-[#F25C2A]" />
          <span className="text-[11px] font-bold tracking-[0.2em] text-[#F2DFC8]">
            SECIMPACT
          </span>
        </div>

        <span className="text-[#323746]">|</span>

        {onGoHome && (
          <button
            type="button"
            onClick={onGoHome}
            className="inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-[11px] text-[#8C93A3] transition hover:bg-[#232731] hover:text-[#F2DFC8]"
          >
            <FolderOpen className="h-3 w-3" />
            {t(lang, "projects")}
          </button>
        )}

        <button
          type="button"
          onClick={onOpenSettings}
          className="inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-[11px] text-[#8C93A3] transition hover:bg-[#232731] hover:text-[#F2DFC8]"
        >
          <Settings className="h-3 w-3" />
          {t(lang, "settings")}
        </button>

        {projectName && (
          <span
            data-tauri-drag-region
            className="hidden md:inline pl-1 text-[11px] text-[#6E7687] truncate max-w-[320px]"
          >
            {projectName}
            {clientName ? ` · ${clientName}` : ""}
          </span>
        )}
      </div>

      {/* Centro arrastrable */}
      <div className="h-full flex-1" data-tauri-drag-region />

      {/* Derecha: controles de ventana personalizados */}
      <div className="flex h-full items-center">
        <button
          type="button"
          onClick={handleMinimize}
          className="flex h-full w-11 items-center justify-center text-[#8C93A3] transition hover:bg-[#232731] hover:text-[#F2DFC8]"
          title="Minimizar"
        >
          <Minus className="h-3.5 w-3.5" />
        </button>
        <button
          type="button"
          onClick={handleToggleMaximize}
          className="flex h-full w-11 items-center justify-center text-[#8C93A3] transition hover:bg-[#232731] hover:text-[#F2DFC8]"
          title="Maximizar / Restaurar"
        >
          <Square className="h-3 w-3" />
        </button>
        <button
          type="button"
          onClick={handleClose}
          className="flex h-full w-11 items-center justify-center text-[#8C93A3] transition hover:bg-[#F25C2A] hover:text-white"
          title="Cerrar"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );
}
