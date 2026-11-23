import { Globe, Moon, Sun, X } from "lucide-react";
import { t, type AppTheme, type Language } from "../i18n";

interface SettingsModalProps {
  lang: Language;
  theme: AppTheme;
  onChangeLang: (lang: Language) => void;
  onChangeTheme: (theme: AppTheme) => void;
  onClose: () => void;
}

export function SettingsModal({
  lang,
  theme,
  onChangeLang,
  onChangeTheme,
  onClose,
}: SettingsModalProps) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-xs"
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-md rounded-xl border border-[#313644] bg-[#1C1F26] p-6 shadow-2xl space-y-5"
      >
        <div className="flex items-center justify-between border-b border-[#2B2F3B] pb-3.5">
          <div className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full border-[2px] border-[#F25C2A]" />
            <h3 className="text-sm font-bold tracking-wide text-[#F2DFC8]">
              {t(lang, "settingsTitle")}
            </h3>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1 text-[#8C93A3] transition hover:bg-[#232731] hover:text-[#F2DFC8]"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Idioma */}
        <div className="space-y-2">
          <label className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-[0.14em] text-[#8C93A3]">
            <Globe className="h-3.5 w-3.5 text-[#F25C2A]" />
            {t(lang, "languageLabel")}
          </label>
          <div className="grid grid-cols-2 gap-2">
            <button
              type="button"
              onClick={() => onChangeLang("es")}
              className={`rounded-lg border px-3 py-2.5 text-xs font-semibold transition ${
                lang === "es"
                  ? "border-[#F25C2A] bg-[#F25C2A] text-white"
                  : "border-[#313644] bg-[#15171D] text-[#949BAA] hover:text-[#F2DFC8]"
              }`}
            >
              Español (ES)
            </button>
            <button
              type="button"
              onClick={() => onChangeLang("en")}
              className={`rounded-lg border px-3 py-2.5 text-xs font-semibold transition ${
                lang === "en"
                  ? "border-[#F25C2A] bg-[#F25C2A] text-white"
                  : "border-[#313644] bg-[#15171D] text-[#949BAA] hover:text-[#F2DFC8]"
              }`}
            >
              English (EN)
            </button>
          </div>
        </div>

        {/* Apariencia Oscuro / Claro */}
        <div className="space-y-2">
          <label className="block text-xs font-semibold uppercase tracking-[0.14em] text-[#8C93A3]">
            {t(lang, "themeLabel")}
          </label>
          <div className="grid grid-cols-2 gap-2">
            <button
              type="button"
              onClick={() => onChangeTheme("dark")}
              className={`inline-flex items-center justify-center gap-2 rounded-lg border px-3 py-2.5 text-xs font-semibold transition ${
                theme === "dark"
                  ? "border-[#F25C2A] bg-[#F25C2A] text-white"
                  : "border-[#313644] bg-[#15171D] text-[#949BAA] hover:text-[#F2DFC8]"
              }`}
            >
              <Moon className="h-3.5 w-3.5" />
              {t(lang, "themeDark")}
            </button>
            <button
              type="button"
              onClick={() => onChangeTheme("light")}
              className={`inline-flex items-center justify-center gap-2 rounded-lg border px-3 py-2.5 text-xs font-semibold transition ${
                theme === "light"
                  ? "border-[#F25C2A] bg-[#F25C2A] text-white"
                  : "border-[#313644] bg-[#15171D] text-[#949BAA] hover:text-[#F2DFC8]"
              }`}
            >
              <Sun className="h-3.5 w-3.5" />
              {t(lang, "themeLight")}
            </button>
          </div>
        </div>

        <div className="flex items-center justify-between border-t border-[#2B2F3B] pt-3.5">
          <span className="font-mono text-[10px] uppercase tracking-widest text-[#6E7687]">
            SecImpact · v0.3.0
          </span>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-[#343A49] bg-[#21252F] px-3.5 py-1.5 text-xs font-semibold text-[#F2DFC8] transition hover:border-[#F25C2A]"
          >
            {t(lang, "close")}
          </button>
        </div>
      </div>
    </div>
  );
}
