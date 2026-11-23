import { useState } from "react";
import { Check, Copy, Download, X } from "lucide-react";

interface MarkdownModalProps {
  markdown: string;
  projectName: string;
  onClose: () => void;
}

export function MarkdownModal({
  markdown,
  projectName,
  onClose,
}: MarkdownModalProps) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    await navigator.clipboard.writeText(markdown);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function handleDownload() {
    const blob = new Blob([markdown], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${projectName.toLowerCase().replace(/\s+/g, "-")}-reporte.md`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-sm">
      <div className="flex max-h-[85vh] w-full max-w-3xl flex-col rounded-xl border border-slate-700 bg-slate-900 shadow-2xl">
        <div className="flex items-center justify-between border-b border-slate-800 px-5 py-3.5">
          <h3 className="text-base font-semibold text-slate-100">
            Reporte Ejecutivo GRC (Markdown)
          </h3>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleCopy}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 transition hover:bg-slate-700"
            >
              {copied ? (
                <>
                  <Check className="h-3.5 w-3.5 text-emerald-400" /> Copiado
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5" /> Copiar
                </>
              )}
            </button>
            <button
              type="button"
              onClick={handleDownload}
              className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-cyan-500"
            >
              <Download className="h-3.5 w-3.5" /> Descargar .md
            </button>
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-100"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>
        <pre className="flex-1 overflow-auto p-5 font-mono text-xs leading-relaxed text-slate-200 whitespace-pre-wrap">
          {markdown}
        </pre>
      </div>
    </div>
  );
}
