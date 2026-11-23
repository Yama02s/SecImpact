import { pick, translateSla, type Language } from "./i18n";
import { escapeXml, sanitizeFilename, sanitizeSvg } from "./security";
import type { AuditProject, MatrixReport, RiskItem, RiskLevel } from "./types";

function getAxisLabels(
  n: number,
  lang: Language,
): { impact: Record<number, string>; likelihood: Record<number, string> } {
  if (n === 3) {
    return {
      impact: {
        3: pick(lang, "3 · Alto", "3 · High"),
        2: pick(lang, "2 · Moderado", "2 · Moderate"),
        1: pick(lang, "1 · Bajo", "1 · Low"),
      },
      likelihood: {
        1: pick(lang, "1 · Baja", "1 · Low"),
        2: pick(lang, "2 · Media", "2 · Medium"),
        3: pick(lang, "3 · Alta", "3 · High"),
      },
    };
  }
  if (n === 4) {
    return {
      impact: {
        4: pick(lang, "4 · Crítico", "4 · Critical"),
        3: pick(lang, "3 · Mayor", "3 · Major"),
        2: pick(lang, "2 · Moderado", "2 · Moderate"),
        1: pick(lang, "1 · Menor", "1 · Minor"),
      },
      likelihood: {
        1: pick(lang, "1 · Baja", "1 · Low"),
        2: pick(lang, "2 · Media", "2 · Medium"),
        3: pick(lang, "3 · Alta", "3 · High"),
        4: pick(lang, "4 · Muy Alta", "4 · Very High"),
      },
    };
  }
  return {
    impact: {
      5: pick(lang, "5 · Catastrófico", "5 · Catastrophic"),
      4: pick(lang, "4 · Mayor", "4 · Major"),
      3: pick(lang, "3 · Moderado", "3 · Moderate"),
      2: pick(lang, "2 · Menor", "2 · Minor"),
      1: pick(lang, "1 · Insignificante", "1 · Negligible"),
    },
    likelihood: {
      1: pick(lang, "1 · Muy Baja", "1 · Very Low"),
      2: pick(lang, "2 · Baja", "2 · Low"),
      3: pick(lang, "3 · Media", "3 · Medium"),
      4: pick(lang, "4 · Alta", "4 · High"),
      5: pick(lang, "5 · Muy Alta", "5 · Very High"),
    },
  };
}

function levelHex(
  level: RiskLevel,
  theme: "light" | "dark",
  hasItems: boolean,
): { bg: string; border: string; text: string; pillBg: string; pillText: string } {
  if (theme === "light") {
    switch (level) {
      case "critical":
        return hasItems
          ? { bg: "#F25C2A", border: "#D94414", text: "#FFFFFF", pillBg: "rgba(0,0,0,0.22)", pillText: "#FFFFFF" }
          : { bg: "#FDECE6", border: "#F8CBB9", text: "#9E3614", pillBg: "#F8CBB9", pillText: "#9E3614" };
      case "high":
        return hasItems
          ? { bg: "#E88B38", border: "#C96E1E", text: "#FFFFFF", pillBg: "rgba(0,0,0,0.20)", pillText: "#FFFFFF" }
          : { bg: "#FEF4E8", border: "#F6D9B7", text: "#945112", pillBg: "#F6D9B7", pillText: "#945112" };
      case "medium":
        return hasItems
          ? { bg: "#D9B45B", border: "#B8933B", text: "#1C1F26", pillBg: "rgba(255,255,255,0.45)", pillText: "#1C1F26" }
          : { bg: "#FCF8EB", border: "#EDE0B9", text: "#7D621F", pillBg: "#EDE0B9", pillText: "#7D621F" };
      case "low":
        return hasItems
          ? { bg: "#4D8B74", border: "#396D5A", text: "#FFFFFF", pillBg: "rgba(0,0,0,0.20)", pillText: "#FFFFFF" }
          : { bg: "#EEF5F2", border: "#C9DFD6", text: "#2F5C4B", pillBg: "#C9DFD6", pillText: "#2F5C4B" };
    }
  } else {
    switch (level) {
      case "critical":
        return hasItems
          ? { bg: "#F25C2A", border: "#FF7849", text: "#FFFFFF", pillBg: "rgba(0,0,0,0.28)", pillText: "#FFFFFF" }
          : { bg: "#2B2123", border: "#472C2A", text: "#9E6B63", pillBg: "#3D2626", pillText: "#C78E85" };
      case "high":
        return hasItems
          ? { bg: "#C86D2D", border: "#E38644", text: "#FFF5EC", pillBg: "rgba(0,0,0,0.26)", pillText: "#FFF5EC" }
          : { bg: "#282321", border: "#423429", text: "#9A7A5E", pillBg: "#3B2E24", pillText: "#C29F80" };
      case "medium":
        return hasItems
          ? { bg: "#9E8242", border: "#C2A35B", text: "#FFF8EB", pillBg: "rgba(0,0,0,0.24)", pillText: "#FFF8EB" }
          : { bg: "#252420", border: "#3B372B", text: "#8C8266", pillBg: "#333025", pillText: "#B5AB8A" };
      case "low":
        return hasItems
          ? { bg: "#3B665A", border: "#4E8575", text: "#ECF7F3", pillBg: "rgba(0,0,0,0.24)", pillText: "#ECF7F3" }
          : { bg: "#1E2526", border: "#2B3A39", text: "#65827C", pillBg: "#253332", pillText: "#8BA8A2" };
    }
  }
}

export function buildMatrixSvg(
  audit: AuditProject,
  report: MatrixReport,
  theme: "light" | "dark",
  lang: Language = "es",
): string {
  const n = report.summary.matrixSize;
  const labels = getAxisLabels(n, lang);
  const openItems = report.items.filter((i) => i.status === "open");

  // Asignar código corto R1, R2, R3... en orden de prioridad para cruzar matriz <-> leyenda
  const refCodeById = new Map<string, string>();
  openItems.forEach((item, idx) => {
    refCodeById.set(item.id, `R${idx + 1}`);
  });

  const cellW = 132;
  const cellH = 112;
  const gap = 10;
  const padLeft = 148;
  const padTop = 96;
  const padRight = 36;

  const gridW = n * cellW + (n - 1) * gap;
  const gridH = n * cellH + (n - 1) * gap;
  const width = padLeft + gridW + padRight;

  // Altura dinámica para leyenda de colores + tabla de referencia R1..Rn
  const legendY = padTop + gridH + 54;
  const visibleRefs = openItems.slice(0, 12);
  const refRowH = 24;
  const refSectionH =
    visibleRefs.length > 0 ? 48 + visibleRefs.length * refRowH + (openItems.length > 12 ? 22 : 0) : 28;
  const height = legendY + 42 + refSectionH + 34;

  const bg = theme === "light" ? "#FFFFFF" : "#1C1F26";
  const panelBg = theme === "light" ? "#F8FAFC" : "#181B22";
  const panelBorder = theme === "light" ? "#E2E8F0" : "#2C313E";
  const titleColor = theme === "light" ? "#15171D" : "#F2DFC8";
  const textColor = theme === "light" ? "#1E293B" : "#E6E1D9";
  const mutedColor = theme === "light" ? "#64748B" : "#8C93A3";

  const safeSubtitle = `${escapeXml(audit.name)} · ${escapeXml(audit.client)} · ${escapeXml(audit.date)}`;

  let cellsSvg = "";
  for (let row = 0; row < n; row++) {
    const impact = n - row;
    const y = padTop + row * (cellH + gap);
    cellsSvg += `<text x="${padLeft - 14}" y="${y + cellH / 2 + 4}" text-anchor="end" font-size="12" font-weight="600" fill="${titleColor}">${escapeXml(labels.impact[impact] ?? `Impacto ${impact}`)}</text>`;

    for (let col = 0; col < n; col++) {
      const likelihood = col + 1;
      const x = padLeft + col * (cellW + gap);
      const cell = report.cells.find(
        (c) => c.impact === impact && c.likelihood === likelihood,
      );
      const cellItems: RiskItem[] = openItems.filter(
        (it) => it.impact === impact && it.likelihood === likelihood,
      );
      const count = cellItems.length;
      const score = cell?.score ?? impact * likelihood;
      const colors = levelHex(cell?.level ?? "low", theme, count > 0);

      let innerContent = "";
      if (count === 0) {
        innerContent = `
          <text x="${x + cellW / 2}" y="${y + cellH / 2 + 2}" text-anchor="middle" font-size="20" fill="${colors.text}" opacity="0.45">·</text>
          <text x="${x + cellW / 2}" y="${y + cellH - 12}" text-anchor="middle" font-size="10" fill="${colors.text}" opacity="0.75">Score ${score}</text>
        `;
      } else {
        // Cabecera de la celda: Score a la izq + cantidad a la der
        innerContent += `
          <text x="${x + 10}" y="${y + 18}" font-size="10" font-weight="600" fill="${colors.text}" opacity="0.88">Score ${score}</text>
          <text x="${x + cellW - 10}" y="${y + 19}" text-anchor="end" font-size="12" font-weight="700" fill="${colors.text}">${count}</text>
        `;

        // Hasta 3 píldoras con R1 · CVE-... dentro de la celda
        const maxPills = Math.min(cellItems.length, 3);
        for (let p = 0; p < maxPills; p++) {
          const it = cellItems[p];
          const ref = refCodeById.get(it.id) ?? `R${p + 1}`;
          const shortCve =
            it.cveId.length > 14 ? `${it.cveId.slice(0, 13)}…` : it.cveId;
          const py = y + 26 + p * 23;
          innerContent += `
            <rect x="${x + 8}" y="${py}" width="${cellW - 16}" height="19" rx="4" fill="${colors.pillBg}" />
            <text x="${x + 13}" y="${py + 13}" font-size="9.5" font-weight="700" fill="${colors.pillText}">${escapeXml(ref)} · ${escapeXml(shortCve)}</text>
          `;
        }
        if (cellItems.length > 3) {
          innerContent += `<text x="${x + cellW / 2}" y="${y + cellH - 7}" text-anchor="middle" font-size="9" font-weight="600" fill="${colors.text}">+${cellItems.length - 3} hallazgo(s) más</text>`;
        }
      }

      cellsSvg += `
        <rect x="${x}" y="${y}" width="${cellW}" height="${cellH}" rx="8" fill="${colors.bg}" stroke="${colors.border}" stroke-width="1.5" />
        ${innerContent}
      `;

      if (row === n - 1) {
        cellsSvg += `<text x="${x + cellW / 2}" y="${padTop + gridH + 26}" text-anchor="middle" font-size="12" font-weight="600" fill="${titleColor}">${escapeXml(labels.likelihood[likelihood] ?? `Prob. ${likelihood}`)}</text>`;
      }
    }
  }

  // Leyenda de niveles de riesgo
  const legendItems = [
    { label: pick(lang, "Crítico", "Critical"), color: "#F25C2A" },
    { label: pick(lang, "Alto", "High"), color: "#D97A34" },
    { label: pick(lang, "Medio", "Medium"), color: "#C2A35B" },
    { label: pick(lang, "Bajo", "Low"), color: "#4D8B74" },
  ];
  let legendSvg = "";
  legendItems.forEach((lg, idx) => {
    const lx = padLeft + idx * 110;
    legendSvg += `
      <rect x="${lx}" y="${legendY}" width="12" height="12" rx="3" fill="${lg.color}" />
      <text x="${lx + 18}" y="${legendY + 10}" font-size="11" font-weight="600" fill="${textColor}">${lg.label}</text>
    `;
  });

  // Cuadro de Referencia R1..Rn para que el lector sepa exactamente qué hay en cada celda
  let refSvg = "";
  if (visibleRefs.length > 0) {
    const boxY = legendY + 28;
    const boxW = width - 72;
    const boxH = refSectionH;
    refSvg += `
      <rect x="36" y="${boxY}" width="${boxW}" height="${boxH}" rx="8" fill="${panelBg}" stroke="${panelBorder}" stroke-width="1.2" />
      <text x="52" y="${boxY + 24}" font-size="11" font-weight="700" letter-spacing="0.8" fill="${titleColor}">${pick(lang, "REFERENCIA DE HALLAZGOS UBICADOS EN LA MATRIZ", "REFERENCE KEY FOR FINDINGS PLOTTED ON MATRIX")}</text>
    `;
    visibleRefs.forEach((it, idx) => {
      const ry = boxY + 46 + idx * refRowH;
      const ref = refCodeById.get(it.id) ?? `R${idx + 1}`;
      const levelColor =
        it.riskLevel === "critical"
          ? "#F25C2A"
          : it.riskLevel === "high"
            ? "#D97A34"
            : it.riskLevel === "medium"
              ? "#C2A35B"
              : "#4D8B74";
      const lAxis = pick(lang, "P", "L");
      const lineText = `${it.cveId} — ${it.assetName} (I${it.impact}×${lAxis}${it.likelihood} · ${it.riskScore}/${it.maxScore} · SLA: ${translateSla(lang, it.slaWindow)})`;
      const safeLine =
        lineText.length > 94 ? `${lineText.slice(0, 91)}…` : lineText;
      refSvg += `
        <rect x="52" y="${ry - 12}" width="32" height="16" rx="4" fill="${levelColor}" />
        <text x="68" y="${ry}" text-anchor="middle" font-size="9.5" font-weight="700" fill="#FFFFFF">${escapeXml(ref)}</text>
        <text x="94" y="${ry}" font-size="11" fill="${textColor}">${escapeXml(safeLine)}</text>
      `;
    });
    if (openItems.length > 12) {
      refSvg += `<text x="52" y="${boxY + boxH - 12}" font-size="10" fill="${mutedColor}">+ ${openItems.length - 12} ${pick(lang, "hallazgo(s) adicionales detallados en el informe Markdown.", "additional finding(s) listed in the Markdown report.")}</text>`;
    }
  }

  const rawSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" font-family="Inter, Segoe UI, Arial, sans-serif">
    <rect width="100%" height="100%" fill="${bg}" />
    <circle cx="44" cy="36" r="7" fill="none" stroke="#F25C2A" stroke-width="3" />
    <text x="62" y="41" font-size="18" font-weight="700" fill="${titleColor}">SecImpact — ${pick(lang, "Matriz de Impacto vs. Probabilidad", "Impact vs. Likelihood Matrix")} (${n}×${n})</text>
    <text x="62" y="64" font-size="12" fill="${mutedColor}">${safeSubtitle}</text>
    ${cellsSvg}
    ${legendSvg}
    ${refSvg}
    <text x="${width / 2}" y="${height - 14}" text-anchor="middle" font-size="10.5" fill="${mutedColor}">${pick(lang, "Generado con SecImpact · Críticos", "Generated with SecImpact · Critical")}: ${report.summary.criticalCount} · ${pick(lang, "Altos", "High")}: ${report.summary.highCount} · ${pick(lang, "Reducción Residual", "Residual Reduction")}: -${report.summary.riskReductionPct.toFixed(1)}%</text>
  </svg>`;

  return sanitizeSvg(rawSvg);
}

export function downloadSvgFile(svg: string, baseName: string) {
  const safeName = `${sanitizeFilename(baseName)}.svg`;
  const safeSvg = sanitizeSvg(svg);
  const blob = new Blob([safeSvg], { type: "image/svg+xml;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = safeName;
  a.click();
  URL.revokeObjectURL(url);
}

export function downloadPngFromSvg(svg: string, baseName: string) {
  const safeName = `${sanitizeFilename(baseName)}.png`;
  const safeSvg = sanitizeSvg(svg);
  const img = new Image();
  const svgBlob = new Blob([safeSvg], { type: "image/svg+xml;charset=utf-8" });
  const url = URL.createObjectURL(svgBlob);

  img.onload = () => {
    const scale = 2;
    const canvas = document.createElement("canvas");
    canvas.width = img.width * scale;
    canvas.height = img.height * scale;
    const ctx = canvas.getContext("2d");
    if (ctx) {
      ctx.scale(scale, scale);
      ctx.drawImage(img, 0, 0);
      canvas.toBlob((blob) => {
        if (!blob) return;
        const pngUrl = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = pngUrl;
        a.download = safeName;
        a.click();
        URL.revokeObjectURL(pngUrl);
      }, "image/png");
    }
    URL.revokeObjectURL(url);
  };
  img.src = url;
}
