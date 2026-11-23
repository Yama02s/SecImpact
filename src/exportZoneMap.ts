import { pick, type Language } from "./i18n";
import { escapeXml, sanitizeSvg } from "./security";
import type { Asset, AuditProject, Exposure, MatrixReport, RiskLevel } from "./types";

function highestLevelForAsset(assetId: string, report: MatrixReport): {
  level: RiskLevel | "none";
  openCount: number;
  kevCount: number;
} {
  const items = report.items.filter(
    (i) => i.status === "open" && i.assetId === assetId,
  );
  if (items.length === 0) {
    return { level: "none", openCount: 0, kevCount: 0 };
  }
  const order: Record<RiskLevel, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
  };
  let best: RiskLevel = "low";
  for (const it of items) {
    if (order[it.riskLevel] > order[best]) best = it.riskLevel;
  }
  return {
    level: best,
    openCount: items.length,
    kevCount: items.filter((i) => i.inKev).length,
  };
}

function riskStroke(level: RiskLevel | "none", theme: "light" | "dark", lang: Language): {
  border: string;
  badgeBg: string;
  badgeText: string;
  label: string;
} {
  switch (level) {
    case "critical":
      return {
        border: "#F25C2A",
        badgeBg: "#F25C2A",
        badgeText: "#FFFFFF",
        label: pick(lang, "CRÍTICO", "CRITICAL"),
      };
    case "high":
      return {
        border: "#D97A34",
        badgeBg: "#D97A34",
        badgeText: "#FFFFFF",
        label: pick(lang, "ALTO", "HIGH"),
      };
    case "medium":
      return {
        border: "#C2A35B",
        badgeBg: "#C2A35B",
        badgeText: "#15171D",
        label: pick(lang, "MEDIO", "MEDIUM"),
      };
    case "low":
      return {
        border: "#4D8B74",
        badgeBg: "#4D8B74",
        badgeText: "#FFFFFF",
        label: pick(lang, "BAJO", "LOW"),
      };
    default:
      return {
        border: theme === "light" ? "#CBD5E1" : "#343A49",
        badgeBg: theme === "light" ? "#E2E8F0" : "#2B303D",
        badgeText: theme === "light" ? "#475569" : "#949BAA",
        label: pick(lang, "SIN CVES", "NO CVES"),
      };
  }
}

export function buildZoneMapSvg(
  audit: AuditProject,
  report: MatrixReport,
  theme: "light" | "dark",
  lang: Language = "es",
): string {
  const zones: { key: Exposure; title: string; subtitle: string; accent: string }[] = [
    {
      key: "internet",
      title: pick(lang, "01 · INTERNET / PERÍMETRO", "01 · INTERNET / PERIMETER"),
      subtitle: pick(lang, "Exposición directa externa", "Direct external exposure"),
      accent: "#F25C2A",
    },
    {
      key: "dmz",
      title: pick(lang, "02 · ZONA DMZ", "02 · DMZ ZONE"),
      subtitle: pick(lang, "Servicios intermedios segmentados", "Segmented intermediate services"),
      accent: "#D97A34",
    },
    {
      key: "internal",
      title: pick(lang, "03 · RED INTERNA / CORE", "03 · INTERNAL NETWORK / CORE"),
      subtitle: pick(lang, "AD, bases de datos y activos internos", "AD, databases & internal assets"),
      accent: "#4D8B74",
    },
  ];

  const grouped: Record<Exposure, Asset[]> = {
    internet: audit.assets.filter((a) => a.exposure === "internet"),
    dmz: audit.assets.filter((a) => a.exposure === "dmz"),
    internal: audit.assets.filter((a) => a.exposure === "internal"),
  };

  const colW = 310;
  const colGap = 36;
  const padX = 36;
  const padTop = 98;
  const padBottom = 56;
  const cardH = 82;
  const cardGap = 12;

  const maxRows = Math.max(
    1,
    grouped.internet.length,
    grouped.dmz.length,
    grouped.internal.length,
  );
  const colHeaderH = 56;
  const colBodyH = maxRows * cardH + Math.max(0, maxRows - 1) * cardGap + 28;
  const width = padX * 2 + colW * 3 + colGap * 2;
  const height = padTop + colHeaderH + colBodyH + padBottom;

  const bg = theme === "light" ? "#FFFFFF" : "#1C1F26";
  const colBg = theme === "light" ? "#F8FAFC" : "#181B22";
  const colBorder = theme === "light" ? "#E2E8F0" : "#2C313E";
  const cardBg = theme === "light" ? "#FFFFFF" : "#21252F";
  const titleColor = theme === "light" ? "#15171D" : "#F2DFC8";
  const textColor = theme === "light" ? "#1E293B" : "#E6E1D9";
  const mutedColor = theme === "light" ? "#64748B" : "#8C93A3";

  let svgBody = "";

  zones.forEach((zone, zIdx) => {
    const x = padX + zIdx * (colW + colGap);
    const y = padTop;
    const totalColH = colHeaderH + colBodyH;
    const assets = grouped[zone.key];

    // Contenedor de zona
    svgBody += `
      <rect x="${x}" y="${y}" width="${colW}" height="${totalColH}" rx="10" fill="${colBg}" stroke="${colBorder}" stroke-width="1.5" />
      <rect x="${x}" y="${y}" width="${colW}" height="4" rx="2" fill="${zone.accent}" />
      <text x="${x + 16}" y="${y + 26}" font-size="11" font-weight="700" letter-spacing="1" fill="${zone.accent}">${escapeXml(zone.title)}</text>
      <text x="${x + 16}" y="${y + 44}" font-size="11" fill="${mutedColor}">${escapeXml(zone.subtitle)} (${assets.length})</text>
    `;

    // Flecha hacia la siguiente zona
    if (zIdx < 2) {
      const arrowX1 = x + colW + 6;
      const arrowX2 = x + colW + colGap - 6;
      const arrowY = y + totalColH / 2;
      svgBody += `
        <line x1="${arrowX1}" y1="${arrowY}" x2="${arrowX2 - 6}" y2="${arrowY}" stroke="${mutedColor}" stroke-width="1.5" stroke-dasharray="4 3" />
        <polygon points="${arrowX2},${arrowY} ${arrowX2 - 8},${arrowY - 4} ${arrowX2 - 8},${arrowY + 4}" fill="${mutedColor}" />
      `;
    }

    if (assets.length === 0) {
      svgBody += `<text x="${x + colW / 2}" y="${y + colHeaderH + 46}" text-anchor="middle" font-size="11" fill="${mutedColor}">Sin activos en esta zona</text>`;
    } else {
      assets.forEach((asset, aIdx) => {
        const cy = y + colHeaderH + 12 + aIdx * (cardH + cardGap);
        const cx = x + 14;
        const cw = colW - 28;
        const stats = highestLevelForAsset(asset.id, report);
        const style = riskStroke(stats.level, theme, lang);

        const shortName =
          asset.name.length > 26 ? `${asset.name.slice(0, 24)}…` : asset.name;
        const shortHost =
          asset.host.length > 36 ? `${asset.host.slice(0, 34)}…` : asset.host;

        svgBody += `
          <rect x="${cx}" y="${cy}" width="${cw}" height="${cardH}" rx="8" fill="${cardBg}" stroke="${style.border}" stroke-width="1.5" />
          <text x="${cx + 12}" y="${cy + 23}" font-size="12" font-weight="700" fill="${textColor}">${escapeXml(shortName)}</text>
          <text x="${cx + 12}" y="${cy + 41}" font-size="10" fill="${mutedColor}">${escapeXml(shortHost)}</text>
          <rect x="${cx + 12}" y="${cy + 52}" width="66" height="19" rx="4" fill="${style.badgeBg}" />
          <text x="${cx + 45}" y="${cy + 65}" text-anchor="middle" font-size="9" font-weight="700" fill="${style.badgeText}">${style.label}</text>
          <text x="${cx + 86}" y="${cy + 65}" font-size="10" fill="${mutedColor}">Crit. ${asset.criticality}/5 · ${stats.openCount} CVE(s)${stats.kevCount > 0 ? " · KEV" : ""}</text>
        `;
      });
    }
  });

  const safeSubtitle = `${escapeXml(audit.name)} · ${escapeXml(audit.client)} · ${escapeXml(audit.date)}`;

  const rawSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" font-family="Inter, Segoe UI, Arial, sans-serif">
    <rect width="100%" height="100%" fill="${bg}" />
    <circle cx="44" cy="36" r="7" fill="none" stroke="#F25C2A" stroke-width="3" />
    <text x="62" y="41" font-size="18" font-weight="700" fill="${titleColor}">SecImpact — ${pick(lang, "Mapa de Exposición por Zonas", "Zone Exposure Map")}</text>
    <text x="62" y="64" font-size="12" fill="${mutedColor}">${safeSubtitle}</text>
    ${svgBody}
    <text x="${width / 2}" y="${height - 18}" text-anchor="middle" font-size="11" fill="${mutedColor}">${pick(lang, "Superficie de ataque", "Attack surface")}: Internet (${grouped.internet.length}) → DMZ (${grouped.dmz.length}) → ${pick(lang, "Red Interna", "Internal Network")} (${grouped.internal.length}) · ${pick(lang, "Generado con SecImpact", "Generated with SecImpact")}</text>
  </svg>`;

  return sanitizeSvg(rawSvg);
}
