import { invoke } from "@tauri-apps/api/core";
import type {
  Asset,
  AuditProject,
  CveEnrichment,
  Finding,
  GrcFramework,
  MatrixCell,
  MatrixReport,
  NmapImportResult,
  RiskItem,
  RiskLevel,
} from "./types";

export function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export async function lookupCve(cveId: string): Promise<CveEnrichment | null> {
  if (isTauriRuntime()) {
    try {
      return await invoke<CveEnrichment>("lookup_cve", { cveId });
    } catch {
      return null;
    }
  }
  return null;
}

export async function importNmapXml(xmlContent: string): Promise<NmapImportResult> {
  if (isTauriRuntime()) {
    return invoke<NmapImportResult>("import_nmap_xml", { xmlContent });
  }
  throw new Error("La importación de Nmap XML requiere ejecutar la aplicación de escritorio.");
}

export async function fetchSampleAudit(): Promise<AuditProject> {
  if (isTauriRuntime()) {
    return invoke<AuditProject>("get_sample_audit");
  }
  return fallbackSampleAudit();
}

export async function computeImpactMatrix(audit: AuditProject): Promise<MatrixReport> {
  if (isTauriRuntime()) {
    return invoke<MatrixReport>("calculate_impact_matrix", { audit });
  }
  return fallbackCalculateMatrix(audit);
}

export async function generateMarkdownReport(audit: AuditProject): Promise<string> {
  if (isTauriRuntime()) {
    return invoke<string>("export_markdown_report", { audit });
  }
  return fallbackMarkdown(audit);
}

// --- Fallback en navegador para vista previa rápida con `npm run dev` ---

function classifyRiskLevel(score: number, matrixSize: number): RiskLevel {
  const ratio = score / (matrixSize * matrixSize);
  if (ratio >= 0.64) return "critical";
  if (ratio >= 0.38) return "high";
  if (ratio >= 0.19) return "medium";
  return "low";
}

function scaleToMatrix(val5: number, n: number): number {
  const clamped = Math.min(5, Math.max(1, val5));
  const scaled = 1 + ((clamped - 1) / 4) * (n - 1);
  return Math.min(n, Math.max(1, Math.round(scaled)));
}

function detectVulnCategory(asset: Asset, finding: Finding) {
  const t = `${finding.cveId} ${finding.cwe ?? ""} ${finding.title} ${finding.description}`.toLowerCase();
  if (/backdoor|malicious|trojan|supply chain|vsftpd|cwe-506|cwe-912/.test(t)) return "backdoor";
  if (/denial of service|denegación de servicio| dos |range header|resource consumption|exhaustion|cwe-400|cwe-770/.test(t)) return "dos";
  if (/rce|command injection|shell metacharacters|arbitrary commands|execute arbitrary|log4j|log4shell|jndi|deserializ|ejecución remota|cwe-78|cwe-77|cwe-94|cwe-502/.test(t)) return "rce";
  if (/ntlm|kerberos|privilege|privilegio|authentication|autenticación|bypass|credencial|cwe-287|cwe-269|cwe-306/.test(t) || asset.assetType === "activeDirectory") return "auth";
  if (/sql|database|base de datos|postgres|mysql|cwe-89/.test(t) || asset.assetType === "database") return "db";
  if (/vpn|ssh|smb|samba|firewall|gateway|perimetral/.test(t) || asset.assetType === "network") return "net";
  if (/xss|csrf|ssrf|cross-site|http|apache|nginx|api|cwe-79|cwe-352|cwe-918/.test(t) || asset.assetType === "webApp") return "web";
  if (/buffer overflow|heap|libcurl|openssl|memory|memoria|cwe-119|cwe-120|cwe-787/.test(t)) return "mem";
  return "general";
}

function mapGrcControl(fw: GrcFramework, asset: Asset, finding: Finding): string {
  const cat = detectVulnCategory(asset, finding);
  const map: Record<GrcFramework, Record<string, string>> = {
    cisControls: {
      backdoor: "CIS v8 · 2.5 / 10.1 (Software Autorizado y Defensa Antimalware)",
      dos: "CIS v8 · 4.1 / 13.6 (Configuración Segura y Protección de Red)",
      auth: "CIS v8 · 5.2 / 6.3 (Gestión de Cuentas y Control de Acceso)",
      rce: "CIS v8 · 7.4 / 16.11 (Remediación Crítica y Código Seguro)",
      db: "CIS v8 · 3.3 / 3.11 (Protección de Datos y Mínimo Privilegio)",
      net: "CIS v8 · 12.2 / 13.6 (Infraestructura Segura y Segmentación)",
      web: "CIS v8 · 16.1 / 16.12 (Seguridad de Aplicaciones Web/API)",
      mem: "CIS v8 · 2.2 / 7.4 (Inventario de Librerías y Parcheo)",
      general: "CIS v8 · 7.4 (Gestión Continua de Vulnerabilidades)",
    },
    iso27001: {
      backdoor: "ISO 27001:2022 · A.8.7 / A.8.19 (Protección contra Malware e Integridad)",
      dos: "ISO 27001:2022 · A.8.6 / A.8.20 (Capacidad y Disponibilidad de Red)",
      auth: "ISO 27001:2022 · A.5.15 / A.8.2 (Control de Acceso y Privilegios)",
      rce: "ISO 27001:2022 · A.8.8 / A.8.28 (Vulnerabilidades y Código Seguro)",
      db: "ISO 27001:2022 · A.8.12 / A.8.24 (Prevención de Fuga y Cifrado)",
      net: "ISO 27001:2022 · A.8.20 / A.8.22 (Seguridad y Segmentación de Redes)",
      web: "ISO 27001:2022 · A.8.26 / A.8.28 (Seguridad en Aplicaciones)",
      mem: "ISO 27001:2022 · A.8.8 / A.8.19 (Gestión de Software y Parches)",
      general: "ISO 27001:2022 · A.8.8 (Gestión de Vulnerabilidades Técnicas)",
    },
    nistCsf: {
      backdoor: "NIST CSF 2.0 · GV.SC-07 / DE.CM-09 (Cadena de Suministro y Malware)",
      dos: "NIST CSF 2.0 · PR.IR-04 (Resiliencia y Disponibilidad de Servicios)",
      auth: "NIST CSF 2.0 · PR.AA-01 / PR.AA-05 (Identidades y Privilegios)",
      rce: "NIST CSF 2.0 · ID.RA-01 / RS.MI-02 (Mitigación de RCE Crítico)",
      db: "NIST CSF 2.0 · PR.DS-01 / PR.DS-02 (Protección de Datos)",
      net: "NIST CSF 2.0 · PR.IR-01 / DE.CM-01 (Perímetro y Monitoreo de Red)",
      web: "NIST CSF 2.0 · PR.PS-06 (Desarrollo y Despliegue Seguro)",
      mem: "NIST CSF 2.0 · PR.PS-02 (Mantenimiento de Software y Librerías)",
      general: "NIST CSF 2.0 · ID.RA-01 (Identificación de Vulnerabilidades)",
    },
    owaspTop10: {
      backdoor: "OWASP A03:2025 · Software Supply Chain Failures",
      dos: "OWASP A10:2025 · Mishandling of Exceptional Conditions",
      auth: "OWASP A07:2025 · Authentication Failures",
      rce: "OWASP A05:2025 · Injection (RCE / Command Injection)",
      db: "OWASP A05:2025 · Injection / A04 Cryptographic Failures",
      net: "OWASP A02:2025 · Security Misconfiguration",
      web: "OWASP A01:2025 · Broken Access Control (incl. SSRF)",
      mem: "OWASP A03:2025 · Software Supply Chain Failures",
      general: "OWASP A03:2025 · Software Supply Chain Failures",
    },
  };
  return map[fw][cat];
}

function slaForLevel(level: RiskLevel): string {
  if (level === "critical") return "Inmediato (24–72h)";
  if (level === "high") return "Corto plazo (7–15 días)";
  if (level === "medium") return "Mediano plazo (30 días)";
  return "Mantenimiento (90 días)";
}

function fallbackCalculateMatrix(audit: AuditProject): MatrixReport {
  const n = audit.config?.matrixSize ?? 5;
  const maxScore = n * n;
  const assetMap = new Map(audit.assets.map((a) => [a.id, a]));
  const planned = new Set(audit.plannedRemediationIds ?? []);
  const overrides = audit.overrides ?? {};
  const items: RiskItem[] = [];

  for (const finding of audit.findings) {
    for (const assetId of finding.assetIds) {
      const asset = assetMap.get(assetId);
      if (!asset) continue;

      const id = `${finding.id}__${asset.id}`;
      const crit = Math.min(5, Math.max(1, asset.criticality));
      const cvssScaled = (Math.min(10, Math.max(0, finding.cvss)) / 10) * 4 + 1;
      const suggestedImpact = scaleToMatrix(crit * 0.65 + cvssScaled * 0.35, n);

      const epss = Math.min(100, Math.max(0, finding.epss));
      let l5 = epss >= 70 ? 5 : epss >= 40 ? 4 : epss >= 15 ? 3 : epss >= 3 ? 2 : 1;
      if (finding.inKev) l5 = Math.max(l5, 4) + 1;
      if (asset.exposure === "internet") l5 += 0.8;
      else if (asset.exposure === "dmz") l5 += 0.3;
      else l5 -= 0.4;
      const suggestedLikelihood = scaleToMatrix(l5, n);

      const ov = overrides[id];
      const impact = ov ? Math.min(n, Math.max(1, ov.impact)) : suggestedImpact;
      const likelihood = ov ? Math.min(n, Math.max(1, ov.likelihood)) : suggestedLikelihood;
      const riskScore = impact * likelihood;
      const expTxt =
        asset.exposure === "internet"
          ? "expuesto a Internet"
          : asset.exposure === "dmz"
            ? "en DMZ"
            : "en red interna";

      items.push({
        id,
        findingId: finding.id,
        cveId: finding.cveId,
        title: finding.title,
        assetId: asset.id,
        assetName: asset.name,
        assetHost: asset.host,
        assetType: asset.assetType,
        exposure: asset.exposure,
        assetCriticality: asset.criticality,
        cvss: finding.cvss,
        epss: finding.epss,
        inKev: finding.inKev,
        status: finding.status,
        suggestedImpact,
        suggestedLikelihood,
        suggestionReason: `Criticidad ${asset.criticality}/5 (${expTxt}) · CVSS ${finding.cvss.toFixed(1)} · EPSS ${finding.epss.toFixed(1)}%${finding.inKev ? " + CISA KEV" : ""}`,
        impact,
        likelihood,
        isCalibrated: Boolean(ov),
        auditorNote: ov?.note ?? "",
        riskScore,
        maxScore,
        riskLevel: classifyRiskLevel(riskScore, n),
        slaWindow: slaForLevel(classifyRiskLevel(riskScore, n)),
        grcControl: ov?.customGrcControl || mapGrcControl(audit.config.framework, asset, finding),
        remediation: finding.remediation,
        inRemediationPlan: planned.has(id),
      });
    }
  }

  items.sort((a, b) => {
    const ao = a.status === "open" ? 1 : 0;
    const bo = b.status === "open" ? 1 : 0;
    if (bo !== ao) return bo - ao;
    if (b.riskScore !== a.riskScore) return b.riskScore - a.riskScore;
    if (b.inKev !== a.inKev) return Number(b.inKev) - Number(a.inKev);
    return b.cvss - a.cvss;
  });

  const cells: MatrixCell[] = [];
  for (let impact = n; impact >= 1; impact--) {
    for (let likelihood = 1; likelihood <= n; likelihood++) {
      const matching = items
        .filter((i) => i.status === "open" && i.impact === impact && i.likelihood === likelihood)
        .map((i) => i.id);
      const score = impact * likelihood;
      cells.push({
        impact,
        likelihood,
        score,
        level: classifyRiskLevel(score, n),
        count: matching.length,
        itemIds: matching,
      });
    }
  }

  const openItems = items.filter((i) => i.status === "open");
  const residualItems = openItems.filter((i) => !i.inRemediationPlan);
  const currentSum = openItems.reduce((s, i) => s + i.riskScore, 0);
  const residualSum = residualItems.reduce((s, i) => s + i.riskScore, 0);

  return {
    summary: {
      matrixSize: n,
      maxScore,
      totalAssets: audit.assets.length,
      totalFindings: audit.findings.length,
      openRiskPairs: openItems.length,
      criticalCount: openItems.filter((i) => i.riskLevel === "critical").length,
      highCount: openItems.filter((i) => i.riskLevel === "high").length,
      mediumCount: openItems.filter((i) => i.riskLevel === "medium").length,
      lowCount: openItems.filter((i) => i.riskLevel === "low").length,
      kevCount: openItems.filter((i) => i.inKev).length,
      calibratedCount: openItems.filter((i) => i.isCalibrated).length,
      currentAvgScore:
        openItems.length === 0 ? 0 : Math.round((currentSum / openItems.length) * 10) / 10,
      residualOpenPairs: residualItems.length,
      residualCriticalCount: residualItems.filter((i) => i.riskLevel === "critical").length,
      residualHighCount: residualItems.filter((i) => i.riskLevel === "high").length,
      residualAvgScore:
        residualItems.length === 0 ? 0 : Math.round((residualSum / residualItems.length) * 10) / 10,
      riskReductionPct:
        currentSum <= 0 ? 0 : Math.round(((currentSum - residualSum) / currentSum) * 1000) / 10,
    },
    cells,
    items,
  };
}

function fallbackMarkdown(audit: AuditProject): string {
  const report = fallbackCalculateMatrix(audit);
  const n = report.summary.matrixSize;
  return [
    `# Informe de Gestión de Riesgos — ${audit.name}`,
    "",
    `- **Organización:** ${audit.client}`,
    `- **Auditor:** ${audit.auditor}`,
    `- **Metodología:** Matriz ${n}×${n}`,
    "",
    `## Riesgo Actual vs. Residual`,
    `- Críticos: **${report.summary.criticalCount} → ${report.summary.residualCriticalCount}**`,
    `- Reducción estimada: **-${report.summary.riskReductionPct.toFixed(1)}%**`,
    "",
    "## Plan de Remediación Priorizado",
    "",
    "| CVE | Activo | Nivel | Score | Control GRC | Nota |",
    "| :--- | :--- | :---: | :---: | :--- | :--- |",
    ...report.items
      .filter((i) => i.status === "open")
      .map(
        (i) =>
          `| \`${i.cveId}\` | ${i.assetName} | **${i.riskLevel.toUpperCase()}** | ${i.riskScore}/${i.maxScore} | ${i.grcControl} | ${i.auditorNote || "Automático"} |`,
      ),
  ].join("\n");
}

function fallbackSampleAudit(): AuditProject {
  return {
    name: "Auditoría Infraestructura Q4",
    client: "Acme FinTech S.A.",
    auditor: "Equipo Seguridad & GRC",
    date: "2026-11-22",
    config: {
      matrixSize: 5,
      framework: "cisControls",
    },
    assets: [
      {
        id: "asset-1",
        name: "Portal Clientes Web",
        host: "portal.acmefintech.com (203.0.113.15)",
        assetType: "webApp",
        exposure: "internet",
        criticality: 5,
        owner: "Ingeniería Web",
      },
      {
        id: "asset-2",
        name: "VPN Gateway Perimetral",
        host: "vpn.acmefintech.com (203.0.113.2)",
        assetType: "network",
        exposure: "internet",
        criticality: 5,
        owner: "Infraestructura & Redes",
      },
      {
        id: "asset-3",
        name: "Base de Datos Core Clientes",
        host: "10.20.4.10",
        assetType: "database",
        exposure: "internal",
        criticality: 5,
        owner: "DBA / Datos",
      },
      {
        id: "asset-4",
        name: "Active Directory Principal (DC01)",
        host: "10.20.1.5",
        assetType: "activeDirectory",
        exposure: "internal",
        criticality: 5,
        owner: "Identidad y Accesos",
      },
      {
        id: "asset-5",
        name: "Servidor API Pagos (DMZ)",
        host: "172.16.10.22",
        assetType: "server",
        exposure: "dmz",
        criticality: 4,
        owner: "Plataforma Pagos",
      },
      {
        id: "asset-6",
        name: "Servidor Staging / Pruebas",
        host: "10.20.99.40",
        assetType: "server",
        exposure: "internal",
        criticality: 2,
        owner: "QA",
      },
    ],
    findings: [
      {
        id: "find-1",
        cveId: "CVE-2024-21887",
        title: "Command Injection en Gateway VPN",
        description: "Ejecución remota de comandos en appliance perimetral.",
        cvss: 9.1,
        epss: 94.2,
        inKev: true,
        status: "open",
        assetIds: ["asset-2"],
        remediation: "Aplicar parche del fabricante y rotar credenciales VPN.",
      },
      {
        id: "find-2",
        cveId: "CVE-2021-44228",
        title: "Log4Shell — RCE en componente Java",
        description: "Ejecución remota de código vía JNDI lookup.",
        cvss: 10.0,
        epss: 97.5,
        inKev: true,
        status: "open",
        assetIds: ["asset-1", "asset-5"],
        remediation: "Actualizar Log4j >= 2.17.1 y bloquear salidas LDAP/RMI.",
      },
      {
        id: "find-3",
        cveId: "CVE-2024-6387",
        title: "regreSSHion — Race Condition en OpenSSH",
        description: "Condición de carrera en sshd que permite RCE como root.",
        cvss: 8.1,
        epss: 36.4,
        inKev: false,
        status: "open",
        assetIds: ["asset-5", "asset-6"],
        remediation: "Actualizar OpenSSH >= 9.8p1 y restringir SSH al bastión.",
      },
      {
        id: "find-4",
        cveId: "CVE-2023-23397",
        title: "Elevación de privilegios / NTLM Hash Leak",
        description: "Exposición de hashes NTLM internos.",
        cvss: 9.8,
        epss: 78.0,
        inKev: true,
        status: "open",
        assetIds: ["asset-4"],
        remediation: "Deshabilitar NTLMv1, bloquear SMB saliente y parchar.",
      },
      {
        id: "find-5",
        cveId: "CVE-2024-10978",
        title: "Fuga de memoria / Permisos en motor SQL",
        description: "Parche pendiente en base de datos interna.",
        cvss: 6.5,
        epss: 8.2,
        inKev: false,
        status: "open",
        assetIds: ["asset-3"],
        remediation: "Actualizar motor DB y revisar mínimo privilegio.",
      },
      {
        id: "find-6",
        cveId: "CVE-2023-38545",
        title: "Heap Buffer Overflow en libcurl (SOCKS5)",
        description: "Desbordamiento en librería cliente en servidor de pruebas.",
        cvss: 7.5,
        epss: 2.1,
        inKev: false,
        status: "open",
        assetIds: ["asset-6"],
        remediation: "Actualizar curl/libcurl >= 8.4.0.",
      },
    ],
    overrides: {},
    plannedRemediationIds: ["find-1__asset-2", "find-2__asset-1"],
  };
}
